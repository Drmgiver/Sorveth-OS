#![no_std]

//! Allocation-free physical frame accounting for the first Sorveth kernel.
//!
//! This is a *frame ownership planner*, not an installed memory manager.
//! It does not map memory, create page tables, access RAM or synchronize CPUs.
//! The caller must retain the allocator and reserve any independently owned
//! physical buffers before allocations. Releasing frames is intentionally
//! unsupported until object-lifetime and zeroing rules are implemented.

use sorveth_memory::{MapError, MemoryMap, PAGE_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysSpan {
    pub start: u64,
    pub pages: u64,
}

impl PhysSpan {
    pub fn end_exclusive(self) -> u64 {
        // Returned spans always satisfy this operation, proved at allocation.
        self.start + self.pages * PAGE_BYTES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidMap(MapError),
    InvalidRange,
    OverlappingFirmwareRegions,
    TooManyRegions,
    OutOfMemory,
    ReservationsClosed,
    ClaimLedgerFull,
}

#[derive(Clone, Copy)]
struct Region {
    start: u64,
    end: u64,
}
impl Region {
    const EMPTY: Self = Self { start: 0, end: 0 };
    fn pages(self) -> u64 {
        (self.end - self.start) / PAGE_BYTES
    }
    fn intersects(self, other: Region) -> bool {
        self.start < other.end && other.start < self.end
    }
}

pub struct FrameAllocator<const N: usize> {
    regions: [Region; N],
    used: usize,
    available_pages: u64,
    allocations_started: bool,
    claims: [Option<PhysSpan>; N],
    claim_count: usize,
}

impl<const N: usize> FrameAllocator<N> {
    /// Only UEFI ConventionalMemory is included. Loader, runtime, ACPI, MMIO
    /// and reserved types are deliberately not reclaimable at this phase.
    pub fn from_map(map: &MemoryMap<'_>) -> Result<Self, Error> {
        map.summarize().map_err(Error::InvalidMap)?;
        let mut result = Self {
            regions: [Region::EMPTY; N],
            used: 0,
            available_pages: 0,
            allocations_started: false,
            claims: [None; N],
            claim_count: 0,
        };

        for entry in map.descriptors() {
            if !entry.immediately_allocatable() || entry.number_of_pages == 0 {
                continue;
            }
            let end = entry.physical_end().map_err(Error::InvalidMap)?;
            if result.used == N {
                return Err(Error::TooManyRegions);
            }
            result.regions[result.used] = Region {
                start: entry.physical_start,
                end,
            };
            result.used += 1;
            result.available_pages = result
                .available_pages
                .checked_add(entry.number_of_pages)
                .ok_or(Error::InvalidRange)?;
        }

        // Sort the modest conventional-region list in-place. No heap or libc.
        // Detect overlapping descriptors: allocating the same frame twice is
        // substantially worse than refusing an odd firmware memory map.
        for i in 1..result.used {
            let mut j = i;
            while j > 0 && result.regions[j].start < result.regions[j - 1].start {
                result.regions.swap(j, j - 1);
                j -= 1;
            }
        }
        for i in 1..result.used {
            if result.regions[i - 1].end > result.regions[i].start {
                return Err(Error::OverlappingFirmwareRegions);
            }
        }

        // Also refuse a conventional range overlapping any *reserved* UEFI
        // descriptor; otherwise an inconsistent map could give out device RAM.
        for i in 0..result.used {
            let available = result.regions[i];
            for entry in map.descriptors() {
                if entry.immediately_allocatable() || entry.number_of_pages == 0 {
                    continue;
                }
                let other = Region {
                    start: entry.physical_start,
                    end: entry.physical_end().map_err(Error::InvalidMap)?,
                };
                if available.intersects(other) {
                    return Err(Error::OverlappingFirmwareRegions);
                }
            }
        }
        Ok(result)
    }

    pub fn available_pages(&self) -> u64 {
        self.available_pages
    }
    pub fn region_count(&self) -> usize {
        self.used
    }

    /// Number of irreversible spans claimed from conventional memory.
    pub fn claim_count(&self) -> usize {
        self.claim_count
    }

    /// Return one recorded claim without exposing allocator internals.
    pub fn claim_at(&self, index: usize) -> Option<PhysSpan> {
        if index < self.claim_count {
            self.claims[index]
        } else {
            None
        }
    }

    /// Whether an aligned physical page belongs to any recorded claim.
    pub fn owns_frame(&self, frame: u64) -> bool {
        if frame % PAGE_BYTES != 0 {
            return false;
        }
        self.claims[..self.claim_count]
            .iter()
            .flatten()
            .any(|span| frame >= span.start && frame < span.end_exclusive())
    }

    /// Prevent future allocation of a physical range. This must complete
    /// before the first frame allocation to avoid reserving an in-use page.
    /// A reservation may overlap gaps; only conventional pages are removed.
    /// On failure the available regions remain unmodified.
    pub fn reserve(&mut self, start: u64, pages: u64) -> Result<(), Error> {
        if self.allocations_started {
            return Err(Error::ReservationsClosed);
        }
        if pages == 0 || start % PAGE_BYTES != 0 {
            return Err(Error::InvalidRange);
        }
        let length = pages.checked_mul(PAGE_BYTES).ok_or(Error::InvalidRange)?;
        let end = start.checked_add(length).ok_or(Error::InvalidRange)?;
        let reservation = Region { start, end };
        let mut splits = 0usize;
        for index in 0..self.used {
            let r = self.regions[index];
            if r.intersects(reservation) && start > r.start && end < r.end {
                splits += 1;
            }
        }
        if splits > N - self.used {
            return Err(Error::TooManyRegions);
        }

        let mut index = 0;
        while index < self.used {
            let r = self.regions[index];
            if !r.intersects(reservation) {
                index += 1;
                continue;
            }
            let overlap_start = r.start.max(start);
            let overlap_end = r.end.min(end);
            self.available_pages -= (overlap_end - overlap_start) / PAGE_BYTES;
            if overlap_start == r.start && overlap_end == r.end {
                // O(1) removal; region order is not significant to safety.
                self.used -= 1;
                self.regions[index] = self.regions[self.used];
                self.regions[self.used] = Region::EMPTY;
                continue;
            }
            if overlap_start == r.start {
                self.regions[index].start = overlap_end;
            } else if overlap_end == r.end {
                self.regions[index].end = overlap_start;
            } else {
                self.regions[index].end = overlap_start;
                self.regions[self.used] = Region {
                    start: overlap_end,
                    end: r.end,
                };
                self.used += 1;
            }
            index += 1;
        }
        Ok(())
    }

    /// Reserve all physical pages touched by an arbitrary byte range.
    /// Unlike reserve(), this accepts unaligned buffer addresses and lengths.
    /// Refuses wraparound rather than silently leaving a tail unprotected.
    pub fn reserve_bytes(&mut self, start: u64, bytes: u64) -> Result<(), Error> {
        if bytes == 0 {
            return Ok(());
        }
        let end = start.checked_add(bytes).ok_or(Error::InvalidRange)?;
        let rounded_end =
            end.checked_add(PAGE_BYTES - 1).ok_or(Error::InvalidRange)? & !(PAGE_BYTES - 1);
        let aligned_start = start & !(PAGE_BYTES - 1);
        self.reserve(aligned_start, (rounded_end - aligned_start) / PAGE_BYTES)
    }

    /// Hand out one contiguous physical span, without mapping or touching it.
    /// All allocations are page-aligned and permanently removed from this
    /// prototype planner's free ranges. A future manager must also zero pages.
    pub fn allocate(&mut self, pages: u64) -> Result<PhysSpan, Error> {
        if pages == 0 {
            return Err(Error::InvalidRange);
        }
        for index in 0..self.used {
            let range = self.regions[index];
            if range.pages() >= pages {
                if self.claim_count == N {
                    return Err(Error::ClaimLedgerFull);
                }
                let bytes = pages.checked_mul(PAGE_BYTES).ok_or(Error::InvalidRange)?;
                let start = range.start;
                // A failed request must not lock out later reservations.
                self.allocations_started = true;
                self.regions[index].start += bytes;
                self.available_pages -= pages;
                if self.regions[index].start == self.regions[index].end {
                    self.used -= 1;
                    self.regions[index] = self.regions[self.used];
                    self.regions[self.used] = Region::EMPTY;
                }
                let claim = PhysSpan { start, pages };
                self.claims[self.claim_count] = Some(claim);
                self.claim_count += 1;
                return Ok(claim);
            }
        }
        Err(Error::OutOfMemory)
    }
}

/// A page claim means *ownership*, not that the bytes are mapped or zeroed.
/// No reclaimed pages are admitted, so claims remain irreversible in M1-A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStatus {
    pub available_pages: u64,
    pub regions: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    NotInstalled,
    AlreadyInstalled,
    Allocation(Error),
}

/// A single persistent, statically allocated frame ledger.
/// The atomic guard serializes access if other CPUs are introduced.
/// Locking is non-reentrant; do not invoke callbacks or halt while holding it.
pub struct FramePool<const N: usize> {
    locked: core::sync::atomic::AtomicBool,
    state: core::cell::UnsafeCell<Option<FrameAllocator<N>>>,
}

// Safety: all access to UnsafeCell is mediated by the acquire/release spinlock.
// FrameAllocator only stores integers and has no references to firmware buffers.
unsafe impl<const N: usize> Sync for FramePool<N> {}

struct PoolGuard<'a, const N: usize> {
    pool: &'a FramePool<N>,
}

impl<const N: usize> PoolGuard<'_, N> {
    fn state(&mut self) -> &mut Option<FrameAllocator<N>> {
        // Safety: only a successful atomic lock acquisition creates a guard.
        unsafe { &mut *self.pool.state.get() }
    }
}

impl<const N: usize> Drop for PoolGuard<'_, N> {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        self.pool.locked.store(false, Ordering::Release);
    }
}

impl<const N: usize> FramePool<N> {
    pub const fn new() -> Self {
        Self {
            locked: core::sync::atomic::AtomicBool::new(false),
            state: core::cell::UnsafeCell::new(None),
        }
    }

    fn lock(&self) -> PoolGuard<'_, N> {
        use core::sync::atomic::Ordering;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        PoolGuard { pool: self }
    }

    /// Transfers ownership of the prepared allocator into the permanent pool.
    /// Rejects accidental reinitialization; never resets existing claims.
    pub fn install(&self, allocator: FrameAllocator<N>) -> Result<(), PoolError> {
        let mut guard = self.lock();
        let slot = guard.state();
        if slot.is_some() {
            return Err(PoolError::AlreadyInstalled);
        }
        *slot = Some(allocator);
        Ok(())
    }

    pub fn status(&self) -> Result<PoolStatus, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_ref().ok_or(PoolError::NotInstalled)?;
        Ok(PoolStatus {
            available_pages: allocator.available_pages(),
            regions: allocator.region_count(),
        })
    }

    /// Claims a frame span without mapping or clearing it. Do not dereference
    /// the returned physical address until paging and zeroing are implemented.
    pub fn claim_unmapped(&self, pages: u64) -> Result<PhysSpan, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator.allocate(pages).map_err(PoolError::Allocation)
    }

    /// Number of persistent physical claims, including claims made before
    /// the ledger was installed into this pool.
    pub fn claim_count(&self) -> Result<usize, PoolError> {
        let mut guard = self.lock();
        Ok(guard
            .state()
            .as_ref()
            .ok_or(PoolError::NotInstalled)?
            .claim_count())
    }

    /// Read a claim span from the ownership ledger.
    pub fn claim_at(&self, index: usize) -> Result<Option<PhysSpan>, PoolError> {
        let mut guard = self.lock();
        Ok(guard
            .state()
            .as_ref()
            .ok_or(PoolError::NotInstalled)?
            .claim_at(index))
    }

    /// Check whether one aligned page belongs to a recorded Sorveth claim.
    pub fn owns_frame(&self, frame: u64) -> Result<bool, PoolError> {
        let mut guard = self.lock();
        Ok(guard
            .state()
            .as_ref()
            .ok_or(PoolError::NotInstalled)?
            .owns_frame(frame))
    }
}

impl<const N: usize> Default for FramePool<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn desc(kind: u32, addr: u64, pages: u64) -> Vec<u8> {
        let mut data = std::vec![0; 48];
        data[0..4].copy_from_slice(&kind.to_le_bytes());
        data[8..16].copy_from_slice(&addr.to_le_bytes());
        data[24..32].copy_from_slice(&pages.to_le_bytes());
        data
    }
    fn map(bytes: &[u8]) -> MemoryMap<'_> {
        MemoryMap::from_bytes(bytes, 48).unwrap()
    }

    #[test]
    fn allocates_only_conventional_and_preserves_distinct_frames() {
        let mut data = desc(7, 0x1000, 4);
        data.extend_from_slice(&desc(11, 0x5000, 4));
        data.extend_from_slice(&desc(7, 0x9000, 2));
        let mut a = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        assert_eq!(a.available_pages(), 6);
        let first = a.allocate(3).unwrap();
        assert_eq!(
            first,
            PhysSpan {
                start: 0x1000,
                pages: 3
            }
        );
        assert_eq!(first.end_exclusive(), 0x4000);
        assert_eq!(a.allocate(2).unwrap().start, 0x9000);
        assert_eq!(a.allocate(1).unwrap().start, 0x4000);
        assert_eq!(a.available_pages(), 0);
        assert_eq!(a.allocate(1), Err(Error::OutOfMemory));
    }

    #[test]
    fn reservation_splits_ranges_and_never_returns_reserved_frames() {
        let data = desc(7, 0x1000, 10);
        let mut a = FrameAllocator::<2>::from_map(&map(&data)).unwrap();
        a.reserve(0x4000, 3).unwrap(); // Remove 0x4000..0x7000.
        assert_eq!(a.region_count(), 2);
        assert_eq!(a.available_pages(), 7);
        assert_eq!(a.allocate(3).unwrap().start, 0x1000);
        assert_eq!(a.allocate(4).unwrap().start, 0x7000);
        assert_eq!(a.allocate(1), Err(Error::OutOfMemory));
    }

    #[test]
    fn failed_split_is_transactional() {
        let data = desc(7, 0x1000, 10);
        let mut a = FrameAllocator::<1>::from_map(&map(&data)).unwrap();
        assert_eq!(a.reserve(0x4000, 3), Err(Error::TooManyRegions));
        assert_eq!(a.available_pages(), 10);
        assert_eq!(a.allocate(10).unwrap().start, 0x1000);
    }

    #[test]
    fn forbids_reservation_after_allocations_begin() {
        let data = desc(7, 0x1000, 3);
        let mut a = FrameAllocator::<2>::from_map(&map(&data)).unwrap();
        a.allocate(1).unwrap();
        assert_eq!(a.reserve(0x2000, 1), Err(Error::ReservationsClosed));
        assert_eq!(a.available_pages(), 2);
    }

    #[test]
    fn failed_allocation_does_not_close_reservation_phase() {
        let data = desc(7, 0x1000, 3);
        let mut a = FrameAllocator::<2>::from_map(&map(&data)).unwrap();
        assert_eq!(a.allocate(4), Err(Error::OutOfMemory));
        assert_eq!(a.available_pages(), 3);
        a.reserve(0x2000, 1).unwrap();
        assert_eq!(a.available_pages(), 2);
        assert_eq!(a.allocate(1).unwrap().start, 0x1000);
        assert_eq!(a.allocate(1).unwrap().start, 0x3000);
        assert_eq!(a.allocate(1), Err(Error::OutOfMemory));
    }

    #[test]
    fn byte_reservations_include_partial_pages_and_fail_closed() {
        let data = desc(7, 0x1000, 6);
        let mut a = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        a.reserve_bytes(0x2001, 4096).unwrap();
        assert_eq!(a.available_pages(), 4);
        assert_eq!(a.allocate(2).unwrap().start, 0x4000);
        assert_eq!(a.allocate(1).unwrap().start, 0x1000);
        assert_eq!(a.allocate(1).unwrap().start, 0x6000);
        assert_eq!(a.allocate(1), Err(Error::OutOfMemory));

        let mut b = FrameAllocator::<2>::from_map(&map(&data)).unwrap();
        assert_eq!(b.reserve_bytes(u64::MAX - 3, 8), Err(Error::InvalidRange));
        assert_eq!(b.available_pages(), 6);
        b.reserve_bytes(0x1000, 0).unwrap();
        assert_eq!(b.available_pages(), 6);
    }

    #[test]
    fn persistent_pool_tracks_claims_and_cannot_be_reinitialized() {
        let data = desc(7, 0x1000, 5);
        let pool = FramePool::<4>::new();
        assert_eq!(pool.status(), Err(PoolError::NotInstalled));
        assert_eq!(pool.claim_unmapped(1), Err(PoolError::NotInstalled));

        let mut planner = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        planner.reserve_bytes(0x1000, 4096).unwrap();
        pool.install(planner).unwrap();
        assert_eq!(pool.status().unwrap().available_pages, 4);
        assert_eq!(
            pool.install(FrameAllocator::<4>::from_map(&map(&data)).unwrap()),
            Err(PoolError::AlreadyInstalled)
        );
        assert_eq!(pool.claim_unmapped(2).unwrap().start, 0x2000);
        assert_eq!(pool.claim_unmapped(2).unwrap().start, 0x4000);
        assert_eq!(pool.status().unwrap().available_pages, 0);
        assert_eq!(
            pool.claim_unmapped(1),
            Err(PoolError::Allocation(Error::OutOfMemory))
        );
    }

    #[test]
    fn overlapping_firmware_descriptors_are_rejected() {
        let mut data = desc(7, 0x1000, 4);
        data.extend_from_slice(&desc(11, 0x3000, 1));
        assert!(matches!(
            FrameAllocator::<4>::from_map(&map(&data)),
            Err(Error::OverlappingFirmwareRegions)
        ));
        let mut data = desc(7, 0x1000, 4);
        data.extend_from_slice(&desc(7, 0x4000, 3));
        assert!(matches!(
            FrameAllocator::<4>::from_map(&map(&data)),
            Err(Error::OverlappingFirmwareRegions)
        ));
    }

    #[test]
    fn handles_empty_and_invalid_requests() {
        let data = desc(7, 0x1000, 1);
        let mut a = FrameAllocator::<1>::from_map(&map(&data)).unwrap();
        assert_eq!(a.reserve(0x1001, 1), Err(Error::InvalidRange));
        assert_eq!(a.reserve(0x1000, u64::MAX), Err(Error::InvalidRange));
        assert_eq!(a.allocate(0), Err(Error::InvalidRange));
        assert_eq!(a.allocate(2), Err(Error::OutOfMemory));
        assert_eq!(a.allocate(1).unwrap().start, 0x1000);
    }
}
