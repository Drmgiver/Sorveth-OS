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
}

#[derive(Clone, Copy)]
struct Region { start: u64, end: u64 }
impl Region {
    const EMPTY: Self = Self { start: 0, end: 0 };
    fn pages(self) -> u64 { (self.end - self.start) / PAGE_BYTES }
    fn intersects(self, other: Region) -> bool {
        self.start < other.end && other.start < self.end
    }
}

pub struct FrameAllocator<const N: usize> {
    regions: [Region; N],
    used: usize,
    available_pages: u64,
    allocations_started: bool,
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
        };

        for entry in map.descriptors() {
            if !entry.immediately_allocatable() || entry.number_of_pages == 0 {
                continue;
            }
            let end = entry.physical_end().map_err(Error::InvalidMap)?;
            if result.used == N { return Err(Error::TooManyRegions); }
            result.regions[result.used] = Region {
                start: entry.physical_start,
                end,
            };
            result.used += 1;
            result.available_pages = result.available_pages
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

    pub fn available_pages(&self) -> u64 { self.available_pages }
    pub fn region_count(&self) -> usize { self.used }

    /// Prevent future allocation of a physical range. This must complete
    /// before the first frame allocation to avoid reserving an in-use page.
    /// A reservation may overlap gaps; only conventional pages are removed.
    /// On failure the available regions remain unmodified.
    pub fn reserve(&mut self, start: u64, pages: u64) -> Result<(), Error> {
        if self.allocations_started { return Err(Error::ReservationsClosed); }
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
        if splits > N - self.used { return Err(Error::TooManyRegions); }

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
                self.regions[self.used] = Region { start: overlap_end, end: r.end };
                self.used += 1;
            }
            index += 1;
        }
        Ok(())
    }

    /// Hand out one contiguous physical span, without mapping or touching it.
    /// All allocations are page-aligned and permanently removed from this
    /// prototype planner's free ranges. A future manager must also zero pages.
    pub fn allocate(&mut self, pages: u64) -> Result<PhysSpan, Error> {
        if pages == 0 { return Err(Error::InvalidRange); }
        for index in 0..self.used {
            let range = self.regions[index];
            if range.pages() >= pages {
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
                return Ok(PhysSpan { start, pages });
            }
        }
        Err(Error::OutOfMemory)
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
        assert_eq!(first, PhysSpan { start: 0x1000, pages: 3 });
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
    fn overlapping_firmware_descriptors_are_rejected() {
        let mut data = desc(7, 0x1000, 4);
        data.extend_from_slice(&desc(11, 0x3000, 1));
        assert!(matches!(FrameAllocator::<4>::from_map(&map(&data)),
            Err(Error::OverlappingFirmwareRegions)));
        let mut data = desc(7, 0x1000, 4);
        data.extend_from_slice(&desc(7, 0x4000, 3));
        assert!(matches!(FrameAllocator::<4>::from_map(&map(&data)),
            Err(Error::OverlappingFirmwareRegions)));
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
