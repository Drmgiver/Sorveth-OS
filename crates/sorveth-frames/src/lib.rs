#![no_std]

//! Allocation-free physical frame accounting for the first Sorveth kernel.
//!
//! This is a *frame ownership planner*, not an installed memory manager.
//! It does not map memory, create page tables, access RAM or synchronize CPUs.
//! The caller must retain the allocator and reserve any independently owned
//! physical buffers before allocations. A quarantined claim can only be
//! recycled through an explicit zero-before-reuse callback.

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
    InvalidClaim,
    StaleClaim,
    WrongOwner,
    ClaimReferenceUnderflow,
    ClaimReferenceOverflow,
    ClaimMappingUnderflow,
    ClaimReferencesActive,
    ClaimMappingsActive,
    ClaimAlreadyQuarantined,
    ClaimTicketMismatch,
    ClaimGenerationExhausted,
    ReclaimOverlap,
    ReclaimRegionFull,
    ZeroingFailed,
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
    claims: [Option<ClaimRecord>; N],
    generations: [u32; N],
    claim_count: usize,
}

/// Stable kernel identity recorded on each allocation claim.
///
/// This identifier is accounting metadata, not a user-facing authority token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameOwner(u64);

impl FrameOwner {
    /// Owner used by the current bootstrap callers until each subsystem has
    /// an explicit lifetime identity.
    pub const BOOTSTRAP: Self = Self(1);
    pub const ROOT_BOOTSTRAP: Self = Self(2);
    pub const KERNEL_SCRATCH: Self = Self(3);
    pub const USER_PROBE_CODE: Self = Self(4);
    pub const USER_PROBE_STACK: Self = Self(5);
    pub const PROCESS_FIRST_DATA: Self = Self(6);
    pub const PROCESS_SECOND_DATA: Self = Self(7);

    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Generation-bound reference to one allocation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimHandle {
    slot: u16,
    generation: u32,
}

impl ClaimHandle {
    pub const fn slot(self) -> u16 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Physical claim plus its owner/reference-ledger identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedSpan {
    pub span: PhysSpan,
    pub handle: ClaimHandle,
}

/// Read-only view of one persistent allocation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimRecord {
    span: PhysSpan,
    owner: FrameOwner,
    generation: u32,
    references: u32,
    mappings: u32,
    quarantined: bool,
}

impl ClaimRecord {
    pub const fn span(self) -> PhysSpan {
        self.span
    }

    pub const fn owner(self) -> FrameOwner {
        self.owner
    }

    pub const fn references(self) -> u32 {
        self.references
    }

    pub const fn mappings(self) -> u32 {
        self.mappings
    }

    pub const fn is_quarantined(self) -> bool {
        self.quarantined
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// A claim whose owner references and known mappings have both reached zero.
/// It is still reserved and cannot be reused until the span has been zeroed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuarantineTicket {
    span: PhysSpan,
    pub handle: ClaimHandle,
}

impl QuarantineTicket {
    pub const fn span(self) -> PhysSpan {
        self.span
    }
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
            generations: [1; N],
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

    /// Number of active or quarantined claims in the ownership ledger.
    pub fn claim_count(&self) -> usize {
        self.claim_count
    }

    /// Return the claim occupying one ledger slot, if any.
    pub fn claim_at(&self, index: usize) -> Option<PhysSpan> {
        self.claims.get(index).copied().flatten().map(ClaimRecord::span)
    }

    /// Read ownership and reference metadata for one ledger slot.
    pub fn claim_record_at(&self, index: usize) -> Option<ClaimRecord> {
        self.claims.get(index).copied().flatten()
    }

    /// Whether an aligned physical page belongs to any recorded claim.
    pub fn owns_frame(&self, frame: u64) -> bool {
        if frame % PAGE_BYTES != 0 {
            return false;
        }
        self.claims
            .iter()
            .flatten()
            .any(|claim| {
                !claim.quarantined
                    && (claim.references != 0 || claim.mappings != 0)
                    && frame >= claim.span.start
                    && frame < claim.span.end_exclusive()
            })
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
    /// Allocated pages remain absent from free ranges until they pass through
    /// quarantine and the zero-before-reuse path.
    pub fn allocate(&mut self, pages: u64) -> Result<PhysSpan, Error> {
        self.allocate_owned(pages, FrameOwner::BOOTSTRAP)
            .map(|claim| claim.span)
    }

    /// Claim a contiguous span and attach its initial owner reference.
    /// Claims stay physically reserved after their logical references reach
    /// zero until all mappings are removed, invalidations complete, and the
    /// quarantined span has been zeroed.
    pub fn allocate_owned(&mut self, pages: u64, owner: FrameOwner) -> Result<OwnedSpan, Error> {
        if pages == 0 {
            return Err(Error::InvalidRange);
        }
        for index in 0..self.used {
            let range = self.regions[index];
            if range.pages() >= pages {
                let slot = self
                    .claims
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::ClaimLedgerFull)?;
                if slot > u16::MAX as usize {
                    return Err(Error::ClaimLedgerFull);
                }
                let generation = self.generations[slot];
                if generation == 0 {
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
                let span = PhysSpan { start, pages };
                self.claims[slot] = Some(ClaimRecord {
                    span,
                    owner,
                    generation,
                    references: 1,
                    mappings: 0,
                    quarantined: false,
                });
                self.claim_count += 1;
                return Ok(OwnedSpan {
                    span,
                    handle: ClaimHandle {
                        slot: slot as u16,
                        generation,
                    },
                });
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Add another logical reference to a live owner claim.
    pub fn retain_claim(&mut self, handle: ClaimHandle, owner: FrameOwner) -> Result<u32, Error> {
        let claim = self.claim_mut(handle, owner)?;
        if claim.references == 0 || claim.quarantined {
            return Err(Error::InvalidClaim);
        }
        claim.references = claim
            .references
            .checked_add(1)
            .ok_or(Error::ClaimReferenceOverflow)?;
        Ok(claim.references)
    }

    /// Drop one logical reference without releasing the physical pages.
    /// The final drop retires only this record; the span remains unavailable
    /// for reuse until mapping unmap, CPU invalidation, and zeroing are added.
    pub fn release_claim_reference(
        &mut self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<u32, Error> {
        let claim = self.claim_mut(handle, owner)?;
        if claim.references == 0 {
            return Err(Error::ClaimReferenceUnderflow);
        }
        claim.references -= 1;
        Ok(claim.references)
    }

    /// Record a mapping on a claim with a live owner reference.
    pub fn retain_mapping(&mut self, handle: ClaimHandle, owner: FrameOwner) -> Result<u32, Error> {
        let claim = self.claim_mut(handle, owner)?;
        if claim.references == 0 || claim.quarantined {
            return Err(Error::InvalidClaim);
        }
        claim.mappings = claim
            .mappings
            .checked_add(1)
            .ok_or(Error::ClaimReferenceOverflow)?;
        Ok(claim.mappings)
    }

    /// Drop a mapping reference after its PTE is removed and the required
    /// local TLB invalidation or address-space shootdown has completed.
    pub fn release_mapping(
        &mut self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<u32, Error> {
        let claim = self.claim_mut(handle, owner)?;
        if claim.mappings == 0 || claim.quarantined {
            return Err(Error::ClaimMappingUnderflow);
        }
        claim.mappings -= 1;
        Ok(claim.mappings)
    }

    /// Quarantine a claim only after all owners and mappings are gone.
    /// This does not return the span to the allocator or prove zeroing.
    pub fn begin_quarantine(
        &mut self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<QuarantineTicket, Error> {
        let claim = self.claim_mut(handle, owner)?;
        if claim.references != 0 {
            return Err(Error::ClaimReferencesActive);
        }
        if claim.mappings != 0 {
            return Err(Error::ClaimMappingsActive);
        }
        if claim.quarantined {
            return Err(Error::ClaimAlreadyQuarantined);
        }
        claim.quarantined = true;
        Ok(QuarantineTicket {
            span: claim.span,
            handle,
        })
    }

    /// Zero a quarantined span and return it to the conventional free ranges.
    ///
    /// Range insertion and generation advancement are checked before `zero`
    /// runs. If either preflight or zeroing fails, the claim remains
    /// quarantined and unavailable. The callback must clear every byte in the
    /// span and must not re-enter this allocator.
    pub fn recycle_quarantined(
        &mut self,
        ticket: QuarantineTicket,
        owner: FrameOwner,
        mut zero: impl FnMut(PhysSpan) -> bool,
    ) -> Result<(), Error> {
        let slot = ticket.handle.slot as usize;
        let claim = self
            .claims
            .get(slot)
            .and_then(Option::as_ref)
            .copied()
            .filter(|claim| claim.generation == ticket.handle.generation)
            .ok_or(Error::StaleClaim)?;
        if claim.owner != owner {
            return Err(Error::WrongOwner);
        }
        if self.generations[slot] != claim.generation {
            return Err(Error::StaleClaim);
        }
        if claim.span != ticket.span {
            return Err(Error::ClaimTicketMismatch);
        }
        if !claim.quarantined {
            return Err(Error::InvalidClaim);
        }
        if claim.references != 0 {
            return Err(Error::ClaimReferencesActive);
        }
        if claim.mappings != 0 {
            return Err(Error::ClaimMappingsActive);
        }

        let next_generation = claim
            .generation
            .checked_add(1)
            .ok_or(Error::ClaimGenerationExhausted)?;
        let length = claim
            .span
            .pages
            .checked_mul(PAGE_BYTES)
            .ok_or(Error::InvalidRange)?;
        let end = claim
            .span
            .start
            .checked_add(length)
            .ok_or(Error::InvalidRange)?;
        let mut next_regions = self.regions;
        let mut next_used = self.used;
        Self::insert_reclaimed_region(
            &mut next_regions,
            &mut next_used,
            Region {
                start: claim.span.start,
                end,
            },
        )?;
        let next_available = self
            .available_pages
            .checked_add(claim.span.pages)
            .ok_or(Error::InvalidRange)?;

        if !zero(claim.span) {
            return Err(Error::ZeroingFailed);
        }

        self.regions = next_regions;
        self.used = next_used;
        self.available_pages = next_available;
        self.claims[slot] = None;
        self.generations[slot] = next_generation;
        self.claim_count -= 1;
        Ok(())
    }

    fn insert_reclaimed_region(
        regions: &mut [Region; N],
        used: &mut usize,
        incoming: Region,
    ) -> Result<(), Error> {
        let position = (0..*used)
            .find(|&index| regions[index].start >= incoming.start)
            .unwrap_or(*used);
        if position > 0 && regions[position - 1].end > incoming.start
            || position < *used && incoming.end > regions[position].start
        {
            return Err(Error::ReclaimOverlap);
        }

        let joins_previous = position > 0 && regions[position - 1].end == incoming.start;
        let joins_next = position < *used && incoming.end == regions[position].start;
        match (joins_previous, joins_next) {
            (true, true) => {
                regions[position - 1].end = regions[position].end;
                for index in position..(*used - 1) {
                    regions[index] = regions[index + 1];
                }
                *used -= 1;
                regions[*used] = Region::EMPTY;
            }
            (true, false) => regions[position - 1].end = incoming.end,
            (false, true) => regions[position].start = incoming.start,
            (false, false) => {
                if *used == N {
                    return Err(Error::ReclaimRegionFull);
                }
                for index in (position..*used).rev() {
                    regions[index + 1] = regions[index];
                }
                regions[position] = incoming;
                *used += 1;
            }
        }
        Ok(())
    }

    fn claim_mut(
        &mut self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<&mut ClaimRecord, Error> {
        let claim = self
            .claims
            .get_mut(handle.slot as usize)
            .and_then(Option::as_mut)
            .filter(|claim| claim.generation == handle.generation)
            .ok_or(Error::StaleClaim)?;
        if claim.owner != owner {
            return Err(Error::WrongOwner);
        }
        Ok(claim)
    }
}

/// A page claim means *ownership*, not that the bytes are mapped or zeroed.
/// Claims are reusable only after quarantine and explicit zeroing.
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
        self.claim_unmapped_for(pages, FrameOwner::BOOTSTRAP)
            .map(|claim| claim.span)
    }

    /// Claim a span while recording the subsystem owner and generation handle.
    pub fn claim_unmapped_for(
        &self,
        pages: u64,
        owner: FrameOwner,
    ) -> Result<OwnedSpan, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .allocate_owned(pages, owner)
            .map_err(PoolError::Allocation)
    }

    /// Add a logical owner reference to a generation-matched claim.
    pub fn retain_claim(&self, handle: ClaimHandle, owner: FrameOwner) -> Result<u32, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .retain_claim(handle, owner)
            .map_err(PoolError::Allocation)
    }

    /// Drop one logical owner reference without making pages allocator-visible.
    pub fn release_claim_reference(
        &self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<u32, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .release_claim_reference(handle, owner)
            .map_err(PoolError::Allocation)
    }

    /// Record an installed mapping on a live owner claim.
    pub fn retain_mapping(&self, handle: ClaimHandle, owner: FrameOwner) -> Result<u32, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .retain_mapping(handle, owner)
            .map_err(PoolError::Allocation)
    }

    /// Drop a mapping reference after removing the PTE and invalidating its
    /// translation on every CPU that could have used it.
    pub fn release_mapping(
        &self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<u32, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .release_mapping(handle, owner)
            .map_err(PoolError::Allocation)
    }

    /// Quarantine an ownerless, unmapped claim without making it reusable.
    pub fn begin_quarantine(
        &self,
        handle: ClaimHandle,
        owner: FrameOwner,
    ) -> Result<QuarantineTicket, PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .begin_quarantine(handle, owner)
            .map_err(PoolError::Allocation)
    }

    /// Zero and recycle an ownerless, unmapped quarantine ticket.
    ///
    /// The pool lock remains held during `zero`; the callback must not call
    /// back into this pool. The caller must also prevent interrupt or CPU
    /// activity that could violate the callback's access assumptions.
    pub fn recycle_quarantined(
        &self,
        ticket: QuarantineTicket,
        owner: FrameOwner,
        zero: impl FnMut(PhysSpan) -> bool,
    ) -> Result<(), PoolError> {
        let mut guard = self.lock();
        let allocator = guard.state().as_mut().ok_or(PoolError::NotInstalled)?;
        allocator
            .recycle_quarantined(ticket, owner, zero)
            .map_err(PoolError::Allocation)
    }

    /// Number of active or quarantined physical claims.
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

    /// Read a persistent claim's owner, reference count, and generation.
    pub fn claim_record_at(&self, index: usize) -> Result<Option<ClaimRecord>, PoolError> {
        let mut guard = self.lock();
        Ok(guard
            .state()
            .as_ref()
            .ok_or(PoolError::NotInstalled)?
            .claim_record_at(index))
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
    fn owner_references_are_generation_checked_and_never_reclaim_pages() {
        let data = desc(7, 0x1000, 4);
        let mut allocator = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        let owner = FrameOwner::new(0xCAFE);
        let other = FrameOwner::new(0xBEEF);
        let claim = allocator.allocate_owned(1, owner).unwrap();
        assert_eq!(claim.span.start, 0x1000);
        assert_eq!(allocator.claim_record_at(0).unwrap().owner(), owner);
        assert_eq!(allocator.claim_record_at(0).unwrap().references(), 1);
        assert_eq!(allocator.retain_claim(claim.handle, owner), Ok(2));
        assert_eq!(
            allocator.retain_claim(claim.handle, other),
            Err(Error::WrongOwner)
        );
        assert_eq!(
            allocator.retain_claim(
                ClaimHandle {
                    generation: 2,
                    ..claim.handle
                },
                owner
            ),
            Err(Error::StaleClaim)
        );
        assert_eq!(
            allocator.release_claim_reference(claim.handle, owner),
            Ok(1)
        );
        assert_eq!(
            allocator.release_claim_reference(claim.handle, owner),
            Ok(0)
        );
        assert!(!allocator.owns_frame(claim.span.start));
        assert_eq!(
            allocator.retain_claim(claim.handle, owner),
            Err(Error::InvalidClaim)
        );
        assert_eq!(
            allocator.release_claim_reference(claim.handle, owner),
            Err(Error::ClaimReferenceUnderflow)
        );
        assert_eq!(allocator.available_pages(), 3);
        assert_eq!(allocator.allocate(3).unwrap().start, 0x2000);
        assert_eq!(allocator.available_pages(), 0);
    }

    #[test]
    fn persistent_pool_serializes_owned_claim_reference_updates() {
        let data = desc(7, 0x1000, 3);
        let pool = FramePool::<4>::new();
        pool.install(FrameAllocator::<4>::from_map(&map(&data)).unwrap())
            .unwrap();
        let owner = FrameOwner::ROOT_BOOTSTRAP;
        let claim = pool.claim_unmapped_for(1, owner).unwrap();
        assert_eq!(pool.claim_record_at(0).unwrap().unwrap().owner(), owner);
        assert_eq!(pool.retain_claim(claim.handle, owner), Ok(2));
        assert_eq!(pool.release_claim_reference(claim.handle, owner), Ok(1));
        assert_eq!(pool.release_claim_reference(claim.handle, owner), Ok(0));
        assert_eq!(pool.status().unwrap().available_pages, 2);
        assert_eq!(pool.owns_frame(claim.span.start), Ok(false));
    }

    #[test]
    fn mapping_references_block_quarantine_until_owner_and_map_are_gone() {
        let data = desc(7, 0x1000, 3);
        let mut allocator = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        let owner = FrameOwner::new(0xCAFE);
        let claim = allocator.allocate_owned(1, owner).unwrap();
        assert_eq!(allocator.retain_mapping(claim.handle, owner), Ok(1));
        assert_eq!(
            allocator.release_claim_reference(claim.handle, owner),
            Ok(0)
        );
        assert!(allocator.owns_frame(claim.span.start));
        assert_eq!(
            allocator.begin_quarantine(claim.handle, owner),
            Err(Error::ClaimMappingsActive)
        );
        assert_eq!(
            allocator.retain_mapping(claim.handle, owner),
            Err(Error::InvalidClaim)
        );
        assert_eq!(allocator.release_mapping(claim.handle, owner), Ok(0));
        assert!(!allocator.owns_frame(claim.span.start));
        let ticket = allocator.begin_quarantine(claim.handle, owner).unwrap();
        assert_eq!(ticket.span(), claim.span);
        assert!(allocator.claim_record_at(0).unwrap().is_quarantined());
        assert_eq!(allocator.available_pages(), 2);
    }

    #[test]
    fn recycled_quarantine_is_zeroed_before_reuse_with_new_generation() {
        let data = desc(7, 0x1000, 3);
        let mut allocator = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        let owner = FrameOwner::new(0xCAFE);
        let first = allocator.allocate_owned(1, owner).unwrap();
        assert_eq!(allocator.release_claim_reference(first.handle, owner), Ok(0));
        let ticket = allocator.begin_quarantine(first.handle, owner).unwrap();
        let mut zeroed = None;

        assert_eq!(
            allocator.recycle_quarantined(ticket, owner, |span| {
                zeroed = Some(span);
                true
            }),
            Ok(())
        );
        assert_eq!(zeroed, Some(first.span));
        assert_eq!(allocator.claim_count(), 0);
        assert_eq!(allocator.available_pages(), 3);

        let second = allocator.allocate_owned(1, owner).unwrap();
        assert_eq!(second.span, first.span);
        assert_eq!(second.handle.slot, first.handle.slot);
        assert_eq!(second.handle.generation, first.handle.generation + 1);
        assert_eq!(
            allocator.retain_claim(first.handle, owner),
            Err(Error::StaleClaim)
        );
        assert_eq!(
            allocator.recycle_quarantined(ticket, owner, |_| true),
            Err(Error::StaleClaim)
        );
    }

    #[test]
    fn failed_zeroing_keeps_quarantined_pages_unavailable() {
        let data = desc(7, 0x1000, 3);
        let mut allocator = FrameAllocator::<4>::from_map(&map(&data)).unwrap();
        let owner = FrameOwner::new(0xCAFE);
        let claim = allocator.allocate_owned(1, owner).unwrap();
        assert_eq!(allocator.release_claim_reference(claim.handle, owner), Ok(0));
        let ticket = allocator.begin_quarantine(claim.handle, owner).unwrap();

        assert_eq!(
            allocator.recycle_quarantined(ticket, owner, |_| false),
            Err(Error::ZeroingFailed)
        );
        assert_eq!(allocator.available_pages(), 2);
        assert_eq!(allocator.claim_count(), 1);
        assert!(allocator
            .claim_record_at(claim.handle.slot as usize)
            .unwrap()
            .is_quarantined());
        assert_eq!(allocator.allocate(3), Err(Error::OutOfMemory));
    }

    #[test]
    fn generation_exhaustion_is_rejected_before_zeroing_or_reuse() {
        let data = desc(7, 0x1000, 2);
        let mut allocator = FrameAllocator::<2>::from_map(&map(&data)).unwrap();
        let owner = FrameOwner::BOOTSTRAP;
        let claim = allocator.allocate_owned(1, owner).unwrap();
        assert_eq!(allocator.release_claim_reference(claim.handle, owner), Ok(0));
        let mut ticket = allocator.begin_quarantine(claim.handle, owner).unwrap();
        let slot = claim.handle.slot as usize;
        allocator.claims[slot].as_mut().unwrap().generation = u32::MAX;
        allocator.generations[slot] = u32::MAX;
        ticket.handle.generation = u32::MAX;
        let mut called = false;

        assert_eq!(
            allocator.recycle_quarantined(ticket, owner, |_| {
                called = true;
                true
            }),
            Err(Error::ClaimGenerationExhausted)
        );
        assert!(!called);
        assert_eq!(allocator.available_pages(), 1);
        assert_eq!(allocator.claim_count(), 1);
    }

    #[test]
    fn owner_reference_count_overflow_is_rejected_without_wrapping() {
        let data = desc(7, 0x1000, 2);
        let mut allocator = FrameAllocator::<2>::from_map(&map(&data)).unwrap();
        let owner = FrameOwner::BOOTSTRAP;
        let claim = allocator.allocate_owned(1, owner).unwrap();
        allocator.claims[claim.handle.slot as usize]
            .as_mut()
            .unwrap()
            .references = u32::MAX;
        assert_eq!(
            allocator.retain_claim(claim.handle, owner),
            Err(Error::ClaimReferenceOverflow)
        );
        assert_eq!(
            allocator
                .claim_record_at(claim.handle.slot as usize)
                .unwrap()
                .references(),
            u32::MAX
        );
        assert_eq!(allocator.available_pages(), 1);
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
