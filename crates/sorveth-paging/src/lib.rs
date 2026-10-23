#![no_std]

//! Allocation-free 4 KiB mapping policy and read-only x86-64 paging audit.
//! Does NOT change CR3, install tables, map frames or execute user processes.
//! An eventual installer must prove NX support and zero owned page-table frames.

pub const PAGE_BYTES: u64 = 4096;
pub const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
pub const USER_LIMIT: u64 = 0x0000_8000_0000_0000;
const PHYS_LIMIT: u64 = 1 << 52;
const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NX: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    ZeroPages,
    Misaligned,
    NonCanonical,
    Overflow,
    InvalidPhysical,
    PermissionBoundary,
    WritableExecutable,
    VirtualOverlap,
    PhysicalAlias,
    PlanFull,
    PageOutOfBounds,
    NoPaging,
    UnsupportedMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub user: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Permissions {
    pub const KERNEL_CODE: Self = Self { user: false, writable: false, executable: true };
    pub const KERNEL_DATA: Self = Self { user: false, writable: true, executable: false };
    pub const USER_CODE: Self = Self { user: true, writable: false, executable: true };
    pub const USER_DATA: Self = Self { user: true, writable: true, executable: false };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub virtual_start: u64,
    pub physical_start: u64,
    pub pages: u64,
    pub permissions: Permissions,
}

impl Mapping {
    pub fn virtual_end(&self) -> u64 {
        self.virtual_start + self.pages * PAGE_BYTES
    }

    pub fn physical_end(&self) -> u64 {
        self.physical_start + self.pages * PAGE_BYTES
    }

    /// Returns a *proposed* leaf PTE, not a live hardware mapping.
    /// An installer must enable the CPU's NXE bit before using NX PTEs.
    pub fn leaf_pte(&self, offset: u64) -> Result<u64, Error> {
        if offset >= self.pages {
            return Err(Error::PageOutOfBounds);
        }
        let mut pte = ((self.physical_start + offset * PAGE_BYTES) & PHYS_MASK) | PRESENT;
        if self.permissions.writable {
            pte |= WRITE;
        }
        if self.permissions.user {
            pte |= USER;
        }
        if !self.permissions.executable {
            pte |= NX;
        }
        Ok(pte)
    }
}

fn canonical_48(address: u64) -> bool {
    address < USER_LIMIT || address >= KERNEL_BASE
}

fn overlaps(start1: u64, end1: u64, start2: u64, end2: u64) -> bool {
    start1 < end2 && start2 < end1
}

/// The mapping plan owns metadata only and cannot access or reuse memory.
pub struct MappingPlan<const N: usize> {
    entries: [Option<Mapping>; N],
    len: usize,
}

impl<const N: usize> MappingPlan<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N], len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn get(&self, index: usize) -> Option<Mapping> {
        if index < self.len { self.entries[index] } else { None }
    }

    pub fn add(&mut self, mapping: Mapping) -> Result<(), Error> {
        if mapping.pages == 0 {
            return Err(Error::ZeroPages);
        }
        if mapping.virtual_start % PAGE_BYTES != 0 || mapping.physical_start % PAGE_BYTES != 0 {
            return Err(Error::Misaligned);
        }
        if mapping.physical_start == 0 {
            return Err(Error::InvalidPhysical);
        }
        if mapping.permissions.writable && mapping.permissions.executable {
            return Err(Error::WritableExecutable);
        }

        let bytes = mapping.pages.checked_mul(PAGE_BYTES).ok_or(Error::Overflow)?;
        let virt_end = mapping.virtual_start.checked_add(bytes).ok_or(Error::Overflow)?;
        let phys_end = mapping.physical_start.checked_add(bytes).ok_or(Error::Overflow)?;
        if phys_end > PHYS_LIMIT {
            return Err(Error::InvalidPhysical);
        }
        if !canonical_48(mapping.virtual_start) || !canonical_48(virt_end - 1) {
            return Err(Error::NonCanonical);
        }
        if mapping.permissions.user {
            if mapping.virtual_start < PAGE_BYTES || virt_end > USER_LIMIT {
                return Err(Error::PermissionBoundary);
            }
        } else if mapping.virtual_start < KERNEL_BASE {
            return Err(Error::PermissionBoundary);
        }

        for existing in self.entries[..self.len].iter().flatten() {
            if overlaps(mapping.virtual_start, virt_end, existing.virtual_start, existing.virtual_end()) {
                return Err(Error::VirtualOverlap);
            }
            if overlaps(mapping.physical_start, phys_end, existing.physical_start, existing.physical_end()) {
                return Err(Error::PhysicalAlias);
            }
        }
        if self.len == N {
            return Err(Error::PlanFull);
        }
        self.entries[self.len] = Some(mapping);
        self.len += 1;
        Ok(())
    }
}

impl<const N: usize> Default for MappingPlan<N> {
    fn default() -> Self { Self::new() }
}

/// Current CPU firmware paging state; does not imply Sorveth owns any tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivePaging {
    pub root_physical: u64,
    pub write_protect_enabled: bool,
}

/// Requires ring 0 (valid after the UEFI handoff), reads CR0/CR3/CR4 only.
/// Rejects disabled paging, disabled PAE, and LA57 five-level configurations.
pub fn audit_inherited() -> Result<ActivePaging, Error> {
    #[cfg(target_arch = "x86_64")]
    {
        let (cr0, cr3, cr4): (u64, u64, u64);
        // SAFETY: caller is the privileged bootstrap kernel; reads only.
        unsafe {
            core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        }
        if cr0 & (1 << 31) == 0 || cr4 & (1 << 5) == 0 {
            return Err(Error::NoPaging);
        }
        if cr4 & (1 << 12) != 0 {
            return Err(Error::UnsupportedMode);
        }
        let root = cr3 & PHYS_MASK;
        if root == 0 {
            return Err(Error::InvalidPhysical);
        }
        Ok(ActivePaging { root_physical: root, write_protect_enabled: cr0 & (1 << 16) != 0 })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(Error::UnsupportedMode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_map(v: u64, p: u64, n: u64, flags: Permissions) -> Mapping {
        Mapping { virtual_start: v, physical_start: p, pages: n, permissions: flags }
    }

    #[test]
    fn encode_user_code_and_nonexecutable_kernel_data() {
        let mut plan = MappingPlan::<3>::new();
        plan.add(test_map(KERNEL_BASE, 0x3000, 2, Permissions::KERNEL_DATA)).unwrap();
        plan.add(test_map(0x4000, 0xa000, 2, Permissions::USER_CODE)).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.get(0).unwrap().leaf_pte(0), Ok(0x3000 | PRESENT | WRITE | NX));
        assert_eq!(plan.get(1).unwrap().leaf_pte(1), Ok(0xb000 | PRESENT | USER));
        assert_eq!(plan.get(1).unwrap().leaf_pte(2), Err(Error::PageOutOfBounds));
    }

    #[test]
    fn reject_writable_executable_and_privilege_crossings() {
        let mut plan = MappingPlan::<3>::new();
        let wx = Permissions { user: false, writable: true, executable: true };
        assert_eq!(plan.add(test_map(KERNEL_BASE, 0x1000, 1, wx)), Err(Error::WritableExecutable));
        assert_eq!(plan.add(test_map(0x3000, 0x1000, 1, Permissions::KERNEL_CODE)), Err(Error::PermissionBoundary));
        assert_eq!(plan.add(test_map(KERNEL_BASE, 0x1000, 1, Permissions::USER_DATA)), Err(Error::PermissionBoundary));
        assert_eq!(plan.add(test_map(0, 0x1000, 1, Permissions::USER_DATA)), Err(Error::PermissionBoundary));
        assert_eq!(plan.len(), 0);
    }

    #[test]
    fn reject_overlaps_and_aliases_transactionally() {
        let mut plan = MappingPlan::<2>::new();
        plan.add(test_map(0x1000, 0x10000, 4, Permissions::USER_DATA)).unwrap();
        assert_eq!(plan.add(test_map(0x4000, 0x20000, 2, Permissions::USER_DATA)), Err(Error::VirtualOverlap));
        assert_eq!(plan.add(test_map(0x8000, 0x11000, 2, Permissions::USER_CODE)), Err(Error::PhysicalAlias));
        assert_eq!(plan.len(), 1);
        plan.add(test_map(KERNEL_BASE, 0x20000, 1, Permissions::KERNEL_CODE)).unwrap();
        assert_eq!(plan.add(test_map(KERNEL_BASE + PAGE_BYTES, 0x30000, 1, Permissions::KERNEL_CODE)), Err(Error::PlanFull));
    }

    #[test]
    fn reject_malformed_and_overflowing_ranges() {
        let mut plan = MappingPlan::<1>::new();
        assert_eq!(plan.add(test_map(0x1001, 0x1000, 1, Permissions::USER_DATA)), Err(Error::Misaligned));
        assert_eq!(plan.add(test_map(0x1000, 0x1000, 0, Permissions::USER_DATA)), Err(Error::ZeroPages));
        assert_eq!(plan.add(test_map(0x1000, 0, 1, Permissions::USER_DATA)), Err(Error::InvalidPhysical));
        assert_eq!(plan.add(test_map(USER_LIMIT, 0x1000, 1, Permissions::USER_DATA)), Err(Error::NonCanonical));
        assert_eq!(plan.add(test_map(USER_LIMIT - PAGE_BYTES, 0x1000, 2, Permissions::USER_DATA)), Err(Error::NonCanonical));
        assert_eq!(plan.add(test_map(KERNEL_BASE, PHYS_LIMIT - PAGE_BYTES, 2, Permissions::KERNEL_DATA)), Err(Error::InvalidPhysical));
        assert_eq!(plan.add(test_map(KERNEL_BASE, 0x1000, u64::MAX, Permissions::KERNEL_DATA)), Err(Error::Overflow));
    }
}
