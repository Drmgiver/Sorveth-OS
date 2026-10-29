//! M2-I.1/I.2: separate top-level PML4 roots and owned user-data pages.
//!
//! Both roots still share Sorveth's lower-level *kernel* paging trees,
//! including inherited OVMF mappings. Every present PML4 entry has its
//! USER bit cleared; future process-private USER subtrees must be mapped
//! separately in the initially absent lower-half slots. M2-I.2 creates
//! disjoint USER RW/NX physical mappings behind these process-owned slots.
//! This is single-core QEMU bootstrap code, not yet complete process isolation.

#[cfg(target_arch = "x86_64")]
use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[cfg(target_arch = "x86_64")]
const PRESENT: u64 = 1;
#[cfg(target_arch = "x86_64")]
const USER: u64 = 1 << 2;
#[cfg(target_arch = "x86_64")]
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(target_arch = "x86_64")]
const WRITE: u64 = 1 << 1;
#[cfg(target_arch = "x86_64")]
const NO_EXECUTE: u64 = 1 << 63;
#[cfg(target_arch = "x86_64")]
const USER_TABLE_FLAGS: u64 = PRESENT | WRITE | USER;
#[cfg(target_arch = "x86_64")]
const USER_DATA_FLAGS: u64 = USER_TABLE_FLAGS | NO_EXECUTE;
#[cfg(target_arch = "x86_64")]
const FIRST_TEST_WORD: u64 = 0x534f_5256_4541_4f4e;
#[cfg(target_arch = "x86_64")]
const SECOND_TEST_WORD: u64 = 0x534f_5256_4542_4f4e;

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct Page([u64; 512]);

#[cfg(target_arch = "x86_64")]
static mut FIRST: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SECOND: Page = Page([0; 512]);

// Unlike inherited firmware trees, these six lower-level tables are owned
// separately by Sorveth and never referenced by the other process root.
#[cfg(target_arch = "x86_64")]
static mut FIRST_PDPT: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut FIRST_PD: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut FIRST_PT: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SECOND_PDPT: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SECOND_PD: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SECOND_PT: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static FIRST_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static MAPPED: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static FIRST_FRAME: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_FRAME: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static FIRST_SLOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_SLOT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    AlreadyPrepared,
    KernelUnavailable,
    IdentityMapMissing,
    PrivateSlotsUnavailable,
    VerificationFailed,
    FrameUnavailable,
    AlreadyMapped,
    PageTableStorageUnavailable,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Process {
    First,
    Second,
}

#[cfg(target_arch = "x86_64")]
fn supervisor_entry(entry: u64) -> u64 {
    if entry & PRESENT == 0 {
        0
    } else {
        entry & !USER
    }
}

#[cfg(target_arch = "x86_64")]
fn vacant_slots(mut entry: impl FnMut(usize) -> u64) -> Option<(usize, usize)> {
    let mut first = None;
    for slot in (1..256).rev() {
        if entry(slot) & PRESENT == 0 {
            if let Some(chosen) = first {
                return Some((chosen, slot));
            }
            first = Some(slot);
        }
    }
    None
}

/// Initialize two distinct static PML4 pages, then switch CR3 to each and
/// back while verifying the existing supervisor scratch mapping.
///
/// # Safety
/// Requires CPL0, Sorveth's active root, single CPU, disabled IRQs and
/// validated identity mappings of static page-table storage. Never call
/// concurrently, after scheduling starts or on physical hardware.
pub unsafe fn prepare_and_verify() -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if READY.load(Ordering::Acquire) {
            return Err(Error::AlreadyPrepared);
        }
        let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
        let scratch = crate::root::kernel_private_address().ok_or(Error::KernelUnavailable)?;
        let a = ptr::addr_of_mut!(FIRST).cast::<u64>() as u64;
        let b = ptr::addr_of_mut!(SECOND).cast::<u64>() as u64;
        if a == b || a == kernel || b == kernel || a & 4095 != 0 || b & 4095 != 0 {
            return Err(Error::VerificationFailed);
        }
        if !crate::root::identity_mapped(a) || !crate::root::identity_mapped(b) {
            return Err(Error::IdentityMapMissing);
        }
        let mut active: u64;
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if active & ADDRESS_MASK != kernel {
            return Err(Error::KernelUnavailable);
        }
        let source = kernel as *const u64;
        let (slot_a, slot_b) = vacant_slots(|i| ptr::read_volatile(source.add(i)))
            .ok_or(Error::PrivateSlotsUnavailable)?;
        let a_ptr = a as *mut u64;
        let b_ptr = b as *mut u64;
        for index in 0..512 {
            let entry = supervisor_entry(ptr::read_volatile(source.add(index)));
            ptr::write_volatile(a_ptr.add(index), entry);
            ptr::write_volatile(b_ptr.add(index), entry);
        }
        for root in [a_ptr, b_ptr] {
            if ptr::read_volatile(root.add(slot_a)) != 0
                || ptr::read_volatile(root.add(slot_b)) != 0
            {
                return Err(Error::VerificationFailed);
            }
            for index in 0..512 {
                let present = ptr::read_volatile(root.add(index));
                let expected = supervisor_entry(ptr::read_volatile(source.add(index)));
                if present != expected || (present & PRESENT != 0 && present & USER != 0) {
                    return Err(Error::VerificationFailed);
                }
            }
        }
        let expected = ptr::read_volatile(scratch as *const u64);
        let mut success = true;
        for process_root in [a, b] {
            asm!("mov cr3, {}", in(reg) process_root, options(nostack, preserves_flags));
            asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
            if active & ADDRESS_MASK != process_root
                || ptr::read_volatile(scratch as *const u64) != expected
            {
                success = false;
                break;
            }
        }
        // Restore the kernel CR3 even after a nonfatal verification mismatch.
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if !success
            || active & ADDRESS_MASK != kernel
            || ptr::read_volatile(scratch as *const u64) != expected
        {
            return Err(Error::VerificationFailed);
        }
        FIRST_ROOT.store(a, Ordering::Release);
        SECOND_ROOT.store(b, Ordering::Release);
        FIRST_SLOT.store(slot_a as u64, Ordering::Release);
        SECOND_SLOT.store(slot_b as u64, Ordering::Release);
        READY.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(Error::Unsupported)
    }
}

#[cfg(target_arch = "x86_64")]
pub fn process_root(process: Process) -> Option<(u64, u16)> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    let (root, slot) = match process {
        Process::First => (
            FIRST_ROOT.load(Ordering::Acquire),
            FIRST_SLOT.load(Ordering::Acquire),
        ),
        Process::Second => (
            SECOND_ROOT.load(Ordering::Acquire),
            SECOND_SLOT.load(Ordering::Acquire),
        ),
    };
    if root == 0 || slot == 0 {
        None
    } else {
        Some((root, slot as u16))
    }
}

/// One intentionally small physical user data page mapped at offset zero
/// of a process-owned lower-canonical PML4 slot. Not executable.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[cfg(target_arch = "x86_64")]
fn user_base(slot: u16) -> Option<u64> {
    if (1..256).contains(&slot) {
        Some((slot as u64) << 39)
    } else {
        None
    }
}

/// Returns an immutable descriptor, not a pointer for untrusted code.
#[cfg(target_arch = "x86_64")]
pub fn mapped_page(process: Process) -> Option<Mapping> {
    if !MAPPED.load(Ordering::Acquire) {
        return None;
    }
    let (_, slot) = process_root(process)?;
    let physical_address = match process {
        Process::First => FIRST_FRAME.load(Ordering::Acquire),
        Process::Second => SECOND_FRAME.load(Ordering::Acquire),
    };
    if physical_address == 0 || physical_address & 4095 != 0 {
        return None;
    }
    Some(Mapping {
        virtual_address: user_base(slot)?,
        physical_address,
    })
}

/// Test-only: make the QEMU harness code/stack subtree visible in *only*
/// one selected process root. The foreign process root remains unchanged.
/// The same lower-level test-code tables are also in the kernel test root,
/// which is intentionally not a production process-loading strategy.
#[cfg(any(feature = "qemu-isolate-a", feature = "qemu-isolate-b"))]
pub unsafe fn attach_isolation_probe(process: Process, entry: u64) -> Result<u64, Error> {
    let (owner_root, owner_slot) = process_root(process).ok_or(Error::KernelUnavailable)?;
    let other = match process {
        Process::First => Process::Second,
        Process::Second => Process::First,
    };
    let (other_root, foreign_slot) = process_root(other).ok_or(Error::KernelUnavailable)?;
    let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
    if entry >= 0x0000_8000_0000_0000 || entry & ((1u64 << 39) - 1) != 0 {
        return Err(Error::VerificationFailed);
    }
    let slot = (entry >> 39) as usize;
    if slot == 0
        || slot >= 256
        || slot == owner_slot as usize
        || slot == foreign_slot as usize
        || owner_root == other_root
    {
        return Err(Error::VerificationFailed);
    }
    let source = ptr::read_volatile((kernel as *const u64).add(slot));
    let destination = (owner_root as *mut u64).add(slot);
    if source & USER_TABLE_FLAGS != USER_TABLE_FLAGS
        || ptr::read_volatile(destination) != 0
        || ptr::read_volatile((other_root as *const u64).add(slot)) != 0
        || ptr::read_volatile((owner_root as *const u64).add(foreign_slot as usize)) != 0
        || ptr::read_volatile((other_root as *const u64).add(owner_slot as usize)) != 0
    {
        return Err(Error::VerificationFailed);
    }
    ptr::write_volatile(destination, source);
    if ptr::read_volatile(destination) != source {
        return Err(Error::VerificationFailed);
    }
    Ok(owner_root)
}

/// Check all four PML4/PDPT/PD/PT entries without using user virtual
/// addresses. The QEMU bootstrap has verified identity mapping of every
/// page-table frame, so reading these raw entries is safe *for this test*.
#[cfg(target_arch = "x86_64")]
unsafe fn validate_user_path(root: u64, slot: u16, pdpt: u64, pd: u64, pt: u64, data: u64) -> bool {
    let pml4_entry = ptr::read_volatile((root as *const u64).add(slot as usize));
    let pdpt_entry = ptr::read_volatile(pdpt as *const u64);
    let pd_entry = ptr::read_volatile(pd as *const u64);
    let leaf_entry = ptr::read_volatile(pt as *const u64);
    pml4_entry == (pdpt | USER_TABLE_FLAGS)
        && pdpt_entry == (pd | USER_TABLE_FLAGS)
        && pd_entry == (pt | USER_TABLE_FLAGS)
        && leaf_entry == (data | USER_DATA_FLAGS)
        && (leaf_entry & NO_EXECUTE) != 0
}

/// Claim two distinct conventional physical frames from the permanent ledger,
/// zero them, and install private USER RW/NX leaf mappings in each process
/// root's reserved slot. Test real CPU reads/writes after CR3 transitions.
///
/// # Safety
/// Single QEMU bootstrap CPU only, kernel CPL0, interrupts masked; M2-I.1
/// must be complete, and both roots and page-table frames identity-mapped.
/// No process is executing concurrently, and mappings are never reclaimed.
/// This verifies mapping ownership, NOT safe general userland or fault recovery.
pub unsafe fn map_private_pages(pool: &sorveth_frames::FramePool<256>) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if !READY.load(Ordering::Acquire) {
            return Err(Error::KernelUnavailable);
        }
        if MAPPED.load(Ordering::Acquire) {
            return Err(Error::AlreadyMapped);
        }
        let (first_root, first_slot) =
            process_root(Process::First).ok_or(Error::KernelUnavailable)?;
        let (second_root, second_slot) =
            process_root(Process::Second).ok_or(Error::KernelUnavailable)?;
        let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
        let first_virt = user_base(first_slot).ok_or(Error::VerificationFailed)?;
        let second_virt = user_base(second_slot).ok_or(Error::VerificationFailed)?;
        if first_root == second_root || first_slot == second_slot || first_virt == second_virt {
            return Err(Error::VerificationFailed);
        }
        let active: u64;
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if active & ADDRESS_MASK != kernel {
            return Err(Error::KernelUnavailable);
        }

        let tables = [
            ptr::addr_of_mut!(FIRST_PDPT).cast::<u64>() as u64,
            ptr::addr_of_mut!(FIRST_PD).cast::<u64>() as u64,
            ptr::addr_of_mut!(FIRST_PT).cast::<u64>() as u64,
            ptr::addr_of_mut!(SECOND_PDPT).cast::<u64>() as u64,
            ptr::addr_of_mut!(SECOND_PD).cast::<u64>() as u64,
            ptr::addr_of_mut!(SECOND_PT).cast::<u64>() as u64,
        ];
        for (i, &table) in tables.iter().enumerate() {
            if table == 0
                || table & 4095 != 0
                || !crate::root::identity_mapped(table)
                || tables[..i].contains(&table)
            {
                return Err(Error::PageTableStorageUnavailable);
            }
        }
        for table in tables {
            ptr::write_bytes(table as *mut u8, 0, 4096);
        }

        let frame_a = pool
            .claim_unmapped(1)
            .map_err(|_| Error::FrameUnavailable)?
            .start;
        let frame_b = pool
            .claim_unmapped(1)
            .map_err(|_| Error::FrameUnavailable)?
            .start;
        if frame_a == frame_b
            || frame_a == 0
            || frame_b == 0
            || frame_a & 4095 != 0
            || frame_b & 4095 != 0
            || !crate::root::identity_mapped(frame_a)
            || !crate::root::identity_mapped(frame_b)
        {
            return Err(Error::FrameUnavailable);
        }
        ptr::write_bytes(frame_a as *mut u8, 0, 4096);
        ptr::write_bytes(frame_b as *mut u8, 0, 4096);
        if ptr::read_volatile(frame_a as *const u64) != 0
            || ptr::read_volatile(frame_b as *const u64) != 0
        {
            return Err(Error::VerificationFailed);
        }

        // Each process gets physically distinct PML4/PDPT/PD/PT ancestors.
        let a_root = first_root as *mut u64;
        let b_root = second_root as *mut u64;
        if ptr::read_volatile(a_root.add(first_slot as usize)) != 0
            || ptr::read_volatile(b_root.add(second_slot as usize)) != 0
            || ptr::read_volatile(a_root.add(second_slot as usize)) != 0
            || ptr::read_volatile(b_root.add(first_slot as usize)) != 0
            || ptr::read_volatile((kernel as *const u64).add(first_slot as usize)) != 0
            || ptr::read_volatile((kernel as *const u64).add(second_slot as usize)) != 0
        {
            return Err(Error::VerificationFailed);
        }
        let (a_pdpt, a_pd, a_pt) = (tables[0], tables[1], tables[2]);
        let (b_pdpt, b_pd, b_pt) = (tables[3], tables[4], tables[5]);
        ptr::write_volatile(a_pt as *mut u64, frame_a | USER_DATA_FLAGS);
        ptr::write_volatile(b_pt as *mut u64, frame_b | USER_DATA_FLAGS);
        ptr::write_volatile(a_pd as *mut u64, a_pt | USER_TABLE_FLAGS);
        ptr::write_volatile(b_pd as *mut u64, b_pt | USER_TABLE_FLAGS);
        ptr::write_volatile(a_pdpt as *mut u64, a_pd | USER_TABLE_FLAGS);
        ptr::write_volatile(b_pdpt as *mut u64, b_pd | USER_TABLE_FLAGS);
        ptr::write_volatile(a_root.add(first_slot as usize), a_pdpt | USER_TABLE_FLAGS);
        ptr::write_volatile(b_root.add(second_slot as usize), b_pdpt | USER_TABLE_FLAGS);
        if !validate_user_path(first_root, first_slot, a_pdpt, a_pd, a_pt, frame_a)
            || !validate_user_path(second_root, second_slot, b_pdpt, b_pd, b_pt, frame_b)
            || ptr::read_volatile(a_root.add(second_slot as usize)) != 0
            || ptr::read_volatile(b_root.add(first_slot as usize)) != 0
        {
            return Err(Error::VerificationFailed);
        }

        // Actual x86 translation and memory writes under each independent
        // CR3 root, with a full CR3 reload flushing non-global TLB entries.
        let mut valid = true;
        for (root, address, expected, frame) in [
            (first_root, first_virt, FIRST_TEST_WORD, frame_a),
            (second_root, second_virt, SECOND_TEST_WORD, frame_b),
        ] {
            asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
            let mut observed: u64;
            asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
            if observed & ADDRESS_MASK != root {
                valid = false;
                break;
            }
            ptr::write_volatile(address as *mut u64, expected);
            if ptr::read_volatile(address as *const u64) != expected
                || ptr::read_volatile(frame as *const u64) != expected
            {
                valid = false;
                break;
            }
        }
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
        let restored: u64;
        asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
        if !valid
            || restored & ADDRESS_MASK != kernel
            || ptr::read_volatile(frame_a as *const u64) != FIRST_TEST_WORD
            || ptr::read_volatile(frame_b as *const u64) != SECOND_TEST_WORD
            || ptr::read_volatile((kernel as *const u64).add(first_slot as usize)) != 0
            || ptr::read_volatile((kernel as *const u64).add(second_slot as usize)) != 0
        {
            return Err(Error::VerificationFailed);
        }
        FIRST_FRAME.store(frame_a, Ordering::Release);
        SECOND_FRAME.store(frame_b, Ordering::Release);
        MAPPED.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = pool;
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn private_data_mapping_has_user_read_write_but_never_execute() {
        assert_eq!(USER_DATA_FLAGS & USER, USER);
        assert_eq!(USER_DATA_FLAGS & WRITE, WRITE);
        assert_eq!(USER_DATA_FLAGS & PRESENT, PRESENT);
        assert_ne!(USER_DATA_FLAGS & NO_EXECUTE, 0);
        assert_eq!(USER_TABLE_FLAGS & NO_EXECUTE, 0);
        assert_eq!(user_base(0), None);
        assert_eq!(user_base(256), None);
        assert_eq!(user_base(255), Some(255u64 << 39));
        assert_eq!(user_base(254), Some(254u64 << 39));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn inherited_user_bit_is_removed_and_absent_entries_zeroed() {
        assert_eq!(supervisor_entry(0x1007), 0x1003);
        assert_eq!(supervisor_entry(0x2007 | 1 << 63), 0x2003 | 1 << 63);
        assert_eq!(supervisor_entry(0xffe), 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn process_slots_must_be_distinct_lower_half_and_empty() {
        let mut pml4 = [1u64; 512];
        pml4[0] = 0;
        pml4[255] = 0;
        pml4[254] = 0;
        assert_eq!(vacant_slots(|i| pml4[i]), Some((255, 254)));
        pml4[254] = 1;
        assert_eq!(vacant_slots(|i| pml4[i]), None);
        pml4[253] = 0;
        assert_eq!(vacant_slots(|i| pml4[i]), Some((255, 253)));
    }
}
