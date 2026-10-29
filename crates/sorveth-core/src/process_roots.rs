//! M2-I.1: separate top-level PML4 roots for future processes.
//!
//! Both roots still share Sorveth's lower-level *kernel* paging trees,
//! including inherited OVMF mappings. Every present PML4 entry has its
//! USER bit cleared; future process-private USER subtrees must be mapped
//! separately in the currently absent lower-half slots.
//! This is single-core QEMU bootstrap code, not yet process isolation.

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
#[repr(C, align(4096))]
struct Page([u64; 512]);

#[cfg(target_arch = "x86_64")]
static mut FIRST: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SECOND: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static FIRST_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_ROOT: AtomicU64 = AtomicU64::new(0);
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

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use super::*;

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
