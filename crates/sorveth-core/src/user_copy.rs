//! M2-J.3: bounded kernel-controlled copy from the private data page of
//! one experimental process. Not a public syscall.
//!
//! Security contract: an approved process identity is passed by privileged
//! kernel code. Every byte's range is checked, all page-table entries are
//! walked under the selected process PML4, then every physical frame is
//! checked against its permanent ledger-owned data frame before any read.
//! The kernel copies through a verified identity mapping while its own
//! CR3 remains active. An invalid request leaves the destination intact.
//!
//! This implementation requires the single-core QEMU bootstrap, interrupts
//! off, permanently allocated data frames and no concurrent page-table
//! mutation or reclamation. It cannot safely handle a general process with
//! remappable buffers yet. Those lifetime protections are later work.

use core::{arch::asm, ptr};

use sorveth_paging::{
    user_copy::{copy_from_resolved, copy_to_resolved, CopyError},
    user_range::{validate_user_range, UserRangeError},
    user_walk::{UserAccess, WalkError},
    PAGE_BYTES,
};

use crate::process_roots::{self, Process};

const CR3_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyInError {
    InvalidRange(UserRangeError),
    InvalidMapping(WalkError),
    PhysicalSource(CopyError),
    KernelRootUnavailable,
    WrongCpuContext,
    UnmappedPhysicalSource,
}

/// Copy into an already valid, kernel-owned destination slice.
///
/// # Safety
/// Must be called in CPL0 on the sole bootstrap CPU, with interrupts
/// disabled and Sorveth's kernel CR3 active; no concurrent page-table
/// changes, frame reclamation or user scheduling may occur. Destination
/// must be kernel-owned memory with a valid exclusive mutable borrow.
/// The source mapping is limited to the permanently owned single 4-KiB
/// data page installed by M2-I.2; arbitrary process pages are NOT allowed.
/// These assumptions are checked where possible but not generally enforced.
pub unsafe fn copy_from_process(
    process: Process,
    start: u64,
    destination: &mut [u8],
) -> Result<(), CopyInError> {
    // No data pointers are dereferenced before all numeric checks succeed.
    let range =
        validate_user_range(start, destination.len() as u64).map_err(CopyInError::InvalidRange)?;

    let kernel = crate::root::kernel_root_physical().ok_or(CopyInError::KernelRootUnavailable)?;
    let active: u64;
    let flags: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if active & CR3_MASK != kernel || flags & (1 << 9) != 0 {
        return Err(CopyInError::WrongCpuContext);
    }

    let owner = process_roots::mapped_page(process).ok_or(CopyInError::UnmappedPhysicalSource)?;
    let pages = process_roots::walk_process_user_range(process, range, UserAccess::Read)
        .map_err(CopyInError::InvalidMapping)?;

    // The frame ledger never releases these distinct process pages. The
    // QEMU identity map must also contain the WHOLE physical data frame;
    // no unchecked PTE-derived pointer can ever pass the allowlist.
    if !crate::root::identity_mapped(owner.physical_address)
        || !crate::root::identity_mapped(owner.physical_address + PAGE_BYTES - 1)
    {
        return Err(CopyInError::UnmappedPhysicalSource);
    }

    copy_from_resolved(
        range,
        &pages,
        destination,
        |page| page == owner.physical_address,
        |physical_address, out| unsafe {
            // Safe only under the strict QEMU bootstrap + ownership
            // preconditions above. ptr::copy tolerates overlap.
            ptr::copy(physical_address as *const u8, out.as_mut_ptr(), out.len());
        },
    )
    .map_err(CopyInError::PhysicalSource)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyOutError {
    InvalidRange(UserRangeError),
    InvalidMapping(WalkError),
    PhysicalDestination(CopyError),
    KernelRootUnavailable,
    WrongCpuContext,
    UnmappedPhysicalDestination,
}

/// Copy trusted kernel bytes to the chosen process's writable data page.
///
/// Every virtual destination page must pass M2-J.1 range validation and
/// M2-J.2 UserAccess::Write walking. Every resolved physical frame must
/// belong to this specific process, with a verified writable identity
/// mapping for the entire permanently owned page. The kernel must be
/// active with maskable interrupts off. Preflight precedes ALL writes.
///
/// # Safety
/// Same single-CPU QEMU bootstrap lifetime restrictions as
/// copy_from_process: no SMP, IRQ, preemption, remapping or frame reclaim.
/// The source must be genuine, stable, kernel-owned memory and must NOT
/// alias the process's physical data frame. This is a private kernel API,
/// NOT a general syscall or a fault-recoverable user memory operation.
pub unsafe fn copy_to_process(
    process: Process,
    destination: u64,
    source: &[u8],
) -> Result<(), CopyOutError> {
    let range = validate_user_range(destination, source.len() as u64)
        .map_err(CopyOutError::InvalidRange)?;

    let kernel = crate::root::kernel_root_physical().ok_or(CopyOutError::KernelRootUnavailable)?;
    let active: u64;
    let flags: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if active & CR3_MASK != kernel || flags & (1 << 9) != 0 {
        return Err(CopyOutError::WrongCpuContext);
    }

    let owner = process_roots::mapped_page(process)
        .ok_or(CopyOutError::UnmappedPhysicalDestination)?;
    // This explicitly requests write permission at *every* page-table level.
    let pages = process_roots::walk_process_user_range(process, range, UserAccess::Write)
        .map_err(CopyOutError::InvalidMapping)?;

    if !crate::root::identity_mapped(owner.physical_address)
        || !crate::root::identity_mapped(owner.physical_address + PAGE_BYTES - 1)
    {
        return Err(CopyOutError::UnmappedPhysicalDestination);
    }

    copy_to_resolved(
        range,
        &pages,
        source,
        |page| page == owner.physical_address,
        |physical_address, bytes| unsafe {
            // Safe only for the permanently allocated, verified,
            // kernel-writable QEMU identity-mapped process data page.
            // The source is nonaliasing kernel storage by contract.
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                physical_address as *mut u8,
                bytes.len(),
            );
        },
    )
    .map_err(CopyOutError::PhysicalDestination)
}

/// QEMU acceptance for the restricted copy-to-user path. Both process
/// frames are checked for successful writes and verified to be restored
/// before later ring-3/IPC tests depend on their original values.
///
/// # Safety
/// Single QEMU bootstrap CPU; IRQs off and immutable permanent mappings.
pub unsafe fn verify_copy_to_user() -> bool {
    for (process, other) in [
        (Process::First, Process::Second),
        (Process::Second, Process::First),
    ] {
        let own = match process_roots::mapped_page(process) {
            Some(value) => value,
            None => return false,
        };
        let foreign = match process_roots::mapped_page(other) {
            Some(value) => value,
            None => return false,
        };
        let original = ptr::read_volatile(own.physical_address as *const u64);
        let foreign_original = ptr::read_volatile(foreign.physical_address as *const u64);
        let original_bytes = original.to_le_bytes();
        let replacement = [0x5au8, 0xa5, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];

        // Modify the actual process-private frame through the audited
        // physical mapping, then independently read through copy-in.
        if copy_to_process(process, own.virtual_address, &replacement).is_err() {
            return false;
        }
        let mut observed = [0u8; 8];
        let matched = copy_from_process(process, own.virtual_address, &mut observed).is_ok()
            && observed == replacement
            && ptr::read_volatile(own.physical_address as *const u64)
                == u64::from_le_bytes(replacement);

        // Restore the original sentinel regardless of the readback result.
        if copy_to_process(process, own.virtual_address, &original_bytes).is_err() {
            return false;
        }
        if !matched
            || ptr::read_volatile(own.physical_address as *const u64) != original
            || ptr::read_volatile(foreign.physical_address as *const u64) != foreign_original
        {
            return false;
        }

        // Write a single byte at the final mapped offset, then restore it.
        let last_address = own.virtual_address + PAGE_BYTES - 1;
        let last_physical = (own.physical_address + PAGE_BYTES - 1) as *const u8;
        let last_before = ptr::read_volatile(last_physical);
        if copy_to_process(process, last_address, &[0xee]).is_err() {
            return false;
        }
        let mut last_observed = [0u8; 1];
        let end_matched = copy_from_process(process, last_address, &mut last_observed).is_ok()
            && last_observed == [0xee]
            && ptr::read_volatile(last_physical) == 0xee;
        if copy_to_process(process, last_address, &[last_before]).is_err() {
            return false;
        }
        if !end_matched || ptr::read_volatile(last_physical) != last_before {
            return false;
        }

        // Every rejected request must leave both processes' data intact.
        let source = [0xf0u8, 0x0f];
        if copy_to_process(process, foreign.virtual_address, &source)
            != Err(CopyOutError::InvalidMapping(WalkError::MissingMapping))
        {
            return false;
        }
        if copy_to_process(process, last_address, &source)
            != Err(CopyOutError::InvalidMapping(WalkError::MissingMapping))
        {
            return false;
        }
        if copy_to_process(process, 0, &source)
            != Err(CopyOutError::InvalidRange(UserRangeError::NullPage))
        {
            return false;
        }
        if copy_to_process(process, u64::MAX, &source)
            != Err(CopyOutError::InvalidRange(UserRangeError::ArithmeticOverflow))
        {
            return false;
        }
        if copy_to_process(process, 0xffff_8000_0000_0000, &source)
            != Err(CopyOutError::InvalidRange(UserRangeError::OutsideUserSpace))
        {
            return false;
        }
        if copy_to_process(process, own.virtual_address, &[])
            != Err(CopyOutError::InvalidRange(UserRangeError::ZeroLength))
        {
            return false;
        }

        // A CPU-visible read-only permission must deny a write, even
        // when the buffer address and process identity are otherwise good.
        if !process_roots::verify_readonly_copy_out_denied(process) {
            return false;
        }

        if ptr::read_volatile(own.physical_address as *const u64) != original
            || ptr::read_volatile(foreign.physical_address as *const u64) != foreign_original
        {
            return false;
        }
    }
    true
}

/// Execute controlled positive and negative copy-in checks for both private
/// process pages, without running any user-mode syscall or changing data.
///
/// # Safety
/// Same single-CPU, masked-interrupt, stable-frame preconditions as
/// copy_from_process. The ordinary kernel root must be active.
pub unsafe fn verify_copy_from_user() -> bool {
    use sorveth_paging::user_range::{UserRangeError, MAX_USER_TRANSFER_BYTES};
    use sorveth_paging::user_walk::WalkError;

    for (process, foreign) in [
        (Process::First, Process::Second),
        (Process::Second, Process::First),
    ] {
        let own = match process_roots::mapped_page(process) {
            Some(page) => page,
            None => return false,
        };
        let other = match process_roots::mapped_page(foreign) {
            Some(page) => page,
            None => return false,
        };
        let before = ptr::read_volatile(own.physical_address as *const u64);
        let foreign_before = ptr::read_volatile(other.physical_address as *const u64);
        let expected = before.to_le_bytes();

        let mut full = [0xa5u8; 8];
        if copy_from_process(process, own.virtual_address, &mut full).is_err() || full != expected {
            return false;
        }
        let mut partial = [0xa5u8; 7];
        if copy_from_process(process, own.virtual_address + 1, &mut partial).is_err()
            || partial != expected[1..]
        {
            return false;
        }
        let mut final_byte = [0x5au8; 1];
        if copy_from_process(
            process,
            own.virtual_address + PAGE_BYTES - 1,
            &mut final_byte,
        )
        .is_err()
            || final_byte != [0]
        {
            return false;
        }

        // Numeric address is valid, but belongs to the other process.
        let mut denied = [0xa5u8; 8];
        if copy_from_process(process, other.virtual_address, &mut denied)
            != Err(CopyInError::InvalidMapping(WalkError::MissingMapping))
            || denied != [0xa5; 8]
        {
            return false;
        }

        // Preflight the entire buffer. The first byte is present, but the
        // second lands in an unmapped page: neither output byte may change.
        let mut crossing = [0xb6u8; 2];
        if copy_from_process(process, own.virtual_address + PAGE_BYTES - 1, &mut crossing)
            != Err(CopyInError::InvalidMapping(WalkError::MissingMapping))
            || crossing != [0xb6; 2]
        {
            return false;
        }

        let mut invalid = [0xc7u8; 8];
        if copy_from_process(process, 0, &mut invalid)
            != Err(CopyInError::InvalidRange(UserRangeError::NullPage))
            || invalid != [0xc7; 8]
        {
            return false;
        }
        if copy_from_process(process, u64::MAX, &mut invalid)
            != Err(CopyInError::InvalidRange(
                UserRangeError::ArithmeticOverflow,
            ))
            || invalid != [0xc7; 8]
        {
            return false;
        }
        if copy_from_process(process, own.virtual_address, &mut [])
            != Err(CopyInError::InvalidRange(UserRangeError::ZeroLength))
        {
            return false;
        }

        // Oversize is bounded by policy. No 64-KiB scratch buffer is
        // allocated in this 128-KiB bootstrap stack: host tests cover
        // MAX_USER_TRANSFER_BYTES+1, and J.1 already enforces that limit.
        if MAX_USER_TRANSFER_BYTES != 64 * 1024 {
            return false;
        }

        // Copy-in must never alter the source, or another process's data.
        if ptr::read_volatile(own.physical_address as *const u64) != before
            || ptr::read_volatile(other.physical_address as *const u64) != foreign_before
        {
            return false;
        }
    }
    true
}
