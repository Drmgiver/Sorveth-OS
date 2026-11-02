//! M2-I.4: QEMU-only bidirectional ring-3 process-memory denial.
//! Only one of qemu-isolate-a and qemu-isolate-b is enabled per QEMU run.
//! The CPU must report a nonpresent user-read #PF at the foreign private
//! virtual address after a validated read of the current process's own page.

use core::{
    arch::asm,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::process_roots::{self, Process};

pub const SIGNAL: u64 = 0x61;
pub const REPLY: u64 = 0x5349_534f;
static CONFIRMED_OWN: AtomicBool = AtomicBool::new(false);
const CR3_MASK: u64 = 0x000f_ffff_ffff_f000;

pub const fn owner() -> Process {
    #[cfg(feature = "qemu-isolate-a")]
    {
        Process::First
    }
    #[cfg(all(feature = "qemu-isolate-b", not(feature = "qemu-isolate-a")))]
    {
        Process::Second
    }
}

pub const fn foreign() -> Process {
    #[cfg(feature = "qemu-isolate-a")]
    {
        Process::Second
    }
    #[cfg(all(feature = "qemu-isolate-b", not(feature = "qemu-isolate-a")))]
    {
        Process::First
    }
}

/// Trusted INT80 handler. Ring-3 already compared its own page's value
/// before issuing this signal. Caller/task identity is never accepted
/// from a user register.
pub fn confirm_own_page(number: u64, caller_cs: u64) -> Option<u64> {
    if number != SIGNAL || caller_cs & 3 != 3 || CONFIRMED_OWN.load(Ordering::Acquire) {
        return None;
    }
    let (expected, _) = process_roots::process_root(owner())?;
    let observed: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
    }
    if observed & CR3_MASK != expected {
        return None;
    }
    let own = process_roots::mapped_page(owner())?;
    let other = process_roots::mapped_page(foreign())?;
    if own.physical_address == other.physical_address
        || own.virtual_address == other.virtual_address
    {
        return None;
    }
    CONFIRMED_OWN.store(true, Ordering::Release);
    crate::serial::write_line("SORVETH ISOLATION: own process memory read in ring 3");
    Some(REPLY)
}

/// Only an exact ring-3, nonpresent read #PF at the foreign process's
/// address is accepted. All expected values originate in kernel-owned
/// mapping descriptors, not user-provided registers.
pub fn expected_foreign_fault(address: u64, error: u64) -> bool {
    if !CONFIRMED_OWN.load(Ordering::Acquire) || (error & 0x1f) != 0x4 {
        return false;
    }
    let (root, own_slot) = match process_roots::process_root(owner()) {
        Some(v) => v,
        None => return false,
    };
    let (_, foreign_slot) = match process_roots::process_root(foreign()) {
        Some(v) => v,
        None => return false,
    };
    let other = match process_roots::mapped_page(foreign()) {
        Some(v) => v,
        None => return false,
    };
    if address != other.virtual_address || own_slot == foreign_slot {
        return false;
    }
    let current: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) current, options(nomem, nostack, preserves_flags));
    }
    if current & CR3_MASK != root {
        return false;
    }
    // Process roots are physical frames, not identity-mapped pointers. Switch
    // to the kernel root and inspect both slots through the owned frame window.
    let kernel = match crate::root::kernel_root_physical() {
        Some(kernel) => kernel,
        None => return false,
    };
    unsafe {
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
    }
    let own_entry = unsafe { process_roots::read_process_root_slot(owner(), own_slot) };
    let foreign_entry = unsafe { process_roots::read_process_root_slot(owner(), foreign_slot) };
    unsafe {
        asm!("mov cr3, {}", in(reg) current, options(nostack, preserves_flags));
    }
    own_entry.map_or(false, |entry| entry & 0x5 == 0x5) && foreign_entry == Some(0)
}

pub fn success_marker() -> &'static str {
    #[cfg(feature = "qemu-isolate-a")]
    {
        "SORVETH PROCESS A -> B USER ACCESS DENIED: verified"
    }
    #[cfg(all(feature = "qemu-isolate-b", not(feature = "qemu-isolate-a")))]
    {
        "SORVETH PROCESS B -> A USER ACCESS DENIED: verified"
    }
}
