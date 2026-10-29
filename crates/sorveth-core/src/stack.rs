//! Dedicated Sorveth bootstrap kernel stack (M1-E).
//!
//! This is a permanent, statically allocated stack in the loader image, not
//! a protected/guarded per-task stack. The firmware mapping of this memory
//! is still inherited. After leaving the EFI entry stack, this trampoline
//! must never return to it. Interrupts stay masked.

use sorveth_memory::MapSummary;

#[cfg(target_arch = "x86_64")]
use core::{arch::asm, ptr};

#[cfg(target_arch = "x86_64")]
const STACK_BYTES: usize = 128 * 1024;

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct KernelStack([u8; STACK_BYTES]);

#[cfg(target_arch = "x86_64")]
static mut KERNEL_STACK: KernelStack = KernelStack([0; STACK_BYTES]);

#[cfg(target_arch = "x86_64")]
static mut SAVED_MEMORY: MapSummary = MapSummary {
    descriptors: 0,
    conventional_pages: 0,
    highest_physical_end: 0,
};

/// Transfer to the Sorveth-owned stack, preserving the memory-map summary.
/// The EFI loader's stack is never reused by this kernel entry afterward.
pub fn enter(memory: MapSummary) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!(SAVED_MEMORY), memory);
        let base = ptr::addr_of_mut!(KERNEL_STACK).cast::<u8>() as u64;
        let top = base + STACK_BYTES as u64;
        // Win64/efiapi requires 16-byte stack alignment at the call site
        // and 32 bytes of shadow space. CALL then pushes the return address.
        // Continuation is diverging and cannot return to the EFI stack.
        asm!(
            "mov rsp, {stack_top}",
            "and rsp, -16",
            "sub rsp, 32",
            "call {entry}",
            "ud2",
            stack_top = in(reg) top,
            entry = sym continue_on_owned_stack,
            options(noreturn),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = memory;
        crate::halt_forever()
    }
}

#[cfg(target_arch = "x86_64")]
extern "efiapi" fn continue_on_owned_stack() -> ! {
    let base = ptr::addr_of!(KERNEL_STACK) as u64;
    let end = base + STACK_BYTES as u64;
    let rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    if !(base < rsp && rsp < end) {
        crate::serial::write_line("FATAL: Sorveth kernel stack transfer failed");
        crate::halt_forever();
    }
    crate::serial::write_line("Sorveth dedicated kernel stack: active");
    if !crate::fibers::verify_roundtrip() {
        crate::serial::write_line("FATAL: native kernel context switch failed");
        crate::halt_forever();
    }
    crate::serial::write_line("Sorveth native context switch: two worker roundtrips verified");
    if !crate::fibers::verify_scheduled_workers() {
        crate::serial::write_line("FATAL: scheduled kernel workers did not complete");
        crate::halt_forever();
    }
    crate::serial::write_line("Sorveth scheduled kernel contexts: A B A B verified");
    if unsafe { crate::process_roots::prepare_and_verify() }.is_err() {
        crate::serial::write_line("FATAL: private process PML4 roots did not pass validation");
        crate::halt_forever();
    }
    crate::serial::write_line("Sorveth process roots: two distinct supervisor PML4 roots verified");
    if unsafe { crate::process_roots::map_private_pages(&crate::FRAME_POOL) }.is_err() {
        crate::serial::write_line("FATAL: process-private user mapping validation failed");
        crate::halt_forever();
    }
    crate::serial::write_line(
        "Sorveth private process pages: distinct user RW/NX mappings verified",
    );
    if unsafe { crate::address_scheduler::verify_scheduled_switches() }.is_err() {
        crate::serial::write_line("FATAL: scheduler address-space switching failed");
        crate::halt_forever();
    }
    crate::serial::write_line("Sorveth scheduler CR3: A B A B private address spaces verified");
    if unsafe { crate::address_scheduler::verify_lifecycle_hardening() }.is_err() {
        crate::serial::write_line("FATAL: task address-space lifecycle guards failed");
        crate::halt_forever();
    }
    crate::serial::write_line("SORVETH M2-I HARDENING: blocked, stale and damaged mappings denied");
    #[cfg(feature = "qemu-user")]
    {
        let (allowed, foreign) = match crate::user::initialize_broker() {
            Some(handles) => handles,
            None => {
                crate::serial::write_line("FATAL: task broker initialization failed");
                crate::halt_forever();
            }
        };
        let probe = match crate::root::prepare_user_probe(&crate::FRAME_POOL, allowed, foreign) {
            Ok(probe) => probe,
            Err(_) => {
                crate::serial::write_line("FATAL: ring-3 user mappings unavailable");
                crate::halt_forever();
            }
        };
        let (cs, ss) = match crate::tss::user_selectors() {
            Some(selectors) => selectors,
            None => {
                crate::serial::write_line("FATAL: ring-3 selectors not loaded");
                crate::halt_forever();
            }
        };
        if !crate::interrupts::install_user_gateway() {
            crate::serial::write_line("FATAL: ring-3 trap gateway unavailable");
            crate::halt_forever();
        }
        #[cfg(any(feature = "qemu-isolate-a", feature = "qemu-isolate-b"))]
        {
            let target_root = match unsafe {
                crate::process_roots::attach_isolation_probe(crate::isolation::owner(), probe.entry)
            } {
                Ok(root) => root,
                Err(_) => {
                    crate::serial::write_line("FATAL: cannot attach selected process test code");
                    crate::halt_forever();
                }
            };
            crate::serial::write_line("Sorveth ring-3 isolation: process-owned CR3 armed");
            unsafe {
                asm!("mov cr3, {}", in(reg) target_root, options(nostack, preserves_flags));
            }
        }
        crate::serial::write_line("Sorveth ring-3 probe: user mappings and trap ready");
        unsafe { crate::user::enter(probe.entry, probe.stack, cs, ss) }
    }
    let summary = unsafe { ptr::read_volatile(ptr::addr_of!(SAVED_MEMORY)) };

    // The controlled #PF must now be serviced on Sorveth's own stack too.
    #[cfg(feature = "qemu-fault")]
    {
        let address = match crate::root::deliberate_fault_address() {
            Some(address) => address,
            None => {
                crate::serial::write_line("FATAL: missing unmapped test address");
                crate::halt_forever();
            }
        };
        unsafe {
            ptr::read_volatile(address as *const u64);
        }
        crate::serial::write_line("FATAL: intentional page fault returned unexpectedly");
        crate::halt_forever();
    }

    crate::serial::write_line("SORVETH CORE ONLINE / end of milestone 0");

    #[cfg(feature = "qemu-smoke")]
    {
        unsafe {
            asm!(
                "out dx, al",
                in("dx") 0xf4u16,
                in("al") 0x10u8,
                options(nomem, nostack, preserves_flags)
            );
        }
        crate::halt_forever();
    }

    #[cfg(not(any(feature = "qemu-smoke", feature = "qemu-fault", feature = "qemu-user")))]
    crate::monitor::run(summary, &crate::FRAME_POOL);

    #[cfg(any(feature = "qemu-fault", feature = "qemu-user"))]
    crate::halt_forever()
}

#[cfg(test)]
mod tests {
    #[test]
    fn stack_is_larger_than_initial_64k_and_page_aligned() {
        #[cfg(target_arch = "x86_64")]
        {
            assert!(super::STACK_BYTES >= 128 * 1024);
            assert_eq!(core::mem::align_of::<super::KernelStack>(), 4096);
        }
    }
}
