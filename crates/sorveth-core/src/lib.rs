#![no_std]

//! Sorveth Core: first freestanding kernel execution after ExitBootServices.
//! Boot milestone only; paging, protection rings, tasks and IPC are NOT ready.

mod screen;
mod serial;

use sorveth_abi::{BootInfo, BOOT_PROTOCOL_VERSION};
use sorveth_cap::{CapabilitySpace, ObjectId, ObjectKind, Rights};
use sorveth_memory::MemoryMap;
use sorveth_frames::FrameAllocator;

/// Never returns, and never calls firmware boot services.
pub fn kernel_main(boot: &BootInfo) -> ! {
    // x86 COM1 port I/O is available to the kernel without UEFI services.
    serial::init();
    serial::write_line("SORVETH OS / Sorveth Core");
    serial::write_line("Native kernel execution: EFI boot services exited");

    if boot.protocol_version != BOOT_PROTOCOL_VERSION || !boot.is_valid() {
        serial::write_line("FATAL: invalid boot protocol");
        halt_forever();
    }
    serial::write_line("Boot protocol v1: OK");

    // The loader owns the memory-map backing buffer, and its static storage
    // remains mapped after firmware boot services have exited. Never allocate
    // or reclaim frames based solely on this read-only diagnostic stage.
    let map = match unsafe { MemoryMap::from_boot_info(boot) } {
        Ok(map) => map,
        Err(_) => {
            serial::write_line("FATAL: physical memory map malformed");
            halt_forever();
        }
    };
    match map.summarize() {
        Ok(summary) if summary.conventional_pages >= 2 => {
            serial::write_line("UEFI physical memory map: validated");
        }
        _ => {
            serial::write_line("FATAL: physical memory map invalid or insufficient");
            halt_forever();
        }
    }

    // Bootstrap exercise: audit physical-frame ownership against the firmware
    // map. No frame is mapped, accessed, zeroed, or given to untrusted code.
    // All loader/kernel/boot-services allocations are deliberately excluded:
    // this early allocator only accepts conventional memory descriptors.
    // This is NOT yet the installed persistent kernel memory manager.
    let mut frames = match FrameAllocator::<256>::from_map(&map) {
        Ok(frames) => frames,
        Err(_) => {
            serial::write_line("FATAL: unsafe or oversized physical frame map");
            halt_forever();
        }
    };
    let distinct_frames = match (frames.allocate(1), frames.allocate(1)) {
        (Ok(first), Ok(second)) =>
            first.end_exclusive() <= second.start || second.end_exclusive() <= first.start,
        _ => false,
    };
    if !distinct_frames {
        serial::write_line("FATAL: physical frame ownership test failed");
        halt_forever();
    }
    serial::write_line("Physical frame planner: validated (no mappings written)");

    // This is the first isolated *data structure*, not process isolation.
    // The kernel remains privileged; untrusted code is not yet executing.
    let mut caps = CapabilitySpace::<32>::new();
    let rights = Rights::WRITE.union(Rights::READ).union(Rights::DERIVE);
    let probe_ok = match caps.grant_root(ObjectId(1), ObjectKind::Memory, rights) {
        Ok(root) => caps.authorize(root, Rights::WRITE).is_ok(),
        Err(_) => false,
    };
    if probe_ok { serial::write_line("Capability table: initialized"); }
    else { serial::write_line("FATAL: capability table unavailable"); halt_forever(); }

    if boot.framebuffer.is_usable() {
        screen::paint(&boot.framebuffer);
        serial::write_line("Native framebuffer: painted");
    } else {
        serial::write_line("Native framebuffer: unsupported or unavailable");
    }
    serial::write_line("SORVETH CORE ONLINE / end of milestone 0");
    // Only the dedicated CI smoke image signals the QEMU debug-exit device.
    // A normal kernel image does not use this emulator-only port.
    #[cfg(all(target_arch = "x86_64", feature = "qemu-smoke"))]
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0xf4u16, in("al") 0x10u8,
            options(nomem, nostack, preserves_flags));
    }
    halt_forever()
}

#[inline(never)]
fn halt_forever() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    }
}
