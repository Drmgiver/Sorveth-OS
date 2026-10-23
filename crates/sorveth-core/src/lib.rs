#![no_std]

//! Sorveth Core: first freestanding kernel execution after ExitBootServices.
//! Boot milestone only; paging, protection rings, tasks and IPC are NOT ready.

mod monitor;
mod screen;
mod serial;

use sorveth_abi::{BootInfo, BOOT_PROTOCOL_VERSION};
use sorveth_cap::{CapabilitySpace, ObjectId, ObjectKind, Rights};
use sorveth_frames::{FrameAllocator, FramePool};
use sorveth_memory::MemoryMap;

static FRAME_POOL: FramePool<256> = FramePool::new();

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
    let memory_summary = match map.summarize() {
        Ok(summary) if summary.conventional_pages >= 2 => {
            serial::write_line("UEFI physical memory map: validated");
            summary
        }
        _ => {
            serial::write_line("FATAL: physical memory map invalid or insufficient");
            halt_forever();
        }
    };

    // M1-A: retain an immutable-ownership *ledger* for conventional pages.
    // Never reclaim loader/kernel/runtime allocations from UEFI at this stage;
    // no physical page is dereferenced, mapped or treated as zeroed.
    let mut frames = match FrameAllocator::<256>::from_map(&map) {
        Ok(frames) => frames,
        Err(_) => {
            serial::write_line("FATAL: unsafe or oversized physical frame map");
            halt_forever();
        }
    };

    // Additional guard rails: even on a misclassified firmware map, no claim
    // may intersect the loader's descriptor buffer, BootInfo, or display.
    let map_buffer = frames.reserve_bytes(boot.memory_map_address, boot.memory_map_size);
    let boot_info = frames.reserve_bytes(
        boot as *const BootInfo as u64,
        core::mem::size_of::<BootInfo>() as u64,
    );
    let display = if boot.framebuffer.is_usable() {
        frames.reserve_bytes(boot.framebuffer.address, boot.framebuffer.size_bytes)
    } else {
        Ok(())
    };
    if map_buffer.is_err() || boot_info.is_err() || display.is_err()
        || frames.available_pages() < 2
    {
        serial::write_line("FATAL: physical frame reservations could not be secured");
        halt_forever();
    }
    if FRAME_POOL.install(frames).is_err() {
        serial::write_line("FATAL: physical frame ledger initialized twice");
        halt_forever();
    }
    serial::write_line("Physical frame planner: validated (no mappings written)");
    serial::write_line("Persistent physical frame ledger: installed (unmapped)");

    // This is the first isolated *data structure*, not process isolation.
    // The kernel remains privileged; untrusted code is not yet executing.
    let mut caps = CapabilitySpace::<32>::new();
    let rights = Rights::WRITE.union(Rights::READ).union(Rights::DERIVE);
    let probe_ok = match caps.grant_root(ObjectId(1), ObjectKind::Memory, rights) {
        Ok(root) => caps.authorize(root, Rights::WRITE).is_ok(),
        Err(_) => false,
    };
    if probe_ok {
        serial::write_line("Capability table: initialized");
    } else {
        serial::write_line("FATAL: capability table unavailable");
        halt_forever();
    }

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
    #[cfg(feature = "qemu-smoke")]
    halt_forever();

    #[cfg(not(feature = "qemu-smoke"))]
    monitor::run(memory_summary, &FRAME_POOL)
}

#[inline(never)]
fn halt_forever() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    }
}
