#![no_std]

//! Sorveth Core: first freestanding kernel execution after ExitBootServices.
//! Early privileged bootstrap: page mapping, exception diagnostics, task
//! bookkeeping and kernel-local IPC are prototypes, not isolated userspace.

mod fibers;
mod interrupts;
mod monitor;
mod process_roots;
mod root;
mod screen;
mod serial;
mod stack;
mod tss;
#[cfg(feature = "qemu-user")]
mod user;

use sorveth_abi::{BootInfo, BOOT_PROTOCOL_VERSION};
use sorveth_cap::{CapabilitySpace, ObjectId, ObjectKind, Rights};
use sorveth_exchange::{Exchange, Receive};
use sorveth_frames::{FrameAllocator, FramePool};
use sorveth_ipc::{Mailbox, Message};
use sorveth_memory::MemoryMap;
use sorveth_paging::audit_inherited;
use sorveth_task::Scheduler;

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

    // Audit inherited firmware paging before installing Sorveth-owned tables.
    // The later root transition remains restricted to the QEMU bootstrap.
    let inherited = match audit_inherited() {
        Ok(paging) => paging,
        Err(_) => {
            serial::write_line("FATAL: unsupported inherited x86 paging state");
            halt_forever();
        }
    };
    serial::write_line("Inherited x86 paging: validated (read-only)");

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
    if map_buffer.is_err() || boot_info.is_err() || display.is_err() || frames.available_pages() < 2
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

    // M1-B2: change only the top-level PML4 root. The firmware-provided
    // lower tables remain shared; do not reclaim or rewrite any of them.
    // QEMU acceptance tests must see serial output AFTER this CR3 write.
    if unsafe { root::install(inherited.root_physical, &FRAME_POOL) }.is_err() {
        serial::write_line("FATAL: owned PML4 root transition failed");
        halt_forever();
    }
    serial::write_line("Sorveth PML4 root: active (firmware lower levels shared)");
    serial::write_line("Sorveth private supervisor NX mapping: verified");

    // M1-C: first owned x86 IDT. Keep maskable interrupts disabled until
    // timer/IRQ delivery and proper alternate fault stacks are implemented.
    if interrupts::install().is_err()
        || unsafe { tss::install() }.is_err()
        || !interrupts::enable_fault_stacks()
        || !interrupts::breakpoint_roundtrip()
    {
        serial::write_line("FATAL: x86 exception/TSS initialization failed");
        halt_forever();
    }
    serial::write_line("Sorveth IDT: installed; breakpoint roundtrip verified");
    serial::write_line("Sorveth emergency fault stacks: TSS loaded; IST1/IST2 armed");

    // Exercise two distinct supervisor NX mappings after the IDT is active.
    let first_page = root::claim_kernel_scratch(&FRAME_POOL);
    let second_page = root::claim_kernel_scratch(&FRAME_POOL);
    match (first_page, second_page) {
        (Ok(first), Ok(second)) if first != second && root::private_pages() == 3 => {
            serial::write_line("Sorveth dynamic private pages: 2 additional mappings verified");
        }
        _ => {
            serial::write_line("FATAL: private page allocator did not pass validation");
            halt_forever();
        }
    }

    // Fault-probe execution is deferred until the owned-stack continuation.

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

    // M2-A: kernel-internal IPC endpoint proof. No process or syscall has
    // access to these Rust objects yet; all authority checks are kernel-side.
    let ipc_ok = (|| {
        let root = caps
            .grant_root(
                ObjectId(2),
                ObjectKind::Endpoint,
                Rights::SEND | Rights::READ | Rights::DERIVE,
            )
            .ok()?;
        let send = caps.derive(root, Rights::SEND).ok()?;
        let recv = caps.derive(root, Rights::READ).ok()?;
        let mut endpoint = Mailbox::<4>::new(ObjectId(2)).ok()?;
        let msg = Message::from_bytes(0x534f, b"Sorveth").ok()?;
        endpoint.send(&caps, send, msg).ok()?;
        let delivered = endpoint.receive(&caps, recv).ok()?;
        caps.revoke(root).ok()?;
        Some(
            delivered == msg
                && endpoint.receive(&caps, recv).is_err()
                && endpoint.send(&caps, send, msg).is_err(),
        )
    })()
    .unwrap_or(false);
    if !ipc_ok {
        serial::write_line("FATAL: kernel IPC authorization test failed");
        halt_forever();
    }
    serial::write_line("Sorveth IPC: capability-checked mailbox and revocation validated");

    // M2-B bookkeeping only: select runnable task identities. There are no
    // saved CPU contexts or unprivileged task address spaces yet.
    let mut scheduler = Scheduler::<4>::new();
    let task_probe_ok = (|| {
        let first = scheduler.spawn(ObjectId(100)).ok()?;
        let second = scheduler.spawn(ObjectId(200)).ok()?;
        if scheduler.select_next() != Some(first) || scheduler.select_next() != Some(second) {
            return None;
        }
        scheduler.block(first).ok()?;
        if scheduler.select_next() != Some(second) {
            return None;
        }
        scheduler.wake(first).ok()?;
        scheduler.exit(second).ok()?;
        Some(
            scheduler.select_next() == Some(first)
                && scheduler.inspect(second).is_err()
                && scheduler.len() == 1,
        )
    })()
    .unwrap_or(false);
    if !task_probe_ok {
        serial::write_line("FATAL: task registry selection test failed");
        halt_forever();
    }
    serial::write_line("Sorveth task registry: fair selection and stale IDs validated");

    // M2-C: tie authorized IPC delivery to scheduler parking and wakeup.
    // This remains kernel-local; there is no CPU context switch or ring 3.
    let exchange_probe_ok = (|| {
        let mut exchange_caps = CapabilitySpace::<8>::new();
        let root = exchange_caps
            .grant_root(
                ObjectId(300),
                ObjectKind::Endpoint,
                Rights::SEND | Rights::READ | Rights::DERIVE,
            )
            .ok()?;
        let send = exchange_caps.derive(root, Rights::SEND).ok()?;
        let receive = exchange_caps.derive(root, Rights::READ).ok()?;
        let mut exchange = Exchange::<2, 2>::new(ObjectId(300)).ok()?;
        let reader = exchange.spawn(ObjectId(301)).ok()?;
        let writer = exchange.spawn(ObjectId(302)).ok()?;
        if exchange
            .receive_or_park(&exchange_caps, reader, receive)
            .ok()?
            != Receive::Parked
            || exchange.next_runnable() != Some(writer)
        {
            return None;
        }
        let msg = Message::from_bytes(0x534f, b"wakeup").ok()?;
        exchange.send(&exchange_caps, send, msg).ok()?;
        if exchange.next_runnable() != Some(reader)
            || exchange
                .receive_or_park(&exchange_caps, reader, receive)
                .ok()?
                != Receive::Delivered(msg)
            || exchange.pending_messages() != 0
        {
            return None;
        }
        exchange_caps.revoke(root).ok()?;
        Some(exchange.send(&exchange_caps, send, msg).is_err())
    })()
    .unwrap_or(false);
    if !exchange_probe_ok {
        serial::write_line("FATAL: capability-gated task wakeup test failed");
        halt_forever();
    }
    serial::write_line("Sorveth exchange: authorized send wakes a parked task");

    if boot.framebuffer.is_usable() {
        screen::paint(&boot.framebuffer);
        serial::write_line("Native framebuffer: painted");
    } else {
        serial::write_line("Native framebuffer: unsupported or unavailable");
    }
    // Never return into UEFI's stack. Both QEMU modes and the interactive
    // monitor execute on Sorveth's own statically retained kernel stack.
    stack::enter(memory_summary)
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
