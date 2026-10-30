//! Dedicated Sorveth bootstrap kernel stack (M1-E).
//!
//! This is a permanent, statically allocated stack in the loader image, not
//! a protected/guarded per-task stack. The firmware mapping of this memory
//! is still inherited. After leaving the EFI entry stack, this trampoline
//! must never return to it. Interrupts stay masked.

use sorveth_abi::BootInfo;
use sorveth_memory::{MapSummary, MemoryMap};

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

#[cfg(target_arch = "x86_64")]
static mut SAVED_BOOT: Option<BootInfo> = None;

/// Transfer to the Sorveth-owned stack, preserving the memory-map summary.
/// The EFI loader's stack is never reused by this kernel entry afterward.
pub fn enter(memory: MapSummary, boot: BootInfo) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!(SAVED_MEMORY), memory);
        // Retain an owned value copy: the original firmware entry stack
        // is abandoned permanently when the kernel changes RSP.
        ptr::write_volatile(ptr::addr_of_mut!(SAVED_BOOT), Some(boot));
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
        let _ = (memory, boot);
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
    // K.1d controlled QEMU proof: briefly run on the image-only root while
    // already on Sorveth's own PE-resident stack, and restore the prior
    // inherited lower-level root before any other kernel operation.
    let boot_info = unsafe { ptr::read_volatile(ptr::addr_of!(SAVED_BOOT)) };
    let root_test = match boot_info {
        Some(info) => unsafe {
            crate::image_page_tables::verify_temporary_image_root(
                info.image_base,
                info.image_size,
                base,
                end,
            )
        },
        None => Err(crate::image_page_tables::Error::InvalidImage),
    };
    if root_test.is_err() {
        crate::serial::write_line("FATAL: temporary PE-only CR3 transition failed");
        crate::halt_forever();
    }
    crate::serial::write_line(
        "SORVETH M2-K.1d: temporary PE-only CR3 transition and stack access verified",
    );

    // K.1d read-only survival inventory: no root is replaced here. Require
    // trusted, supervisor-only live mappings of code, CPU tables and every
    // page of the kernel, worker, fault and trap stacks before future work
    // removes OVMF lower-level page-table inheritance.
    let survived = unsafe { crate::supervisor_audit::verify_bootstrap_survival(base, end) };
    match survived {
        Ok(report) if report.inspected_pages >= 16 => {
            crate::serial::write_line(
                "SORVETH M2-K.1d: live supervisor code stack IDT TSS mappings audited",
            );
            crate::serial::write("Sorveth inherited supervisor samples: ");
            crate::serial::write_u64(report.inspected_pages);
            crate::serial::write(" (legacy writable+executable: ");
            crate::serial::write_u64(report.legacy_write_execute_pages);
            crate::serial::write_line(")");
        }
        _ => {
            crate::serial::write_line("FATAL: supervisor survival mapping audit failed");
            crate::halt_forever();
        }
    }
    // Build an immutable bounded physical-page inventory on the retained
    // kernel stack, not on the abandoned UEFI entry stack. The copied
    // BootInfo refers to the loader-owned, still-mapped descriptor buffer.
    let boot = match unsafe { ptr::read_volatile(ptr::addr_of!(SAVED_BOOT)) } {
        Some(info) => info,
        None => {
            crate::serial::write_line("FATAL: saved handoff data unavailable");
            crate::halt_forever();
        }
    };
    let map = match unsafe { MemoryMap::from_boot_info(&boot) } {
        Ok(value) => value,
        Err(_) => {
            crate::serial::write_line("FATAL: retained descriptor map unavailable");
            crate::halt_forever();
        }
    };
    let manifest = unsafe { crate::supervisor_manifest::capture::<192>(&map, &boot, (base, end)) };
    match manifest {
        Ok(found)
            if found.len() >= 48
                && found.count_kind(crate::supervisor_manifest::Kind::KernelPaging) == 4 =>
        {
            crate::serial::write_line(
                "SORVETH M2-K.1d: physical backing and UEFI provenance manifest audited",
            );
            crate::serial::write_line(
                "SORVETH M2-K.1d: four owned kernel paging frames provenance verified",
            );
            crate::serial::write("Sorveth manifest mapped pages: ");
            crate::serial::write_u64(found.len() as u64);
            crate::serial::write(" (legacy WX: ");
            crate::serial::write_u64(found.legacy_writable_executable() as u64);
            crate::serial::write(", unclassified device pages: ");
            crate::serial::write_u64(found.unknown_device_pages() as u64);
            crate::serial::write_line(")");

            let private_window =
                match unsafe { crate::root::audit_private_window(&crate::FRAME_POOL) } {
                    Ok(evidence) => evidence,
                    Err(reason) => {
                        crate::serial::write(
                            "FATAL: private high-half frame ownership audit failed, code ",
                        );
                        crate::serial::write_u64(reason.code());
                        crate::serial::write_line("");
                        crate::halt_forever();
                    }
                };
            crate::serial::write_line(
                "SORVETH M2-K.1f: private high-half scratch mappings are allocator-owned",
            );
            crate::serial::write("Sorveth private-window scratch pages: ");
            crate::serial::write_u64(private_window.mapped_pages);
            crate::serial::write(" (range ");
            crate::serial::write_u64(private_window.first_virtual_page);
            crate::serial::write("..");
            crate::serial::write_u64(private_window.last_virtual_page);
            crate::serial::write_line(")");

            // Compile the manifest into candidate mappings without installing
            // them. The PE image builder owns image mappings; this planner
            // contributes verified non-image supervisor pages and defers
            // framebuffer endpoints until cache policy is explicit.
            let image_header = unsafe {
                core::slice::from_raw_parts(
                    boot.image_base as *const u8,
                    crate::image_sections::HEADER_LIMIT,
                )
            };
            let mut plan = match unsafe {
                crate::supervisor_root_plan::compile(&found, &boot, image_header)
            } {
                Ok(plan) if plan.image_records() > 0 => plan,
                _ => {
                    crate::serial::write_line("FATAL: supervisor survival mapping plan failed");
                    crate::halt_forever();
                }
            };
            if crate::supervisor_root_plan::include_private_window(
                &mut plan,
                &private_window,
                &found,
                &boot,
                image_header,
            )
            .is_err()
            {
                crate::serial::write_line("FATAL: private-window mapping plan failed");
                crate::halt_forever();
            }
            crate::serial::write_line(
                "SORVETH M2-K.1g: audited high-half mappings added to candidate plan",
            );
            let candidate_evidence = match unsafe {
                crate::image_page_tables::extend_and_verify_survival_plan(
                    &boot, &map, &plan, &found,
                )
            } {
                Ok(evidence)
                    if evidence.planner_mappings == plan.mapping_count()
                        && evidence.survival_records_verified == found.len()
                        && evidence.framebuffer_pages
                            == plan
                                .framebuffer()
                                .map_or(0, |framebuffer| framebuffer.pages) =>
                {
                    evidence
                }
                _ => {
                    crate::serial::write_line(
                        "FATAL: inactive supervisor candidate hierarchy verification failed",
                    );
                    crate::halt_forever();
                }
            };
            crate::serial::write_line(
                "SORVETH M2-K.1j: inactive complete planned mappings verified",
            );
            crate::serial::write_line(
                "SORVETH M2-K.1k: every survival manifest record verified in candidate",
            );
            let alias = (0..plan.mapping_count())
                .filter_map(|index| plan.mapping(index))
                .find(|mapping| {
                    mapping.kind == crate::supervisor_manifest::Kind::KernelPaging
                        && ((mapping.virtual_page >> 12) & 511) == 510
                });
            let private_base = alias.and_then(|mapping| mapping.virtual_page.checked_sub(510 * 4096));
            let probe_frame = private_base.and_then(|window| {
                (0..plan.mapping_count())
                    .filter_map(|index| plan.mapping(index))
                    .find(|mapping| {
                        mapping.virtual_page >= window
                            && mapping.virtual_page < window + 510 * 4096
                            && mapping.writable
                            && !mapping.executable
                    })
                    .map(|mapping| mapping.physical_page)
            });
            if let (Some(window_base), Some(probe_frame)) = (private_base, probe_frame) {
                if unsafe {
                    crate::image_page_tables::verify_temporary_survival_root(
                        boot.image_base,
                        boot.image_size,
                        base,
                        end,
                        window_base,
                        probe_frame,
                    )
                }
                .is_err()
                {
                    crate::serial::write_line(
                        "FATAL: candidate physical-window lifecycle probe failed",
                    );
                    crate::halt_forever();
                }
            } else {
                crate::serial::write_line("FATAL: candidate physical-window probe target missing");
                crate::halt_forever();
            }
            crate::serial::write_line(
                "SORVETH M2-K.1l: candidate frame window mapped, read, cleared and invalidated",
            );
            crate::serial::write_line(
                "SORVETH M2-K.1k: expanded candidate CR3 and kernel stack restored safely",
            );
            crate::serial::write("Sorveth verified planner leaves: ");
            crate::serial::write_u64(candidate_evidence.planner_mappings as u64);
            crate::serial::write(" (framebuffer UC pages: ");
            crate::serial::write_u64(candidate_evidence.framebuffer_pages);
            crate::serial::write_line(")");

            crate::serial::write("Sorveth private-window plan records: ");
            crate::serial::write_u64(plan.private_window_records() as u64);
            crate::serial::write_line("");
            crate::serial::write_line(
                "SORVETH M2-K.1e: bounded supervisor survival mapping plan compiled",
            );
            crate::serial::write("Sorveth external supervisor mappings: ");
            crate::serial::write_u64(plan.mapping_count() as u64);
            crate::serial::write(" (image records checked: ");
            crate::serial::write_u64(plan.image_records() as u64);
            crate::serial::write(", framebuffer endpoint records checked: ");
            crate::serial::write_u64(plan.device_endpoint_records() as u64);
            crate::serial::write_line(")");
        }
        _ => {
            crate::serial::write_line("FATAL: supervisor physical backing manifest failed");
            crate::halt_forever();
        }
    }
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
    crate::serial::write_line("SORVETH M2-K.1d: owned PML4 root clone and verification complete");
    if unsafe { crate::process_roots::map_private_pages(&crate::FRAME_POOL) }.is_err() {
        crate::serial::write_line("FATAL: process-private user mapping validation failed");
        crate::halt_forever();
    }
    crate::serial::write_line(
        "Sorveth private process pages: distinct user RW/NX mappings verified",
    );
    crate::serial::write_line("SORVETH M2-K.1c: owned process paging-table construction verified");
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
    crate::serial::write_line(
        "SORVETH M2-K.1d: scheduler owned-frame audit and restored root denial verified",
    );
    crate::serial::write_line(
        "SORVETH M2-K.1c: registered process-table audit through owned window verified",
    );
    if !verify_user_buffer_policy() {
        crate::serial::write_line("FATAL: numeric user-buffer range validation failed");
        crate::halt_forever();
    }
    crate::serial::write_line("SORVETH M2-J.1: bounded user address ranges validated");
    if !unsafe { crate::process_roots::verify_user_page_walk() } {
        crate::serial::write_line(
            "FATAL: process-specific user page translation validation failed",
        );
        crate::halt_forever();
    }
    crate::serial::write_line("SORVETH M2-J.2: process-owned read/write page walks verified");
    crate::serial::write_line(
        "SORVETH M2-K.1b: owned page-table reads and process frames verified",
    );
    if !unsafe { crate::user_copy::verify_copy_from_user() } {
        crate::serial::write_line("FATAL: bounded process-owned user copy-in failed");
        crate::halt_forever();
    }
    crate::serial::write_line("SORVETH M2-J.3: bounded copy-in and denied buffers verified");
    if !unsafe { crate::user_copy::verify_copy_to_user() } {
        crate::serial::write_line("FATAL: bounded writable user copy-out failed");
        crate::halt_forever();
    }
    crate::serial::write_line("SORVETH M2-J.4: bounded writable copy-out and denial verified");
    crate::serial::write_line(
        "SORVETH M2-K.1d: user-copy integrity verified through owned frame aliases",
    );
    crate::serial::write_line("SORVETH M2-K.1d: owned read-only mapping denial verified");
    crate::serial::write_line("SORVETH M2-K.1b: user copy via owned frame window verified");
    #[cfg(feature = "qemu-user")]
    {
        #[cfg(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b"))]
        let (allowed, foreign) = match crate::transfer::initialize() {
            Some(handles) => handles,
            None => {
                crate::serial::write_line("FATAL: memory syscall authority unavailable");
                crate::halt_forever();
            }
        };
        #[cfg(not(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b")))]
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
        crate::serial::write_line("SORVETH M2-K.1d: owned ring-3 code stack and paging verified");
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
                crate::process_roots::attach_test_probe(crate::isolation::owner(), probe.entry)
            } {
                Ok(root) => root,
                Err(_) => {
                    crate::serial::write_line("FATAL: cannot attach selected process test code");
                    crate::halt_forever();
                }
            };
            crate::serial::write_line(
                "SORVETH M2-K.1d: owned ring-3 probe root attachment verified",
            );
            crate::serial::write_line("Sorveth ring-3 isolation: process-owned CR3 armed");
            unsafe {
                asm!("mov cr3, {}", in(reg) target_root, options(nostack, preserves_flags));
            }
        }
        #[cfg(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b"))]
        {
            let root = match unsafe {
                crate::process_roots::attach_test_probe(crate::transfer::owner(), probe.entry)
            } {
                Ok(value) => value,
                Err(_) => {
                    crate::serial::write_line("FATAL: memory syscall probe mapping failed");
                    crate::halt_forever();
                }
            };
            crate::serial::write_line(
                "SORVETH M2-K.1d: owned ring-3 probe root attachment verified",
            );
            crate::serial::write_line("Sorveth ring-3 memory gateway: process CR3 armed");
            unsafe {
                asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
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

/// QEMU bootstrap self-test for M2-J.1's numeric-only user range policy.
/// Even a valid numeric range can still be unmapped or belong to a different
/// process. No pointer dereference or page-table walk occurs here.
#[cfg(target_arch = "x86_64")]
fn verify_user_buffer_policy() -> bool {
    use sorveth_paging::user_range::{
        validate_user_range, UserRangeError, MAX_USER_TRANSFER_BYTES,
    };
    use sorveth_paging::{PAGE_BYTES, USER_LIMIT};
    let a = match crate::process_roots::mapped_page(crate::process_roots::Process::First) {
        Some(value) => value,
        None => return false,
    };
    let b = match crate::process_roots::mapped_page(crate::process_roots::Process::Second) {
        Some(value) => value,
        None => return false,
    };
    let valid_a = validate_user_range(a.virtual_address, 8);
    let valid_b = validate_user_range(b.virtual_address, PAGE_BYTES);
    let cross_page = validate_user_range(a.virtual_address + PAGE_BYTES - 1, 2);
    matches!(valid_a, Ok(range) if range.start() == a.virtual_address && range.page_count() == 1)
        && matches!(valid_b, Ok(range) if range.start() == b.virtual_address && range.page_count() == 1)
        && matches!(cross_page, Ok(range) if range.page_count() == 2)
        && validate_user_range(0xfff, 1) == Err(UserRangeError::NullPage)
        && validate_user_range(USER_LIMIT - 1, 2) == Err(UserRangeError::OutsideUserSpace)
        && validate_user_range(u64::MAX, 1) == Err(UserRangeError::ArithmeticOverflow)
        && validate_user_range(a.virtual_address, 0) == Err(UserRangeError::ZeroLength)
        && validate_user_range(a.virtual_address, MAX_USER_TRANSFER_BYTES + 1)
            == Err(UserRangeError::TooLarge)
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
