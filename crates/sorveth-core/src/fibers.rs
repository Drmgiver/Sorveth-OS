//! M2-D: first reversible native x86-64 kernel context switch.
//!
//! The test boots on Sorveth's dedicated kernel stack, saves the complete
//! Win64 callee-preserved register set and RSP, returns onto a separate
//! statically owned worker stack, then switches back twice.
//!
//! This is single-core, synchronous ring-0 execution; it does NOT schedule
//! timer interrupts, install user address spaces, or enter privilege ring 3.
//! No x87/AVX extended state is saved, so arbitrary task execution is NOT
//! yet supported. Only the controlled bootstrap proof uses this switcher.

#[cfg(target_arch = "x86_64")]
use core::{
    arch::global_asm,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

#[cfg(target_arch = "x86_64")]
const WORK_STACK_BYTES: usize = 64 * 1024;

/// Offset layout is consumed directly by the assembly routine.
/// XMM6-XMM15 are nonvolatile under the EFI / Microsoft x64 ABI.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct CpuContext {
    rsp: u64,
    rbx: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    xmm_nonvolatile: [u8; 160],
}

#[cfg(target_arch = "x86_64")]
impl CpuContext {
    const EMPTY: Self = Self {
        rsp: 0,
        rbx: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        xmm_nonvolatile: [0; 160],
    };
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct WorkerStack([u8; WORK_STACK_BYTES]);

#[cfg(target_arch = "x86_64")]
static mut WORKER_STACK: WorkerStack = WorkerStack([0; WORK_STACK_BYTES]);
#[cfg(target_arch = "x86_64")]
static mut BOOT_CONTEXT: CpuContext = CpuContext::EMPTY;
#[cfg(target_arch = "x86_64")]
static mut WORKER_CONTEXT: CpuContext = CpuContext::EMPTY;

#[cfg(target_arch = "x86_64")]
static STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static PROGRESS: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".global sorveth_swap_kernel_context",
    "sorveth_swap_kernel_context:",
    // rcx=previous, rdx=next according to the Windows x64 calling ABI.
    "mov [rcx + 0], rsp",
    "mov [rcx + 8], rbx",
    "mov [rcx + 16], rbp",
    "mov [rcx + 24], rdi",
    "mov [rcx + 32], rsi",
    "mov [rcx + 40], r12",
    "mov [rcx + 48], r13",
    "mov [rcx + 56], r14",
    "mov [rcx + 64], r15",
    "movdqu xmmword ptr [rcx + 72], xmm6",
    "movdqu xmmword ptr [rcx + 88], xmm7",
    "movdqu xmmword ptr [rcx + 104], xmm8",
    "movdqu xmmword ptr [rcx + 120], xmm9",
    "movdqu xmmword ptr [rcx + 136], xmm10",
    "movdqu xmmword ptr [rcx + 152], xmm11",
    "movdqu xmmword ptr [rcx + 168], xmm12",
    "movdqu xmmword ptr [rcx + 184], xmm13",
    "movdqu xmmword ptr [rcx + 200], xmm14",
    "movdqu xmmword ptr [rcx + 216], xmm15",
    "mov rsp, [rdx + 0]",
    "mov rbx, [rdx + 8]",
    "mov rbp, [rdx + 16]",
    "mov rdi, [rdx + 24]",
    "mov rsi, [rdx + 32]",
    "mov r12, [rdx + 40]",
    "mov r13, [rdx + 48]",
    "mov r14, [rdx + 56]",
    "mov r15, [rdx + 64]",
    "movdqu xmm6, xmmword ptr [rdx + 72]",
    "movdqu xmm7, xmmword ptr [rdx + 88]",
    "movdqu xmm8, xmmword ptr [rdx + 104]",
    "movdqu xmm9, xmmword ptr [rdx + 120]",
    "movdqu xmm10, xmmword ptr [rdx + 136]",
    "movdqu xmm11, xmmword ptr [rdx + 152]",
    "movdqu xmm12, xmmword ptr [rdx + 168]",
    "movdqu xmm13, xmmword ptr [rdx + 184]",
    "movdqu xmm14, xmmword ptr [rdx + 200]",
    "movdqu xmm15, xmmword ptr [rdx + 216]",
    "ret"
);

#[cfg(target_arch = "x86_64")]
extern "win64" {
    fn sorveth_swap_kernel_context(old: *mut CpuContext, next: *const CpuContext);
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
extern "win64" fn worker_entry() -> ! {
    PROGRESS.store(1, Ordering::Release);
    unsafe {
        sorveth_swap_kernel_context(
            ptr::addr_of_mut!(WORKER_CONTEXT),
            ptr::addr_of!(BOOT_CONTEXT),
        );
    }
    // The second entry must pick up where the first one yielded, proving
    // the preserved instruction pointer and worker stack frame survived.
    PROGRESS.store(2, Ordering::Release);
    unsafe {
        sorveth_swap_kernel_context(
            ptr::addr_of_mut!(WORKER_CONTEXT),
            ptr::addr_of!(BOOT_CONTEXT),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

/// One-shot test from the already established Sorveth kernel stack.
/// A fresh worker starts at a synthetic return address, with the ABI's
/// 32-byte caller shadow space and correct 16-byte call alignment.
pub fn verify_roundtrip() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if STARTED.swap(true, Ordering::AcqRel) {
            return false;
        }
        unsafe {
            let top = ptr::addr_of_mut!(WORKER_STACK).cast::<u8>() as u64 + WORK_STACK_BYTES as u64;
            // Top is page-aligned; RSP before RET is 0 (mod 16), and the
            // resulting worker-entry RSP is 8 (mod 16), as if CALL ran.
            let synthetic_rsp = top - 48;
            ptr::write(synthetic_rsp as *mut u64, worker_entry as usize as u64);
            ptr::write(
                ptr::addr_of_mut!(WORKER_CONTEXT),
                CpuContext {
                    rsp: synthetic_rsp,
                    ..CpuContext::EMPTY
                },
            );
            sorveth_swap_kernel_context(
                ptr::addr_of_mut!(BOOT_CONTEXT),
                ptr::addr_of!(WORKER_CONTEXT),
            );
            if PROGRESS.load(Ordering::Acquire) != 1 {
                return false;
            }
            sorveth_swap_kernel_context(
                ptr::addr_of_mut!(BOOT_CONTEXT),
                ptr::addr_of!(WORKER_CONTEXT),
            );
            PROGRESS.load(Ordering::Acquire) == 2
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
static mut SCHEDULED_BOOT: CpuContext = CpuContext::EMPTY;
#[cfg(target_arch = "x86_64")]
static mut SCHEDULED_A: CpuContext = CpuContext::EMPTY;
#[cfg(target_arch = "x86_64")]
static mut SCHEDULED_B: CpuContext = CpuContext::EMPTY;
#[cfg(target_arch = "x86_64")]
static mut SCHEDULED_A_STACK: WorkerStack = WorkerStack([0; WORK_STACK_BYTES]);
#[cfg(target_arch = "x86_64")]
static mut SCHEDULED_B_STACK: WorkerStack = WorkerStack([0; WORK_STACK_BYTES]);
#[cfg(target_arch = "x86_64")]
static A_RUNS: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "x86_64")]
static B_RUNS: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "x86_64")]
static SCHEDULED_ONCE: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
#[inline(never)]
extern "win64" fn task_a_entry() -> ! {
    A_RUNS.fetch_add(1, Ordering::AcqRel);
    unsafe {
        sorveth_swap_kernel_context(
            ptr::addr_of_mut!(SCHEDULED_A),
            ptr::addr_of!(SCHEDULED_BOOT),
        );
    }
    A_RUNS.fetch_add(1, Ordering::AcqRel);
    unsafe {
        sorveth_swap_kernel_context(
            ptr::addr_of_mut!(SCHEDULED_A),
            ptr::addr_of!(SCHEDULED_BOOT),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
extern "win64" fn task_b_entry() -> ! {
    B_RUNS.fetch_add(1, Ordering::AcqRel);
    unsafe {
        sorveth_swap_kernel_context(
            ptr::addr_of_mut!(SCHEDULED_B),
            ptr::addr_of!(SCHEDULED_BOOT),
        );
    }
    B_RUNS.fetch_add(1, Ordering::AcqRel);
    unsafe {
        sorveth_swap_kernel_context(
            ptr::addr_of_mut!(SCHEDULED_B),
            ptr::addr_of!(SCHEDULED_BOOT),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

/// A bootstrap-only round-robin scheduler selects which *native* worker
/// context is restored. Every continuation executes on its own 64 KiB stack.
/// This is CPU execution switching under a trusted kernel dispatcher, not
/// timer-driven multitasking, ring-3 isolation, or a general context ABI.
pub fn verify_scheduled_workers() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use sorveth_cap::ObjectId;
        use sorveth_task::Scheduler;

        if SCHEDULED_ONCE.swap(true, Ordering::AcqRel) {
            return false;
        }
        let mut tasks = Scheduler::<2>::new();
        let a = match tasks.spawn(ObjectId(401)) {
            Ok(id) => id,
            Err(_) => return false,
        };
        let b = match tasks.spawn(ObjectId(402)) {
            Ok(id) => id,
            Err(_) => return false,
        };
        unsafe {
            let a_top =
                ptr::addr_of_mut!(SCHEDULED_A_STACK).cast::<u8>() as u64 + WORK_STACK_BYTES as u64;
            let b_top =
                ptr::addr_of_mut!(SCHEDULED_B_STACK).cast::<u8>() as u64 + WORK_STACK_BYTES as u64;
            let a_rsp = a_top - 48;
            let b_rsp = b_top - 48;
            ptr::write(a_rsp as *mut u64, task_a_entry as usize as u64);
            ptr::write(b_rsp as *mut u64, task_b_entry as usize as u64);
            ptr::write(
                ptr::addr_of_mut!(SCHEDULED_A),
                CpuContext {
                    rsp: a_rsp,
                    ..CpuContext::EMPTY
                },
            );
            ptr::write(
                ptr::addr_of_mut!(SCHEDULED_B),
                CpuContext {
                    rsp: b_rsp,
                    ..CpuContext::EMPTY
                },
            );

            for (index, selected) in [a, b, a, b].iter().enumerate() {
                if tasks.select_next() != Some(*selected) {
                    return false;
                }
                let next = if *selected == a {
                    ptr::addr_of!(SCHEDULED_A)
                } else {
                    ptr::addr_of!(SCHEDULED_B)
                };
                sorveth_swap_kernel_context(ptr::addr_of_mut!(SCHEDULED_BOOT), next);
                let expected_a = match index {
                    0 | 1 => 1,
                    _ => 2,
                };
                let expected_b = match index {
                    0 => 0,
                    1 | 2 => 1,
                    _ => 2,
                };
                if A_RUNS.load(Ordering::Acquire) != expected_a
                    || B_RUNS.load(Ordering::Acquire) != expected_b
                {
                    return false;
                }
            }
        }
        tasks.exit(a).is_ok()
            && tasks.exit(b).is_ok()
            && A_RUNS.load(Ordering::Acquire) == 2
            && B_RUNS.load(Ordering::Acquire) == 2
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// The bootstrap kernel worker stack must also be mapped across CR3.
#[cfg(target_arch = "x86_64")]
pub(crate) fn survival_stack_bounds() -> (u64, u64) {
    let base = ptr::addr_of!(WORKER_STACK) as u64;
    (base, base + WORK_STACK_BYTES as u64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn win64_context_offsets_match_assembly_and_worker_has_shadow_space() {
        #[cfg(target_arch = "x86_64")]
        {
            use super::*;
            use core::mem::{align_of, offset_of, size_of};
            assert_eq!(align_of::<CpuContext>(), 16);
            assert_eq!(size_of::<CpuContext>(), 240);
            assert_eq!(offset_of!(CpuContext, rsp), 0);
            assert_eq!(offset_of!(CpuContext, rbx), 8);
            assert_eq!(offset_of!(CpuContext, rbp), 16);
            assert_eq!(offset_of!(CpuContext, rdi), 24);
            assert_eq!(offset_of!(CpuContext, rsi), 32);
            assert_eq!(offset_of!(CpuContext, r12), 40);
            assert_eq!(offset_of!(CpuContext, r13), 48);
            assert_eq!(offset_of!(CpuContext, r14), 56);
            assert_eq!(offset_of!(CpuContext, r15), 64);
            assert_eq!(offset_of!(CpuContext, xmm_nonvolatile), 72);
            assert_eq!(align_of::<WorkerStack>(), 4096);
            assert_eq!((WORK_STACK_BYTES - 48 + 8) % 16, 8);
        }
    }
}
