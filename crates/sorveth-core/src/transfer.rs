//! M2-J.5: QEMU-only, capability-checked INT80 memory-transfer gateway.
//!
//! A ring-3 caller executes under a specific process CR3 root. The kernel
//! verifies that root and uses its own saved TaskId/Process binding; NO
//! user-supplied process/task ID or page-table root is accepted. Tokens
//! are opaque, generation-bound memory capabilities.
//!
//! This intentionally tests fixed 8-byte transfers to the two permanent
//! private bootstrap pages. Not a production ABI: no preemption, SMP,
//! page reclaim, arbitrary pageable buffers, or fault recovery exists.

use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use sorveth_broker::{memory_authority::MemoryAuthority, REPLY_DENIED};
use sorveth_cap::{ObjectId, Rights};
use sorveth_task::TaskId;

use crate::process_roots::{self, Process};

const CR3_MASK: u64 = 0x000f_ffff_ffff_f000;
const OBJECT_A: ObjectId = ObjectId(0x5a01);
const OBJECT_B: ObjectId = ObjectId(0x5a02);
const PATTERN: [u8; 8] = [0xd5, 0x31, 0x28, 0x7b, 0x9a, 0xee, 0x40, 0x16];

pub const SYS_COPY_IN: u64 = 0x70;
pub const SYS_COPY_OUT: u64 = 0x71;
pub const SYS_COMPLETE: u64 = 0x72;
pub const COPY_IN_OK: u64 = 0x5356_4a52;
pub const COPY_OUT_OK: u64 = 0x5356_4a57;
pub const COPY_DENIED: u64 = REPLY_DENIED;

struct State {
    authority: MemoryAuthority<2, 4>,
    task: TaskId,
    process: Process,
    root: u64,
    read_handle: u64,
    write_handle: u64,
    foreign_handle: u64,
    original: u64,
    foreign_original: u64,
    completed: u8,
}

static mut STATE: Option<State> = None;
static READY: AtomicBool = AtomicBool::new(false);

pub const fn owner() -> Process {
    #[cfg(feature = "qemu-transfer-a")]
    {
        Process::First
    }
    #[cfg(all(feature = "qemu-transfer-b", not(feature = "qemu-transfer-a")))]
    {
        Process::Second
    }
}

pub const fn other() -> Process {
    #[cfg(feature = "qemu-transfer-a")]
    {
        Process::Second
    }
    #[cfg(all(feature = "qemu-transfer-b", not(feature = "qemu-transfer-a")))]
    {
        Process::First
    }
}

fn object(process: Process) -> ObjectId {
    match process {
        Process::First => OBJECT_A,
        Process::Second => OBJECT_B,
    }
}

fn fatal() -> ! {
    crate::serial::write_line("FATAL: ring-3 memory syscall test invalid");
    crate::halt_forever()
}

/// Privileged boot-time authority setup on the sole QEMU CPU.
/// No capability grants are ever initiated by user code.
pub fn initialize() -> Option<(u64, u64)> {
    if READY.load(Ordering::Acquire) {
        return None;
    }
    let process = owner();
    let root = unsafe { process_roots::checked_process_root(process) }?;
    let own = process_roots::mapped_page(process)?;
    let foreign = process_roots::mapped_page(other())?;
    if own.physical_address == foreign.physical_address {
        return None;
    }
    let mut authority = MemoryAuthority::<2, 4>::new();
    let task = authority.spawn(ObjectId(0x5b01)).ok()?;
    let foreign_task = authority.spawn(ObjectId(0x5b02)).ok()?;
    let read_handle = authority.grant(task, object(process), Rights::READ).ok()?.raw();
    let write_handle = authority.grant(task, object(process), Rights::WRITE).ok()?.raw();
    let foreign_handle = authority.grant(foreign_task, object(other()), Rights::WRITE).ok()?.raw();
    let original = unsafe { ptr::read_volatile(own.physical_address as *const u64) };
    let foreign_original = unsafe { ptr::read_volatile(foreign.physical_address as *const u64) };
    unsafe {
        ptr::write(
            ptr::addr_of_mut!(STATE),
            Some(State {
                authority,
                task,
                process,
                root,
                read_handle,
                write_handle,
                foreign_handle,
                original,
                foreign_original,
                completed: 0,
            }),
        );
    }
    READY.store(true, Ordering::Release);
    Some((read_handle, foreign_handle))
}

/// Only test-machine-code generation uses this kernel-initialized token.
pub fn write_handle() -> Option<u64> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    unsafe { (*ptr::addr_of!(STATE)).as_ref().map(|s| s.write_handle) }
}

pub const fn pattern() -> [u8; 8] {
    PATTERN
}

/// RAII restoration of the original caller's CR3 after the kernel runs its
/// existing copy-in/out primitives. The interrupt frame is deliberately
/// not switched or rewritten; IRETQ resumes under this same process root.
struct CallerRoot {
    caller: u64,
}

impl CallerRoot {
    unsafe fn enter(caller: u64) -> Option<Self> {
        let kernel = crate::root::kernel_root_physical()?;
        if caller == kernel || caller == 0 || kernel == 0 {
            return None;
        }
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
        Some(Self { caller })
    }
}

impl Drop for CallerRoot {
    fn drop(&mut self) {
        unsafe {
            asm!("mov cr3, {}", in(reg) self.caller, options(nostack, preserves_flags));
        }
    }
}

/// Real INT80 dispatch. Arguments originate in user registers, but the
/// identity of the current process is derived exclusively from the
/// verified active CR3 and a saved, generation-safe kernel task binding.
/// The existing copy functions require kernel CR3, so we temporarily
/// select it and restore the process root before returning to ring 3.
///
/// # Safety
/// Called only from the installed ring-3 INT80 gate on the bootstrap CPU
/// with IF=0, static kernel mappings available under both roots, and
/// permanently retained paging/data frames. Not reentrant or SMP safe.
pub unsafe fn dispatch(
    number: u64,
    caller_cs: u64,
    raw_handle: u64,
    user_address: u64,
    length: u64,
) -> u64 {
    if caller_cs & 3 != 3 || !READY.load(Ordering::Acquire) {
        fatal();
    }
    let active: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    let state = match (*ptr::addr_of_mut!(STATE)).as_mut() {
        Some(s) => s,
        None => fatal(),
    };
    // No TaskId, Process or root is accepted from any user argument.
    if active & CR3_MASK != state.root || state.process != owner() {
        fatal();
    }
    let guard = match CallerRoot::enter(state.root) {
        Some(guard) => guard,
        None => fatal(),
    };
    let mapped = match process_roots::mapped_page(state.process) {
        Some(m) => m,
        None => fatal(),
    };
    let foreign = match process_roots::mapped_page(other()) {
        Some(m) => m,
        None => fatal(),
    };
    let expected = match state.completed {
        0 => (SYS_COPY_IN, state.read_handle, mapped.virtual_address, 8, COPY_IN_OK),
        1 => (SYS_COPY_IN, state.read_handle, foreign.virtual_address, 8, COPY_DENIED),
        2 => (SYS_COPY_OUT, state.read_handle, mapped.virtual_address, 8, COPY_DENIED),
        3 => (SYS_COPY_OUT, state.foreign_handle, mapped.virtual_address, 8, COPY_DENIED),
        4 => (SYS_COPY_IN, 0, mapped.virtual_address, 8, COPY_DENIED),
        5 => (SYS_COPY_IN, state.read_handle, mapped.virtual_address, 0, COPY_DENIED),
        6 => (SYS_COPY_OUT, state.write_handle, mapped.virtual_address + 4095, 2, COPY_DENIED),
        7 => (SYS_COPY_OUT, state.write_handle, mapped.virtual_address, 8, COPY_OUT_OK),
        8 => (SYS_COMPLETE, 0, mapped.virtual_address, 8, 0),
        _ => fatal(),
    };
    if (number, raw_handle, user_address, length) != (expected.0, expected.1, expected.2, expected.3) {
        fatal();
    }

    let result = match number {
        SYS_COPY_IN | SYS_COPY_OUT => {
            let needed = if number == SYS_COPY_IN { Rights::READ } else { Rights::WRITE };
            if state
                .authority
                .authorize(state.task, raw_handle, object(state.process), needed)
                .is_err()
            {
                COPY_DENIED
            } else if length != 8 {
                COPY_DENIED
            } else if number == SYS_COPY_IN {
                let mut output = [0u8; 8];
                if crate::user_copy::copy_from_process(state.process, user_address, &mut output)
                    .is_ok()
                    && u64::from_le_bytes(output) == state.original
                {
                    COPY_IN_OK
                } else {
                    COPY_DENIED
                }
            } else if crate::user_copy::copy_to_process(state.process, user_address, &PATTERN)
                .is_ok()
            {
                COPY_OUT_OK
            } else {
                COPY_DENIED
            }
        }
        SYS_COMPLETE => {
            if state.completed != 8 {
                fatal();
            }
            let mut read_back = [0u8; 8];
            if crate::user_copy::copy_from_process(
                state.process,
                mapped.virtual_address,
                &mut read_back,
            ).is_err()
                || read_back != PATTERN
                || ptr::read_volatile(foreign.physical_address as *const u64) != state.foreign_original
            {
                fatal();
            }
            // Restore the original data for future bootstrap invariants.
            if crate::user_copy::copy_to_process(
                state.process,
                mapped.virtual_address,
                &state.original.to_le_bytes(),
            ).is_err()
                || ptr::read_volatile(mapped.physical_address as *const u64) != state.original
            {
                fatal();
            }
            0
        }
        _ => fatal(),
    };
    if result != expected.4 {
        fatal();
    }
    state.completed += 1;
    if number == SYS_COMPLETE {
        if state.completed != 9 {
            fatal();
        }
        crate::serial::write_line("SORVETH M2-J.5: ring-3 memory syscalls authorized and denied");
        // Only after both copy operations, all denial paths, and original
        // frame restoration are verified does QEMU exit successfully.
        asm!(
            "out dx, al",
            in("dx") 0xf4u16,
            in("al") 0x10u8,
            options(nomem, nostack, preserves_flags),
        );
        fatal();
    }
    drop(guard); // caller CR3 restored before entry stub performs IRETQ
    result
}
