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
const WRITE_PHASE: u8 = 16;
const COMPLETE_PHASE: u8 = 21;
const UNKNOWN_SYSCALL: u64 = 0x7f;

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
    original_checksum: u64,
    written_checksum: u64,
    foreign_checksum: u64,
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

/// Hash every byte of a permanently owned frame through the short-lived
/// high-half physical window, not via firmware's physical identity mapping.
/// The eight-byte override computes a predicted image without modifying RAM.
/// This is only a QEMU test integrity oracle, not cryptographic protection.
///
/// # Safety
/// Kernel CR3 active, CPL0 on the only CPU, maskable IRQs off, and the
/// ledger-owned frame is never unmapped or reclaimed during this operation.
unsafe fn frame_checksum(physical: u64, override_word: Option<[u8; 8]>) -> Option<u64> {
    crate::root::with_physical_window(physical, |window| {
        let mut checksum = 0xcbf2_9ce4_8422_2325u64;
        for offset in 0..4096usize {
            let value = if offset < 8 {
                match override_word {
                    Some(word) => word[offset],
                    None => ptr::read_volatile(window.add(offset) as *const u8),
                }
            } else {
                ptr::read_volatile(window.add(offset) as *const u8)
            };
            checksum = (checksum ^ value as u64).wrapping_mul(0x100_0000_01b3);
        }
        checksum
    })
    .ok()
}

/// Return the first 64-bit word of a permanently owned process frame through
/// the transient supervisor-only physical window.
///
/// # Safety
/// The same single-core QEMU preconditions as frame_checksum apply.
unsafe fn process_word(physical: u64) -> Option<u64> {
    crate::root::with_physical_window(physical, |window| {
        ptr::read_volatile(window as *const u64)
    })
    .ok()
}

/// Verify *all* 4096 bytes of both physical process data pages and
/// revalidate the live capability grants and page-table ownership. This
/// is run before AND after every real CPL3 syscall, including failures.
///
/// # Safety
/// Single core, IF=0, active Sorveth kernel root, stable page tables.
unsafe fn integrity_holds(state: &State, expected_owner: u64) -> bool {
    let own = match process_roots::mapped_page(state.process) {
        Some(page) => page,
        None => return false,
    };
    let foreign = match process_roots::mapped_page(other()) {
        Some(page) => page,
        None => return false,
    };
    frame_checksum(own.physical_address, None) == Some(expected_owner)
        && frame_checksum(foreign.physical_address, None) == Some(state.foreign_checksum)
        && process_roots::checked_process_root(state.process) == Some(state.root)
        && process_roots::checked_process_root(other()).is_some()
        && state
            .authority
            .authorize(
                state.task,
                state.read_handle,
                object(state.process),
                Rights::READ,
            )
            .is_ok()
        && state
            .authority
            .authorize(
                state.task,
                state.write_handle,
                object(state.process),
                Rights::WRITE,
            )
            .is_ok()
        && state
            .authority
            .authorize(
                state.task,
                state.foreign_handle,
                object(state.process),
                Rights::WRITE,
            )
            .is_err()
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
    let read_handle = authority
        .grant(task, object(process), Rights::READ)
        .ok()?
        .raw();
    let write_handle = authority
        .grant(task, object(process), Rights::WRITE)
        .ok()?
        .raw();
    let foreign_handle = authority
        .grant(foreign_task, object(other()), Rights::WRITE)
        .ok()?
        .raw();
    let original = unsafe { process_word(own.physical_address) }?;
    let foreign_original = unsafe { process_word(foreign.physical_address) }?;
    let original_checksum = unsafe { frame_checksum(own.physical_address, None) }?;
    let written_checksum = unsafe { frame_checksum(own.physical_address, Some(PATTERN)) }?;
    let foreign_checksum = unsafe { frame_checksum(foreign.physical_address, None) }?;
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
                original_checksum,
                written_checksum,
                foreign_checksum,
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
    // In all denied phases, the physical pages and trusted authority
    // must be *identical* before and after entering the syscall.
    let pre_expected = if state.completed > WRITE_PHASE {
        state.written_checksum
    } else {
        state.original_checksum
    };
    if !integrity_holds(state, pre_expected) {
        fatal();
    }
    let expected = match state.completed {
        0 => (
            SYS_COPY_IN,
            state.read_handle,
            mapped.virtual_address,
            8,
            COPY_IN_OK,
        ),
        1 => (
            SYS_COPY_IN,
            state.read_handle,
            foreign.virtual_address,
            8,
            COPY_DENIED,
        ),
        2 => (
            SYS_COPY_OUT,
            state.read_handle,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        3 => (
            SYS_COPY_OUT,
            state.foreign_handle,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        4 => (SYS_COPY_IN, 0, mapped.virtual_address, 8, COPY_DENIED),
        5 => (
            SYS_COPY_IN,
            state.read_handle,
            mapped.virtual_address,
            0,
            COPY_DENIED,
        ),
        6 => (
            SYS_COPY_OUT,
            state.write_handle,
            mapped.virtual_address + 4095,
            2,
            COPY_DENIED,
        ),
        7 => (
            SYS_COPY_OUT,
            state.write_handle,
            foreign.virtual_address,
            8,
            COPY_DENIED,
        ),
        8 => (
            SYS_COPY_IN,
            state.write_handle,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        9 => (
            SYS_COPY_IN,
            u64::MAX,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        10 => (SYS_COPY_IN, state.read_handle, 0, 8, COPY_DENIED),
        11 => (SYS_COPY_IN, state.read_handle, u64::MAX, 8, COPY_DENIED),
        12 => (
            SYS_COPY_OUT,
            state.write_handle,
            0xffff_8000_0000_0000,
            8,
            COPY_DENIED,
        ),
        13 => (
            SYS_COPY_IN,
            state.read_handle,
            0x0000_7fff_ffff_fffc,
            8,
            COPY_DENIED,
        ),
        14 => (
            SYS_COPY_IN,
            state.read_handle,
            mapped.virtual_address,
            65537,
            COPY_DENIED,
        ),
        15 => (
            SYS_COPY_OUT,
            state.write_handle,
            mapped.virtual_address,
            0,
            COPY_DENIED,
        ),
        WRITE_PHASE => (
            SYS_COPY_OUT,
            state.write_handle,
            mapped.virtual_address,
            8,
            COPY_OUT_OK,
        ),
        17 => (
            SYS_COPY_OUT,
            state.read_handle,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        18 => (
            SYS_COPY_OUT,
            state.foreign_handle,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        19 => (
            SYS_COPY_OUT,
            state.write_handle,
            foreign.virtual_address,
            8,
            COPY_DENIED,
        ),
        20 => (
            UNKNOWN_SYSCALL,
            state.write_handle,
            mapped.virtual_address,
            8,
            COPY_DENIED,
        ),
        COMPLETE_PHASE => (SYS_COMPLETE, 0, mapped.virtual_address, 8, 0),
        _ => fatal(),
    };
    if (number, raw_handle, user_address, length)
        != (expected.0, expected.1, expected.2, expected.3)
    {
        fatal();
    }

    let result = match number {
        SYS_COPY_IN | SYS_COPY_OUT => {
            let needed = if number == SYS_COPY_IN {
                Rights::READ
            } else {
                Rights::WRITE
            };
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
            if state.completed != COMPLETE_PHASE {
                fatal();
            }
            let mut read_back = [0u8; 8];
            if crate::user_copy::copy_from_process(
                state.process,
                mapped.virtual_address,
                &mut read_back,
            )
            .is_err()
                || read_back != PATTERN
                || process_word(foreign.physical_address) != Some(state.foreign_original)
            {
                fatal();
            }
            // Restore the original data for future bootstrap invariants.
            if crate::user_copy::copy_to_process(
                state.process,
                mapped.virtual_address,
                &state.original.to_le_bytes(),
            )
            .is_err()
                || process_word(mapped.physical_address) != Some(state.original)
            {
                fatal();
            }
            0
        }
        _ => COPY_DENIED,
    };
    if result != expected.4 {
        fatal();
    }
    let post_expected = if state.completed >= WRITE_PHASE && state.completed < COMPLETE_PHASE {
        state.written_checksum
    } else {
        state.original_checksum
    };
    if !integrity_holds(state, post_expected) {
        fatal();
    }
    state.completed += 1;
    if number == SYS_COMPLETE {
        if state.completed != COMPLETE_PHASE + 1 {
            fatal();
        }
        crate::serial::write_line("SORVETH M2-J.5: ring-3 memory syscalls authorized and denied");
        crate::serial::write_line(
            "SORVETH M2-J.6: full-frame and capability integrity verified after every syscall",
        );
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
