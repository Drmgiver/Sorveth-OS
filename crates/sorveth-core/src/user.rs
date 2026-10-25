//! Test-only x86-64 transition to an explicitly mapped ring-3 code page.
//! No normal kernel image enters this path. The unprivileged probe invokes
//! INT 0x80 twice, and the kernel's test handler exits QEMU after the second.

/// # Safety
/// Requires a loaded ring-3 GDT/TSS, valid user-executable page, user stack,
/// and DPL3 INT80 handler. This is the QEMU-only acceptance path.
pub unsafe fn enter(entry: u64, stack: u64, user_cs: u16, user_ss: u16) -> ! {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "push {ss}",
        "push {stack}",
        "pushfq",
        "push {cs}",
        "push {entry}",
        "iretq",
        ss = in(reg) user_ss as u64,
        stack = in(reg) stack,
        cs = in(reg) user_cs as u64,
        entry = in(reg) entry,
        options(noreturn),
    );
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (entry, stack, user_cs, user_ss);
        loop {
            core::hint::spin_loop();
        }
    }
}

// M2-H QEMU-only, fixed task identity supplied by privileged bootstrap.
// The ring-3 program never chooses its caller TaskId or gets a reference
// to the broker. The mutable state is accessed only on the single test CPU,
// while maskable interrupts remain disabled.
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_arch = "x86_64")]
use sorveth_broker::{Broker, REPLY_DENIED};
#[cfg(target_arch = "x86_64")]
use sorveth_cap::{ObjectId, Rights};
#[cfg(target_arch = "x86_64")]
use sorveth_task::TaskId;

pub const RESOURCE_PROBE_VALUE: u64 = 0x5356_5256;

#[cfg(target_arch = "x86_64")]
struct TestState {
    broker: Broker<2, 8>,
    current_task: TaskId,
}

#[cfg(target_arch = "x86_64")]
static mut TEST_STATE: Option<TestState> = None;
#[cfg(target_arch = "x86_64")]
static BROKER_READY: AtomicBool = AtomicBool::new(false);

/// Kernel-only authority initialization. Returns two opaque *global* handles:
/// one READ for the test task, one WRITE owned by a different task.
pub fn initialize_broker() -> Option<(u64, u64)> {
    #[cfg(target_arch = "x86_64")]
    {
        if BROKER_READY.load(Ordering::Acquire) {
            return None;
        }
        let mut broker = Broker::<2, 8>::new(RESOURCE_PROBE_VALUE);
        let current = broker.spawn(ObjectId(501)).ok()?;
        let foreign = broker.spawn(ObjectId(502)).ok()?;
        let allowed = broker.grant_resource(current, Rights::READ).ok()?;
        let foreign_token = broker.grant_resource(foreign, Rights::WRITE).ok()?;
        // SAFETY: only called once before entering ring 3, on one CPU.
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(TEST_STATE),
                Some(TestState {
                    broker,
                    current_task: current,
                }),
            );
        }
        BROKER_READY.store(true, Ordering::Release);
        Some((allowed.raw(), foreign_token.raw()))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// No user pointers or caller-provided task identity. The kernel selects the
/// task from its own saved context and all capability checks happen here.
pub fn dispatch(number: u64, handle: u64, value: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if !BROKER_READY.load(Ordering::Acquire) {
            return REPLY_DENIED;
        }
        // SAFETY: QEMU probe only, one CPU, no preemption, no reentrancy.
        // We never make a reference to this state outside this call.
        unsafe {
            match (*core::ptr::addr_of_mut!(TEST_STATE)).as_mut() {
                Some(state) => state
                    .broker
                    .dispatch(state.current_task, number, handle, value),
                None => REPLY_DENIED,
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (number, handle, value);
        0xffff_ff01
    }
}
