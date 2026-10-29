//! M2-I.3: task-selection decisions drive actual process CR3 changes.
//!
//! The selected generation-safe TaskId is resolved to a kernel-owned
//! Process binding. Neither a raw user-provided CR3 nor an arbitrary address
//! controls the CPU's page-table root. QEMU proves the A-B-A-B order using
//! real x86 CR3 writes and separate process-private data pages.
//!
//! This deliberately runs trusted kernel verification code on one CPU;
//! it is NOT yet a ring-3 process context switch or preemptive scheduling.

use core::{arch::asm, ptr};

use sorveth_cap::ObjectId;
use sorveth_task::{Error as TaskError, Scheduler, State, TaskId};

use crate::process_roots::{self, Process};

const CR3_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const SENTINEL_SALT: u64 = 0x4949_4900_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Task(TaskError),
    DuplicateProcess,
    MissingBinding,
    MissingAddressSpace,
    IncorrectSelection,
    HardwareMismatch,
    BlockedTask,
    InvalidRoot,
}

impl From<TaskError> for Error {
    fn from(value: TaskError) -> Self {
        Self::Task(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorizedSpace {
    task: TaskId,
    process: Process,
    root: u64,
}

/// Restrict CR3 switches to known kernel-owned roots. Restore kernel CR3
/// on every normal Rust return path, including early errors.
///
/// # Safety
/// The caller has already verified QEMU identity mappings and supervisor
/// kernel/stack mappings; one CPU, interrupts disabled, no user preemption.
struct KernelRootGuard {
    kernel: u64,
}

impl KernelRootGuard {
    unsafe fn enter(kernel: u64, target: u64) -> Result<Self, Error> {
        if kernel == 0
            || target == 0
            || target == kernel
            || kernel & 4095 != 0
            || target & 4095 != 0
        {
            return Err(Error::InvalidRoot);
        }
        let active: u64;
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if active & CR3_ADDRESS_MASK != kernel {
            return Err(Error::HardwareMismatch);
        }
        asm!("mov cr3, {}", in(reg) target, options(nostack, preserves_flags));
        Ok(Self { kernel })
    }
}

impl Drop for KernelRootGuard {
    fn drop(&mut self) {
        // This guard only exists with a verified, continually mapped
        // supervisor kernel page and stack on the single bootstrap CPU.
        unsafe {
            asm!("mov cr3, {}", in(reg) self.kernel, options(nostack, preserves_flags));
        }
    }
}

/// Kernel-only association of generation-safe tasks with process-owned roots.
/// The scheduler decides the next task; callers may not provide a CR3 value.
struct AddressScheduler<const N: usize> {
    tasks: Scheduler<N>,
    bindings: [Option<(TaskId, Process)>; N],
}

impl<const N: usize> AddressScheduler<N> {
    const fn new() -> Self {
        Self {
            tasks: Scheduler::new(),
            bindings: [None; N],
        }
    }

    fn spawn(&mut self, object: ObjectId, process: Process) -> Result<TaskId, Error> {
        if self.bindings.iter().flatten().any(|(_, p)| *p == process) {
            return Err(Error::DuplicateProcess);
        }
        let id = self.tasks.spawn(object)?;
        let slot = self
            .bindings
            .get_mut(id.slot() as usize)
            .ok_or(Error::MissingBinding)?;
        if slot.is_some() {
            return Err(Error::MissingBinding);
        }
        *slot = Some((id, process));
        Ok(id)
    }

    fn lookup(&self, id: TaskId) -> Result<Process, Error> {
        self.tasks.inspect(id)?;
        match self.bindings.get(id.slot() as usize).copied().flatten() {
            Some((owned, process)) if owned == id => Ok(process),
            _ => Err(Error::MissingBinding),
        }
    }

    /// The task must still exist with its original generation and Ready
    /// state. The resolver is privileged kernel code that audits a root;
    /// unprivileged tasks cannot supply an arbitrary CR3 value.
    fn authorize(
        &self,
        id: TaskId,
        resolve: impl FnOnce(Process) -> Option<u64>,
    ) -> Result<AuthorizedSpace, Error> {
        let process = self.lookup(id)?;
        if self.tasks.inspect(id)?.state != State::Ready {
            return Err(Error::BlockedTask);
        }
        let root = resolve(process).ok_or(Error::MissingAddressSpace)?;
        if root == 0 || root & 4095 != 0 {
            return Err(Error::InvalidRoot);
        }
        Ok(AuthorizedSpace {
            task: id,
            process,
            root,
        })
    }

    fn select_next(&mut self) -> Result<Option<(TaskId, Process)>, Error> {
        match self.tasks.select_next() {
            Some(id) => Ok(Some((id, self.lookup(id)?))),
            None => Ok(None),
        }
    }

    fn block(&mut self, id: TaskId) -> Result<(), Error> {
        self.lookup(id)?;
        self.tasks.block(id)?;
        Ok(())
    }

    fn wake(&mut self, id: TaskId) -> Result<(), Error> {
        self.lookup(id)?;
        self.tasks.wake(id)?;
        Ok(())
    }

    fn exit(&mut self, id: TaskId) -> Result<(), Error> {
        self.lookup(id)?;
        self.tasks.exit(id)?;
        self.bindings[id.slot() as usize] = None;
        Ok(())
    }
}

/// Run a QEMU-only bootstrap test of the kernel scheduler and CR3 switching.
/// Independent USER RW/NX data pages must have been installed by M2-I.2.
/// This returns with Sorveth's kernel root active on success or error.
///
/// # Safety
/// Requires CPL0, one CPU, interrupts disabled, stable process page roots,
/// and no concurrent task execution. Physical supervisor table and test
/// frame reads use Sorveth-owned mappings; other kernel mappings still
/// depend on the verified OVMF bootstrap environment.
/// Not valid on physical hardware or during preemptive scheduling.
pub unsafe fn verify_scheduled_switches() -> Result<(), Error> {
    let kernel = crate::root::kernel_root_physical().ok_or(Error::MissingAddressSpace)?;
    let (root_a, slot_a) =
        process_roots::process_root(Process::First).ok_or(Error::MissingAddressSpace)?;
    let (root_b, slot_b) =
        process_roots::process_root(Process::Second).ok_or(Error::MissingAddressSpace)?;
    let memory_a = process_roots::mapped_page(Process::First).ok_or(Error::MissingAddressSpace)?;
    let memory_b = process_roots::mapped_page(Process::Second).ok_or(Error::MissingAddressSpace)?;
    if root_a == root_b
        || root_a == kernel
        || root_b == kernel
        || slot_a == slot_b
        || memory_a.virtual_address == memory_b.virtual_address
        || memory_a.physical_address == memory_b.physical_address
    {
        return Err(Error::HardwareMismatch);
    }
    let mut observed: u64;
    asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
    if observed & CR3_ADDRESS_MASK != kernel {
        return Err(Error::HardwareMismatch);
    }
    if process_roots::read_process_root_slot(Process::First, slot_b) != Some(0)
        || process_roots::read_process_root_slot(Process::Second, slot_a) != Some(0)
    {
        return Err(Error::HardwareMismatch);
    }

    let mut scheduler = AddressScheduler::<2>::new();
    let a = scheduler.spawn(ObjectId(0x1_301), Process::First)?;
    let b = scheduler.spawn(ObjectId(0x1_302), Process::Second)?;
    let mut expected_a =
        process_roots::read_process_frame_word(Process::First).ok_or(Error::HardwareMismatch)?;
    let mut expected_b =
        process_roots::read_process_frame_word(Process::Second).ok_or(Error::HardwareMismatch)?;

    for (round, expected_process) in [
        Process::First,
        Process::Second,
        Process::First,
        Process::Second,
    ]
    .iter()
    .enumerate()
    {
        let (selected_id, selected_process) =
            scheduler.select_next()?.ok_or(Error::IncorrectSelection)?;
        if selected_process != *expected_process
            || selected_id
                != if selected_process == Process::First {
                    a
                } else {
                    b
                }
        {
            return Err(Error::IncorrectSelection);
        }
        // The task identity determines which of the two verified roots
        // the kernel loads. It is never specified by unprivileged code.
        let authorized = scheduler.authorize(selected_id, |p| unsafe {
            process_roots::checked_process_root(p)
        })?;
        if authorized.task != selected_id || authorized.process != selected_process {
            return Err(Error::IncorrectSelection);
        }
        let (root, own_page, expected_value) = if selected_process == Process::First {
            (root_a, memory_a, expected_a)
        } else {
            (root_b, memory_b, expected_b)
        };
        if authorized.root != root {
            return Err(Error::HardwareMismatch);
        }
        let cross_slot = if selected_process == Process::First {
            slot_b
        } else {
            slot_a
        };
        if process_roots::read_process_root_slot(selected_process, cross_slot) != Some(0) {
            return Err(Error::HardwareMismatch);
        }
        let other_process = if selected_process == Process::First {
            Process::Second
        } else {
            Process::First
        };
        let other_before =
            process_roots::read_process_frame_word(other_process).ok_or(Error::HardwareMismatch)?;
        let next_value = expected_value ^ SENTINEL_SALT ^ ((round as u64) + 1);

        let process_guard = KernelRootGuard::enter(kernel, authorized.root)?;
        asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
        // These addresses were verified present by M2-I.2. Each access
        // takes place under the scheduler-selected process root.
        let root_correct = observed & CR3_ADDRESS_MASK == root;
        let initial_correct =
            ptr::read_volatile(own_page.virtual_address as *const u64) == expected_value;
        if root_correct && initial_correct {
            ptr::write_volatile(own_page.virtual_address as *mut u64, next_value);
        }
        let stored_correct = root_correct
            && initial_correct
            && ptr::read_volatile(own_page.virtual_address as *const u64) == next_value;

        // Always restore the kernel root before inspecting or returning.
        drop(process_guard);
        asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
        if !stored_correct
            || observed & CR3_ADDRESS_MASK != kernel
            || process_roots::read_process_frame_word(selected_process) != Some(next_value)
            || process_roots::read_process_frame_word(other_process) != Some(other_before)
        {
            return Err(Error::HardwareMismatch);
        }
        if selected_process == Process::First {
            expected_a = next_value;
        } else {
            expected_b = next_value;
        }
    }

    // Confirm scheduler state transitions still control which process runs.
    scheduler.block(a)?;
    if scheduler.select_next()? != Some((b, Process::Second)) {
        return Err(Error::IncorrectSelection);
    }
    scheduler.wake(a)?;
    scheduler.exit(b)?;
    if scheduler.select_next()? != Some((a, Process::First)) {
        return Err(Error::IncorrectSelection);
    }
    scheduler.exit(a)?;
    if scheduler.select_next()?.is_some() || scheduler.lookup(a).is_ok() {
        return Err(Error::IncorrectSelection);
    }
    Ok(())
}

/// A second QEMU-only negative acceptance proof: blocked, exited,
/// generation-stale or corrupted task/root mappings cannot be activated.
/// The deliberately damaged inactive PML4 entry is restored before CR3
/// changes, and the kernel CR3 must remain active for all failed requests.
///
/// # Safety
/// CPL0, single CPU, IRQs disabled, verified bootstrap kernel mappings;
/// neither process has been entered in ring 3 or scheduled concurrently.
/// Root entry access is through the registered owned supervisor window.
pub unsafe fn verify_lifecycle_hardening() -> Result<(), Error> {
    let kernel = crate::root::kernel_root_physical().ok_or(Error::MissingAddressSpace)?;
    let (root_a, _) =
        process_roots::process_root(Process::First).ok_or(Error::MissingAddressSpace)?;
    let (root_b, _) =
        process_roots::process_root(Process::Second).ok_or(Error::MissingAddressSpace)?;
    let resolve = |p| unsafe { process_roots::checked_process_root(p) };
    if resolve(Process::First) != Some(root_a) || resolve(Process::Second) != Some(root_b) {
        return Err(Error::MissingAddressSpace);
    }
    let mut scheduler = AddressScheduler::<2>::new();
    let old = scheduler.spawn(ObjectId(0x1_401), Process::First)?;
    let other = scheduler.spawn(ObjectId(0x1_402), Process::Second)?;
    if scheduler.authorize(old, resolve)?.root != root_a {
        return Err(Error::HardwareMismatch);
    }
    scheduler.block(old)?;
    if scheduler.authorize(old, resolve) != Err(Error::BlockedTask)
        || scheduler.select_next()? != Some((other, Process::Second))
    {
        return Err(Error::IncorrectSelection);
    }
    scheduler.wake(old)?;
    scheduler.exit(old)?;
    if scheduler.authorize(old, resolve) != Err(Error::Task(TaskError::InvalidTask)) {
        return Err(Error::IncorrectSelection);
    }
    let replacement = scheduler.spawn(ObjectId(0x1_403), Process::First)?;
    if replacement == old
        || scheduler.authorize(old, resolve) != Err(Error::Task(TaskError::InvalidTask))
        || scheduler.authorize(replacement, resolve)?.root != root_a
    {
        return Err(Error::IncorrectSelection);
    }

    // The owned-table helper restores this one known PML4 entry even when
    // the negative authorization predicate returns false.
    let denied = process_roots::verify_temporary_root_user_denial(Process::First, || {
        scheduler.authorize(replacement, resolve) == Err(Error::MissingAddressSpace)
    });
    if !denied || scheduler.authorize(replacement, resolve)?.root != root_a {
        return Err(Error::HardwareMismatch);
    }

    let decision = scheduler.authorize(replacement, resolve)?;
    {
        let _guard = KernelRootGuard::enter(kernel, decision.root)?;
        let current: u64;
        asm!("mov {}, cr3", out(reg) current, options(nomem, nostack, preserves_flags));
        if current & CR3_ADDRESS_MASK != root_a {
            return Err(Error::HardwareMismatch);
        }
    }
    let restored: u64;
    asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
    if restored & CR3_ADDRESS_MASK != kernel {
        return Err(Error::HardwareMismatch);
    }
    scheduler.exit(replacement)?;
    scheduler.exit(other)?;
    if scheduler.authorize(replacement, resolve) != Err(Error::Task(TaskError::InvalidTask))
        || scheduler.authorize(other, resolve) != Err(Error::Task(TaskError::InvalidTask))
        || scheduler.select_next()?.is_some()
    {
        return Err(Error::IncorrectSelection);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_binding_tracks_ready_and_blocked_tasks() {
        let mut s = AddressScheduler::<2>::new();
        let a = s.spawn(ObjectId(101), Process::First).unwrap();
        let b = s.spawn(ObjectId(102), Process::Second).unwrap();
        assert_eq!(s.select_next(), Ok(Some((a, Process::First))));
        assert_eq!(s.select_next(), Ok(Some((b, Process::Second))));
        s.block(a).unwrap();
        assert_eq!(s.select_next(), Ok(Some((b, Process::Second))));
        s.wake(a).unwrap();
        assert_eq!(s.select_next(), Ok(Some((a, Process::First))));
    }

    #[test]
    fn duplicates_stale_generation_and_capacity_fail_closed() {
        let mut s = AddressScheduler::<2>::new();
        let old = s.spawn(ObjectId(17), Process::First).unwrap();
        assert_eq!(
            s.spawn(ObjectId(18), Process::First),
            Err(Error::DuplicateProcess)
        );
        let other = s.spawn(ObjectId(19), Process::Second).unwrap();
        assert_eq!(
            s.spawn(ObjectId(20), Process::First),
            Err(Error::DuplicateProcess)
        );
        s.exit(old).unwrap();
        assert_eq!(s.lookup(old), Err(Error::Task(TaskError::InvalidTask)));
        assert_eq!(s.block(old), Err(Error::Task(TaskError::InvalidTask)));
        let replacement = s.spawn(ObjectId(21), Process::First).unwrap();
        assert_ne!(old, replacement);
        assert_eq!(s.lookup(replacement), Ok(Process::First));
        assert_eq!(s.lookup(other), Ok(Process::Second));
        assert_eq!(s.lookup(old), Err(Error::Task(TaskError::InvalidTask)));
    }

    #[test]
    fn a_blocked_or_stale_task_cannot_authorize_a_valid_root() {
        let mut s = AddressScheduler::<2>::new();
        let old = s.spawn(ObjectId(3), Process::First).unwrap();
        assert_eq!(s.authorize(old, |_| Some(0x1000)).unwrap().root, 0x1000);
        s.block(old).unwrap();
        assert_eq!(s.authorize(old, |_| Some(0x1000)), Err(Error::BlockedTask));
        s.wake(old).unwrap();
        s.exit(old).unwrap();
        let reused = s.spawn(ObjectId(4), Process::First).unwrap();
        assert_ne!(old, reused);
        assert_eq!(
            s.authorize(old, |_| Some(0x1000)),
            Err(Error::Task(TaskError::InvalidTask))
        );
        assert_eq!(s.authorize(reused, |_| Some(0x3000)).unwrap().root, 0x3000);
    }

    #[test]
    fn resolver_cannot_authorize_missing_or_misaligned_process_root() {
        let mut s = AddressScheduler::<2>::new();
        let id = s.spawn(ObjectId(11), Process::Second).unwrap();
        assert_eq!(s.authorize(id, |_| None), Err(Error::MissingAddressSpace));
        assert_eq!(s.authorize(id, |_| Some(0)), Err(Error::InvalidRoot));
        assert_eq!(s.authorize(id, |_| Some(0x1234)), Err(Error::InvalidRoot));
        assert_eq!(
            s.authorize(id, |p| if p == Process::Second {
                Some(0x5000)
            } else {
                None
            }),
            Ok(AuthorizedSpace {
                task: id,
                process: Process::Second,
                root: 0x5000
            })
        );
    }

    #[test]
    fn empty_and_exhausted_schedulers_behave_predictably() {
        let mut none = AddressScheduler::<0>::new();
        assert_eq!(none.select_next(), Ok(None));
        assert_eq!(
            none.spawn(ObjectId(1), Process::First),
            Err(Error::Task(TaskError::NoCapacity))
        );
        let mut s = AddressScheduler::<1>::new();
        let a = s.spawn(ObjectId(1), Process::First).unwrap();
        assert_eq!(
            s.spawn(ObjectId(2), Process::Second),
            Err(Error::Task(TaskError::NoCapacity))
        );
        s.exit(a).unwrap();
        assert_eq!(s.select_next(), Ok(None));
    }
}
