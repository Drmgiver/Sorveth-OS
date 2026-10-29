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
use sorveth_task::{Error as TaskError, Scheduler, TaskId};

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
}

impl From<TaskError> for Error {
    fn from(value: TaskError) -> Self {
        Self::Task(value)
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
/// the verified OVMF identity window, and no concurrent task execution.
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
    if ptr::read_volatile((root_a as *const u64).add(slot_b as usize)) != 0
        || ptr::read_volatile((root_b as *const u64).add(slot_a as usize)) != 0
    {
        return Err(Error::HardwareMismatch);
    }

    let mut scheduler = AddressScheduler::<2>::new();
    let a = scheduler.spawn(ObjectId(0x1_301), Process::First)?;
    let b = scheduler.spawn(ObjectId(0x1_302), Process::Second)?;
    let mut expected_a = ptr::read_volatile(memory_a.physical_address as *const u64);
    let mut expected_b = ptr::read_volatile(memory_b.physical_address as *const u64);

    for (round, expected_process) in [
        Process::First,
        Process::Second,
        Process::First,
        Process::Second,
    ]
    .iter()
    .enumerate()
    {
        let (selected_id, selected_process) = scheduler
            .select_next()?
            .ok_or(Error::IncorrectSelection)?;
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
        let (root, own_page, expected_value, other_page) = if selected_process == Process::First {
            (root_a, memory_a, expected_a, memory_b)
        } else {
            (root_b, memory_b, expected_b, memory_a)
        };
        let cross_slot = if selected_process == Process::First {
            slot_b
        } else {
            slot_a
        };
        if ptr::read_volatile((root as *const u64).add(cross_slot as usize)) != 0 {
            return Err(Error::HardwareMismatch);
        }
        let other_before = ptr::read_volatile(other_page.physical_address as *const u64);
        let next_value = expected_value ^ SENTINEL_SALT ^ ((round as u64) + 1);

        asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
        // These addresses were verified present by M2-I.2. Each access
        // takes place under the scheduler-selected process root.
        let root_correct = observed & CR3_ADDRESS_MASK == root;
        let initial_correct = ptr::read_volatile(own_page.virtual_address as *const u64)
            == expected_value;
        if root_correct && initial_correct {
            ptr::write_volatile(own_page.virtual_address as *mut u64, next_value);
        }
        let stored_correct = root_correct
            && initial_correct
            && ptr::read_volatile(own_page.virtual_address as *const u64) == next_value;

        // Always restore the kernel root before inspecting or returning.
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
        if !stored_correct
            || observed & CR3_ADDRESS_MASK != kernel
            || ptr::read_volatile(own_page.physical_address as *const u64) != next_value
            || ptr::read_volatile(other_page.physical_address as *const u64) != other_before
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
