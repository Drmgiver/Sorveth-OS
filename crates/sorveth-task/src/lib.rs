#![no_std]

//! No-heap task registry and fair runnable selection.
//!
//! This crate holds no machine context and does not switch CPUs/stacks.
//! It is the bookkeeping foundation for a future privilege-separated
//! scheduler, not yet a functioning multitasking operating system.
//! Only the trusted kernel may mutate a registry.

use sorveth_cap::ObjectId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId {
    slot: u32,
    generation: u32,
}

impl TaskId {
    pub fn slot(self) -> u32 {
        self.slot
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task {
    pub object: ObjectId,
    pub state: State,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidObject,
    DuplicateObject,
    NoCapacity,
    InvalidTask,
    WrongState,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    task: Option<Task>,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 1,
        task: None,
    };

    fn retire(&mut self) {
        self.task = None;
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }
    }
}

pub struct Scheduler<const N: usize> {
    slots: [Slot; N],
    cursor: usize,
    count: usize,
}

impl<const N: usize> Scheduler<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            cursor: 0,
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn spawn(&mut self, object: ObjectId) -> Result<TaskId, Error> {
        if object.0 == 0 {
            return Err(Error::InvalidObject);
        }
        if self.slots.iter().any(|slot| {
            slot.task.map(|task| task.object == object).unwrap_or(false)
        }) {
            return Err(Error::DuplicateObject);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if index >= u32::MAX as usize {
                break;
            }
            if slot.task.is_none() {
                let id = TaskId {
                    slot: index as u32,
                    generation: slot.generation,
                };
                slot.task = Some(Task { object, state: State::Ready });
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::NoCapacity)
    }

    pub fn inspect(&self, id: TaskId) -> Result<Task, Error> {
        let slot = self.slots.get(id.slot as usize).ok_or(Error::InvalidTask)?;
        if id.generation != slot.generation {
            return Err(Error::InvalidTask);
        }
        slot.task.ok_or(Error::InvalidTask)
    }

    fn update_state(&mut self, id: TaskId, expected: State, next: State) -> Result<(), Error> {
        let current = self.inspect(id)?;
        if current.state != expected {
            return Err(Error::WrongState);
        }
        self.slots[id.slot as usize].task = Some(Task {
            object: current.object,
            state: next,
        });
        Ok(())
    }

    pub fn block(&mut self, id: TaskId) -> Result<(), Error> {
        self.update_state(id, State::Ready, State::Blocked)
    }

    pub fn wake(&mut self, id: TaskId) -> Result<(), Error> {
        self.update_state(id, State::Blocked, State::Ready)
    }

    pub fn exit(&mut self, id: TaskId) -> Result<(), Error> {
        self.inspect(id)?;
        self.slots[id.slot as usize].retire();
        self.count -= 1;
        Ok(())
    }

    /// FIFO-ish circular fair selection among runnable slots; this does not
    /// switch stacks or run the task. Blocked tasks cannot be selected.
    pub fn select_next(&mut self) -> Option<TaskId> {
        if N == 0 {
            return None;
        }
        for offset in 0..N {
            let index = (self.cursor + offset) % N;
            let slot = self.slots[index];
            if matches!(slot.task, Some(Task { state: State::Ready, .. })) {
                self.cursor = (index + 1) % N;
                return Some(TaskId {
                    slot: index as u32,
                    generation: slot.generation,
                });
            }
        }
        None
    }
}

impl<const N: usize> Default for Scheduler<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_skips_blocked_and_stays_fair() {
        let mut scheduler = Scheduler::<3>::new();
        let a = scheduler.spawn(ObjectId(10)).unwrap();
        let b = scheduler.spawn(ObjectId(20)).unwrap();
        let c = scheduler.spawn(ObjectId(30)).unwrap();
        assert_eq!(scheduler.select_next(), Some(a));
        assert_eq!(scheduler.select_next(), Some(b));
        assert_eq!(scheduler.select_next(), Some(c));
        scheduler.block(b).unwrap();
        assert_eq!(scheduler.select_next(), Some(a));
        assert_eq!(scheduler.select_next(), Some(c));
        scheduler.wake(b).unwrap();
        assert_eq!(scheduler.select_next(), Some(a));
        assert_eq!(scheduler.select_next(), Some(b));
    }

    #[test]
    fn blocked_registry_has_no_runnable_tasks() {
        let mut scheduler = Scheduler::<1>::new();
        let id = scheduler.spawn(ObjectId(1)).unwrap();
        scheduler.block(id).unwrap();
        assert_eq!(scheduler.select_next(), None);
        assert_eq!(scheduler.block(id), Err(Error::WrongState));
        scheduler.wake(id).unwrap();
        assert_eq!(scheduler.wake(id), Err(Error::WrongState));
        assert_eq!(scheduler.select_next(), Some(id));
    }

    #[test]
    fn stale_ids_cannot_control_reused_slots() {
        let mut scheduler = Scheduler::<1>::new();
        let first = scheduler.spawn(ObjectId(1)).unwrap();
        scheduler.exit(first).unwrap();
        assert_eq!(scheduler.inspect(first), Err(Error::InvalidTask));
        assert_eq!(scheduler.wake(first), Err(Error::InvalidTask));
        assert_eq!(scheduler.exit(first), Err(Error::InvalidTask));
        let second = scheduler.spawn(ObjectId(2)).unwrap();
        assert_ne!(first, second);
        assert_eq!(scheduler.select_next(), Some(second));
    }

    #[test]
    fn rejects_duplicates_invalid_objects_and_exhaustion() {
        let mut scheduler = Scheduler::<1>::new();
        assert_eq!(scheduler.spawn(ObjectId(0)), Err(Error::InvalidObject));
        let first = scheduler.spawn(ObjectId(1)).unwrap();
        assert_eq!(scheduler.spawn(ObjectId(1)), Err(Error::DuplicateObject));
        assert_eq!(scheduler.spawn(ObjectId(2)), Err(Error::NoCapacity));
        assert_eq!(scheduler.len(), 1);
        scheduler.exit(first).unwrap();
        assert_eq!(scheduler.len(), 0);
        assert_eq!(Scheduler::<0>::new().select_next(), None);
        assert_eq!(Scheduler::<0>::new().spawn(ObjectId(1)), Err(Error::NoCapacity));
    }
}
