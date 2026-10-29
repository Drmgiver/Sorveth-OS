//! Kernel-only memory capability authority shared by future syscalls.
//!
//! This registry binds generation-safe TaskIds, object IDs and opaque
//! capabilities together. A caller identity must come from the kernel's
//! active CPU/task context, NEVER from an untrusted syscall argument.
//! No lock, SMP, user pointer or CPU context switch lives in this crate.

use sorveth_cap::{CapabilitySpace, Handle, ObjectId, ObjectKind, Rights};
use sorveth_task::{Scheduler, State, TaskId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidTask,
    InvalidRights,
    NoCapacity,
    Denied,
}

#[derive(Clone, Copy)]
struct Grant {
    task: TaskId,
    object: ObjectId,
    handle: Handle,
}

pub struct MemoryAuthority<const TASKS: usize, const CAPS: usize> {
    tasks: Scheduler<TASKS>,
    caps: CapabilitySpace<CAPS>,
    grants: [Option<Grant>; CAPS],
}

impl<const TASKS: usize, const CAPS: usize> MemoryAuthority<TASKS, CAPS> {
    pub const fn new() -> Self {
        Self {
            tasks: Scheduler::new(),
            caps: CapabilitySpace::new(),
            grants: [None; CAPS],
        }
    }

    pub fn spawn(&mut self, task_object: ObjectId) -> Result<TaskId, Error> {
        self.tasks.spawn(task_object).map_err(|_| Error::NoCapacity)
    }

    pub fn grant(
        &mut self,
        task: TaskId,
        memory_object: ObjectId,
        rights: Rights,
    ) -> Result<Handle, Error> {
        if self.tasks.inspect(task).is_err() {
            return Err(Error::InvalidTask);
        }
        let allowed = Rights::READ | Rights::WRITE;
        if memory_object.0 == 0
            || rights.is_empty()
            || !allowed.contains(rights)
        {
            return Err(Error::InvalidRights);
        }
        let free = self
            .grants
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoCapacity)?;
        let handle = self
            .caps
            .grant_root(memory_object, ObjectKind::Memory, rights)
            .map_err(|_| Error::NoCapacity)?;
        self.grants[free] = Some(Grant {
            task,
            object: memory_object,
            handle,
        });
        Ok(handle)
    }

    /// The caller's TaskId is always kernel-supplied. A valid global
    /// capability token owned by another task is just as unauthorized
    /// as an unknown token.
    pub fn authorize(
        &self,
        current: TaskId,
        raw_handle: u64,
        memory_object: ObjectId,
        right: Rights,
    ) -> Result<(), Error> {
        match self.tasks.inspect(current) {
            Ok(task) if task.state == State::Ready => {}
            _ => return Err(Error::InvalidTask),
        }
        if right != Rights::READ && right != Rights::WRITE {
            return Err(Error::InvalidRights);
        }
        let handle = Handle::from_raw(raw_handle);
        if !self.grants.iter().flatten().any(|grant| {
            grant.task == current && grant.object == memory_object && grant.handle == handle
        }) {
            return Err(Error::Denied);
        }
        let entry = self.caps.authorize(handle, right).map_err(|_| Error::Denied)?;
        if entry.kind != ObjectKind::Memory || entry.object != memory_object {
            return Err(Error::Denied);
        }
        Ok(())
    }

    pub fn block(&mut self, task: TaskId) -> Result<(), Error> {
        self.tasks.block(task).map_err(|_| Error::InvalidTask)
    }

    pub fn wake(&mut self, task: TaskId) -> Result<(), Error> {
        self.tasks.wake(task).map_err(|_| Error::InvalidTask)
    }

    pub fn retire(&mut self, task: TaskId) -> Result<(), Error> {
        self.tasks.inspect(task).map_err(|_| Error::InvalidTask)?;
        for grant in self.grants.iter_mut() {
            if let Some(owned) = grant {
                if owned.task == task {
                    self.caps.revoke(owned.handle).map_err(|_| Error::Denied)?;
                    *grant = None;
                }
            }
        }
        self.tasks.exit(task).map_err(|_| Error::InvalidTask)
    }
}

impl<const TASKS: usize, const CAPS: usize> Default for MemoryAuthority<TASKS, CAPS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_object_and_task_owner_must_all_match() {
        let mut authority = MemoryAuthority::<2, 4>::new();
        let a = authority.spawn(ObjectId(1)).unwrap();
        let b = authority.spawn(ObjectId(2)).unwrap();
        let read = authority.grant(a, ObjectId(101), Rights::READ).unwrap();
        let write = authority.grant(a, ObjectId(101), Rights::WRITE).unwrap();
        let foreign = authority.grant(b, ObjectId(102), Rights::WRITE).unwrap();

        assert_eq!(authority.authorize(a, read.raw(), ObjectId(101), Rights::READ), Ok(()));
        assert_eq!(authority.authorize(a, write.raw(), ObjectId(101), Rights::WRITE), Ok(()));
        for bad in [
            authority.authorize(a, read.raw(), ObjectId(101), Rights::WRITE),
            authority.authorize(a, write.raw(), ObjectId(101), Rights::READ),
            authority.authorize(a, foreign.raw(), ObjectId(101), Rights::WRITE),
            authority.authorize(a, read.raw(), ObjectId(102), Rights::READ),
            authority.authorize(a, 0, ObjectId(101), Rights::READ),
            authority.authorize(a, u64::MAX, ObjectId(101), Rights::READ),
        ] {
            assert_eq!(bad, Err(Error::Denied));
        }
    }

    #[test]
    fn blocked_stale_and_reused_task_generations_never_regain_memory_rights() {
        let mut authority = MemoryAuthority::<1, 4>::new();
        let original = authority.spawn(ObjectId(5)).unwrap();
        let handle = authority.grant(original, ObjectId(11), Rights::READ).unwrap();
        authority.block(original).unwrap();
        assert_eq!(
            authority.authorize(original, handle.raw(), ObjectId(11), Rights::READ),
            Err(Error::InvalidTask)
        );
        authority.wake(original).unwrap();
        assert_eq!(
            authority.authorize(original, handle.raw(), ObjectId(11), Rights::READ),
            Ok(())
        );
        authority.retire(original).unwrap();
        let replacement = authority.spawn(ObjectId(6)).unwrap();
        assert_ne!(original, replacement);
        assert_eq!(
            authority.authorize(original, handle.raw(), ObjectId(11), Rights::READ),
            Err(Error::InvalidTask)
        );
        assert_eq!(
            authority.authorize(replacement, handle.raw(), ObjectId(11), Rights::READ),
            Err(Error::Denied)
        );
    }

    #[test]
    fn rejects_unknown_task_invalid_rights_and_exhausted_caps() {
        let mut authority = MemoryAuthority::<1, 1>::new();
        let task = authority.spawn(ObjectId(1)).unwrap();
        assert_eq!(authority.grant(task, ObjectId(2), Rights::NONE), Err(Error::InvalidRights));
        assert_eq!(authority.grant(task, ObjectId(2), Rights::EXECUTE), Err(Error::InvalidRights));
        let read = authority.grant(task, ObjectId(2), Rights::READ).unwrap();
        assert_eq!(authority.grant(task, ObjectId(3), Rights::READ), Err(Error::NoCapacity));
        assert_eq!(authority.authorize(task, read.raw(), ObjectId(2), Rights::EXECUTE), Err(Error::InvalidRights));
    }
}
