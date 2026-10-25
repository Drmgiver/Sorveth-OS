#![no_std]

//! Kernel-owned syscall authority broker (M2-H prototype).
//!
//! The caller identity MUST be selected by the kernel from its active task,
//! NEVER accepted as a userspace register value. Raw user handles are opaque
//! lookup tokens, not pointers. Every capability has one owning TaskId;
//! a numerically valid handle belonging to another task grants no authority.
//! This no-heap broker has no user pointer, address-space, or IRQ handling.

use sorveth_cap::{
    CapabilitySpace, Error as CapError, Handle, ObjectId, ObjectKind, Rights,
};
use sorveth_task::{Error as TaskError, Scheduler, TaskId};

pub const SYS_RESOURCE_READ: u64 = 9;
pub const SYS_RESOURCE_WRITE: u64 = 10;
pub const REPLY_DENIED: u64 = 0xffff_ff01;
pub const REPLY_UNKNOWN: u64 = 0xffff_ff02;
pub const RESOURCE_ID: ObjectId = ObjectId(0x5356_5245);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Task(TaskError),
    Capability(CapError),
    WrongObject,
    LedgerFull,
}

#[derive(Clone, Copy)]
struct Ownership {
    handle: Handle,
    task: TaskId,
}

/// Single-core, trusted-kernel-only prototype. An eventual syscall entry
/// must serialize access and bind current_task to the saved CPU task context.
pub struct Broker<const TASKS: usize, const CAPS: usize> {
    tasks: Scheduler<TASKS>,
    caps: CapabilitySpace<CAPS>,
    owners: [Option<Ownership>; CAPS],
    resource_value: u64,
}

impl<const TASKS: usize, const CAPS: usize> Broker<TASKS, CAPS> {
    pub const fn new(value: u64) -> Self {
        Self {
            tasks: Scheduler::new(),
            caps: CapabilitySpace::new(),
            owners: [None; CAPS],
            resource_value: value,
        }
    }

    pub fn spawn(&mut self, object: ObjectId) -> Result<TaskId, Error> {
        self.tasks.spawn(object).map_err(Error::Task)
    }

    /// Only trusted kernel initialization may grant root authority.
    /// Every grant installs a separate global handle and ownership record.
    pub fn grant_resource(&mut self, task: TaskId, rights: Rights) -> Result<Handle, Error> {
        self.tasks.inspect(task).map_err(Error::Task)?;
        let free = self
            .owners
            .iter()
            .position(Option::is_none)
            .ok_or(Error::LedgerFull)?;
        let handle = self
            .caps
            .grant_root(RESOURCE_ID, ObjectKind::Resource, rights)
            .map_err(Error::Capability)?;
        self.owners[free] = Some(Ownership { handle, task });
        Ok(handle)
    }

    /// Kernel-only attenuation: derived rights may not exceed the parent,
    /// and derived handles remain owned by the same task.
    pub fn derive(&mut self, task: TaskId, parent: Handle, rights: Rights) -> Result<Handle, Error> {
        self.ensure_owner(task, parent)?;
        let free = self
            .owners
            .iter()
            .position(Option::is_none)
            .ok_or(Error::LedgerFull)?;
        let handle = self.caps.derive(parent, rights).map_err(Error::Capability)?;
        self.owners[free] = Some(Ownership { handle, task });
        Ok(handle)
    }

    fn ensure_owner(&self, task: TaskId, handle: Handle) -> Result<(), Error> {
        self.tasks.inspect(task).map_err(Error::Task)?;
        if self
            .owners
            .iter()
            .flatten()
            .any(|owner| owner.task == task && owner.handle == handle)
        {
            Ok(())
        } else {
            // Do not reveal whether a token belongs to a different task.
            Err(Error::Capability(CapError::InvalidHandle))
        }
    }

    fn authorized(&self, task: TaskId, raw: u64, right: Rights) -> Result<(), Error> {
        let handle = Handle::from_raw(raw);
        self.ensure_owner(task, handle)?;
        let cap = self.caps.authorize(handle, right).map_err(Error::Capability)?;
        if cap.kind != ObjectKind::Resource || cap.object != RESOURCE_ID {
            return Err(Error::WrongObject);
        }
        Ok(())
    }

    /// Small register-only syscall surface: no user-provided address is
    /// dereferenced. Permission failures intentionally share one reply code.
    pub fn dispatch(&mut self, task: TaskId, number: u64, raw: u64, value: u64) -> u64 {
        match number {
            SYS_RESOURCE_READ => {
                if self.authorized(task, raw, Rights::READ).is_ok() {
                    self.resource_value
                } else {
                    REPLY_DENIED
                }
            }
            SYS_RESOURCE_WRITE => {
                if self.authorized(task, raw, Rights::WRITE).is_ok() {
                    self.resource_value = value;
                    0
                } else {
                    REPLY_DENIED
                }
            }
            _ => REPLY_UNKNOWN,
        }
    }

    /// Kernel-only root revocation: associated descendants are rejected
    /// on the very next syscall even if their owner ledger entry remains.
    pub fn revoke(&mut self, task: TaskId, handle: Handle) -> Result<(), Error> {
        self.ensure_owner(task, handle)?;
        self.caps.revoke(handle).map_err(Error::Capability)
    }

    /// A retired generation must not retain authority over any live object.
    /// Revoking each surviving token also recursively invalidates descendants.
    pub fn exit(&mut self, task: TaskId) -> Result<(), Error> {
        self.tasks.inspect(task).map_err(Error::Task)?;
        for ownership in self.owners.iter_mut() {
            if let Some(record) = ownership {
                if record.task == task {
                    let _ = self.caps.revoke(record.handle);
                    *ownership = None;
                }
            }
        }
        self.tasks.exit(task).map_err(Error::Task)
    }

    pub fn value(&self) -> u64 {
        self.resource_value
    }
}

impl<const TASKS: usize, const CAPS: usize> Default for Broker<TASKS, CAPS> {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_and_task_identity_enforced_for_register_only_syscalls() {
        let mut b = Broker::<2, 8>::new(0x5356_5256);
        let alice = b.spawn(ObjectId(101)).unwrap();
        let bob = b.spawn(ObjectId(202)).unwrap();
        let read = b.grant_resource(alice, Rights::READ).unwrap();
        let write = b.grant_resource(bob, Rights::WRITE).unwrap();

        assert_eq!(b.dispatch(alice, SYS_RESOURCE_READ, read.raw(), 0), 0x5356_5256);
        assert_eq!(b.dispatch(alice, SYS_RESOURCE_WRITE, read.raw(), 0xffff), REPLY_DENIED);
        assert_eq!(b.dispatch(alice, SYS_RESOURCE_READ, write.raw(), 0), REPLY_DENIED);
        assert_eq!(b.dispatch(bob, SYS_RESOURCE_READ, read.raw(), 0), REPLY_DENIED);
        assert_eq!(b.dispatch(alice, SYS_RESOURCE_READ, 0, 0), REPLY_DENIED);
        assert_eq!(b.dispatch(alice, SYS_RESOURCE_READ, u64::MAX, 0), REPLY_DENIED);
        assert_eq!(b.dispatch(alice, 0xffff, read.raw(), 0), REPLY_UNKNOWN);
        assert_eq!(b.value(), 0x5356_5256);
        assert_eq!(b.dispatch(bob, SYS_RESOURCE_WRITE, write.raw(), 77), 0);
        assert_eq!(b.dispatch(alice, SYS_RESOURCE_READ, read.raw(), 0), 77);
    }

    #[test]
    fn derived_handles_are_attenuated_and_revoked() {
        let mut b = Broker::<1, 4>::new(5);
        let task = b.spawn(ObjectId(1)).unwrap();
        let root = b.grant_resource(task, Rights::READ | Rights::DERIVE).unwrap();
        let derived = b.derive(task, root, Rights::READ).unwrap();
        assert_eq!(b.derive(task, root, Rights::WRITE), Err(Error::Capability(CapError::PermissionDenied)));
        assert_eq!(b.dispatch(task, SYS_RESOURCE_READ, derived.raw(), 0), 5);
        b.revoke(task, root).unwrap();
        assert_eq!(b.dispatch(task, SYS_RESOURCE_READ, derived.raw(), 0), REPLY_DENIED);
        assert_eq!(b.dispatch(task, SYS_RESOURCE_READ, root.raw(), 0), REPLY_DENIED);
    }

    #[test]
    fn generation_reuse_does_not_restore_exited_task_rights() {
        let mut b = Broker::<1, 2>::new(18);
        let old = b.spawn(ObjectId(12)).unwrap();
        let old_token = b.grant_resource(old, Rights::READ).unwrap();
        b.exit(old).unwrap();
        let new = b.spawn(ObjectId(13)).unwrap();
        assert_ne!(old, new);
        assert_eq!(b.dispatch(old, SYS_RESOURCE_READ, old_token.raw(), 0), REPLY_DENIED);
        let token = b.grant_resource(new, Rights::READ).unwrap();
        assert_ne!(token.raw(), old_token.raw());
        assert_eq!(b.dispatch(new, SYS_RESOURCE_READ, old_token.raw(), 0), REPLY_DENIED);
        assert_eq!(b.dispatch(new, SYS_RESOURCE_READ, token.raw(), 0), 18);
    }

    #[test]
    fn capacity_and_unknown_task_fail_closed() {
        let mut b = Broker::<1, 1>::new(5);
        let id = b.spawn(ObjectId(1)).unwrap();
        let token = b.grant_resource(id, Rights::READ).unwrap();
        assert_eq!(b.grant_resource(id, Rights::READ), Err(Error::LedgerFull));
        assert_eq!(b.derive(id, token, Rights::READ), Err(Error::LedgerFull));
        b.exit(id).unwrap();
        assert_eq!(b.revoke(id, token), Err(Error::Task(TaskError::InvalidTask)));
        assert_eq!(b.dispatch(id, SYS_RESOURCE_READ, token.raw(), 0), REPLY_DENIED);
    }
}
