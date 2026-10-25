#![no_std]

//! Kernel-owned rendezvous between the task registry and a bounded mailbox.
//!
//! Tasks do not execute here: this is a scheduling and authorization state
//! machine, not a context switch, IRQ handler or userspace syscall boundary.
//! A successful authorized send can wake a parked receiver. The receiver
//! retains exclusive dequeue priority until it receives, cancels or exits.
//! Only the trusted kernel may hold a mutable Exchange reference.

use sorveth_cap::{CapabilitySpace, Handle, ObjectId};
use sorveth_ipc::{Error as IpcError, Mailbox, Message};
use sorveth_task::{Error as TaskError, Scheduler, State, TaskId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Task(TaskError),
    Ipc(IpcError),
    ReservedForWaiter,
    NotWaiting,
}

impl From<TaskError> for Error {
    fn from(value: TaskError) -> Self {
        Self::Task(value)
    }
}

impl From<IpcError> for Error {
    fn from(value: IpcError) -> Self {
        Self::Ipc(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receive {
    Delivered(Message),
    Parked,
}

/// A single endpoint and scheduler with at most one reserved receiver.
/// The queue and scheduler are private to prevent bypassing the wakeup rules.
pub struct Exchange<const TASKS: usize, const DEPTH: usize> {
    tasks: Scheduler<TASKS>,
    queue: Mailbox<DEPTH>,
    waiter: Option<TaskId>,
}

impl<const TASKS: usize, const DEPTH: usize> Exchange<TASKS, DEPTH> {
    pub const fn new(endpoint: ObjectId) -> Result<Self, Error> {
        let queue = match Mailbox::<DEPTH>::new(endpoint) {
            Ok(queue) => queue,
            Err(err) => return Err(Error::Ipc(err)),
        };
        Ok(Self {
            tasks: Scheduler::new(),
            queue,
            waiter: None,
        })
    }

    pub fn spawn(&mut self, object: ObjectId) -> Result<TaskId, Error> {
        self.tasks.spawn(object).map_err(Error::Task)
    }

    pub fn exit(&mut self, id: TaskId) -> Result<(), Error> {
        self.tasks.exit(id)?;
        if self.waiter == Some(id) {
            self.waiter = None;
        }
        Ok(())
    }

    pub fn next_runnable(&mut self) -> Option<TaskId> {
        self.tasks.select_next()
    }

    pub fn task_state(&self, id: TaskId) -> Result<State, Error> {
        Ok(self.tasks.inspect(id)?.state)
    }

    pub fn pending_messages(&self) -> usize {
        self.queue.len()
    }

    pub fn reserved_receiver(&self) -> Option<TaskId> {
        self.waiter
    }

    /// A message is enqueued first. Only a successful send can wake the
    /// reserved receiver; denied and full sends have no scheduling effects.
    pub fn send<const CAPS: usize>(
        &mut self,
        caps: &CapabilitySpace<CAPS>,
        handle: Handle,
        message: Message,
    ) -> Result<(), Error> {
        // Validate internal state before committing the enqueue.
        let state = match self.waiter {
            Some(task) => Some(self.tasks.inspect(task)?.state),
            None => None,
        };
        self.queue.send(caps, handle, message)?;
        if let (Some(waiter), Some(State::Blocked)) = (self.waiter, state) {
            // The only state mutator lives here, so this cannot fail if the
            // pre-enqueue inspection succeeded.
            self.tasks.wake(waiter)?;
        }
        Ok(())
    }

    /// Receive one message or park a runnable task on an empty endpoint.
    ///
    /// Mailbox authorization is checked *before* a task can become blocked.
    /// After waking, the intended receiver has the dequeue reservation;
    /// another task cannot take the message out from under that receiver.
    pub fn receive_or_park<const CAPS: usize>(
        &mut self,
        caps: &CapabilitySpace<CAPS>,
        task: TaskId,
        handle: Handle,
    ) -> Result<Receive, Error> {
        if self.tasks.inspect(task)?.state != State::Ready {
            return Err(Error::Task(TaskError::WrongState));
        }
        if self.waiter.is_some() && self.waiter != Some(task) {
            return Err(Error::ReservedForWaiter);
        }
        match self.queue.receive(caps, handle) {
            Ok(message) => {
                if self.waiter == Some(task) {
                    self.waiter = None;
                }
                Ok(Receive::Delivered(message))
            }
            Err(IpcError::Empty) => {
                self.tasks.block(task)?;
                self.waiter = Some(task);
                Ok(Receive::Parked)
            }
            Err(err) => {
                // If the receive capability was revoked while the task was
                // parked, release its reservation without losing the message.
                if self.waiter == Some(task) {
                    self.waiter = None;
                }
                Err(Error::Ipc(err))
            }
        }
    }

    /// Cancel an outstanding receive, restoring Ready state if still parked.
    /// An exited task cannot cancel another task's reserved message.
    pub fn cancel_receive(&mut self, id: TaskId) -> Result<(), Error> {
        self.tasks.inspect(id)?;
        if self.waiter != Some(id) {
            return Err(Error::NotWaiting);
        }
        if self.tasks.inspect(id)?.state == State::Blocked {
            self.tasks.wake(id)?;
        }
        self.waiter = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sorveth_cap::{Error as CapError, ObjectKind, Rights};

    fn setup() -> (CapabilitySpace<8>, Handle, Handle, Handle) {
        let mut caps = CapabilitySpace::<8>::new();
        let root = caps
            .grant_root(
                ObjectId(77),
                ObjectKind::Endpoint,
                Rights::SEND | Rights::READ | Rights::DERIVE,
            )
            .unwrap();
        let send = caps.derive(root, Rights::SEND).unwrap();
        let read = caps.derive(root, Rights::READ).unwrap();
        (caps, root, send, read)
    }

    #[test]
    fn authorized_send_wakes_only_parked_receiver_and_reserves_delivery() {
        let (caps, _, tx, rx) = setup();
        let mut exchange = Exchange::<3, 2>::new(ObjectId(77)).unwrap();
        let reader = exchange.spawn(ObjectId(101)).unwrap();
        let writer = exchange.spawn(ObjectId(102)).unwrap();
        let competitor = exchange.spawn(ObjectId(103)).unwrap();
        assert_eq!(
            exchange.receive_or_park(&caps, reader, rx),
            Ok(Receive::Parked)
        );
        assert_eq!(exchange.task_state(reader), Ok(State::Blocked));
        assert_eq!(exchange.next_runnable(), Some(writer));
        assert_eq!(exchange.next_runnable(), Some(competitor));
        let msg = Message::from_bytes(8, b"wake").unwrap();
        exchange.send(&caps, tx, msg).unwrap();
        assert_eq!(exchange.task_state(reader), Ok(State::Ready));
        assert_eq!(exchange.reserved_receiver(), Some(reader));
        assert_eq!(
            exchange.receive_or_park(&caps, competitor, rx),
            Err(Error::ReservedForWaiter)
        );
        assert_eq!(exchange.pending_messages(), 1);
        assert_eq!(
            exchange.receive_or_park(&caps, reader, rx),
            Ok(Receive::Delivered(msg))
        );
        assert_eq!(exchange.reserved_receiver(), None);
        assert_eq!(exchange.pending_messages(), 0);
    }

    #[test]
    fn unauthorized_receive_does_not_park_task() {
        let (caps, _, tx, _) = setup();
        let mut exchange = Exchange::<1, 1>::new(ObjectId(77)).unwrap();
        let task = exchange.spawn(ObjectId(111)).unwrap();
        assert_eq!(
            exchange.receive_or_park(&caps, task, tx),
            Err(Error::Ipc(IpcError::Permission(CapError::PermissionDenied)))
        );
        assert_eq!(exchange.task_state(task), Ok(State::Ready));
        assert_eq!(exchange.reserved_receiver(), None);
    }

    #[test]
    fn unauthorized_and_full_sends_do_not_modify_waiter_state() {
        let (caps, _, tx, rx) = setup();
        let mut exchange = Exchange::<2, 1>::new(ObjectId(77)).unwrap();
        let task = exchange.spawn(ObjectId(151)).unwrap();
        assert_eq!(
            exchange.receive_or_park(&caps, task, rx),
            Ok(Receive::Parked)
        );
        let msg = Message::from_bytes(5, b"a").unwrap();
        assert_eq!(
            exchange.send(&caps, rx, msg),
            Err(Error::Ipc(IpcError::Permission(CapError::PermissionDenied)))
        );
        assert_eq!(exchange.task_state(task), Ok(State::Blocked));
        assert_eq!(exchange.pending_messages(), 0);
        exchange.send(&caps, tx, msg).unwrap();
        assert_eq!(exchange.task_state(task), Ok(State::Ready));
        assert_eq!(
            exchange.send(&caps, tx, msg),
            Err(Error::Ipc(IpcError::Full))
        );
        assert_eq!(exchange.pending_messages(), 1);
        assert_eq!(exchange.reserved_receiver(), Some(task));
    }

    #[test]
    fn exiting_or_cancelling_waiter_releases_reservation() {
        let (caps, _, _, rx) = setup();
        let mut exchange = Exchange::<2, 2>::new(ObjectId(77)).unwrap();
        let a = exchange.spawn(ObjectId(1)).unwrap();
        let b = exchange.spawn(ObjectId(2)).unwrap();
        assert_eq!(exchange.receive_or_park(&caps, a, rx), Ok(Receive::Parked));
        assert_eq!(exchange.cancel_receive(b), Err(Error::NotWaiting));
        exchange.cancel_receive(a).unwrap();
        assert_eq!(exchange.task_state(a), Ok(State::Ready));
        assert_eq!(exchange.reserved_receiver(), None);
        assert_eq!(exchange.receive_or_park(&caps, b, rx), Ok(Receive::Parked));
        exchange.exit(b).unwrap();
        assert_eq!(exchange.reserved_receiver(), None);
        assert_eq!(
            exchange.task_state(b),
            Err(Error::Task(TaskError::InvalidTask))
        );
        assert_eq!(
            exchange.cancel_receive(b),
            Err(Error::Task(TaskError::InvalidTask))
        );
        assert_eq!(exchange.next_runnable(), Some(a));
    }

    #[test]
    fn revocation_after_wakeup_does_not_steal_queued_message() {
        let (mut caps, root, tx, rx) = setup();
        let mut exchange = Exchange::<2, 1>::new(ObjectId(77)).unwrap();
        let a = exchange.spawn(ObjectId(1)).unwrap();
        let b = exchange.spawn(ObjectId(2)).unwrap();
        assert_eq!(exchange.receive_or_park(&caps, a, rx), Ok(Receive::Parked));
        let msg = Message::from_bytes(91, b"private").unwrap();
        exchange.send(&caps, tx, msg).unwrap();
        caps.revoke(root).unwrap();
        assert_eq!(
            exchange.receive_or_park(&caps, a, rx),
            Err(Error::Ipc(IpcError::Permission(CapError::InvalidHandle)))
        );
        assert_eq!(exchange.reserved_receiver(), None);
        assert_eq!(exchange.pending_messages(), 1);
        let new_root = caps
            .grant_root(ObjectId(77), ObjectKind::Endpoint, Rights::READ)
            .unwrap();
        assert_eq!(
            exchange.receive_or_park(&caps, b, new_root),
            Ok(Receive::Delivered(msg))
        );
    }

    #[test]
    fn invalid_construction_and_empty_registry_fail_closed() {
        assert!(matches!(
            Exchange::<2, 0>::new(ObjectId(1)),
            Err(Error::Ipc(IpcError::ZeroCapacity))
        ));
        assert!(matches!(
            Exchange::<2, 1>::new(ObjectId(0)),
            Err(Error::Ipc(IpcError::InvalidEndpoint))
        ));
        let (caps, _, _, rx) = setup();
        let mut exchange = Exchange::<0, 1>::new(ObjectId(77)).unwrap();
        assert_eq!(
            exchange.spawn(ObjectId(1)),
            Err(Error::Task(TaskError::NoCapacity))
        );
        assert_eq!(exchange.next_runnable(), None);
        let _ = caps;
        let _ = rx;
    }
}
