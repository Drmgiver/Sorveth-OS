#![no_std]

//! Fixed-capacity, capability-checked kernel message queues.
//!
//! This is NOT process isolation or a userspace syscall interface. Until
//! Sorveth has separate address spaces, only trusted kernel code may invoke
//! these functions with a serialized mutable mailbox reference.
//! Messages contain owned fixed-size bytes, never pointers or borrowed data.

use sorveth_cap::{CapabilitySpace, Error as CapabilityError, Handle, ObjectId, ObjectKind, Rights};

pub const MAX_PAYLOAD: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub tag: u32,
    pub length: u8,
    pub payload: [u8; MAX_PAYLOAD],
}

impl Message {
    pub fn from_bytes(tag: u32, data: &[u8]) -> Result<Self, Error> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let mut payload = [0; MAX_PAYLOAD];
        payload[..data.len()].copy_from_slice(data);
        Ok(Self {
            tag,
            length: data.len() as u8,
            payload,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.payload[..self.length as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidEndpoint,
    ZeroCapacity,
    Permission(CapabilityError),
    WrongObject,
    Full,
    Empty,
    Closed,
    PayloadTooLarge,
}

/// One bounded endpoint; no heap, task pointers, dynamic allocation or
/// hardware interrupts. A future syscall broker will own this structure.
pub struct Mailbox<const N: usize> {
    object: ObjectId,
    entries: [Option<Message>; N],
    head: usize,
    tail: usize,
    len: usize,
    closed: bool,
}

impl<const N: usize> Mailbox<N> {
    pub const fn new(object: ObjectId) -> Result<Self, Error> {
        if object.0 == 0 {
            return Err(Error::InvalidEndpoint);
        }
        if N == 0 {
            return Err(Error::ZeroCapacity);
        }
        Ok(Self {
            object,
            entries: [None; N],
            head: 0,
            tail: 0,
            len: 0,
            closed: false,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn require<const CAPS: usize>(
        &self,
        capabilities: &CapabilitySpace<CAPS>,
        handle: Handle,
        right: Rights,
    ) -> Result<(), Error> {
        let cap = capabilities
            .authorize(handle, right)
            .map_err(Error::Permission)?;
        if cap.kind != ObjectKind::Endpoint || cap.object != self.object {
            return Err(Error::WrongObject);
        }
        Ok(())
    }

    /// Validate SEND authority and enqueue a deep-copied, bounded message.
    /// Full queues fail without mutating their contents or order.
    pub fn send<const CAPS: usize>(
        &mut self,
        capabilities: &CapabilitySpace<CAPS>,
        handle: Handle,
        message: Message,
    ) -> Result<(), Error> {
        self.require(capabilities, handle, Rights::SEND)?;
        if self.closed {
            return Err(Error::Closed);
        }
        if self.len == N {
            return Err(Error::Full);
        }
        self.entries[self.tail] = Some(message);
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    /// READ authority is distinct from SEND. A receiver cannot dequeue
    /// another endpoint's messages even with a valid foreign handle.
    pub fn receive<const CAPS: usize>(
        &mut self,
        capabilities: &CapabilitySpace<CAPS>,
        handle: Handle,
    ) -> Result<Message, Error> {
        self.require(capabilities, handle, Rights::READ)?;
        if self.closed {
            return Err(Error::Closed);
        }
        if self.len == 0 {
            return Err(Error::Empty);
        }
        let msg = self.entries[self.head].take().ok_or(Error::Empty)?;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Ok(msg)
    }

    /// A privileged MANAGE capability may permanently close the endpoint.
    /// Queued message slots are invalidated; reopening is not permitted.
    pub fn close<const CAPS: usize>(
        &mut self,
        capabilities: &CapabilitySpace<CAPS>,
        handle: Handle,
    ) -> Result<(), Error> {
        self.require(capabilities, handle, Rights::MANAGE)?;
        self.entries = [None; N];
        self.len = 0;
        self.head = 0;
        self.tail = 0;
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (CapabilitySpace<8>, Handle, Handle, Handle) {
        let mut caps = CapabilitySpace::<8>::new();
        let root = caps
            .grant_root(
                ObjectId(71),
                ObjectKind::Endpoint,
                Rights::SEND | Rights::READ | Rights::DERIVE | Rights::MANAGE,
            )
            .unwrap();
        let tx = caps.derive(root, Rights::SEND).unwrap();
        let rx = caps.derive(root, Rights::READ).unwrap();
        (caps, root, tx, rx)
    }

    #[test]
    fn fifo_wraparound_rejects_overflow_without_losing_messages() {
        let (caps, _, tx, rx) = setup();
        let mut box_ = Mailbox::<2>::new(ObjectId(71)).unwrap();
        assert_eq!(box_.receive(&caps, rx), Err(Error::Empty));
        box_.send(&caps, tx, Message::from_bytes(1, b"A").unwrap()).unwrap();
        box_.send(&caps, tx, Message::from_bytes(2, b"B").unwrap()).unwrap();
        assert_eq!(
            box_.send(&caps, tx, Message::from_bytes(3, b"C").unwrap()),
            Err(Error::Full)
        );
        assert_eq!(box_.receive(&caps, rx).unwrap().bytes(), b"A");
        box_.send(&caps, tx, Message::from_bytes(3, b"C").unwrap()).unwrap();
        assert_eq!(box_.receive(&caps, rx).unwrap().tag, 2);
        assert_eq!(box_.receive(&caps, rx).unwrap().tag, 3);
        assert_eq!(box_.len(), 0);
    }

    #[test]
    fn send_and_receive_rights_are_independent() {
        let (caps, root, tx, rx) = setup();
        let mut box_ = Mailbox::<1>::new(ObjectId(71)).unwrap();
        let msg = Message::from_bytes(8, b"Hi").unwrap();
        assert_eq!(
            box_.send(&caps, rx, msg),
            Err(Error::Permission(CapabilityError::PermissionDenied))
        );
        assert_eq!(
            box_.receive(&caps, tx),
            Err(Error::Permission(CapabilityError::PermissionDenied))
        );
        box_.send(&caps, tx, msg).unwrap();
        assert_eq!(box_.receive(&caps, rx).unwrap(), msg);
        box_.close(&caps, root).unwrap();
        assert_eq!(box_.send(&caps, tx, msg), Err(Error::Closed));
        assert_eq!(box_.receive(&caps, rx), Err(Error::Closed));
    }

    #[test]
    fn rejects_revocation_wrong_kind_wrong_endpoint_and_forgery() {
        let (mut caps, root, tx, rx) = setup();
        let other = caps
            .grant_root(ObjectId(72), ObjectKind::Endpoint, Rights::SEND)
            .unwrap();
        let memory = caps
            .grant_root(ObjectId(71), ObjectKind::Memory, Rights::SEND)
            .unwrap();
        let mut box_ = Mailbox::<1>::new(ObjectId(71)).unwrap();
        let msg = Message::from_bytes(1, b"test").unwrap();
        assert_eq!(box_.send(&caps, other, msg), Err(Error::WrongObject));
        assert_eq!(box_.send(&caps, memory, msg), Err(Error::WrongObject));
        assert_eq!(
            box_.send(&caps, Handle::from_raw(0), msg),
            Err(Error::Permission(CapabilityError::InvalidHandle))
        );
        caps.revoke(root).unwrap();
        assert_eq!(
            box_.send(&caps, tx, msg),
            Err(Error::Permission(CapabilityError::InvalidHandle))
        );
        assert_eq!(
            box_.receive(&caps, rx),
            Err(Error::Permission(CapabilityError::InvalidHandle))
        );
        assert_eq!(box_.len(), 0);
    }

    #[test]
    fn payloads_are_bounded_and_copy_only_the_supplied_length() {
        let data = [7u8; MAX_PAYLOAD + 1];
        assert_eq!(Message::from_bytes(0, &data), Err(Error::PayloadTooLarge));
        let msg = Message::from_bytes(22, b"ok").unwrap();
        assert_eq!(msg.bytes(), b"ok");
        assert!(msg.payload[2..].iter().all(|&b| b == 0));
        assert!(matches!(Mailbox::<0>::new(ObjectId(1)), Err(Error::ZeroCapacity)));
        assert!(matches!(Mailbox::<2>::new(ObjectId(0)), Err(Error::InvalidEndpoint)));
    }
}
