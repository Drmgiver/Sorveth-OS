#![no_std]

//! Minimal fixed-capacity capability space, usable before an allocator exists.
//! A kernel-only authority table, NOT yet a userspace security boundary.
//! No concurrency primitives are provided: the owner must serialize access.

use core::ops::{BitOr, BitOrAssign};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u16);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const SEND: Self = Self(1 << 3);
    pub const DERIVE: Self = Self(1 << 4);
    pub const MANAGE: Self = Self(1 << 5);
    pub const ALL: Self = Self((1 << 6) - 1);

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}
impl BitOrAssign for Rights {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Task,
    Endpoint,
    Memory,
    Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId(pub u64);

/// Opaque user-visible handle: high 32 bits = generation, low 32 bits = slot+1.
/// A zero handle is always invalid. Never treat a handle as a memory pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(u64);

impl Handle {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    const fn new(index: usize, generation: u32) -> Self {
        Self(((generation as u64) << 32) | ((index as u64) + 1))
    }
    const fn parts(self) -> Option<(usize, u32)> {
        let slot_plus_one = self.0 as u32;
        let generation = (self.0 >> 32) as u32;
        if slot_plus_one == 0 || generation == 0 {
            None
        } else {
            Some(((slot_plus_one - 1) as usize, generation))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub object: ObjectId,
    pub kind: ObjectKind,
    pub rights: Rights,
    parent: Option<Handle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidHandle,
    PermissionDenied,
    EmptyRights,
    InvalidObject,
    Full,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    value: Option<Capability>,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 1,
        value: None,
    };
    fn invalidate(&mut self) {
        self.value = None;
        // Generation zero is reserved; stale handles do not match the next grant.
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }
    }
}

pub struct CapabilitySpace<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> CapabilitySpace<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
        }
    }

    fn install(&mut self, cap: Capability) -> Result<Handle, Error> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if index >= u32::MAX as usize {
                break;
            }
            if slot.value.is_none() {
                slot.value = Some(cap);
                return Ok(Handle::new(index, slot.generation));
            }
        }
        Err(Error::Full)
    }

    /// Privileged kernel operation only; no untrusted process may mint root caps.
    pub fn grant_root(
        &mut self,
        object: ObjectId,
        kind: ObjectKind,
        rights: Rights,
    ) -> Result<Handle, Error> {
        if object.0 == 0 {
            return Err(Error::InvalidObject);
        }
        if rights.is_empty() {
            return Err(Error::EmptyRights);
        }
        self.install(Capability {
            object,
            kind,
            rights,
            parent: None,
        })
    }

    /// Require the handle to exist and possess every requested right.
    pub fn authorize(&self, handle: Handle, rights: Rights) -> Result<Capability, Error> {
        let (index, generation) = handle.parts().ok_or(Error::InvalidHandle)?;
        let slot = self.slots.get(index).ok_or(Error::InvalidHandle)?;
        if slot.generation != generation {
            return Err(Error::InvalidHandle);
        }
        let cap = slot.value.ok_or(Error::InvalidHandle)?;
        if !cap.rights.contains(rights) {
            return Err(Error::PermissionDenied);
        }
        Ok(cap)
    }

    /// Attenuation only: derived capabilities cannot gain rights their parent lacks.
    /// The parent must also possess the DERIVE right.
    pub fn derive(&mut self, parent: Handle, rights: Rights) -> Result<Handle, Error> {
        if rights.is_empty() {
            return Err(Error::EmptyRights);
        }
        let original = self.authorize(parent, Rights::DERIVE)?;
        if !original.rights.contains(rights) {
            return Err(Error::PermissionDenied);
        }
        self.install(Capability {
            object: original.object,
            kind: original.kind,
            rights,
            parent: Some(parent),
        })
    }

    /// Kernel-only revocation, including all descendant capabilities.
    pub fn revoke(&mut self, handle: Handle) -> Result<(), Error> {
        self.authorize(handle, Rights::NONE)?;
        let (index, _) = handle.parts().ok_or(Error::InvalidHandle)?;
        self.slots[index].invalidate();
        // Revoke descendants, regardless of slot allocation order or depth.
        loop {
            let mut found = false;
            for index in 0..N {
                let stale_parent = match self.slots[index].value {
                    Some(cap) => match cap.parent {
                        Some(parent) => self.authorize(parent, Rights::NONE).is_err(),
                        None => false,
                    },
                    None => false,
                };
                if stale_parent {
                    self.slots[index].invalidate();
                    found = true;
                }
            }
            if !found {
                break;
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.value.is_some()).count()
    }
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for CapabilitySpace<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cannot_escalate_rights() {
        let mut s = CapabilitySpace::<4>::new();
        let root = s
            .grant_root(
                ObjectId(1),
                ObjectKind::Resource,
                Rights::READ | Rights::WRITE | Rights::DERIVE,
            )
            .unwrap();
        let child = s.derive(root, Rights::READ).unwrap();
        assert!(s.authorize(child, Rights::READ).is_ok());
        assert_eq!(
            s.authorize(child, Rights::WRITE),
            Err(Error::PermissionDenied)
        );
        assert_eq!(s.derive(child, Rights::WRITE), Err(Error::PermissionDenied));
        assert_eq!(
            s.derive(root, Rights::EXECUTE),
            Err(Error::PermissionDenied)
        );
    }
    #[test]
    fn descendants_revoked_and_stale_handles_rejected() {
        let mut s = CapabilitySpace::<4>::new();
        let root = s
            .grant_root(
                ObjectId(7),
                ObjectKind::Memory,
                Rights::READ | Rights::DERIVE,
            )
            .unwrap();
        let child = s.derive(root, Rights::READ | Rights::DERIVE).unwrap();
        let grandchild = s.derive(child, Rights::READ).unwrap();
        s.revoke(root).unwrap();
        assert_eq!(s.len(), 0);
        assert_eq!(s.authorize(child, Rights::NONE), Err(Error::InvalidHandle));
        assert_eq!(
            s.authorize(grandchild, Rights::NONE),
            Err(Error::InvalidHandle)
        );
        let replacement = s
            .grant_root(ObjectId(8), ObjectKind::Task, Rights::READ)
            .unwrap();
        assert_ne!(root.raw(), replacement.raw());
        assert_eq!(s.authorize(root, Rights::NONE), Err(Error::InvalidHandle));
    }
    #[test]
    fn full_space_and_invalid_handles() {
        let mut s = CapabilitySpace::<1>::new();
        assert_eq!(
            s.authorize(Handle::from_raw(0), Rights::NONE),
            Err(Error::InvalidHandle)
        );
        assert_eq!(
            s.grant_root(ObjectId(0), ObjectKind::Task, Rights::READ),
            Err(Error::InvalidObject)
        );
        s.grant_root(ObjectId(1), ObjectKind::Task, Rights::READ)
            .unwrap();
        assert_eq!(
            s.grant_root(ObjectId(2), ObjectKind::Task, Rights::READ),
            Err(Error::Full)
        );
    }
    #[test]
    fn bit_validation() {
        assert_eq!(Rights::from_bits(0x8000), None);
        assert!(Rights::ALL.contains(Rights::MANAGE));
    }
}
