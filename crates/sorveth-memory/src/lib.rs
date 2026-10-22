#![no_std]

//! Read-only, allocation-free interpretation of UEFI memory descriptors.
//! It is not a physical frame allocator. Only conventional pages are counted
//! as immediately available; runtime, MMIO and loader pages are excluded.

use sorveth_abi::BootInfo;

pub const PAGE_BYTES: u64 = 4096;
pub const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const MIN_DESCRIPTOR_BYTES: usize = 40;
const MAX_DESCRIPTOR_BYTES: usize = 4096;
const MAX_MAP_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    InvalidMetadata,
    InvalidDescriptor,
    AddressOverflow,
    MisalignedRegion,
    CountOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl MemoryDescriptor {
    pub fn physical_end(self) -> Result<u64, MapError> {
        let length = self
            .number_of_pages
            .checked_mul(PAGE_BYTES)
            .ok_or(MapError::AddressOverflow)?;
        self.physical_start
            .checked_add(length)
            .ok_or(MapError::AddressOverflow)
    }

    pub const fn immediately_allocatable(self) -> bool {
        self.memory_type == EFI_CONVENTIONAL_MEMORY
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapSummary {
    pub descriptors: usize,
    pub conventional_pages: u64,
    pub highest_physical_end: u64,
}

/// Borrows a validated descriptor byte buffer. The map does not own memory.
pub struct MemoryMap<'a> {
    bytes: &'a [u8],
    stride: usize,
}

fn u32_le(src: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&src[at..at + 4]);
    u32::from_le_bytes(buf)
}
fn u64_le(src: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&src[at..at + 8]);
    u64::from_le_bytes(buf)
}
fn parse(src: &[u8]) -> MemoryDescriptor {
    // The MemoryMap constructor guarantees at least 40 bytes per chunk.
    MemoryDescriptor {
        memory_type: u32_le(src, 0),
        physical_start: u64_le(src, 8),
        virtual_start: u64_le(src, 16),
        number_of_pages: u64_le(src, 24),
        attribute: u64_le(src, 32),
    }
}

impl<'a> MemoryMap<'a> {
    pub fn from_bytes(bytes: &'a [u8], stride: usize) -> Result<Self, MapError> {
        if stride < MIN_DESCRIPTOR_BYTES
            || stride > MAX_DESCRIPTOR_BYTES
            || bytes.is_empty()
            || bytes.len() > MAX_MAP_BYTES
            || bytes.len() % stride != 0
        {
            return Err(MapError::InvalidMetadata);
        }
        Ok(Self { bytes, stride })
    }

    /// Interpret the pointer inherited from firmware after ExitBootServices.
    ///
    /// # Safety
    /// Caller must ensure the BootInfo memory map address is mapped, points to
    /// at least memory_map_size initialized, immutable bytes, and remains valid
    /// for the borrow lifetime. Firmware-derived metadata is not a substitute
    /// for checking the validity and lifetime of the underlying mapping.
    pub unsafe fn from_boot_info(info: &'a BootInfo) -> Result<Self, MapError> {
        if !info.is_valid()
            || info.memory_descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION
            || info.memory_map_address & 7 != 0
        {
            return Err(MapError::InvalidMetadata);
        }
        let size = usize::try_from(info.memory_map_size).map_err(|_| MapError::InvalidMetadata)?;
        let stride =
            usize::try_from(info.memory_descriptor_size).map_err(|_| MapError::InvalidMetadata)?;
        if size > MAX_MAP_BYTES
            || stride < MIN_DESCRIPTOR_BYTES
            || stride > MAX_DESCRIPTOR_BYTES
            || size == 0
            || info.memory_map_address.checked_add(size as u64).is_none()
        {
            return Err(MapError::InvalidMetadata);
        }
        let bytes = core::slice::from_raw_parts(info.memory_map_address as *const u8, size);
        Self::from_bytes(bytes, stride)
    }

    pub fn descriptors(&self) -> impl Iterator<Item = MemoryDescriptor> + '_ {
        self.bytes.chunks_exact(self.stride).map(parse)
    }

    /// Verify descriptor boundaries and report only immediately free pages.
    /// This doesn't authorize allocations or reclaim firmware/loader memory.
    pub fn summarize(&self) -> Result<MapSummary, MapError> {
        let mut summary = MapSummary {
            descriptors: 0,
            conventional_pages: 0,
            highest_physical_end: 0,
        };
        for desc in self.descriptors() {
            summary.descriptors = summary
                .descriptors
                .checked_add(1)
                .ok_or(MapError::CountOverflow)?;
            if desc.physical_start % PAGE_BYTES != 0 {
                return Err(MapError::MisalignedRegion);
            }
            let end = desc.physical_end()?;
            if end < desc.physical_start {
                return Err(MapError::AddressOverflow);
            }
            summary.highest_physical_end = summary.highest_physical_end.max(end);
            if desc.immediately_allocatable() {
                summary.conventional_pages = summary
                    .conventional_pages
                    .checked_add(desc.number_of_pages)
                    .ok_or(MapError::CountOverflow)?;
            }
        }
        if summary.descriptors == 0 {
            return Err(MapError::InvalidDescriptor);
        }
        Ok(summary)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn descriptor(kind: u32, base: u64, pages: u64, stride: usize) -> Vec<u8> {
        let mut d = std::vec![0u8; stride];
        d[0..4].copy_from_slice(&kind.to_le_bytes());
        d[8..16].copy_from_slice(&base.to_le_bytes());
        d[24..32].copy_from_slice(&pages.to_le_bytes());
        d
    }

    #[test]
    fn counts_conventional_pages_but_not_firmware_runtime_or_mmio() {
        let mut data = descriptor(7, 0x1000, 3, 48);
        data.extend_from_slice(&descriptor(6, 0x4000, 4, 48));
        data.extend_from_slice(&descriptor(11, 0x8000, 8, 48));
        let m = MemoryMap::from_bytes(&data, 48).unwrap();
        let s = m.summarize().unwrap();
        assert_eq!(s.descriptors, 3);
        assert_eq!(s.conventional_pages, 3);
        assert_eq!(s.highest_physical_end, 0x10000);
    }

    #[test]
    fn variable_stride_preserves_descriptor_fields() {
        let data = descriptor(7, 0x2000, 2, 64);
        let d = MemoryMap::from_bytes(&data, 64)
            .unwrap()
            .descriptors()
            .next()
            .unwrap();
        assert_eq!(d.physical_start, 0x2000);
        assert_eq!(d.physical_end(), Ok(0x4000));
        assert!(d.immediately_allocatable());
    }

    #[test]
    fn rejects_malformed_descriptor_frames() {
        assert!(matches!(
            MemoryMap::from_bytes(&[0; 40], 0),
            Err(MapError::InvalidMetadata)
        ));
        assert!(matches!(
            MemoryMap::from_bytes(&[0; 41], 40),
            Err(MapError::InvalidMetadata)
        ));
        assert!(matches!(
            MemoryMap::from_bytes(&[], 48),
            Err(MapError::InvalidMetadata)
        ));
        assert!(matches!(
            MemoryMap::from_bytes(&[0; 40], 39),
            Err(MapError::InvalidMetadata)
        ));
    }

    #[test]
    fn rejects_misalignment_and_overflow() {
        let unaligned = descriptor(7, 0x1001, 1, 40);
        assert_eq!(
            MemoryMap::from_bytes(&unaligned, 40).unwrap().summarize(),
            Err(MapError::MisalignedRegion)
        );
        let overflowing = descriptor(7, 0xffff_ffff_ffff_f000, 2, 40);
        assert_eq!(
            MemoryMap::from_bytes(&overflowing, 40).unwrap().summarize(),
            Err(MapError::AddressOverflow)
        );
        let page_overflow = descriptor(7, 0x1000, u64::MAX, 40);
        assert_eq!(
            MemoryMap::from_bytes(&page_overflow, 40)
                .unwrap()
                .summarize(),
            Err(MapError::AddressOverflow)
        );
    }
}
