//! M2-K.1d: bounded evidence of *current* physical backing and UEFI type.
//!
//! This is an inventory, NOT page ownership or permission enforcement for a
//! new CR3. In particular, a UEFI type does not grant a frame to Sorveth.
//! The existing OVMF identity map is still needed to validate page tables.

use sorveth_memory::{MemoryMap, PAGE_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Code,
    KernelStack,
    WorkerStack,
    FaultStack,
    TrapStack,
    CpuTable,
    KernelState,
    BootHandoff,
    MemoryDescriptors,
    FramebufferDevice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    InvalidRange,
    MissingMapping,
    Permission,
    UnknownPhysicalBacking,
    ConflictingFirmwareTypes,
    UnsafeKernelMemoryType,
    AliasedPhysicalBacking,
    Full,
    WrongCpuContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub virtual_page: u64,
    pub physical_page: u64,
    /// The UEFI memory type is evidence of provenance, NOT ownership.
    /// A missing descriptor for MMIO must be resolved before a new root.
    pub uefi_type: Option<u32>,
    pub kind: Kind,
    pub writable: bool,
    pub executable: bool,
}

pub struct Manifest<const N: usize> {
    records: [Option<Record>; N],
    len: usize,
    legacy_writable_executable: usize,
    unknown_device_pages: usize,
}

impl<const N: usize> Manifest<N> {
    pub const fn new() -> Self {
        Self {
            records: [None; N],
            len: 0,
            legacy_writable_executable: 0,
            unknown_device_pages: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn legacy_writable_executable(&self) -> usize {
        self.legacy_writable_executable
    }

    pub const fn unknown_device_pages(&self) -> usize {
        self.unknown_device_pages
    }

    pub fn get(&self, index: usize) -> Option<Record> {
        if index < self.len {
            self.records[index]
        } else {
            None
        }
    }

    /// Refuse any second virtual alias to a critical physical page.
    /// Repeated checks of the very same page are allowed.
    pub fn push(&mut self, record: Record) -> Result<(), ManifestError> {
        if record.virtual_page == 0
            || record.virtual_page & (PAGE_BYTES - 1) != 0
            || record.physical_page & (PAGE_BYTES - 1) != 0
        {
            return Err(ManifestError::InvalidRange);
        }
        for existing in self.records[..self.len].iter().flatten() {
            if existing.virtual_page == record.virtual_page {
                if existing.physical_page != record.physical_page
                    || existing.writable != record.writable
                    || existing.executable != record.executable
                    || existing.uefi_type != record.uefi_type
                {
                    return Err(ManifestError::AliasedPhysicalBacking);
                }
                return Ok(());
            }
            if existing.physical_page == record.physical_page {
                return Err(ManifestError::AliasedPhysicalBacking);
            }
        }
        if self.len >= N {
            return Err(ManifestError::Full);
        }
        if record.writable && record.executable {
            self.legacy_writable_executable += 1;
        }
        if record.kind == Kind::FramebufferDevice && record.uefi_type.is_none() {
            self.unknown_device_pages += 1;
        }
        self.records[self.len] = Some(record);
        self.len += 1;
        Ok(())
    }
}

impl<const N: usize> Default for Manifest<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve one complete 4-KiB physical page to exactly one UEFI descriptor.
/// Gaps and partial descriptor crossings remain UNKNOWN, never allocatable.
/// Inconsistent overlapping descriptor types fail closed.
pub fn uefi_type_of(map: &MemoryMap<'_>, physical_page: u64) -> Result<Option<u32>, ManifestError> {
    if physical_page & (PAGE_BYTES - 1) != 0 {
        return Err(ManifestError::InvalidRange);
    }
    let page_end = physical_page
        .checked_add(PAGE_BYTES)
        .ok_or(ManifestError::InvalidRange)?;
    let mut found = None;
    for descriptor in map.descriptors() {
        if descriptor.number_of_pages == 0 {
            continue;
        }
        let end = descriptor
            .physical_end()
            .map_err(|_| ManifestError::ConflictingFirmwareTypes)?;
        if descriptor.physical_start < page_end && physical_page < end {
            if descriptor.physical_start > physical_page || end < page_end || found.is_some() {
                return Err(ManifestError::ConflictingFirmwareTypes);
            }
            found = Some(descriptor.memory_type);
        }
    }
    Ok(found)
}

fn allowed_critical_type(uefi_type: u32) -> bool {
    // LoaderCode/Data and BootServicesCode/Data were never admitted to the
    // allocator's conventional free list. Neither type proves Sorveth owns
    // the bytes; do not reclaim them from this evidence.
    matches!(uefi_type, 1..=4)
}

#[cfg(target_arch = "x86_64")]
unsafe fn record_one<const N: usize>(
    manifest: &mut Manifest<N>,
    map: &MemoryMap<'_>,
    root: u64,
    virtual_address: u64,
    kind: Kind,
    needs_write: bool,
    needs_execute: bool,
) -> Result<(), ManifestError> {
    let leaf = crate::supervisor_audit::walk(root, virtual_address, |entry| {
        crate::root::read_bootstrap_supervisor_entry(entry)
    })
    .map_err(|_| ManifestError::MissingMapping)?;
    if leaf.user_accessible || needs_write && !leaf.writable || needs_execute && !leaf.executable {
        return Err(ManifestError::Permission);
    }
    let phys_page = leaf.physical_address & !(PAGE_BYTES - 1);
    let uefi_type = uefi_type_of(map, phys_page)?;
    if kind != Kind::FramebufferDevice {
        let descriptor = uefi_type.ok_or(ManifestError::UnknownPhysicalBacking)?;
        if !allowed_critical_type(descriptor) {
            return Err(ManifestError::UnsafeKernelMemoryType);
        }
    } else if leaf.physical_address != virtual_address {
        // The current early GOP painter uses a physical identity pointer.
        // Never assume that MMIO can be rebuilt using a translated address.
        return Err(ManifestError::Permission);
    }
    manifest.push(Record {
        virtual_page: virtual_address & !(PAGE_BYTES - 1),
        physical_page: phys_page,
        uefi_type,
        kind,
        writable: leaf.writable,
        executable: leaf.executable,
    })
}

#[cfg(target_arch = "x86_64")]
unsafe fn record_range<const N: usize>(
    manifest: &mut Manifest<N>,
    map: &MemoryMap<'_>,
    root: u64,
    start: u64,
    bytes: u64,
    kind: Kind,
    needs_write: bool,
) -> Result<(), ManifestError> {
    if start == 0 || bytes == 0 {
        return Err(ManifestError::InvalidRange);
    }
    let last = start
        .checked_add(bytes - 1)
        .ok_or(ManifestError::InvalidRange)?;
    let mut address = start & !(PAGE_BYTES - 1);
    let final_page = last & !(PAGE_BYTES - 1);
    loop {
        record_one(manifest, map, root, address, kind, needs_write, false)?;
        if address == final_page {
            return Ok(());
        }
        address = address
            .checked_add(PAGE_BYTES)
            .ok_or(ManifestError::InvalidRange)?;
    }
}

/// Capture distinct 4-KiB page records required by the current bootstrap.
/// This is a bounded sample of code and static state plus full stack ranges,
/// NOT a complete kernel image section map or a root ready to install.
///
/// # Safety
/// Single QEMU bootstrap CPU, CPL0, IF=0, Sorveth kernel CR3 active.
/// The UEFI descriptor buffer and inherited lower-level mappings must remain
/// accessible and unchanged for the entire call.
#[cfg(target_arch = "x86_64")]
pub unsafe fn capture<const N: usize>(
    map: &MemoryMap<'_>,
    boot: &sorveth_abi::BootInfo,
    kernel_stack: (u64, u64),
) -> Result<Manifest<N>, ManifestError> {
    use core::arch::asm;
    let root = crate::root::kernel_root_physical().ok_or(ManifestError::WrongCpuContext)?;
    let active: u64;
    let flags: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if active & 0x000f_ffff_ffff_f000 != root || flags & (1 << 9) != 0 {
        return Err(ManifestError::WrongCpuContext);
    }

    let mut manifest = Manifest::<N>::new();
    for address in [
        capture::<N> as usize as u64,
        crate::supervisor_audit::verify_bootstrap_survival as usize as u64,
        crate::serial::write_line as usize as u64,
        crate::root::active as usize as u64,
    ] {
        record_one(&mut manifest, map, root, address, Kind::Code, false, true)?;
    }
    for address in crate::interrupts::survival_handler_addresses() {
        record_one(&mut manifest, map, root, address, Kind::Code, false, true)?;
    }
    record_range(
        &mut manifest,
        map,
        root,
        kernel_stack.0,
        kernel_stack.1 - kernel_stack.0,
        Kind::KernelStack,
        true,
    )?;
    let (worker, worker_end) = crate::fibers::survival_stack_bounds();
    record_range(
        &mut manifest,
        map,
        root,
        worker,
        worker_end - worker,
        Kind::WorkerStack,
        true,
    )?;
    let (faults, trap) = crate::tss::survival_stack_bounds();
    for (start, end) in faults {
        record_range(
            &mut manifest,
            map,
            root,
            start,
            end - start,
            Kind::FaultStack,
            true,
        )?;
    }
    if let Some((start, end)) = trap {
        record_range(
            &mut manifest,
            map,
            root,
            start,
            end - start,
            Kind::TrapStack,
            true,
        )?;
    }

    // CPU descriptor memory is required after a CR3 change; it belongs to
    // Sorveth's retained loader image, not to an unclaimed conventional frame.
    let mut idtr = [0u8; 10];
    let mut gdtr = [0u8; 10];
    asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
    asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&idtr[2..10]);
    let idt_start = u64::from_le_bytes(bytes);
    bytes.copy_from_slice(&gdtr[2..10]);
    let gdt_start = u64::from_le_bytes(bytes);
    let idt_len = u16::from_le_bytes([idtr[0], idtr[1]]) as u64 + 1;
    let gdt_len = u16::from_le_bytes([gdtr[0], gdtr[1]]) as u64 + 1;
    if !(16..=4096).contains(&idt_len) || !(24..=4096).contains(&gdt_len) {
        return Err(ManifestError::InvalidRange);
    }
    record_range(
        &mut manifest,
        map,
        root,
        idt_start,
        idt_len,
        Kind::CpuTable,
        true,
    )?;
    record_range(
        &mut manifest,
        map,
        root,
        gdt_start,
        gdt_len,
        Kind::CpuTable,
        true,
    )?;
    record_one(
        &mut manifest,
        map,
        root,
        crate::tss::survival_tss_address(),
        Kind::CpuTable,
        true,
        false,
    )?;

    let ledger = &crate::FRAME_POOL as *const _ as u64;
    record_range(
        &mut manifest,
        map,
        root,
        ledger,
        core::mem::size_of_val(&crate::FRAME_POOL) as u64,
        Kind::KernelState,
        true,
    )?;
    record_range(
        &mut manifest,
        map,
        root,
        boot as *const _ as u64,
        core::mem::size_of::<sorveth_abi::BootInfo>() as u64,
        Kind::BootHandoff,
        true,
    )?;
    record_range(
        &mut manifest,
        map,
        root,
        boot.memory_map_address,
        boot.memory_map_size,
        Kind::MemoryDescriptors,
        false,
    )?;
    if boot.framebuffer.is_usable() {
        record_one(
            &mut manifest,
            map,
            root,
            boot.framebuffer.address,
            Kind::FramebufferDevice,
            true,
            false,
        )?;
        let last = boot.framebuffer.address + boot.framebuffer.size_bytes - 1;
        record_one(
            &mut manifest,
            map,
            root,
            last,
            Kind::FramebufferDevice,
            true,
            false,
        )?;
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(kind: u32, base: u64, pages: u64) -> [u8; 48] {
        let mut data = [0u8; 48];
        data[0..4].copy_from_slice(&kind.to_le_bytes());
        data[8..16].copy_from_slice(&base.to_le_bytes());
        data[24..32].copy_from_slice(&pages.to_le_bytes());
        data
    }

    #[test]
    fn recognizes_loader_pages_but_not_unlisted_or_partial_ownership() {
        let mut data = [0u8; 96];
        data[..48].copy_from_slice(&descriptor(2, 0x1000, 3));
        data[48..].copy_from_slice(&descriptor(11, 0xa000, 2));
        let map = MemoryMap::from_bytes(&data, 48).unwrap();
        assert_eq!(uefi_type_of(&map, 0x2000), Ok(Some(2)));
        assert_eq!(uefi_type_of(&map, 0xa000), Ok(Some(11)));
        assert_eq!(uefi_type_of(&map, 0x9000), Ok(None));
        assert_eq!(uefi_type_of(&map, 0x1001), Err(ManifestError::InvalidRange));
        assert!(allowed_critical_type(2));
        assert!(!allowed_critical_type(7));
        assert!(!allowed_critical_type(11));
    }

    #[test]
    fn rejects_overlapping_descriptors_and_physical_aliases() {
        let mut data = [0u8; 96];
        data[..48].copy_from_slice(&descriptor(2, 0x1000, 3));
        data[48..].copy_from_slice(&descriptor(4, 0x2000, 2));
        let map = MemoryMap::from_bytes(&data, 48).unwrap();
        assert_eq!(
            uefi_type_of(&map, 0x2000),
            Err(ManifestError::ConflictingFirmwareTypes)
        );
        let mut manifest = Manifest::<2>::new();
        let first = Record {
            virtual_page: 0x1000,
            physical_page: 0x5000,
            uefi_type: Some(2),
            kind: Kind::Code,
            writable: false,
            executable: true,
        };
        manifest.push(first).unwrap();
        assert_eq!(manifest.push(first), Ok(()));
        assert_eq!(manifest.len(), 1);
        let mut alias = first;
        alias.virtual_page = 0x2000;
        assert_eq!(
            manifest.push(alias),
            Err(ManifestError::AliasedPhysicalBacking)
        );
        alias.physical_page = 0x6000;
        manifest.push(alias).unwrap();
        alias.virtual_page = 0x3000;
        alias.physical_page = 0x7000;
        assert_eq!(manifest.push(alias), Err(ManifestError::Full));
    }

    #[test]
    fn tracks_legacy_wx_without_claiming_it_secure() {
        let mut m = Manifest::<2>::new();
        m.push(Record {
            virtual_page: 0x1000,
            physical_page: 0x1000,
            uefi_type: Some(1),
            kind: Kind::Code,
            writable: true,
            executable: true,
        })
        .unwrap();
        assert_eq!(m.legacy_writable_executable(), 1);
        assert_eq!(m.unknown_device_pages(), 0);
    }
}
