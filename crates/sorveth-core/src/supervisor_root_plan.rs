//! M2-K.1e: compile the audited supervisor manifest into a bounded
//! mapping plan for pages outside the loaded PE image.
//!
//! This is planning only. It does not allocate page tables, change CR3, or
//! make the bounded manifest a complete kernel ownership database. PE image
//! pages continue to use the strict section policy in image_page_tables;
//! framebuffer mappings are deferred until cache attributes are specified.

use crate::{
    image_sections::{self, PagePolicy},
    supervisor_manifest::{Kind, Manifest, Record},
};
use sorveth_abi::BootInfo;

const PAGE: u64 = 4096;
const PHYSICAL_LIMIT: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidImage,
    InvalidAddress,
    UnclassifiedImagePage,
    NonIdentityImagePage,
    MissingBacking,
    InsufficientCurrentPermission,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub virtual_page: u64,
    pub physical_page: u64,
    pub kind: Kind,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan<const N: usize> {
    mappings: [Option<Mapping>; N],
    mapping_count: usize,
    image_records: usize,
    deferred_device_records: usize,
    private_window_records: usize,
}

impl<const N: usize> Plan<N> {
    const fn new() -> Self {
        Self {
            mappings: [None; N],
            mapping_count: 0,
            image_records: 0,
            deferred_device_records: 0,
            private_window_records: 0,
        }
    }

    pub const fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    pub const fn image_records(&self) -> usize {
        self.image_records
    }

    pub const fn deferred_device_records(&self) -> usize {
        self.deferred_device_records
    }

    pub const fn private_window_records(&self) -> usize {
        self.private_window_records
    }

    pub fn mapping(&self, index: usize) -> Option<Mapping> {
        if index < self.mapping_count {
            self.mappings[index]
        } else {
            None
        }
    }

    fn push(&mut self, mapping: Mapping) -> Result<(), Error> {
        for existing in self.mappings[..self.mapping_count].iter().flatten() {
            if existing.virtual_page == mapping.virtual_page {
                return if *existing == mapping {
                    Ok(())
                } else {
                    Err(Error::InvalidAddress)
                };
            }
            if existing.physical_page == mapping.physical_page {
                return Err(Error::InvalidAddress);
            }
        }
        if self.mapping_count == N {
            return Err(Error::Full);
        }
        self.mappings[self.mapping_count] = Some(mapping);
        self.mapping_count += 1;
        Ok(())
    }
}

fn is_canonical(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    if sign == 0 {
        upper == 0
    } else {
        upper == 0xffff
    }
}

fn image_permissions(policy: PagePolicy) -> Option<(bool, bool)> {
    match policy {
        PagePolicy::Code => Some((false, true)),
        PagePolicy::Writable => Some((true, false)),
        PagePolicy::Headers | PagePolicy::ReadOnly => Some((false, false)),
        PagePolicy::Unclassified => None,
    }
}

fn supervisor_permissions(kind: Kind) -> Option<(bool, bool)> {
    match kind {
        Kind::FramebufferDevice => None,
        Kind::Code => Some((false, true)),
        Kind::MemoryDescriptors | Kind::BootHandoff => Some((false, false)),
        Kind::KernelStack
        | Kind::WorkerStack
        | Kind::FaultStack
        | Kind::TrapStack
        | Kind::CpuTable
        | Kind::KernelPaging
        | Kind::KernelState => Some((true, false)),
    }
}

/// Turn the bounded physical-backing manifest into explicit mappings for
/// each audited non-image supervisor page. Image records are checked against
/// the PE permission plan and left to the existing image-table builder.
///
/// The output is suitable as input to a later independent hierarchy builder,
/// but is not itself a complete supervisor root: manifest coverage remains
/// deliberately bounded, device pages are omitted, and dynamic mappings are
/// not represented.
///
/// # Safety
/// The caller must first complete the loaded-image backing audit and capture
/// the manifest while the current supervisor root and UEFI descriptor bytes
/// remain stable.
pub unsafe fn compile<const N: usize>(
    manifest: &Manifest<N>,
    boot: &BootInfo,
    image_header: &[u8],
) -> Result<Plan<N>, Error> {
    if !boot.is_valid()
        || boot.image_size == 0
        || boot.image_size > 32 * 1024 * 1024
        || boot.image_size & (PAGE - 1) != 0
        || boot.image_base & (PAGE - 1) != 0
    {
        return Err(Error::InvalidImage);
    }
    let image_end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
    if !is_canonical(boot.image_base) || !is_canonical(image_end - 1) {
        return Err(Error::InvalidImage);
    }
    let layout =
        image_sections::parse(image_header, boot.image_size).map_err(|_| Error::InvalidImage)?;
    let mut plan = Plan::new();

    for index in 0..manifest.len() {
        let record: Record = manifest.get(index).ok_or(Error::InvalidAddress)?;
        if record.virtual_page == 0
            || record.virtual_page & (PAGE - 1) != 0
            || !is_canonical(record.virtual_page)
            || record.physical_page & (PAGE - 1) != 0
            || record.physical_page >= PHYSICAL_LIMIT
        {
            return Err(Error::InvalidAddress);
        }

        if record.kind == Kind::FramebufferDevice {
            // The manifest contains endpoint samples only. Do not turn those
            // into RAM mappings or guess the required PAT/cache policy.
            plan.deferred_device_records += 1;
            continue;
        }

        let page_end = record
            .virtual_page
            .checked_add(PAGE)
            .ok_or(Error::InvalidAddress)?;
        let (writable, executable) = if record.virtual_page >= boot.image_base
            && page_end <= image_end
        {
            if record.physical_page != record.virtual_page {
                return Err(Error::NonIdentityImagePage);
            }
            let policy = layout.classify(record.virtual_page - boot.image_base);
            let permissions = image_permissions(policy).ok_or(Error::UnclassifiedImagePage)?;
            plan.image_records += 1;
            permissions
        } else if record.virtual_page < image_end && page_end > boot.image_base {
            // A page straddling the PE boundary cannot be represented by
            // either the image subtree or the external mapping plan.
            return Err(Error::InvalidAddress);
        } else {
            let permissions = supervisor_permissions(record.kind).ok_or(Error::InvalidAddress)?;
            if record.uefi_type.is_none_or(|kind| !(1..=4).contains(&kind)) {
                return Err(Error::MissingBacking);
            }
            permissions
        };

        // The new root may remove rights, but it cannot promise a right that
        // the current audited mapping did not have.
        if writable && !record.writable || executable && !record.executable {
            return Err(Error::InsufficientCurrentPermission);
        }
        if writable && executable {
            return Err(Error::InvalidAddress);
        }

        if record.virtual_page < boot.image_base || page_end > image_end {
            plan.push(Mapping {
                virtual_page: record.virtual_page,
                physical_page: record.physical_page,
                kind: record.kind,
                writable,
                executable,
            })?;
        }
    }

    Ok(plan)
}

/// Add the audited private high-half leaves to the candidate plan. The
/// page-table self-alias is admitted only when the PE image policy already
/// permits the same writable/NX access to that physical page. Other leaves
/// must be allocator-owned pages absent from the physical-backing manifest.
///
/// This remains a plan only; callers must not install it as a complete root.
pub fn include_private_window<const N: usize, const M: usize>(
    plan: &mut Plan<N>,
    private: &crate::root::PrivateWindowEvidence,
    manifest: &Manifest<M>,
    boot: &BootInfo,
    image_header: &[u8],
) -> Result<(), Error> {
    let image_end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
    let layout =
        image_sections::parse(image_header, boot.image_size).map_err(|_| Error::InvalidImage)?;
    let alias_page = private.base.checked_add(510 * PAGE);

    for index in 0..private.mapping_count {
        let mapping = private.mappings[index].ok_or(Error::InvalidAddress)?;
        if mapping.virtual_page == 0
            || mapping.virtual_page & (PAGE - 1) != 0
            || !is_canonical(mapping.virtual_page)
            || mapping.physical_page & (PAGE - 1) != 0
            || mapping.physical_page >= PHYSICAL_LIMIT
            || mapping.writable && mapping.executable
            || (mapping.virtual_page >= boot.image_base && mapping.virtual_page < image_end)
        {
            return Err(Error::InvalidAddress);
        }

        let page_end = mapping
            .physical_page
            .checked_add(PAGE)
            .ok_or(Error::InvalidAddress)?;
        if mapping.physical_page >= boot.image_base && page_end <= image_end {
            let policy = layout.classify(mapping.physical_page - boot.image_base);
            let (image_writable, image_executable) =
                image_permissions(policy).ok_or(Error::UnclassifiedImagePage)?;
            if mapping.writable && !image_writable || mapping.executable && !image_executable {
                return Err(Error::InsufficientCurrentPermission);
            }
        } else {
            for record_index in 0..manifest.len() {
                let record = manifest.get(record_index).ok_or(Error::InvalidAddress)?;
                if record.physical_page == mapping.physical_page {
                    return Err(Error::InvalidAddress);
                }
            }
        }

        let kind = if Some(mapping.virtual_page) == alias_page {
            Kind::KernelPaging
        } else {
            Kind::KernelState
        };
        plan.push(Mapping {
            virtual_page: mapping.virtual_page,
            physical_page: mapping.physical_page,
            kind,
            writable: mapping.writable,
            executable: mapping.executable,
        })?;
        plan.private_window_records += 1;
    }
    Ok(())
}
