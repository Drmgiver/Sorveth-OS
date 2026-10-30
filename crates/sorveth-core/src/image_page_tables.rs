//! M2-K.1d: build and audit a separate PE-image mapping subtree.
//!
//! This is an *inactive candidate*, never installed into CR3. It maps only
//! classified, identity-backed pages of Sorveth's retained UEFI PE image,
//! using separate, statically retained (not firmware lower-level) page
//! tables. A later milestone must supply all non-image supervisor regions,
//! proper lifetime ownership, and an independently tested CR3 transition.

use crate::{image_sections, supervisor_audit, supervisor_manifest};
use sorveth_abi::BootInfo;
use sorveth_memory::MemoryMap;

#[cfg(target_arch = "x86_64")]
use core::{ptr, sync::atomic::{AtomicBool, Ordering}};

const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const NX: u64 = 1 << 63;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
// A <=32-MiB PE image may touch at most 17 different 2-MiB slots if
// the first page is not aligned on a 2-MiB boundary.
const MAX_PT: usize = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongCpuContext,
    InvalidImage,
    CrossesGigabyte,
    UntrustedTableFrame,
    TooManyPageTables,
    AlreadyBuilt,
    ValidationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub mapped_code: u64,
    pub mapped_readonly: u64,
    pub mapped_writable: u64,
    pub holes_unmapped: u64,
    pub table_frames: usize,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct Table([u64; 512]);

#[cfg(target_arch = "x86_64")]
static mut IMAGE_ROOT: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut IMAGE_PDPT: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut IMAGE_PD: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut IMAGE_PTS: [Table; MAX_PT] = [const { Table([0; 512]) }; MAX_PT];
#[cfg(target_arch = "x86_64")]
static BUILT: AtomicBool = AtomicBool::new(false);

fn leaf_flags(policy: image_sections::PagePolicy) -> Option<u64> {
    match policy {
        image_sections::PagePolicy::Code => Some(PRESENT),
        image_sections::PagePolicy::Headers | image_sections::PagePolicy::ReadOnly => {
            Some(PRESENT | NX)
        }
        image_sections::PagePolicy::Writable => Some(PRESENT | WRITE | NX),
        image_sections::PagePolicy::Unclassified => None,
    }
}

fn same_one_gib_region(start: u64, image_size: u64) -> bool {
    if image_size < PAGE || image_size & (PAGE - 1) != 0 {
        return false;
    }
    start.checked_add(image_size - 1)
        .is_some_and(|end| start >> 30 == end >> 30)
}

/// Compute a candidate entry count without trusting the memory backing.
pub fn required_pt_pages(start: u64, bytes: u64) -> Result<usize, Error> {
    if start == 0 || start & (PAGE - 1) != 0 || !same_one_gib_region(start, bytes) {
        return Err(Error::CrossesGigabyte);
    }
    let last = start.checked_add(bytes - 1).ok_or(Error::InvalidImage)?;
    let first_index = start >> 21;
    let last_index = last >> 21;
    let count = (last_index - first_index + 1) as usize;
    if count > MAX_PT {
        return Err(Error::TooManyPageTables);
    }
    Ok(count)
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_candidate_entry(
    address: u64,
    root: u64,
    pdpt: u64,
    pd: u64,
    pts: u64,
    used: usize,
) -> Option<u64> {
    let frame = address & !(PAGE - 1);
    if address & 7 != 0 || !(
        frame == root || frame == pdpt || frame == pd ||
        (frame >= pts && frame < pts + used as u64 * PAGE
            && (frame - pts) & (PAGE - 1) == 0)
    ) {
        return None;
    }
    crate::root::with_physical_window(frame, |window| {
        ptr::read_volatile(window.add((address - frame) as usize) as *const u64)
    }).ok()
}

/// Construct *only* the classified loaded-image subtree into owned, inert
/// static table frames, then walk the new hierarchy through the restricted
/// supervisor window and compare every resulting 4-KiB mapping.
///
/// # Safety
/// Must run at CPL0 on Sorveth kernel CR3, single CPU with IF=0, after both
/// the whole-image backing check and strict PE parsing have succeeded.
/// Loaded PE image and UEFI descriptors remain immutable and identity-backed.
#[cfg(target_arch = "x86_64")]
pub unsafe fn build_and_verify(
    boot: &BootInfo,
    map: &MemoryMap<'_>,
) -> Result<Evidence, Error> {
    if !boot.is_valid() || BUILT.swap(true, Ordering::AcqRel) {
        return Err(Error::AlreadyBuilt);
    }
    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if flags & (1 << 9) != 0 ||
        crate::root::kernel_root_physical() != Some(active & ADDRESS_MASK)
    {
        return Err(Error::WrongCpuContext);
    }
    supervisor_manifest::verify_loaded_image_extent(map, boot)
        .map_err(|_| Error::InvalidImage)?;
    let bytes = core::slice::from_raw_parts(
        boot.image_base as *const u8,
        image_sections::HEADER_LIMIT,
    );
    let layout = image_sections::parse(bytes, boot.image_size)
        .map_err(|_| Error::InvalidImage)?;
    let needed = required_pt_pages(boot.image_base, boot.image_size)?;

    let root = ptr::addr_of_mut!(IMAGE_ROOT) as u64;
    let pdpt = ptr::addr_of_mut!(IMAGE_PDPT) as u64;
    let pd = ptr::addr_of_mut!(IMAGE_PD) as u64;
    let pts = ptr::addr_of_mut!(IMAGE_PTS) as u64;
    // All table frames lie in the previously verified UEFI PE image, so
    // their virtual addresses are trusted as physical identity addresses
    // only for this bootstrap. Explicitly check their current mappings.
    for frame in [root, pdpt, pd] {
        if frame & (PAGE - 1) != 0 || !crate::root::identity_mapped(frame) {
            return Err(Error::UntrustedTableFrame);
        }
    }
    for index in 0..needed {
        let frame = pts + index as u64 * PAGE;
        if !crate::root::identity_mapped(frame) {
            return Err(Error::UntrustedTableFrame);
        }
    }

    ptr::write_bytes(root as *mut u8, 0, PAGE as usize);
    ptr::write_bytes(pdpt as *mut u8, 0, PAGE as usize);
    ptr::write_bytes(pd as *mut u8, 0, PAGE as usize);
    for index in 0..needed {
        ptr::write_bytes((pts + index as u64 * PAGE) as *mut u8, 0, PAGE as usize);
    }
    let pml4_slot = ((boot.image_base >> 39) & 511) as usize;
    let pdpt_slot = ((boot.image_base >> 30) & 511) as usize;
    ptr::write_volatile((root as *mut u64).add(pml4_slot), pdpt | PRESENT | WRITE);
    ptr::write_volatile((pdpt as *mut u64).add(pdpt_slot), pd | PRESENT | WRITE);

    let mut evidence = Evidence {
        mapped_code: 0,
        mapped_readonly: 0,
        mapped_writable: 0,
        holes_unmapped: 0,
        table_frames: needed + 3,
    };
    let end = boot.image_base.checked_add(boot.image_size).ok_or(Error::InvalidImage)?;
    let mut address = boot.image_base;
    let mut assigned = 0usize;
    while address < end {
        let pd_slot = ((address >> 21) & 511) as usize;
        let pt_slot = ((address >> 12) & 511) as usize;
        let current = ptr::read_volatile((pd as *const u64).add(pd_slot));
        let pt_addr = if current == 0 {
            if assigned >= needed {
                return Err(Error::TooManyPageTables);
            }
            let frame = pts + assigned as u64 * PAGE;
            ptr::write_volatile((pd as *mut u64).add(pd_slot), frame | PRESENT | WRITE);
            assigned += 1;
            frame
        } else {
            current & ADDRESS_MASK
        };
        if let Some(bits) = leaf_flags(layout.classify(address - boot.image_base)) {
            ptr::write_volatile(
                (pt_addr as *mut u64).add(pt_slot),
                address | bits,
            );
            match layout.classify(address - boot.image_base) {
                image_sections::PagePolicy::Code => evidence.mapped_code += 1,
                image_sections::PagePolicy::Writable => evidence.mapped_writable += 1,
                _ => evidence.mapped_readonly += 1,
            }
        } else {
            evidence.holes_unmapped += 1;
        }
        address += PAGE;
    }
    if assigned != needed || evidence.mapped_code == 0 || evidence.mapped_writable == 0 {
        return Err(Error::ValidationFailed);
    }
    // Verify through the newly created independent page-table ancestry,
    // *not* via OVMF's lower-level entries or a copied firmware PML4.
    let mut address = boot.image_base;
    while address < end {
        let expected = leaf_flags(layout.classify(address - boot.image_base));
        let observed = supervisor_audit::walk(root, address, |entry| {
            read_candidate_entry(entry, root, pdpt, pd, pts, needed)
        });
        match (expected, observed) {
            (None, Err(supervisor_audit::AuditError::MissingMapping)) => {}
            (Some(bits), Ok(mapped)) if mapped.physical_address == address
                && !mapped.user_accessible
                && mapped.leaf_size == PAGE
                && mapped.writable == (bits & WRITE != 0)
                && mapped.executable == (bits & NX == 0) => {}
            _ => return Err(Error::ValidationFailed),
        }
        address += PAGE;
    }
    // Unmapped image tail: no accidental shared firmware PDPT linkage.
    if supervisor_audit::walk(root, end, |entry| {
        read_candidate_entry(entry, root, pdpt, pd, pts, needed)
    }).is_ok() {
        return Err(Error::ValidationFailed);
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_exact_wx_split_and_rejects_unclassified() {
        assert_eq!(leaf_flags(image_sections::PagePolicy::Code), Some(1));
        assert_eq!(leaf_flags(image_sections::PagePolicy::Writable), Some(1 | 2 | NX));
        assert_eq!(leaf_flags(image_sections::PagePolicy::ReadOnly), Some(1 | NX));
        assert_eq!(leaf_flags(image_sections::PagePolicy::Headers), Some(1 | NX));
        assert_eq!(leaf_flags(image_sections::PagePolicy::Unclassified), None);
    }

    #[test]
    fn limits_candidate_to_bounded_single_one_gib_region() {
        assert_eq!(required_pt_pages(0x20_0000, 0x10_0000), Ok(1));
        assert_eq!(required_pt_pages(0x20_1000, 0x20_0000), Ok(2));
        assert_eq!(required_pt_pages(0x3fff_f000, 0x2000), Err(Error::CrossesGigabyte));
        assert_eq!(required_pt_pages(0x1000, 0), Err(Error::CrossesGigabyte));
        assert_eq!(required_pt_pages(0x1001, 4096), Err(Error::CrossesGigabyte));
        assert_eq!(required_pt_pages(0x1000, u64::MAX), Err(Error::CrossesGigabyte));
    }
}
