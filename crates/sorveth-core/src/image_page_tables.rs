//! M2-K.1d: build and audit a separate PE-image mapping subtree.
//!
//! This is an *inactive candidate*, never installed into CR3. It maps only
//! classified, identity-backed pages of Sorveth's retained UEFI PE image,
//! using separate, statically retained (not firmware lower-level) page
//! tables. A later milestone must supply all non-image supervisor regions,
//! proper lifetime ownership, and an independently tested CR3 transition.

use crate::{
    image_sections, supervisor_audit, supervisor_manifest,
    supervisor_root_plan::{Mapping, Plan},
};
use sorveth_abi::BootInfo;
use sorveth_memory::MemoryMap;

#[cfg(target_arch = "x86_64")]
use core::{
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const LARGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const SURVIVAL_WINDOW_WORD: u64 = 0x4b31_6c57_494e_21;
// The first 128 PT frames cover the PE image and the bounded framebuffer.
// The rest form a bounded pool for planner mappings at arbitrary addresses.
const MAX_PT: usize = 768;
const MAPPING_POOL_START: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongCpuContext,
    InvalidImage,
    CrossesGigabyte,
    UntrustedTableFrame,
    TooManyPageTables,
    AlreadyBuilt,
    ValidationFailed,
    UnsupportedPlan,
    WindowCollision,
    InvalidFramebuffer,
    UnsupportedCachePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub mapped_code: u64,
    pub mapped_readonly: u64,
    pub mapped_writable: u64,
    pub holes_unmapped: u64,
    pub table_frames: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateEvidence {
    pub planner_mappings: usize,
    pub framebuffer_pages: u64,
    pub survival_records_verified: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateTableEvidence {
    pub unique_table_frames: usize,
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
static mut WINDOW_PDPT: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut WINDOW_PD: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut WINDOW_PT: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut FRAMEBUFFER_PDPT: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut FRAMEBUFFER_PD: Table = Table([0; 512]);
#[cfg(target_arch = "x86_64")]
static BUILT: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static WINDOW_BUILT: AtomicBool = AtomicBool::new(false);

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
    start
        .checked_add(image_size - 1)
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
    if address & 7 != 0
        || !(frame == root
            || frame == pdpt
            || frame == pd
            || (frame >= pts
                && frame < pts + used as u64 * PAGE
                && (frame - pts) & (PAGE - 1) == 0))
    {
        return None;
    }
    crate::root::with_physical_window(frame, |window| {
        ptr::read_volatile(window.add((address - frame) as usize) as *const u64)
    })
    .ok()
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
pub unsafe fn build_and_verify(boot: &BootInfo, map: &MemoryMap<'_>) -> Result<Evidence, Error> {
    if !boot.is_valid() || BUILT.swap(true, Ordering::AcqRel) {
        return Err(Error::AlreadyBuilt);
    }
    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if flags & (1 << 9) != 0 || crate::root::kernel_root_physical() != Some(active & ADDRESS_MASK) {
        return Err(Error::WrongCpuContext);
    }
    supervisor_manifest::verify_loaded_image_extent(map, boot).map_err(|_| Error::InvalidImage)?;
    let bytes =
        core::slice::from_raw_parts(boot.image_base as *const u8, image_sections::HEADER_LIMIT);
    let layout = image_sections::parse(bytes, boot.image_size).map_err(|_| Error::InvalidImage)?;
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
    let end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
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
            ptr::write_volatile((pt_addr as *mut u64).add(pt_slot), address | bits);
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
            (Some(bits), Ok(mapped))
                if mapped.physical_address == address
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
    })
    .is_ok()
    {
        return Err(Error::ValidationFailed);
    }
    Ok(evidence)
}

/// Read an entry from either the image candidate hierarchy or the newly
/// constructed private-window subtree, using only explicitly owned table
/// frames through the active root's restricted frame window.
#[cfg(target_arch = "x86_64")]
unsafe fn read_extended_candidate_entry(
    address: u64,
    root: u64,
    pdpt: u64,
    pd: u64,
    pts: u64,
    used: usize,
    window_pdpt: u64,
    window_pd: u64,
    window_pt: u64,
) -> Option<u64> {
    let frame = address & !(PAGE - 1);
    if address & 7 != 0
        || !(frame == root
            || frame == pdpt
            || frame == pd
            || (frame >= pts
                && frame < pts + used as u64 * PAGE
                && (frame - pts) & (PAGE - 1) == 0)
            || frame == window_pdpt
            || frame == window_pd
            || frame == window_pt
            || frame == ptr::addr_of!(FRAMEBUFFER_PDPT) as u64
            || frame == ptr::addr_of!(FRAMEBUFFER_PD) as u64)
    {
        return None;
    }
    crate::root::with_physical_window(frame, |window| {
        ptr::read_volatile(window.add((address - frame) as usize) as *const u64)
    })
    .ok()
}

#[cfg(target_arch = "x86_64")]
struct MappingTablePool<'a> {
    next: usize,
    start: usize,
    frames_used: usize,
    boot: &'a BootInfo,
    layout: &'a image_sections::Layout,
    pts: u64,
}

#[cfg(target_arch = "x86_64")]
fn is_in_private_window(mapping: Mapping, pml4: usize, pdpt: usize, pd: usize) -> bool {
    ((mapping.virtual_page >> 39) & 511) as usize == pml4
        && ((mapping.virtual_page >> 30) & 511) as usize == pdpt
        && ((mapping.virtual_page >> 21) & 511) as usize == pd
}

#[cfg(target_arch = "x86_64")]
unsafe fn allocate_mapping_table(pool: &mut MappingTablePool<'_>) -> Result<u64, Error> {
    if pool.next <= pool.start {
        return Err(Error::TooManyPageTables);
    }
    pool.next -= 1;
    let frame = pool.pts + pool.next as u64 * PAGE;
    let image_end = pool
        .boot
        .image_base
        .checked_add(pool.boot.image_size)
        .ok_or(Error::InvalidImage)?;
    if frame < pool.boot.image_base
        || frame.checked_add(PAGE).is_none_or(|end| end > image_end)
        || !crate::root::identity_mapped(frame)
        || pool.layout.classify(frame - pool.boot.image_base)
            != image_sections::PagePolicy::Writable
    {
        return Err(Error::UntrustedTableFrame);
    }
    ptr::write_bytes(frame as *mut u8, 0, PAGE as usize);
    pool.frames_used += 1;
    Ok(frame)
}

#[cfg(target_arch = "x86_64")]
fn is_candidate_table(frame: u64, root: u64, pts: u64) -> bool {
    frame == root
        || frame == ptr::addr_of!(IMAGE_PDPT) as u64
        || frame == ptr::addr_of!(IMAGE_PD) as u64
        || frame == ptr::addr_of!(WINDOW_PDPT) as u64
        || frame == ptr::addr_of!(WINDOW_PD) as u64
        || frame == ptr::addr_of!(WINDOW_PT) as u64
        || frame == ptr::addr_of!(FRAMEBUFFER_PDPT) as u64
        || frame == ptr::addr_of!(FRAMEBUFFER_PD) as u64
        || (frame >= pts + MAPPING_POOL_START as u64 * PAGE
            && frame < pts + MAX_PT as u64 * PAGE
            && (frame - pts) & (PAGE - 1) == 0)
        || (frame >= pts
            && frame < pts + MAPPING_POOL_START as u64 * PAGE
            && (frame - pts) & (PAGE - 1) == 0)
}

/// Read one entry from the independently owned candidate hierarchy, or from
/// one of the two Sorveth-owned process roots. This is used after the
/// independent CR3 switch, where the transitional firmware identity-map
/// reader is intentionally unavailable.
#[cfg(all(target_arch = "x86_64", feature = "qemu-independent-root"))]
pub(crate) unsafe fn read_candidate_table_entry(address: u64) -> Option<u64> {
    let page = address & !(PAGE - 1);
    if page == 0 || address & 7 != 0 || address - page > PAGE - 8 {
        return None;
    }
    let root = ptr::addr_of!(IMAGE_ROOT) as u64;
    let pts = ptr::addr_of!(IMAGE_PTS) as u64;
    if !crate::process_roots::is_owned_process_root_frame(page)
        && !is_candidate_table(page, root, pts)
    {
        return None;
    }
    crate::root::with_physical_window(page, |window| {
        ptr::read_volatile(window.add((address - page) as usize).cast::<u64>())
    })
    .ok()
}

#[cfg(target_arch = "x86_64")]
unsafe fn ensure_candidate_child(
    parent: u64,
    slot: usize,
    root: u64,
    pool: &mut MappingTablePool<'_>,
) -> Result<u64, Error> {
    let entry = ptr::read_volatile((parent as *const u64).add(slot));
    if entry & PRESENT == 0 {
        let child = allocate_mapping_table(pool)?;
        ptr::write_volatile((parent as *mut u64).add(slot), child | PRESENT | WRITE);
        return Ok(child);
    }
    if entry & LARGE != 0 {
        return Err(Error::WindowCollision);
    }
    let child = entry & ADDRESS_MASK;
    if !is_candidate_table(child, root, pool.pts) || !crate::root::identity_mapped(child) {
        return Err(Error::UntrustedTableFrame);
    }
    Ok(child)
}

#[cfg(target_arch = "x86_64")]
unsafe fn map_additional_planner_mapping(
    root: u64,
    mapping: Mapping,
    pool: &mut MappingTablePool<'_>,
) -> Result<(), Error> {
    let address = mapping.virtual_page;
    if address == 0 || address & (PAGE - 1) != 0 || mapping.physical_page & (PAGE - 1) != 0 {
        return Err(Error::UnsupportedPlan);
    }
    let pml4_slot = ((address >> 39) & 511) as usize;
    let pdpt_slot = ((address >> 30) & 511) as usize;
    let pd_slot = ((address >> 21) & 511) as usize;
    let pt_slot = ((address >> 12) & 511) as usize;
    let pdpt = ensure_candidate_child(root, pml4_slot, root, pool)?;
    let pd = ensure_candidate_child(pdpt, pdpt_slot, root, pool)?;
    let pt = ensure_candidate_child(pd, pd_slot, root, pool)?;
    if ptr::read_volatile((pt as *const u64).add(pt_slot)) != 0 {
        return Err(Error::WindowCollision);
    }
    let mut leaf = mapping.physical_page | PRESENT;
    if mapping.writable {
        leaf |= WRITE;
    }
    if !mapping.executable {
        leaf |= NX;
    }
    ptr::write_volatile((pt as *mut u64).add(pt_slot), leaf);
    Ok(())
}

/// Extend the PE candidate with the private window, framebuffer, and every
/// other mapping in the verified supervisor plan. Additional hierarchy nodes
/// come only from the writable PE-resident table pool. The PT self-alias is
/// rebound to this candidate's own PT frame.
///
/// Every planned leaf is walked through the restricted physical-frame reader;
/// this only mutates inactive tables and never loads them into CR3.
///
/// # Safety
/// Single CPU on the active Sorveth kernel root, IF=0, after the PE-only
/// candidate and supervisor mapping plan have both been verified.
#[cfg(target_arch = "x86_64")]
pub unsafe fn extend_and_verify_survival_plan<const N: usize, const M: usize>(
    boot: &BootInfo,
    map: &MemoryMap<'_>,
    plan: &Plan<N>,
    manifest: &supervisor_manifest::Manifest<M>,
) -> Result<CandidateEvidence, Error> {
    if !BUILT.load(Ordering::Acquire)
        || WINDOW_BUILT.swap(true, Ordering::AcqRel)
        || !boot.is_valid()
        || plan.private_window_records() == 0
        || plan.private_window_records() > plan.mapping_count()
    {
        return Err(Error::UnsupportedPlan);
    }

    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    let root = ptr::addr_of_mut!(IMAGE_ROOT) as u64;
    if flags & (1 << 9) != 0
        || crate::root::kernel_root_physical() != Some(active & ADDRESS_MASK)
        || root == (active & ADDRESS_MASK)
    {
        return Err(Error::WrongCpuContext);
    }

    let alias = (0..plan.mapping_count())
        .filter_map(|index| plan.mapping(index))
        .find(|mapping| {
            mapping.kind == crate::supervisor_manifest::Kind::KernelPaging
                && (mapping.virtual_page >> 12) & 511 == 510
        })
        .ok_or(Error::UnsupportedPlan)?;
    let window_base = alias
        .virtual_page
        .checked_sub(510 * PAGE)
        .ok_or(Error::UnsupportedPlan)?;
    let pml4_slot = ((window_base >> 39) & 511) as usize;
    let pdpt_slot = ((window_base >> 30) & 511) as usize;
    let pd_slot = ((window_base >> 21) & 511) as usize;
    let image_slot = ((boot.image_base >> 39) & 511) as usize;
    if pml4_slot == image_slot || ptr::read_volatile((root as *const u64).add(pml4_slot)) != 0 {
        return Err(Error::WindowCollision);
    }

    let window_pdpt = ptr::addr_of_mut!(WINDOW_PDPT) as u64;
    let window_pd = ptr::addr_of_mut!(WINDOW_PD) as u64;
    let window_pt = ptr::addr_of_mut!(WINDOW_PT) as u64;
    let image_end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
    let header =
        core::slice::from_raw_parts(boot.image_base as *const u8, image_sections::HEADER_LIMIT);
    let layout = image_sections::parse(header, boot.image_size).map_err(|_| Error::InvalidImage)?;
    for frame in [window_pdpt, window_pd, window_pt] {
        if frame & (PAGE - 1) != 0
            || frame < boot.image_base
            || frame.checked_add(PAGE).is_none_or(|end| end > image_end)
            || !crate::root::identity_mapped(frame)
            || layout.classify(frame - boot.image_base) != image_sections::PagePolicy::Writable
        {
            return Err(Error::UntrustedTableFrame);
        }
    }

    let mut expected = [0u64; 512];
    for index in 0..plan.mapping_count() {
        let mapping: Mapping = plan.mapping(index).ok_or(Error::UnsupportedPlan)?;
        if !is_in_private_window(mapping, pml4_slot, pdpt_slot, pd_slot) {
            continue;
        }
        let slot = ((mapping.virtual_page >> 12) & 511) as usize;
        if expected[slot] != 0 {
            return Err(Error::WindowCollision);
        }
        let physical = if mapping.virtual_page == alias.virtual_page {
            window_pt
        } else {
            mapping.physical_page
        };
        let mut entry = physical | PRESENT;
        if mapping.writable {
            entry |= WRITE;
        }
        if !mapping.executable {
            entry |= NX;
        }
        expected[slot] = entry;
    }

    ptr::write_bytes(window_pdpt as *mut u8, 0, PAGE as usize);
    ptr::write_bytes(window_pd as *mut u8, 0, PAGE as usize);
    ptr::write_bytes(window_pt as *mut u8, 0, PAGE as usize);
    ptr::write_volatile(
        (window_pdpt as *mut u64).add(pdpt_slot),
        window_pd | PRESENT | WRITE,
    );
    ptr::write_volatile(
        (window_pd as *mut u64).add(pd_slot),
        window_pt | PRESENT | WRITE,
    );
    for (slot, entry) in expected.iter().copied().enumerate() {
        if entry != 0 {
            ptr::write_volatile((window_pt as *mut u64).add(slot), entry);
        }
    }
    // Publish the new branch only after every child entry is complete.
    ptr::write_volatile(
        (root as *mut u64).add(pml4_slot),
        window_pdpt | PRESENT | WRITE,
    );

    let framebuffer_pages = build_and_verify_framebuffer(boot, map, plan, root, pml4_slot)?;
    let pts = ptr::addr_of!(IMAGE_PTS) as u64;
    let mut pool = MappingTablePool {
        next: MAX_PT,
        start: MAPPING_POOL_START,
        frames_used: 0,
        boot,
        layout: &layout,
        pts,
    };
    for index in 0..plan.mapping_count() {
        let mapping = plan.mapping(index).ok_or(Error::UnsupportedPlan)?;
        if !is_in_private_window(mapping, pml4_slot, pdpt_slot, pd_slot) {
            map_additional_planner_mapping(root, mapping, &mut pool)?;
        }
    }
    let mut verified = 0usize;
    for index in 0..plan.mapping_count() {
        let mapping = plan.mapping(index).ok_or(Error::UnsupportedPlan)?;
        let physical = if mapping.virtual_page == alias.virtual_page {
            window_pt
        } else {
            mapping.physical_page
        };
        let observed = supervisor_audit::walk(root, mapping.virtual_page, |entry| {
            read_extended_candidate_entry(
                entry,
                root,
                ptr::addr_of!(IMAGE_PDPT) as u64,
                ptr::addr_of!(IMAGE_PD) as u64,
                pts,
                MAX_PT,
                window_pdpt,
                window_pd,
                window_pt,
            )
        })
        .map_err(|_| Error::ValidationFailed)?;
        if observed.physical_address != physical
            || observed.user_accessible
            || observed.leaf_size != PAGE
            || observed.writable != mapping.writable
            || observed.executable != mapping.executable
        {
            return Err(Error::ValidationFailed);
        }
        verified += 1;
    }

    for slot in [1u64, 511] {
        let address = window_base + slot * PAGE;
        if supervisor_audit::walk(root, address, |entry| {
            read_extended_candidate_entry(
                entry,
                root,
                ptr::addr_of!(IMAGE_PDPT) as u64,
                ptr::addr_of!(IMAGE_PD) as u64,
                pts,
                MAX_PT,
                window_pdpt,
                window_pd,
                window_pt,
            )
        })
        .is_ok()
        {
            return Err(Error::ValidationFailed);
        }
    }
    let image_end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
    let framebuffer = plan.framebuffer();
    let mut survival_records_verified = 0usize;
    for index in 0..manifest.len() {
        let record = manifest.get(index).ok_or(Error::ValidationFailed)?;
        let (physical, writable, executable) =
            if record.kind == supervisor_manifest::Kind::FramebufferDevice {
                let fb = framebuffer.ok_or(Error::InvalidFramebuffer)?;
                let fb_end = fb
                    .virtual_start
                    .checked_add(fb.pages * PAGE)
                    .ok_or(Error::InvalidFramebuffer)?;
                if record.virtual_page < fb.virtual_start || record.virtual_page >= fb_end {
                    return Err(Error::InvalidFramebuffer);
                }
                (record.physical_page, true, false)
            } else if record.virtual_page >= boot.image_base && record.virtual_page < image_end {
                let bits = leaf_flags(layout.classify(record.virtual_page - boot.image_base))
                    .ok_or(Error::ValidationFailed)?;
                (record.physical_page, bits & WRITE != 0, bits & NX == 0)
            } else {
                let mapping = (0..plan.mapping_count())
                    .filter_map(|mapping_index| plan.mapping(mapping_index))
                    .find(|mapping| mapping.virtual_page == record.virtual_page)
                    .ok_or(Error::ValidationFailed)?;
                (mapping.physical_page, mapping.writable, mapping.executable)
            };
        if physical != record.physical_page {
            return Err(Error::ValidationFailed);
        }
        let observed = supervisor_audit::walk(root, record.virtual_page, |entry| {
            read_extended_candidate_entry(
                entry,
                root,
                ptr::addr_of!(IMAGE_PDPT) as u64,
                ptr::addr_of!(IMAGE_PD) as u64,
                pts,
                MAX_PT,
                window_pdpt,
                window_pd,
                window_pt,
            )
        })
        .map_err(|_| Error::ValidationFailed)?;
        if observed.physical_address != physical
            || observed.user_accessible
            || observed.leaf_size != PAGE
            || observed.writable != writable
            || observed.executable != executable
        {
            return Err(Error::ValidationFailed);
        }
        survival_records_verified += 1;
    }
    Ok(CandidateEvidence {
        planner_mappings: verified,
        framebuffer_pages,
        survival_records_verified,
    })
}

#[cfg(target_arch = "x86_64")]
unsafe fn audit_candidate_table(
    frame: u64,
    level: u8,
    image_base: u64,
    image_end: u64,
    layout: &image_sections::Layout,
    map: &MemoryMap<'_>,
    root: u64,
    pts: u64,
    window_pdpt: u64,
    window_pd: u64,
    window_pt: u64,
    seen: &mut [u64; MAX_PT + 16],
    count: &mut usize,
) -> Result<(), Error> {
    if !(1..=4).contains(&level)
        || !is_candidate_table(frame, root, pts)
        || frame & (PAGE - 1) != 0
        || frame < image_base
        || frame.checked_add(PAGE).is_none_or(|end| end > image_end)
        || layout.classify(frame - image_base) != image_sections::PagePolicy::Writable
        || !matches!(
            supervisor_manifest::uefi_type_of(map, frame),
            Ok(Some(1..=4))
        )
    {
        return Err(Error::UntrustedTableFrame);
    }
    if seen[..*count].contains(&frame) {
        return Ok(());
    }
    if *count >= seen.len() {
        return Err(Error::TooManyPageTables);
    }
    seen[*count] = frame;
    *count += 1;

    let mut entries = [0u64; 512];
    crate::root::with_physical_window(frame, |window| {
        for (index, entry) in entries.iter_mut().enumerate() {
            *entry = ptr::read_volatile(window.add(index * 8).cast::<u64>());
        }
    })
    .map_err(|_| Error::UntrustedTableFrame)?;

    for entry in entries {
        if entry & PRESENT == 0 {
            continue;
        }
        if entry & USER != 0 {
            return Err(Error::ValidationFailed);
        }
        let huge = entry & LARGE != 0;
        if huge {
            return Err(Error::ValidationFailed);
        }
        if level == 1 {
            continue;
        }
        audit_candidate_table(
            entry & ADDRESS_MASK,
            level - 1,
            image_base,
            image_end,
            layout,
            map,
            root,
            pts,
            window_pdpt,
            window_pd,
            window_pt,
            seen,
            count,
        )?;
    }
    Ok(())
}

/// Prove that every present non-leaf table reachable from the candidate PML4
/// is one of Sorveth's PE-resident writable table frames. No firmware PML4,
/// PDPT, PD or PT can pass the restricted frame set and PE ownership checks.
///
/// # Safety
/// Run after the expanded candidate is complete, on the active Sorveth root
/// with IF=0 while the image and UEFI descriptor buffer remain valid.
#[cfg(target_arch = "x86_64")]
pub unsafe fn audit_candidate_table_ancestry(
    boot: &BootInfo,
    map: &MemoryMap<'_>,
) -> Result<CandidateTableEvidence, Error> {
    if !BUILT.load(Ordering::Acquire) || !WINDOW_BUILT.load(Ordering::Acquire) || !boot.is_valid() {
        return Err(Error::UnsupportedPlan);
    }
    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if flags & (1 << 9) != 0 || crate::root::kernel_root_physical() != Some(active & ADDRESS_MASK) {
        return Err(Error::WrongCpuContext);
    }
    let image_end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
    let header =
        core::slice::from_raw_parts(boot.image_base as *const u8, image_sections::HEADER_LIMIT);
    let layout = image_sections::parse(header, boot.image_size).map_err(|_| Error::InvalidImage)?;
    let root = ptr::addr_of!(IMAGE_ROOT) as u64;
    let pts = ptr::addr_of!(IMAGE_PTS) as u64;
    let mut seen = [0u64; MAX_PT + 16];
    let mut count = 0usize;
    audit_candidate_table(
        root,
        4,
        boot.image_base,
        image_end,
        &layout,
        map,
        root,
        pts,
        ptr::addr_of!(WINDOW_PDPT) as u64,
        ptr::addr_of!(WINDOW_PD) as u64,
        ptr::addr_of!(WINDOW_PT) as u64,
        &mut seen,
        &mut count,
    )?;
    Ok(CandidateTableEvidence {
        unique_table_frames: count,
    })
}

/// Activate the fully audited, PE-resident candidate for a dedicated QEMU
/// acceptance image. Ordinary firmware-sharing images keep their existing
/// root and only run the temporary transition probe.
#[cfg(all(target_arch = "x86_64", feature = "qemu-independent-root"))]
pub(crate) unsafe fn activate_verified_survival_root() -> Result<(), Error> {
    if !BUILT.load(Ordering::Acquire) || !WINDOW_BUILT.load(Ordering::Acquire) {
        return Err(Error::UnsupportedPlan);
    }
    crate::root::activate_independent_root(ptr::addr_of!(IMAGE_ROOT) as u64)
        .map_err(|_| Error::WrongCpuContext)
}

/// For 4-KiB leaves, PAT=0 with PCD|PWT selects IA32_PAT entry 3.
#[cfg(target_arch = "x86_64")]
unsafe fn pat_entry_three_is_uncacheable() -> bool {
    if core::arch::x86_64::__cpuid(1).edx & (1 << 16) == 0 {
        return false;
    }
    let low: u32;
    let high: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") 0x277u32,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags),
    );
    let pat = ((high as u64) << 32) | low as u64;
    ((pat >> 24) & 0xff) == 0
}

#[cfg(target_arch = "x86_64")]
unsafe fn build_and_verify_framebuffer<const N: usize>(
    boot: &BootInfo,
    map: &MemoryMap<'_>,
    plan: &Plan<N>,
    root: u64,
    window_pml4_slot: usize,
) -> Result<u64, Error> {
    use crate::supervisor_root_plan::CachePolicy;

    let framebuffer = match plan.framebuffer() {
        Some(value) => value,
        None => return Ok(0),
    };
    if framebuffer.cache_policy != CachePolicy::Uncacheable || !pat_entry_three_is_uncacheable() {
        return Err(Error::UnsupportedCachePolicy);
    }
    const MAX_FRAMEBUFFER_PAGES: u64 = (64 * 1024 * 1024) / PAGE;
    if framebuffer.pages == 0 || framebuffer.pages > MAX_FRAMEBUFFER_PAGES {
        return Err(Error::InvalidFramebuffer);
    }
    let end = framebuffer
        .physical_start
        .checked_add(framebuffer.pages * PAGE)
        .ok_or(Error::InvalidFramebuffer)?;
    if framebuffer.virtual_start != framebuffer.physical_start
        || framebuffer.physical_start & (PAGE - 1) != 0
        || framebuffer.physical_start == 0
        || end > (1u64 << 52)
    {
        return Err(Error::InvalidFramebuffer);
    }
    for index in 0..plan.mapping_count() {
        let record = plan.mapping(index).ok_or(Error::UnsupportedPlan)?;
        if record.physical_page >= framebuffer.physical_start && record.physical_page < end
            || record.virtual_page >= framebuffer.virtual_start
                && record.virtual_page < framebuffer.virtual_start + framebuffer.pages * PAGE
        {
            return Err(Error::InvalidFramebuffer);
        }
    }

    let image_end = boot
        .image_base
        .checked_add(boot.image_size)
        .ok_or(Error::InvalidImage)?;
    if framebuffer.physical_start < image_end && end > boot.image_base {
        return Err(Error::InvalidFramebuffer);
    }
    let fb_last = framebuffer
        .virtual_start
        .checked_add(framebuffer.pages * PAGE - 1)
        .ok_or(Error::InvalidFramebuffer)?;
    let image_pml4_slot = ((boot.image_base >> 39) & 511) as usize;
    let fb_pml4_slot = ((framebuffer.virtual_start >> 39) & 511) as usize;
    let image_pdpt_slot = ((boot.image_base >> 30) & 511) as usize;
    let fb_pdpt_slot = ((framebuffer.virtual_start >> 30) & 511) as usize;
    if fb_pml4_slot == window_pml4_slot
        || fb_pml4_slot != ((fb_last >> 39) & 511) as usize
        || fb_pdpt_slot != ((fb_last >> 30) & 511) as usize
    {
        return Err(Error::InvalidFramebuffer);
    }

    let current_root = crate::root::kernel_root_physical().ok_or(Error::WrongCpuContext)?;
    for page_index in 0..framebuffer.pages {
        let physical = framebuffer
            .physical_start
            .checked_add(page_index * PAGE)
            .ok_or(Error::InvalidFramebuffer)?;
        match supervisor_manifest::uefi_type_of(map, physical)
            .map_err(|_| Error::InvalidFramebuffer)?
        {
            Some(0 | 11) | None => {}
            _ => return Err(Error::InvalidFramebuffer),
        }
        let current = supervisor_audit::walk(current_root, physical, |entry| {
            crate::root::read_bootstrap_supervisor_entry(entry)
        })
        .map_err(|_| Error::InvalidFramebuffer)?;
        if current.physical_address != physical || current.user_accessible || !current.writable {
            return Err(Error::InvalidFramebuffer);
        }
    }

    let framebuffer_pdpt = if fb_pml4_slot == image_pml4_slot {
        ptr::addr_of_mut!(IMAGE_PDPT) as u64
    } else {
        ptr::addr_of_mut!(FRAMEBUFFER_PDPT) as u64
    };
    let framebuffer_pd = if fb_pml4_slot == image_pml4_slot && fb_pdpt_slot == image_pdpt_slot {
        ptr::addr_of_mut!(IMAGE_PD) as u64
    } else {
        ptr::addr_of_mut!(FRAMEBUFFER_PD) as u64
    };
    let framebuffer_pdpt_static = ptr::addr_of_mut!(FRAMEBUFFER_PDPT) as u64;
    let framebuffer_pd_static = ptr::addr_of_mut!(FRAMEBUFFER_PD) as u64;
    let image_pdpt = ptr::addr_of_mut!(IMAGE_PDPT) as u64;
    let pts = ptr::addr_of_mut!(IMAGE_PTS) as u64;
    let needed = required_pt_pages(boot.image_base, boot.image_size)?;
    let header =
        core::slice::from_raw_parts(boot.image_base as *const u8, image_sections::HEADER_LIMIT);
    let layout = image_sections::parse(header, boot.image_size).map_err(|_| Error::InvalidImage)?;

    for frame in [framebuffer_pdpt_static, framebuffer_pd_static] {
        if frame & (PAGE - 1) != 0
            || frame < boot.image_base
            || frame
                .checked_add(PAGE)
                .is_none_or(|frame_end| frame_end > image_end)
            || !crate::root::identity_mapped(frame)
            || layout.classify(frame - boot.image_base) != image_sections::PagePolicy::Writable
        {
            return Err(Error::UntrustedTableFrame);
        }
    }

    if fb_pml4_slot != image_pml4_slot {
        if ptr::read_volatile((root as *const u64).add(fb_pml4_slot)) != 0 {
            return Err(Error::WindowCollision);
        }
        ptr::write_bytes(framebuffer_pdpt as *mut u8, 0, PAGE as usize);
    }
    if fb_pdpt_slot != image_pdpt_slot || fb_pml4_slot != image_pml4_slot {
        if ptr::read_volatile((framebuffer_pdpt as *const u64).add(fb_pdpt_slot)) != 0 {
            return Err(Error::WindowCollision);
        }
        ptr::write_bytes(framebuffer_pd as *mut u8, 0, PAGE as usize);
        ptr::write_volatile(
            (framebuffer_pdpt as *mut u64).add(fb_pdpt_slot),
            framebuffer_pd | PRESENT | WRITE,
        );
    }

    let mut used_pts = needed;
    let mut tracked_pts: [Option<(u64, u64, u64)>; MAX_PT] = [None; MAX_PT];
    let mut tracked_count = 0usize;
    let mut page_index = 0u64;
    while page_index < framebuffer.pages {
        let virtual_page = framebuffer
            .virtual_start
            .checked_add(page_index * PAGE)
            .ok_or(Error::InvalidFramebuffer)?;
        let pd_slot = (virtual_page >> 21) & 511;
        let pt_slot = ((virtual_page >> 12) & 511) as usize;
        let mut parent = ptr::read_volatile((framebuffer_pd as *const u64).add(pd_slot as usize));
        let pt_frame;
        if parent & PRESENT == 0 {
            if used_pts >= MAX_PT {
                return Err(Error::TooManyPageTables);
            }
            pt_frame = pts + used_pts as u64 * PAGE;
            used_pts += 1;
            if pt_frame < boot.image_base
                || pt_frame + PAGE > image_end
                || !crate::root::identity_mapped(pt_frame)
                || layout.classify(pt_frame - boot.image_base)
                    != image_sections::PagePolicy::Writable
            {
                return Err(Error::UntrustedTableFrame);
            }
            ptr::write_bytes(pt_frame as *mut u8, 0, PAGE as usize);
            parent = pt_frame | PRESENT | WRITE;
            ptr::write_volatile((framebuffer_pd as *mut u64).add(pd_slot as usize), parent);
        } else {
            if parent & LARGE != 0 {
                return Err(Error::WindowCollision);
            }
            pt_frame = parent & ADDRESS_MASK;
            if pt_frame < pts
                || pt_frame >= pts + MAX_PT as u64 * PAGE
                || (pt_frame - pts) & (PAGE - 1) != 0
            {
                return Err(Error::UntrustedTableFrame);
            }
        }

        let physical_page = framebuffer
            .physical_start
            .checked_add(page_index * PAGE)
            .ok_or(Error::InvalidFramebuffer)?;
        let entry = physical_page | PRESENT | WRITE | NX | PWT | PCD;
        let leaf = (pt_frame as *mut u64).add(pt_slot);
        if ptr::read_volatile(leaf) != 0 {
            return Err(Error::WindowCollision);
        }
        ptr::write_volatile(leaf, entry);

        if tracked_pts[..tracked_count]
            .iter()
            .flatten()
            .all(|(tracked_pd, tracked_pt, _)| *tracked_pd != pd_slot || *tracked_pt != pt_frame)
        {
            if tracked_count == MAX_PT {
                return Err(Error::TooManyPageTables);
            }
            tracked_pts[tracked_count] = Some((pd_slot, pt_frame, virtual_page));
            tracked_count += 1;
        }
        page_index += 1;
    }

    if fb_pml4_slot != image_pml4_slot {
        ptr::write_volatile(
            (root as *mut u64).add(fb_pml4_slot),
            framebuffer_pdpt | PRESENT | WRITE,
        );
    }

    let pts_reader_limit = MAX_PT;
    let cache_flags = PRESENT | WRITE | NX | PWT | PCD;
    for (pd_slot, pt_frame, first_page) in tracked_pts[..tracked_count].iter().flatten().copied() {
        let result = crate::root::with_physical_window(pt_frame, |window| {
            let mut index = 0u64;
            while index < framebuffer.pages {
                let virtual_page = framebuffer.virtual_start + index * PAGE;
                if (virtual_page >> 21) & 511 == pd_slot {
                    let pt_slot = ((virtual_page >> 12) & 511) as usize;
                    let expected = (framebuffer.physical_start + index * PAGE) | cache_flags;
                    if ptr::read_volatile(window.add(pt_slot * 8) as *const u64) != expected {
                        return false;
                    }
                }
                index += 1;
            }
            true
        })
        .map_err(|_| Error::ValidationFailed)?;
        if !result {
            return Err(Error::ValidationFailed);
        }

        let observed = supervisor_audit::walk(root, first_page, |entry| {
            read_extended_candidate_entry(
                entry,
                root,
                image_pdpt,
                ptr::addr_of!(IMAGE_PD) as u64,
                pts,
                pts_reader_limit,
                ptr::addr_of!(WINDOW_PDPT) as u64,
                ptr::addr_of!(WINDOW_PD) as u64,
                ptr::addr_of!(WINDOW_PT) as u64,
            )
        })
        .map_err(|_| Error::ValidationFailed)?;
        let expected_physical =
            framebuffer.physical_start + (first_page - framebuffer.virtual_start);
        if observed.physical_address != expected_physical
            || observed.user_accessible
            || !observed.writable
            || observed.executable
            || observed.leaf_size != PAGE
        {
            return Err(Error::ValidationFailed);
        }
    }
    Ok(framebuffer.pages)
}

/// In one uninterrupted assembly sequence, transiently activate the
/// image-only PML4, read the active CR3 and one word of the dedicated kernel
/// stack, then restore the original PML4 before returning to Rust. If the
/// candidate cannot execute code or read the stack it will fault in QEMU,
/// and the acceptance marker cannot be emitted. It is NOT kept active.
///
/// # Safety
/// Only on one CPU after a verified candidate has been built, with IRQs
/// masked and the current stack wholly within the verified PE image.
/// Never execute this routine on UEFI's abandoned external entry stack.
/// This image-only probe makes no dynamic mappings or Rust calls while the
/// temporary CR3 is active. The expanded-root probe has its own controlled
/// frame-window lifecycle sequence.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe fn verify_temporary_image_root(
    image_base: u64,
    image_size: u64,
    stack_start: u64,
    stack_end: u64,
) -> Result<(), Error> {
    verify_temporary_root(false, image_base, image_size, stack_start, stack_end, None)
}

/// Temporarily run the same atomic CR3/stack probe under the expanded
/// supervisor candidate after every manifest record has passed its walk.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe fn verify_temporary_survival_root(
    image_base: u64,
    image_size: u64,
    stack_start: u64,
    stack_end: u64,
    window_base: u64,
    probe_frames: [u64; 2],
) -> Result<(), Error> {
    if window_base & (PAGE - 1) != 0
        || probe_frames[0] == probe_frames[1]
        || probe_frames
            .iter()
            .any(|frame| *frame == 0 || frame & (PAGE - 1) != 0)
        || !crate::root::identity_mapped(ptr::addr_of!(WINDOW_PT) as u64)
    {
        return Err(Error::UnsupportedPlan);
    }
    let pte = (ptr::addr_of_mut!(WINDOW_PT) as *mut u64).add(511);
    if ptr::read_volatile(pte) != 0 {
        return Err(Error::WindowCollision);
    }
    let occupied = probe_frames[0] | PRESENT | WRITE | NX;
    ptr::write_volatile(pte, occupied);
    let collision = verify_temporary_root(
        true,
        image_base,
        image_size,
        stack_start,
        stack_end,
        Some((window_base, probe_frames)),
    );
    let preserved = ptr::read_volatile(pte) == occupied;
    ptr::write_volatile(pte, 0);
    let active: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    if !preserved
        || !matches!(collision, Err(Error::WindowCollision))
        || crate::root::kernel_root_physical() != Some(active & ADDRESS_MASK)
    {
        return Err(Error::ValidationFailed);
    }
    verify_temporary_root(
        true,
        image_base,
        image_size,
        stack_start,
        stack_end,
        Some((window_base, probe_frames)),
    )
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn verify_temporary_root(
    require_survival_plan: bool,
    image_base: u64,
    image_size: u64,
    stack_start: u64,
    stack_end: u64,
    window_probe: Option<(u64, [u64; 2])>,
) -> Result<(), Error> {
    if !BUILT.load(Ordering::Acquire)
        || require_survival_plan && !WINDOW_BUILT.load(Ordering::Acquire)
    {
        return Err(Error::InvalidImage);
    }
    let image_end = image_base
        .checked_add(image_size)
        .ok_or(Error::InvalidImage)?;
    let candidate = ptr::addr_of!(IMAGE_ROOT) as u64;
    let original: u64;
    let rsp: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if flags & (1 << 9) != 0
        || crate::root::kernel_root_physical() != Some(original & ADDRESS_MASK)
        || candidate == original & ADDRESS_MASK
        || candidate & (PAGE - 1) != 0
        || !(image_base <= candidate && candidate < image_end)
        || !(image_base <= verify_temporary_image_root as usize as u64
            && (verify_temporary_image_root as usize as u64) < image_end)
        || !(image_base <= stack_start
            && stack_start < rsp
            && rsp < stack_end
            && stack_end <= image_end)
    {
        return Err(Error::WrongCpuContext);
    }

    let window_probe_state = if let Some((window_base, probe_frames)) = window_probe {
        let window_address = window_base + 511 * PAGE;
        let self_alias = window_base + 510 * PAGE;
        let self_alias_pte = self_alias + 511 * core::mem::size_of::<u64>() as u64;
        if window_base & (PAGE - 1) != 0
            || probe_frames[0] == probe_frames[1]
            || probe_frames
                .iter()
                .any(|frame| *frame == 0 || frame & (PAGE - 1) != 0)
            || !crate::root::identity_mapped(ptr::addr_of!(WINDOW_PT) as u64)
        {
            return Err(Error::UnsupportedPlan);
        }
        let pte = (ptr::addr_of_mut!(WINDOW_PT) as *mut u64).add(511);
        if ptr::read_volatile(pte) != 0 {
            return Err(Error::WindowCollision);
        }
        let sentinels = [
            SURVIVAL_WINDOW_WORD,
            SURVIVAL_WINDOW_WORD ^ 0x5a5a_a5a5_3c3c_c3c3,
        ];
        let mut previous_words = [0u64; 2];
        for index in 0..probe_frames.len() {
            match crate::root::with_physical_window(probe_frames[index], |window| {
                let previous = ptr::read_volatile(window as *const u64);
                ptr::write_volatile(window as *mut u64, sentinels[index]);
                previous
            }) {
                Ok(previous) => previous_words[index] = previous,
                Err(_) => {
                    for restore in 0..index {
                        let frame = probe_frames[restore];
                        let previous = previous_words[restore];
                        let _ = crate::root::with_physical_window(frame, |window| {
                            ptr::write_volatile(window as *mut u64, previous);
                        });
                    }
                    return Err(Error::ValidationFailed);
                }
            }
        }
        ptr::write_volatile(pte, probe_frames[0] | PRESENT | WRITE | NX);
        Some((
            window_address,
            self_alias_pte,
            pte,
            probe_frames,
            previous_words,
            sentinels,
        ))
    } else {
        None
    };

    let observed_cr3: u64;
    let observed_stack: u64;
    let observed_windows: [u64; 2];
    let restored: u64;
    if let Some((window_address, self_alias_pte, _, probe_frames, _, _)) = window_probe_state {
        // No Rust calls or stack writes occur while the candidate root is
        // active. The leaf is cleared and reused through the candidate's
        // own PT self-alias, with invalidation after every PTE change.
        let second_frame_pte = probe_frames[1] | PRESENT | WRITE | NX;
        let observed_first: u64;
        let observed_second: u64;
        core::arch::asm!(
            "mov rax, cr3",
            "mov cr3, {candidate}",
            "invlpg [{window_address}]",
            "mov {observed_cr3}, cr3",
            "mov {observed_stack}, qword ptr [rsp]",
            "mov {observed_first}, qword ptr [{window_address}]",
            "mov qword ptr [{self_alias_pte}], 0",
            "invlpg [{window_address}]",
            "mov qword ptr [{self_alias_pte}], {second_frame_pte}",
            "invlpg [{window_address}]",
            "mov {observed_second}, qword ptr [{window_address}]",
            "mov qword ptr [{self_alias_pte}], 0",
            "invlpg [{window_address}]",
            "mov cr3, rax",
            candidate = in(reg) candidate,
            window_address = in(reg) window_address,
            self_alias_pte = in(reg) self_alias_pte,
            second_frame_pte = in(reg) second_frame_pte,
            observed_cr3 = out(reg) observed_cr3,
            observed_stack = out(reg) observed_stack,
            observed_first = out(reg) observed_first,
            observed_second = out(reg) observed_second,
            out("rax") _,
            options(nostack, preserves_flags)
        );
        observed_windows = [observed_first, observed_second];
        core::arch::asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
    } else {
        observed_windows = [0; 2];
        core::arch::asm!(
            "mov rax, cr3",
            "mov cr3, {candidate}",
            "mov {observed_cr3}, cr3",
            "mov {observed_stack}, qword ptr [rsp]",
            "mov cr3, rax",
            candidate = in(reg) candidate,
            observed_cr3 = lateout(reg) observed_cr3,
            observed_stack = lateout(reg) observed_stack,
            out("rax") _,
            options(nostack, preserves_flags)
        );
        core::arch::asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
    }

    let _ = observed_stack;
    if let Some((_, _, pte, probe_frames, previous_words, sentinels)) = window_probe_state {
        let cleared = ptr::read_volatile(pte) == 0;
        if !cleared {
            ptr::write_volatile(pte, 0);
        }
        let mut restored = true;
        for index in 0..probe_frames.len() {
            if crate::root::with_physical_window(probe_frames[index], |window| {
                ptr::write_volatile(window as *mut u64, previous_words[index]);
            })
            .is_err()
            {
                restored = false;
            }
        }
        if !cleared || !restored || observed_windows != sentinels {
            return Err(Error::ValidationFailed);
        }
    }
    if observed_cr3 & ADDRESS_MASK != candidate || restored != original {
        return Err(Error::ValidationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_exact_wx_split_and_rejects_unclassified() {
        assert_eq!(leaf_flags(image_sections::PagePolicy::Code), Some(1));
        assert_eq!(
            leaf_flags(image_sections::PagePolicy::Writable),
            Some(1 | 2 | NX)
        );
        assert_eq!(
            leaf_flags(image_sections::PagePolicy::ReadOnly),
            Some(1 | NX)
        );
        assert_eq!(
            leaf_flags(image_sections::PagePolicy::Headers),
            Some(1 | NX)
        );
        assert_eq!(leaf_flags(image_sections::PagePolicy::Unclassified), None);
    }

    #[test]
    fn limits_candidate_to_bounded_single_one_gib_region() {
        assert_eq!(required_pt_pages(0x20_0000, 0x10_0000), Ok(1));
        assert_eq!(required_pt_pages(0x20_1000, 0x20_0000), Ok(2));
        assert_eq!(
            required_pt_pages(0x3fff_f000, 0x2000),
            Err(Error::CrossesGigabyte)
        );
        assert_eq!(required_pt_pages(0x1000, 0), Err(Error::CrossesGigabyte));
        assert_eq!(required_pt_pages(0x1001, 4096), Err(Error::CrossesGigabyte));
        assert_eq!(
            required_pt_pages(0x1000, u64::MAX),
            Err(Error::CrossesGigabyte)
        );
    }
}
