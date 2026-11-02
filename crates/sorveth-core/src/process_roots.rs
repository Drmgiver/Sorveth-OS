//! M2-I.1/I.2: separate top-level PML4 roots and owned user-data pages.
//!
//! Both roots still share Sorveth's lower-level *kernel* paging trees,
//! including inherited OVMF mappings. Every present PML4 entry has its
//! USER bit cleared; future process-private USER subtrees must be mapped
//! separately in the initially absent lower-half slots. M2-I.2 creates
//! disjoint USER RW/NX physical mappings behind these process-owned slots.
//! This is single-core QEMU bootstrap code, not yet complete process isolation.

#[cfg(target_arch = "x86_64")]
use core::{
    arch::asm,
    ptr,
    sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering},
};

#[cfg(target_arch = "x86_64")]
const PRESENT: u64 = 1;
#[cfg(target_arch = "x86_64")]
const USER: u64 = 1 << 2;
#[cfg(target_arch = "x86_64")]
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(target_arch = "x86_64")]
const PAGE: u64 = 4096;
#[cfg(target_arch = "x86_64")]
const WRITE: u64 = 1 << 1;
#[cfg(target_arch = "x86_64")]
const NO_EXECUTE: u64 = 1 << 63;
#[cfg(target_arch = "x86_64")]
const USER_TABLE_FLAGS: u64 = PRESENT | WRITE | USER;
#[cfg(target_arch = "x86_64")]
const USER_DATA_FLAGS: u64 = USER_TABLE_FLAGS | NO_EXECUTE;
#[cfg(target_arch = "x86_64")]
const ACCESSED: u64 = 1 << 5;
#[cfg(target_arch = "x86_64")]
const DIRTY: u64 = 1 << 6;
#[cfg(target_arch = "x86_64")]
const FIRST_TEST_WORD: u64 = 0x534f_5256_4541_4f4e;
#[cfg(target_arch = "x86_64")]
const SECOND_TEST_WORD: u64 = 0x534f_5256_4542_4f4e;
#[cfg(target_arch = "x86_64")]
const INHERITED_TABLE_CAPACITY: usize = 8192;

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct Page([u64; 512]);

#[cfg(target_arch = "x86_64")]
static mut FIRST: Page = Page([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SECOND: Page = Page([0; 512]);

// The two roots are still bootstrap fixtures, but their private lower-level
// paging frames are claimed from the frame ledger for each address-space
// mapping lifetime instead of being permanently pinned in BSS.
#[cfg(target_arch = "x86_64")]
static mut PROCESS_TABLE_CLAIMS: [Option<sorveth_frames::OwnedSpan>; 6] = [None; 6];
#[cfg(target_arch = "x86_64")]
static READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static FIRST_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static MAPPED: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static FIRST_FRAME: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_FRAME: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static FIRST_GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static RECLAIMED_ONCE: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static mut FIRST_CLAIM: Option<sorveth_frames::OwnedSpan> = None;
#[cfg(target_arch = "x86_64")]
static mut SECOND_CLAIM: Option<sorveth_frames::OwnedSpan> = None;

#[cfg(all(target_arch = "x86_64", feature = "qemu-independent-root"))]
pub(crate) fn is_owned_process_root_frame(frame: u64) -> bool {
    frame == ptr::addr_of!(FIRST) as u64 || frame == ptr::addr_of!(SECOND) as u64
}
#[cfg(target_arch = "x86_64")]
static FIRST_SLOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static SECOND_SLOT: AtomicU64 = AtomicU64::new(0);

// The inventory runs on the retained bootstrap stack, but its bounded
// deduplication set lives in BSS so it does not consume several KiB of that
// small stack. It is only touched by the single bootstrap CPU with IF=0.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct InheritedTableFrame {
    physical: u64,
    visits: u16,
    roots: u8,
}

#[cfg(target_arch = "x86_64")]
const EMPTY_INHERITED_TABLE: InheritedTableFrame = InheritedTableFrame {
    physical: 0,
    visits: 0,
    roots: 0,
};

#[cfg(target_arch = "x86_64")]
static mut INHERITED_TABLES: [InheritedTableFrame; INHERITED_TABLE_CAPACITY] =
    [EMPTY_INHERITED_TABLE; INHERITED_TABLE_CAPACITY];
#[cfg(target_arch = "x86_64")]
static mut INHERITED_TABLE_COUNT: usize = 0;
#[cfg(target_arch = "x86_64")]
static mut INHERITED_UEFI_TYPE_COUNTS: [u16; 16] = [0; 16];
#[cfg(target_arch = "x86_64")]
static mut INHERITED_OTHER_UEFI_TYPES: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    AlreadyPrepared,
    KernelUnavailable,
    IdentityMapMissing,
    PrivateSlotsUnavailable,
    VerificationFailed,
    FrameUnavailable,
    AlreadyMapped,
    NotMapped,
    SetupFailureInjected,
    PageTableStorageUnavailable,
    SupervisorMappingMismatch,
    InheritedTableInventoryFailed,
    InheritedTableInventoryFull,
    InheritedRootAncestryMismatch,
}

/// Bounded facts about the inherited page-table ancestry reachable from
/// both scheduler roots. UEFI types identify descriptor provenance only;
/// they do not grant ownership of any frame.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritedTableInventory {
    pub unique_table_frames: usize,
    pub shared_table_frames: usize,
    pub uefi_type_counts: [u16; 16],
    pub other_uefi_types: u32,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Process {
    First,
    Second,
}

#[cfg(target_arch = "x86_64")]
fn supervisor_entry(entry: u64) -> u64 {
    if entry & PRESENT == 0 {
        0
    } else {
        entry & !USER
    }
}

#[cfg(target_arch = "x86_64")]
fn vacant_slots(mut entry: impl FnMut(usize) -> u64) -> Option<(usize, usize)> {
    let mut first = None;
    for slot in (1..256).rev() {
        if entry(slot) & PRESENT == 0 {
            if let Some(chosen) = first {
                return Some((chosen, slot));
            }
            first = Some(slot);
        }
    }
    None
}

/// Initialize two distinct static PML4 pages, then switch CR3 to each and
/// back while verifying the existing supervisor scratch mapping.
///
/// # Safety
/// Requires CPL0, Sorveth's active root, one CPU, IRQs masked and static
/// PML4 frame ownership. The PML4 pages are copied through an owned virtual
/// frame window; supervisor executable/stack mapping inheritance remains.

pub unsafe fn prepare_and_verify() -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if READY.load(Ordering::Acquire) {
            return Err(Error::AlreadyPrepared);
        }
        let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
        let scratch = crate::root::kernel_private_address().ok_or(Error::KernelUnavailable)?;
        let a = ptr::addr_of_mut!(FIRST).cast::<u64>() as u64;
        let b = ptr::addr_of_mut!(SECOND).cast::<u64>() as u64;
        if a == b || a == kernel || b == kernel || a & 4095 != 0 || b & 4095 != 0 {
            return Err(Error::VerificationFailed);
        }
        let mut active: u64;
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if active & ADDRESS_MASK != kernel {
            return Err(Error::KernelUnavailable);
        }
        // Snapshot Sorveth's known kernel PML4 while its own CR3 is active.
        // Only the existing owned window may dereference physical table RAM.
        let mut entries = [0u64; 512];
        crate::root::with_physical_window(kernel, |window| {
            let source = window as *const u64;
            for (index, entry) in entries.iter_mut().enumerate() {
                *entry = ptr::read_volatile(source.add(index));
            }
        })
        .map_err(|_| Error::PageTableStorageUnavailable)?;
        let (slot_a, slot_b) =
            vacant_slots(|i| entries[i]).ok_or(Error::PrivateSlotsUnavailable)?;
        for entry in &mut entries {
            *entry = supervisor_entry(*entry);
        }
        // The entire process root is initialized and verified through the
        // Sorveth-owned high-half alias, without physical-pointer dereference.
        for process_root in [a, b] {
            let verified = crate::root::with_physical_window(process_root, |window| {
                let destination = window as *mut u64;
                for (index, entry) in entries.iter().enumerate() {
                    ptr::write_volatile(destination.add(index), *entry);
                }
                if ptr::read_volatile(destination.add(slot_a)) != 0
                    || ptr::read_volatile(destination.add(slot_b)) != 0
                {
                    return false;
                }
                for (index, expected) in entries.iter().enumerate() {
                    let actual = ptr::read_volatile(destination.add(index));
                    if actual != *expected || (actual & PRESENT != 0 && actual & USER != 0) {
                        return false;
                    }
                }
                true
            })
            .map_err(|_| Error::PageTableStorageUnavailable)?;
            if !verified {
                return Err(Error::VerificationFailed);
            }
        }
        let expected = ptr::read_volatile(scratch as *const u64);
        let mut success = true;
        for process_root in [a, b] {
            asm!("mov cr3, {}", in(reg) process_root, options(nostack, preserves_flags));
            asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
            if active & ADDRESS_MASK != process_root
                || ptr::read_volatile(scratch as *const u64) != expected
            {
                success = false;
                break;
            }
        }
        // Restore the kernel CR3 even after a nonfatal verification mismatch.
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if !success
            || active & ADDRESS_MASK != kernel
            || ptr::read_volatile(scratch as *const u64) != expected
        {
            return Err(Error::VerificationFailed);
        }
        FIRST_ROOT.store(a, Ordering::Release);
        SECOND_ROOT.store(b, Ordering::Release);
        FIRST_SLOT.store(slot_a as u64, Ordering::Release);
        SECOND_SLOT.store(slot_b as u64, Ordering::Release);
        READY.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(Error::Unsupported)
    }
}

#[cfg(target_arch = "x86_64")]
pub fn process_root(process: Process) -> Option<(u64, u16)> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    let (root, slot) = match process {
        Process::First => (
            FIRST_ROOT.load(Ordering::Acquire),
            FIRST_SLOT.load(Ordering::Acquire),
        ),
        Process::Second => (
            SECOND_ROOT.load(Ordering::Acquire),
            SECOND_SLOT.load(Ordering::Acquire),
        ),
    };
    if root == 0 || slot == 0 {
        None
    } else {
        Some((root, slot as u16))
    }
}

/// Confirm that both scheduler roots retain every mapping in the verified
/// supervisor plan, including the framebuffer's first and last pages. The
/// roots still inherit their current page-table ancestry; this audit only
/// verifies that those live roots can supply the same planned dependencies.
///
/// # Safety
/// Kernel CR3 must be active on the single bootstrap CPU with interrupts
/// disabled, and inherited supervisor tables must remain immutable.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn audit_supervisor_plan<const N: usize>(
    plan: &crate::supervisor_root_plan::Plan<N>,
) -> Result<usize, Error> {
    let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
    let active: u64;
    let flags: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if active & ADDRESS_MASK != kernel || flags & (1 << 9) != 0 {
        return Err(Error::KernelUnavailable);
    }

    let mut verified = 0usize;
    for process in [Process::First, Process::Second] {
        let root = process_root(process)
            .map(|(root, _)| root)
            .ok_or(Error::KernelUnavailable)?;
        if root == kernel {
            return Err(Error::VerificationFailed);
        }
        for index in 0..plan.mapping_count() {
            let mapping = plan
                .mapping(index)
                .ok_or(Error::SupervisorMappingMismatch)?;
            #[cfg(feature = "qemu-independent-root")]
            let expected_physical =
                crate::image_page_tables::candidate_self_alias_frame(mapping.virtual_page)
                    .unwrap_or(mapping.physical_page);
            #[cfg(not(feature = "qemu-independent-root"))]
            let expected_physical = mapping.physical_page;
            let observed =
                match crate::supervisor_audit::walk(root, mapping.virtual_page, |entry| {
                    read_supervisor_table_entry(entry)
                }) {
                    Ok(observed) => observed,
                    Err(_error) => {
                        #[cfg(feature = "qemu-independent-root")]
                        {
                            crate::serial::write("K.1r process mapping walk failed at ");
                            crate::serial::write_u64(mapping.virtual_page);
                            crate::serial::write(" (reason ");
                            crate::serial::write_u64(_error as u64);
                            crate::serial::write_line(")");
                        }
                        return Err(Error::SupervisorMappingMismatch);
                    }
                };
            if observed.physical_address != expected_physical
                || observed.user_accessible
                || mapping.writable && !observed.writable
                || mapping.executable && !observed.executable
            {
                #[cfg(feature = "qemu-independent-root")]
                {
                    crate::serial::write("K.1r process mapping mismatch at ");
                    crate::serial::write_u64(mapping.virtual_page);
                    crate::serial::write(" expected ");
                    crate::serial::write_u64(expected_physical);
                    crate::serial::write(" observed ");
                    crate::serial::write_u64(observed.physical_address);
                    crate::serial::write_line("");
                }
                return Err(Error::SupervisorMappingMismatch);
            }
            verified = verified
                .checked_add(1)
                .ok_or(Error::SupervisorMappingMismatch)?;
        }
        if let Some(framebuffer) = plan.framebuffer() {
            let last_offset = framebuffer
                .pages
                .checked_sub(1)
                .and_then(|pages| pages.checked_mul(PAGE))
                .ok_or(Error::SupervisorMappingMismatch)?;
            for offset in [0, last_offset] {
                let virtual_page = framebuffer
                    .virtual_start
                    .checked_add(offset)
                    .ok_or(Error::SupervisorMappingMismatch)?;
                let physical_page = framebuffer
                    .physical_start
                    .checked_add(offset)
                    .ok_or(Error::SupervisorMappingMismatch)?;
                let observed = crate::supervisor_audit::walk(root, virtual_page, |entry| {
                    read_supervisor_table_entry(entry)
                })
                .map_err(|_error| {
                    #[cfg(feature = "qemu-independent-root")]
                    {
                        crate::serial::write("K.1r framebuffer walk failed at ");
                        crate::serial::write_u64(virtual_page);
                        crate::serial::write(" (reason ");
                        crate::serial::write_u64(_error as u64);
                        crate::serial::write_line(")");
                    }
                    Error::SupervisorMappingMismatch
                })?;
                if observed.physical_address != physical_page
                    || observed.user_accessible
                    || !observed.writable
                {
                    #[cfg(feature = "qemu-independent-root")]
                    {
                        crate::serial::write("K.1r framebuffer mismatch at ");
                        crate::serial::write_u64(virtual_page);
                        crate::serial::write(" expected ");
                        crate::serial::write_u64(physical_page);
                        crate::serial::write(" observed ");
                        crate::serial::write_u64(observed.physical_address);
                        crate::serial::write_line("");
                    }
                    return Err(Error::SupervisorMappingMismatch);
                }
                verified = verified
                    .checked_add(1)
                    .ok_or(Error::SupervisorMappingMismatch)?;
            }
        }
    }
    Ok(verified)
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_supervisor_table_entry(address: u64) -> Option<u64> {
    #[cfg(feature = "qemu-independent-root")]
    {
        crate::image_page_tables::read_candidate_table_entry(address)
    }
    #[cfg(not(feature = "qemu-independent-root"))]
    {
        crate::root::read_bootstrap_supervisor_entry(address)
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inventory_inherited_table(
    frame: u64,
    level: u8,
    root_bit: u8,
    map: &sorveth_memory::MemoryMap<'_>,
) -> Result<(), Error> {
    if !(1..=4).contains(&level)
        || frame == 0
        || frame & (PAGE - 1) != 0
        || frame & !ADDRESS_MASK != 0
    {
        return Err(Error::InheritedTableInventoryFailed);
    }

    let tables = ptr::addr_of_mut!(INHERITED_TABLES).cast::<InheritedTableFrame>();
    let count = ptr::addr_of_mut!(INHERITED_TABLE_COUNT);
    let mut slot = ((frame / PAGE) as usize) & (INHERITED_TABLE_CAPACITY - 1);
    let mut found = false;
    for _ in 0..INHERITED_TABLE_CAPACITY {
        let physical = ptr::read_volatile(ptr::addr_of!((*tables.add(slot)).physical));
        if physical == frame {
            found = true;
            break;
        }
        if physical == 0 {
            break;
        }
        slot = (slot + 1) & (INHERITED_TABLE_CAPACITY - 1);
    }

    let visit_bit = 1u16 << ((level as u16 - 1) * 2 + root_bit.trailing_zeros() as u16);
    let record = tables.add(slot);
    if found {
        let mut visits = ptr::read_volatile(ptr::addr_of!((*record).visits));
        let old_roots = ptr::read_volatile(ptr::addr_of!((*record).roots));
        ptr::write_volatile(ptr::addr_of_mut!((*record).roots), old_roots | root_bit);
        if visits & visit_bit != 0 {
            return Ok(());
        }
        visits |= visit_bit;
        ptr::write_volatile(ptr::addr_of_mut!((*record).visits), visits);
    } else {
        let current = ptr::read_volatile(count);
        if current >= INHERITED_TABLE_CAPACITY {
            return Err(Error::InheritedTableInventoryFull);
        }
        let descriptor = crate::supervisor_manifest::uefi_type_of(map, frame)
            .map_err(|_| Error::InheritedTableInventoryFailed)?
            .ok_or(Error::InheritedTableInventoryFailed)?;
        ptr::write_volatile(
            record,
            InheritedTableFrame {
                physical: frame,
                visits: visit_bit,
                roots: root_bit,
            },
        );
        ptr::write_volatile(count, current + 1);
        if (descriptor as usize) < 16 {
            let counts = ptr::addr_of_mut!(INHERITED_UEFI_TYPE_COUNTS).cast::<u16>();
            let type_count = counts.add(descriptor as usize);
            let next = ptr::read_volatile(type_count)
                .checked_add(1)
                .ok_or(Error::InheritedTableInventoryFailed)?;
            ptr::write_volatile(type_count, next);
        } else {
            let other = ptr::addr_of_mut!(INHERITED_OTHER_UEFI_TYPES);
            let next = ptr::read_volatile(other)
                .checked_add(1)
                .ok_or(Error::InheritedTableInventoryFailed)?;
            ptr::write_volatile(other, next);
        }
    }

    let mut entries = [0u64; 512];
    if !crate::root::read_bootstrap_supervisor_table(frame, &mut entries) {
        return Err(Error::InheritedTableInventoryFailed);
    }
    for entry_index in 0..512u64 {
        let entry = entries[entry_index as usize];
        if entry & PRESENT == 0 {
            continue;
        }
        let huge = entry & (1 << 7) != 0;
        if level == 4 {
            if huge {
                return Err(Error::InheritedTableInventoryFailed);
            }
        } else if level == 1 || huge {
            continue;
        }
        let child = entry & ADDRESS_MASK;
        if child == 0 {
            return Err(Error::InheritedTableInventoryFailed);
        }
        inventory_inherited_table(child, level - 1, root_bit, map)?;
    }

    Ok(())
}

/// Inventory the page-table ancestry reachable from both prepared process
/// roots. Every unique table page must remain identity-readable through the
/// current kernel root and have exactly one covering UEFI descriptor. This
/// intentionally does not interpret descriptor type as frame ownership.
///
/// # Safety
/// Kernel CR3 active on the single bootstrap CPU with interrupts disabled;
/// the UEFI memory map and inherited supervisor page tables remain stable.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn audit_inherited_page_tables(
    map: &sorveth_memory::MemoryMap<'_>,
) -> Result<InheritedTableInventory, Error> {
    let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
    let active: u64;
    let flags: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if active & ADDRESS_MASK != kernel || flags & (1 << 9) != 0 {
        return Err(Error::KernelUnavailable);
    }

    let roots = [
        process_root(Process::First)
            .map(|(root, _)| root)
            .ok_or(Error::KernelUnavailable)?,
        process_root(Process::Second)
            .map(|(root, _)| root)
            .ok_or(Error::KernelUnavailable)?,
    ];
    if roots[0] == roots[1] || roots[0] == kernel || roots[1] == kernel {
        return Err(Error::InheritedRootAncestryMismatch);
    }
    let mut expected_root = [0u64; 512];
    let mut observed_root = [0u64; 512];
    if !crate::root::read_bootstrap_supervisor_table(kernel, &mut expected_root) {
        return Err(Error::InheritedRootAncestryMismatch);
    }
    for entry in &mut expected_root {
        if *entry & PRESENT == 0 {
            *entry = 0;
        } else {
            *entry &= !USER;
        }
    }
    for root in roots {
        if !crate::root::read_bootstrap_supervisor_table(root, &mut observed_root)
            || observed_root != expected_root
        {
            return Err(Error::InheritedRootAncestryMismatch);
        }
    }

    ptr::write_volatile(ptr::addr_of_mut!(INHERITED_TABLE_COUNT), 0);
    ptr::write_bytes(
        ptr::addr_of_mut!(INHERITED_UEFI_TYPE_COUNTS).cast::<u16>(),
        0,
        16,
    );
    ptr::write_volatile(ptr::addr_of_mut!(INHERITED_OTHER_UEFI_TYPES), 0);

    for (process, root_bit) in [(Process::First, 1u8), (Process::Second, 2u8)] {
        let root = roots[match process {
            Process::First => 0,
            Process::Second => 1,
        }];
        inventory_inherited_table(root, 4, root_bit, map)?;
    }

    let tables = ptr::addr_of!(INHERITED_TABLES).cast::<InheritedTableFrame>();
    let count = ptr::read_volatile(ptr::addr_of!(INHERITED_TABLE_COUNT));
    let mut shared = 0usize;
    let mut distinct_roots = 0usize;
    for index in 0..INHERITED_TABLE_CAPACITY {
        let record = tables.add(index);
        let physical = ptr::read_volatile(ptr::addr_of!((*record).physical));
        if physical == 0 {
            continue;
        }
        let roots_seen = ptr::read_volatile(ptr::addr_of!((*record).roots));
        let visits = ptr::read_volatile(ptr::addr_of!((*record).visits));
        if physical == roots[0] || physical == roots[1] {
            let expected_root_mask = if physical == roots[0] { 1 } else { 2 };
            let expected_visit = if physical == roots[0] { 1 << 6 } else { 1 << 7 };
            if roots_seen != expected_root_mask || visits != expected_visit {
                return Err(Error::InheritedRootAncestryMismatch);
            }
            distinct_roots += 1;
        } else {
            let first_root_visits = visits & 0x55;
            let second_root_visits = (visits >> 1) & 0x55;
            if roots_seen != 3 || first_root_visits == 0 || first_root_visits != second_root_visits
            {
                return Err(Error::InheritedRootAncestryMismatch);
            }
            shared = shared
                .checked_add(1)
                .ok_or(Error::InheritedTableInventoryFailed)?;
        }
    }
    if distinct_roots != 2 || shared.checked_add(2) != Some(count) {
        return Err(Error::InheritedRootAncestryMismatch);
    }
    let mut uefi_type_counts = [0u16; 16];
    ptr::copy_nonoverlapping(
        ptr::addr_of!(INHERITED_UEFI_TYPE_COUNTS).cast::<u16>(),
        uefi_type_counts.as_mut_ptr(),
        uefi_type_counts.len(),
    );
    Ok(InheritedTableInventory {
        unique_table_frames: count,
        shared_table_frames: shared,
        uefi_type_counts,
        other_uefi_types: ptr::read_volatile(ptr::addr_of!(INHERITED_OTHER_UEFI_TYPES)),
    })
}

/// One intentionally small physical user data page mapped at offset zero
/// of a process-owned lower-canonical PML4 slot. Not executable.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[cfg(target_arch = "x86_64")]
fn user_base(slot: u16) -> Option<u64> {
    if (1..256).contains(&slot) {
        Some((slot as u64) << 39)
    } else {
        None
    }
}

/// Returns an immutable descriptor, not a pointer for untrusted code.
#[cfg(target_arch = "x86_64")]
pub fn mapped_page(process: Process) -> Option<Mapping> {
    if !MAPPED.load(Ordering::Acquire) {
        return None;
    }
    let (_, slot) = process_root(process)?;
    let physical_address = match process {
        Process::First => FIRST_FRAME.load(Ordering::Acquire),
        Process::Second => SECOND_FRAME.load(Ordering::Acquire),
    };
    if physical_address == 0 || physical_address & 4095 != 0 {
        return None;
    }
    Some(Mapping {
        virtual_address: user_base(slot)?,
        physical_address,
    })
}

/// Test-only: make the QEMU harness code/stack subtree visible in *only*
/// one selected process root. The foreign process root remains unchanged.
/// The same lower-level test-code tables are also in the kernel test root,
/// which is intentionally not a production process-loading strategy.
#[cfg(any(
    feature = "qemu-isolate-a",
    feature = "qemu-isolate-b",
    feature = "qemu-transfer-a",
    feature = "qemu-transfer-b"
))]
pub unsafe fn attach_test_probe(process: Process, entry: u64) -> Result<u64, Error> {
    let (owner_root, owner_slot) = process_root(process).ok_or(Error::KernelUnavailable)?;
    let other = match process {
        Process::First => Process::Second,
        Process::Second => Process::First,
    };
    let (other_root, foreign_slot) = process_root(other).ok_or(Error::KernelUnavailable)?;
    let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
    if entry >= 0x0000_8000_0000_0000 || entry & ((1u64 << 39) - 1) != 0 {
        return Err(Error::VerificationFailed);
    }
    let slot = (entry >> 39) as usize;
    if slot == 0
        || slot >= 256
        || slot == owner_slot as usize
        || slot == foreign_slot as usize
        || owner_root == other_root
    {
        return Err(Error::VerificationFailed);
    }
    // The test-only executable probe subtree is still borrowed from the
    // kernel, but its PML4 entry is now read and installed only through
    // the registered, Sorveth-owned physical-frame window.
    let source = read_registered_table_word(kernel, slot).ok_or(Error::VerificationFailed)?;
    if source & USER_TABLE_FLAGS != USER_TABLE_FLAGS
        || read_registered_table_word(owner_root, slot) != Some(0)
        || read_registered_table_word(other_root, slot) != Some(0)
        || read_registered_table_word(owner_root, foreign_slot as usize) != Some(0)
        || read_registered_table_word(other_root, owner_slot as usize) != Some(0)
    {
        return Err(Error::VerificationFailed);
    }
    write_registered_table_word(owner_root, slot, source).ok_or(Error::VerificationFailed)?;
    if read_registered_table_word(owner_root, slot) != Some(source) {
        return Err(Error::VerificationFailed);
    }
    Ok(owner_root)
}

/// Whitelist individual words of Sorveth's registered PML4/PDPT/PD/PT
/// frames, rejecting arbitrary physical addresses and out-of-page indices.
/// The policy is independent of the mapping used to access the frame.
#[cfg(target_arch = "x86_64")]
fn registered_table_word_allowed(frame: u64, index: usize, pages: &[u64; 9]) -> bool {
    frame != 0 && frame & 4095 == 0 && index < 512 && pages.contains(&frame)
}

/// Read one word of a *registered* kernel/process paging frame using the
/// high-half Sorveth-owned physical window. Never dereference a physical
/// table address supplied by a PTE or by ring-3 code.
///
/// # Safety
/// Requires the existing single-core, IRQ-masked, kernel-CR3 bootstrap.
/// The kernel and bootstrap root frames are fixed; private paging frames must
/// be present in the active process-table claim set.
#[cfg(target_arch = "x86_64")]
fn registered_table_frames() -> Option<[u64; 9]> {
    let kernel = crate::root::kernel_root_physical()?;
    let table_claims = unsafe { PROCESS_TABLE_CLAIMS };
    Some([
        kernel,
        ptr::addr_of!(FIRST).cast::<u64>() as u64,
        ptr::addr_of!(SECOND).cast::<u64>() as u64,
        table_claims[0].map_or(0, |claim| claim.span.start),
        table_claims[1].map_or(0, |claim| claim.span.start),
        table_claims[2].map_or(0, |claim| claim.span.start),
        table_claims[3].map_or(0, |claim| claim.span.start),
        table_claims[4].map_or(0, |claim| claim.span.start),
        table_claims[5].map_or(0, |claim| claim.span.start),
    ])
}

#[cfg(target_arch = "x86_64")]
fn process_table_frames() -> Option<[u64; 6]> {
    let claims = unsafe { PROCESS_TABLE_CLAIMS };
    Some([
        claims[0]?.span.start,
        claims[1]?.span.start,
        claims[2]?.span.start,
        claims[3]?.span.start,
        claims[4]?.span.start,
        claims[5]?.span.start,
    ])
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_registered_table_word(frame: u64, index: usize) -> Option<u64> {
    if !registered_table_word_allowed(frame, index, &registered_table_frames()?) {
        return None;
    }
    crate::root::with_physical_window(frame, |window| {
        ptr::read_volatile((window as *const u64).add(index))
    })
    .ok()
}

/// Read a known process PML4 slot through the owned supervisor window.
/// A caller cannot supply a raw root-frame address or expand the whitelist.
///
/// # Safety
/// The single QEMU bootstrap CPU has kernel CR3 active and IRQs masked.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_process_root_slot(process: Process, slot: u16) -> Option<u64> {
    let (root, _) = process_root(process)?;
    read_registered_table_word(root, slot as usize)
}

/// Read the first word of a permanently owned process test data frame.
/// Never expose the frame as an identity-mapped pointer.
///
/// # Safety
/// Only during the single-core, kernel-CR3, interrupts-off QEMU tests.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_process_frame_word(process: Process) -> Option<u64> {
    let mapping = mapped_page(process)?;
    crate::root::with_physical_window(mapping.physical_address, |window| {
        ptr::read_volatile(window as *const u64)
    })
    .ok()
}

/// Read one byte from the *registered* process data frame at a bounded
/// offset through Sorveth's owned supervisor frame window. The address
/// cannot be chosen outside the currently pinned one-page test mapping.
///
/// # Safety
/// Kernel CR3, one CPU, IRQs masked, process frame not reclaimed.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_process_frame_byte(process: Process, offset: usize) -> Option<u8> {
    if offset >= 4096 {
        return None;
    }
    let mapping = mapped_page(process)?;
    crate::root::with_physical_window(mapping.physical_address, |window| {
        ptr::read_volatile(window.add(offset) as *const u8)
    })
    .ok()
}

/// Temporarily corrupt the chosen known root's USER bit for a negative
/// authorization test, restoring the PML4 entry before returning.
/// The caller never receives a physical PML4 pointer.
///
/// # Safety
/// Kernel CR3, one CPU, IRQs masked, no concurrent root switches.
/// The predicate must neither switch CR3 nor retain physical mappings.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn verify_temporary_root_user_denial(
    process: Process,
    denied_while_corrupt: impl FnOnce() -> bool,
) -> bool {
    let (root, slot) = match process_root(process) {
        Some(value) => value,
        None => return false,
    };
    let saved = match read_registered_table_word(root, slot as usize) {
        Some(value) if value & (PRESENT | USER) == PRESENT | USER => value,
        _ => return false,
    };
    if checked_process_root(process).is_none() {
        return false;
    }
    if write_registered_table_word(root, slot as usize, saved & !USER).is_none() {
        return false;
    }
    let denied = denied_while_corrupt();
    // Restore unconditionally before attempting a potentially failing audit.
    let restored = write_registered_table_word(root, slot as usize, saved).is_some();
    restored
        && denied
        && read_registered_table_word(root, slot as usize) == Some(saved)
        && checked_process_root(process) == Some(root)
}

/// Store a PML4/PDPT/PD/PT word only in trusted bootstrap paging frames,
/// via the same owned temporary supervisor window as the audit reader.
/// Mapping mutations must be serialized and validated by their caller.
///
/// # Safety
/// Kernel CR3 active, IRQs masked, one CPU; the caller performs a full
/// address-space audit and CR3 transition only after tables are complete.
#[cfg(target_arch = "x86_64")]
unsafe fn write_registered_table_word(frame: u64, index: usize, value: u64) -> Option<()> {
    if !registered_table_word_allowed(frame, index, &registered_table_frames()?) {
        return None;
    }
    crate::root::with_physical_window(frame, |window| {
        ptr::write_volatile((window as *mut u64).add(index), value);
    })
    .ok()
}

/// M2-I.5: audit both private page-table paths immediately before a
/// kernel-controlled CR3 transition. Reject missing, aliased, malformed or
/// shared user data mappings before untrusted code could run.
///
/// # Safety
/// Restricted to the single QEMU bootstrap CPU, with IRQs disabled,
/// registered table frames and no concurrent page-table edits.
/// Reads use the Sorveth-owned window, not raw physical-pointer casts.
pub unsafe fn checked_process_root(process: Process) -> Option<u64> {
    if !MAPPED.load(Ordering::Acquire) {
        return None;
    }
    let (root_a, slot_a) = process_root(Process::First)?;
    let (root_b, slot_b) = process_root(Process::Second)?;
    let page_a = mapped_page(Process::First)?;
    let page_b = mapped_page(Process::Second)?;
    let kernel = crate::root::kernel_root_physical()?;
    if root_a == root_b
        || root_a == kernel
        || root_b == kernel
        || slot_a == slot_b
        || page_a.virtual_address == page_b.virtual_address
        || page_a.physical_address == page_b.physical_address
        || page_a.virtual_address != user_base(slot_a)?
        || page_b.virtual_address != user_base(slot_b)?
        || read_registered_table_word(kernel, slot_a as usize) != Some(0)
        || read_registered_table_word(kernel, slot_b as usize) != Some(0)
        || read_registered_table_word(root_a, slot_b as usize) != Some(0)
        || read_registered_table_word(root_b, slot_a as usize) != Some(0)
    {
        return None;
    }
    let tables = process_table_frames()?;
    let tables_a = [tables[0], tables[1], tables[2]];
    let tables_b = [tables[3], tables[4], tables[5]];
    for (i, table) in tables_a.iter().chain(tables_b.iter()).enumerate() {
        if *table == 0
            || *table & 4095 != 0
            || tables_a
                .iter()
                .chain(tables_b.iter())
                .take(i)
                .any(|previous| previous == table)
        {
            return None;
        }
    }
    if !validate_user_path(
        root_a,
        slot_a,
        tables_a[0],
        tables_a[1],
        tables_a[2],
        page_a.physical_address,
    ) || !validate_user_path(
        root_b,
        slot_b,
        tables_b[0],
        tables_b[1],
        tables_b[2],
        page_b.physical_address,
    ) {
        return None;
    }
    Some(match process {
        Process::First => root_a,
        Process::Second => root_b,
    })
}

/// The processor sets A on page-table ancestors and A/D on data leaves
/// during legitimate reads and writes. Compare only the immutable address,
/// permissions and NX policy; never forgive changes to P/W/U or the frame.
#[cfg(target_arch = "x86_64")]
fn entry_matches(actual: u64, expected: u64, leaf: bool) -> bool {
    let volatile = if leaf { ACCESSED | DIRTY } else { ACCESSED };
    actual & !volatile == expected
}

/// Controlled QEMU M2-J.4 regression: temporarily remove write access
/// from the inactive process's owned private data leaf. The general
/// M2-I.5 root audit should deny this altered mapping before any write.
///
/// # Safety
/// Must only run with the original kernel CR3 active on one CPU with
/// interrupts masked and no concurrent use of either user address space.
/// The original PTE is always restored before returning.
#[cfg(target_arch = "x86_64")]
pub unsafe fn verify_readonly_copy_out_denied(process: Process) -> bool {
    let own = match mapped_page(process) {
        Some(value) => value,
        None => return false,
    };
    let tables = match process_table_frames() {
        Some(tables) => tables,
        None => return false,
    };
    let leaf = match process {
        Process::First => tables[2],
        Process::Second => tables[5],
    };
    let previous = match read_registered_table_word(leaf, 0) {
        Some(entry) => entry,
        None => return false,
    };
    if previous & WRITE == 0 || checked_process_root(process).is_none() {
        return false;
    }
    let original = match crate::root::with_physical_window(own.physical_address, |window| {
        ptr::read_volatile(window as *const u64)
    }) {
        Ok(word) => word,
        Err(_) => return false,
    };

    if write_registered_table_word(leaf, 0, previous & !WRITE).is_none() {
        return false;
    }
    // Reuse the existing strict process-root audit. The change to the
    // inactive process's private PTE must be rejected before any copying.
    let denied = crate::user_copy::copy_to_process(process, own.virtual_address, &[0xa5])
        == Err(crate::user_copy::CopyOutError::InvalidMapping(
            sorveth_paging::user_walk::WalkError::InvalidRoot,
        ));
    // Restore before any further checks, including when the denial fails.
    let restored = write_registered_table_word(leaf, 0, previous).is_some();
    let unchanged = crate::root::with_physical_window(own.physical_address, |window| {
        ptr::read_volatile(window as *const u64) == original
    })
    .unwrap_or(false);
    restored
        && denied
        && read_registered_table_word(leaf, 0) == Some(previous)
        && unchanged
        && checked_process_root(process).is_some()
}

/// M2-J.2: inspect a validated user byte range under one trusted
/// process-owned PML4 root, without switching CR3 or touching user data.
/// Only known Sorveth-owned PML4/PDPT/PD/PT table pages can be read.
///
/// # Safety
/// Restricted to this single-CPU QEMU bootstrap. IRQs must remain disabled;
/// the trusted identity map and page tables must stay unchanged for the walk.
/// This returns a snapshot, NOT a pin or permission to copy user memory.
#[cfg(target_arch = "x86_64")]
pub unsafe fn walk_process_user_range(
    process: Process,
    range: sorveth_paging::user_range::UserRange,
    access: sorveth_paging::user_walk::UserAccess,
) -> Result<sorveth_paging::user_walk::ResolvedPages, sorveth_paging::user_walk::WalkError> {
    use sorveth_paging::user_walk::{walk_user_pages, WalkError};

    // Reuse M2-I.5 ownership auditing, not a user-supplied physical root.
    let root = checked_process_root(process).ok_or(WalkError::InvalidRoot)?;
    let tables = process_table_frames().ok_or(WalkError::InvalidRoot)?;
    let owned = match process {
        Process::First => [
            root,
            tables[0],
            tables[1],
            tables[2],
        ],
        Process::Second => [
            root,
            tables[3],
            tables[4],
            tables[5],
        ],
    };

    // Deny any entry outside this process's audited four-frame whitelist,
    // then read through the kernel-owned high-half window. No page-table
    // entry physical address is directly dereferenced as a pointer.
    walk_user_pages(root, range, access, |entry_address| {
        if !approved_table_entry(&owned, entry_address) {
            return None;
        }
        let page = entry_address & !4095;
        crate::root::with_physical_window(page, |window| {
            ptr::read_volatile(window.add((entry_address - page) as usize) as *const u64)
        })
        .ok()
    })
}

/// Read only an aligned u64 entry fully contained in a page-table frame
/// explicitly owned by the selected process. Physical addresses obtained from
/// untrusted PTEs must never expand the caller's whitelist.
#[cfg(target_arch = "x86_64")]
fn approved_table_entry(owned: &[u64; 4], entry_address: u64) -> bool {
    let page = entry_address & !4095;
    entry_address & 7 == 0
        && entry_address
            .checked_sub(page)
            .is_some_and(|offset| offset <= 4096 - 8)
        && owned.contains(&page)
}

/// Live QEMU acceptance: validate both real process-private USER pages,
/// reject the other process's unmapped slot, and reject an otherwise valid
/// two-byte numeric range which crosses into an absent second leaf page.
/// The kernel stays on its root; no user data is dereferenced in this test.
///
/// # Safety
/// One bootstrap CPU, IRQs masked; M2-I.5 and M2-J.1 already passed.
#[cfg(target_arch = "x86_64")]
pub unsafe fn verify_user_page_walk() -> bool {
    use sorveth_paging::{
        user_range::validate_user_range,
        user_walk::{UserAccess, WalkError},
        PAGE_BYTES,
    };

    for (owner, foreign) in [
        (Process::First, Process::Second),
        (Process::Second, Process::First),
    ] {
        let own = match mapped_page(owner) {
            Some(page) => page,
            None => return false,
        };
        let other = match mapped_page(foreign) {
            Some(page) => page,
            None => return false,
        };
        let range = match validate_user_range(own.virtual_address + 7, 16) {
            Ok(range) => range,
            Err(_) => return false,
        };
        for access in [UserAccess::Read, UserAccess::Write] {
            match walk_process_user_range(owner, range, access) {
                Ok(pages)
                    if pages.page_count() == 1
                        && pages.physical_page(0) == Some(own.physical_address)
                        && pages.physical_page(1).is_none() => {}
                _ => return false,
            }
        }

        // The foreign *number* is canonical and lies in the user region,
        // but must not be interpreted as owned by this process.
        let foreign_range = match validate_user_range(other.virtual_address, 8) {
            Ok(range) => range,
            Err(_) => return false,
        };
        if walk_process_user_range(owner, foreign_range, UserAccess::Read)
            != Err(WalkError::MissingMapping)
        {
            return false;
        }

        // First page is present, second is not. A complete walk must
        // reject the entire request rather than return partial success.
        let crossing = match validate_user_range(own.virtual_address + PAGE_BYTES - 1, 2) {
            Ok(range) => range,
            Err(_) => return false,
        };
        if walk_process_user_range(owner, crossing, UserAccess::Read)
            != Err(WalkError::MissingMapping)
        {
            return false;
        }
    }
    true
}

/// Check all four PML4/PDPT/PD/PT entries without using user virtual
/// addresses or a physical identity-pointer dereference. Only the known
/// registered owned paging frames can be read through the owned window.
#[cfg(target_arch = "x86_64")]
unsafe fn validate_user_path(root: u64, slot: u16, pdpt: u64, pd: u64, pt: u64, data: u64) -> bool {
    let (Some(pml4_entry), Some(pdpt_entry), Some(pd_entry), Some(leaf_entry)) = (
        read_registered_table_word(root, slot as usize),
        read_registered_table_word(pdpt, 0),
        read_registered_table_word(pd, 0),
        read_registered_table_word(pt, 0),
    ) else {
        return false;
    };
    entry_matches(pml4_entry, pdpt | USER_TABLE_FLAGS, false)
        && entry_matches(pdpt_entry, pd | USER_TABLE_FLAGS, false)
        && entry_matches(pd_entry, pt | USER_TABLE_FLAGS, false)
        && entry_matches(leaf_entry, data | USER_DATA_FLAGS, true)
}

/// Claim two distinct conventional physical frames from the permanent ledger,
/// zero them, and install private USER RW/NX leaf mappings in each process
/// root's reserved slot. Test real CPU reads/writes after CR3 transitions.
///
/// # Safety
/// Single QEMU bootstrap CPU only, kernel CPL0, interrupts masked; M2-I.1
/// must be complete, and Sorveth's temporary physical window must be active.
/// No process is executing concurrently or retaining an address-space lease.
/// This verifies mapping ownership, NOT safe general userland or fault recovery.
pub unsafe fn map_private_pages(pool: &sorveth_frames::FramePool<256>) -> Result<(), Error> {
    unsafe { map_private_pages_inner(pool, false) }
}

/// Fail after both claims and mapping references are staged, then prove the
/// real setup rollback returns every frame to the allocator.
///
/// # Safety
/// Same single-CPU, kernel-root, IRQ-masked conditions as `map_private_pages`.
pub unsafe fn verify_setup_rollback(pool: &sorveth_frames::FramePool<256>) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        let pages_before = pool
            .status()
            .map_err(|_| Error::FrameUnavailable)?
            .available_pages;
        let claims_before = pool.claim_count().map_err(|_| Error::FrameUnavailable)?;
        match unsafe { map_private_pages_inner(pool, true) } {
            Err(Error::SetupFailureInjected) => {}
            _ => return Err(Error::VerificationFailed),
        }
        if pool
            .status()
            .map_err(|_| Error::FrameUnavailable)?
            .available_pages
            != pages_before
            || pool.claim_count().map_err(|_| Error::FrameUnavailable)? != claims_before
            || MAPPED.load(Ordering::Acquire)
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = pool;
        Err(Error::Unsupported)
    }
}

unsafe fn map_private_pages_inner(
    pool: &sorveth_frames::FramePool<256>,
    inject_failure_after_staging: bool,
) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if !READY.load(Ordering::Acquire) {
            return Err(Error::KernelUnavailable);
        }
        if MAPPED.load(Ordering::Acquire) {
            return Err(Error::AlreadyMapped);
        }
        let (first_root, first_slot) =
            process_root(Process::First).ok_or(Error::KernelUnavailable)?;
        let (second_root, second_slot) =
            process_root(Process::Second).ok_or(Error::KernelUnavailable)?;
        let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
        let first_virt = user_base(first_slot).ok_or(Error::VerificationFailed)?;
        let second_virt = user_base(second_slot).ok_or(Error::VerificationFailed)?;
        if first_root == second_root || first_slot == second_slot || first_virt == second_virt {
            return Err(Error::VerificationFailed);
        }
        let active: u64;
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        if active & ADDRESS_MASK != kernel {
            return Err(Error::KernelUnavailable);
        }

        // Preflight both reserved root slots before changing any of the
        // lower-level tables they might reference.
        if read_registered_table_word(first_root, first_slot as usize) != Some(0)
            || read_registered_table_word(second_root, second_slot as usize) != Some(0)
            || read_registered_table_word(first_root, second_slot as usize) != Some(0)
            || read_registered_table_word(second_root, first_slot as usize) != Some(0)
            || read_registered_table_word(kernel, first_slot as usize) != Some(0)
            || read_registered_table_word(kernel, second_slot as usize) != Some(0)
        {
            return Err(Error::VerificationFailed);
        }

        // Every mapping lifetime owns its six private paging frames through
        // the same generation-checked frame ledger as its user data pages.
        let roots = [(first_root, first_slot), (second_root, second_slot)];
        let mut claims = [None; 8];
        for index in 0..6 {
            match pool.claim_unmapped_for(
                1,
                sorveth_frames::FrameOwner::PROCESS_PAGE_TABLES,
            ) {
                Ok(claim) => claims[index + 2] = Some(claim),
                Err(_) => {
                    unsafe {
                        rollback_private_claims(pool, claims, [false; 8], roots, [0; 6])?
                    };
                    return Err(Error::FrameUnavailable);
                }
            }
        }
        let tables = core::array::from_fn(|index| claims[index + 2].unwrap().span.start);
        for (index, table) in tables.iter().enumerate() {
            if *table == 0 || *table & 4095 != 0 || tables[..index].contains(table) {
                unsafe { rollback_private_claims(pool, claims, [false; 8], roots, tables)? };
                return Err(Error::PageTableStorageUnavailable);
            }
        }
        unsafe {
            PROCESS_TABLE_CLAIMS = core::array::from_fn(|index| claims[index + 2]);
        }
        for table in tables {
            let initialized = crate::root::with_physical_window(table, |window| {
                ptr::write_bytes(window, 0, 4096);
                ptr::read_volatile(window as *const u64) == 0
                    && ptr::read_volatile((window as *const u64).add(511)) == 0
            });
            match initialized {
                Ok(true) => {}
                Ok(false) => {
                    unsafe {
                        rollback_private_claims(pool, claims, [false; 8], roots, tables)?
                    };
                    return Err(Error::VerificationFailed);
                }
                Err(_) => {
                    unsafe {
                        rollback_private_claims(pool, claims, [false; 8], roots, tables)?
                    };
                    return Err(Error::PageTableStorageUnavailable);
                }
            }
        }

        claims[0] = match pool
            .claim_unmapped_for(1, sorveth_frames::FrameOwner::PROCESS_FIRST_DATA)
        {
            Ok(claim) => Some(claim),
            Err(_) => {
                unsafe { rollback_private_claims(pool, claims, [false; 8], roots, tables)? };
                return Err(Error::FrameUnavailable);
            }
        };
        claims[1] = match pool
            .claim_unmapped_for(1, sorveth_frames::FrameOwner::PROCESS_SECOND_DATA)
        {
            Ok(claim) => Some(claim),
            Err(_) => {
                unsafe { rollback_private_claims(pool, claims, [false; 8], roots, tables)? };
                return Err(Error::FrameUnavailable);
            }
        };
        let claim_a = claims[0].unwrap();
        let claim_b = claims[1].unwrap();
        let mut mapping_refs = [false; 8];
        let result = (|| -> Result<(), Error> {
            let frame_a = claim_a.span.start;
            let frame_b = claim_b.span.start;
            if RECLAIMED_ONCE.load(Ordering::Acquire)
                && (frame_a != FIRST_FRAME.load(Ordering::Acquire)
                    || frame_b != SECOND_FRAME.load(Ordering::Acquire)
                    || FIRST_GENERATION.load(Ordering::Acquire).checked_add(1)
                        != Some(claim_a.handle.generation() as u64)
                    || SECOND_GENERATION.load(Ordering::Acquire).checked_add(1)
                        != Some(claim_b.handle.generation() as u64))
            {
                return Err(Error::VerificationFailed);
            }
            if frame_a == frame_b
                || frame_a == 0
                || frame_b == 0
                || frame_a & 4095 != 0
                || frame_b & 4095 != 0
            {
                return Err(Error::FrameUnavailable);
            }
            // Both ledger-claimed data frames are initialized through Sorveth's
            // temporary supervisor alias. Their physical addresses are not
            // directly dereferenced and need no firmware identity mapping.
            for frame in [frame_a, frame_b] {
                let zeroed = crate::root::with_physical_window(frame, |window| {
                    ptr::write_bytes(window, 0, 4096);
                    ptr::read_volatile(window as *const u64) == 0
                })
                .map_err(|_| Error::FrameUnavailable)?;
                if !zeroed {
                    return Err(Error::VerificationFailed);
                }
            }

            // Each process gets distinct PML4/PDPT/PD/PT ancestors. Their root
            // slots were verified empty before any frame was claimed.
            let (a_pdpt, a_pd, a_pt) = (tables[0], tables[1], tables[2]);
            let (b_pdpt, b_pd, b_pt) = (tables[3], tables[4], tables[5]);
            for index in 0..6 {
                let claim = claims[index + 2].ok_or(Error::FrameUnavailable)?;
                if pool
                    .retain_mapping(
                        claim.handle,
                        sorveth_frames::FrameOwner::PROCESS_PAGE_TABLES,
                    )
                    .map_err(|_| Error::FrameUnavailable)?
                    != 1
                {
                    return Err(Error::VerificationFailed);
                }
                mapping_refs[index + 2] = true;
            }
            if pool
                .retain_mapping(
                    claim_a.handle,
                    sorveth_frames::FrameOwner::PROCESS_FIRST_DATA,
                )
                .map_err(|_| Error::FrameUnavailable)?
                != 1
            {
                return Err(Error::VerificationFailed);
            }
            mapping_refs[0] = true;
            if pool
                .retain_mapping(
                    claim_b.handle,
                    sorveth_frames::FrameOwner::PROCESS_SECOND_DATA,
                )
                .map_err(|_| Error::FrameUnavailable)?
                != 1
            {
                return Err(Error::VerificationFailed);
            }
            mapping_refs[1] = true;
            if inject_failure_after_staging {
                return Err(Error::SetupFailureInjected);
            }
            for (table, index, value) in [
                (a_pt, 0, frame_a | USER_DATA_FLAGS),
                (b_pt, 0, frame_b | USER_DATA_FLAGS),
                (a_pd, 0, a_pt | USER_TABLE_FLAGS),
                (b_pd, 0, b_pt | USER_TABLE_FLAGS),
                (a_pdpt, 0, a_pd | USER_TABLE_FLAGS),
                (b_pdpt, 0, b_pd | USER_TABLE_FLAGS),
                (first_root, first_slot as usize, a_pdpt | USER_TABLE_FLAGS),
                (second_root, second_slot as usize, b_pdpt | USER_TABLE_FLAGS),
            ] {
                write_registered_table_word(table, index, value)
                    .ok_or(Error::PageTableStorageUnavailable)?;
            }
            if !validate_user_path(first_root, first_slot, a_pdpt, a_pd, a_pt, frame_a)
                || !validate_user_path(second_root, second_slot, b_pdpt, b_pd, b_pt, frame_b)
                || read_registered_table_word(first_root, second_slot as usize) != Some(0)
                || read_registered_table_word(second_root, first_slot as usize) != Some(0)
            {
                return Err(Error::VerificationFailed);
            }

            // Actual x86 translation and memory writes under each independent
            // CR3 root, with a full CR3 reload flushing non-global TLB entries.
            let mut valid = true;
            for (root, address, expected) in [
                (first_root, first_virt, FIRST_TEST_WORD),
                (second_root, second_virt, SECOND_TEST_WORD),
            ] {
                asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
                let mut observed: u64;
                asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
                if observed & ADDRESS_MASK != root {
                    valid = false;
                    break;
                }
                ptr::write_volatile(address as *mut u64, expected);
                // The user-virtual read proves data visibility under the selected
                // process root. Physical-frame verification follows after the
                // kernel CR3 is restored, through its own mapped window.
                if ptr::read_volatile(address as *const u64) != expected {
                    valid = false;
                    break;
                }
            }
            asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
            let restored: u64;
            asm!("mov {}, cr3", out(reg) restored, options(nomem, nostack, preserves_flags));
            if restored & ADDRESS_MASK != kernel {
                return Err(Error::VerificationFailed);
            }
            let observed_a = crate::root::with_physical_window(frame_a, |window| {
                ptr::read_volatile(window as *const u64)
            })
            .map_err(|_| Error::VerificationFailed)?;
            let observed_b = crate::root::with_physical_window(frame_b, |window| {
                ptr::read_volatile(window as *const u64)
            })
            .map_err(|_| Error::VerificationFailed)?;
            if !valid
                || observed_a != FIRST_TEST_WORD
                || observed_b != SECOND_TEST_WORD
                || ptr::read_volatile((kernel as *const u64).add(first_slot as usize)) != 0
                || ptr::read_volatile((kernel as *const u64).add(second_slot as usize)) != 0
            {
                return Err(Error::VerificationFailed);
            }
            FIRST_FRAME.store(frame_a, Ordering::Release);
            SECOND_FRAME.store(frame_b, Ordering::Release);
            FIRST_GENERATION.store(claim_a.handle.generation() as u64, Ordering::Release);
            SECOND_GENERATION.store(claim_b.handle.generation() as u64, Ordering::Release);
            unsafe {
                FIRST_CLAIM = Some(claim_a);
                SECOND_CLAIM = Some(claim_b);
            }
            RECLAIMED_ONCE.store(false, Ordering::Release);
            MAPPED.store(true, Ordering::Release);
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                rollback_private_claims(
                    pool,
                    claims,
                    mapping_refs,
                    roots,
                    tables,
                )?
            };
        }
        result
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = pool;
        Err(Error::Unsupported)
    }
}

/// Roll back claims that have not been committed as a process address space.
/// Clearing both reserved root slots first covers failures before, during, or
/// after leaf publication; mapping references are dropped only after the local
/// address translations have been invalidated.
#[cfg(target_arch = "x86_64")]
unsafe fn rollback_private_claims(
    pool: &sorveth_frames::FramePool<256>,
    claims: [Option<sorveth_frames::OwnedSpan>; 8],
    mapping_refs: [bool; 8],
    roots: [(u64, u16); 2],
    tables: [u64; 6],
) -> Result<(), Error> {
    let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
    let active: u64;
    asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    if active & ADDRESS_MASK != kernel {
        return Err(Error::KernelUnavailable);
    }
    let addresses = [
        user_base(roots[0].1).ok_or(Error::VerificationFailed)?,
        user_base(roots[1].1).ok_or(Error::VerificationFailed)?,
    ];
    for (root, slot) in roots {
        if write_registered_table_word(root, slot as usize, 0).is_none() {
            return Err(Error::PageTableStorageUnavailable);
        }
    }
    compiler_fence(Ordering::SeqCst);
    for address in addresses {
        asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
    }
    asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
    for table in tables.into_iter().filter(|table| *table != 0) {
        crate::root::with_physical_window(table, |window| {
            ptr::write_bytes(window, 0, 4096);
        })
        .map_err(|_| Error::PageTableStorageUnavailable)?;
    }

    for (index, claim) in claims.into_iter().enumerate() {
        let Some(claim) = claim else {
            continue;
        };
        let owner = match index {
            0 => sorveth_frames::FrameOwner::PROCESS_FIRST_DATA,
            1 => sorveth_frames::FrameOwner::PROCESS_SECOND_DATA,
            _ => sorveth_frames::FrameOwner::PROCESS_PAGE_TABLES,
        };
        if mapping_refs[index]
            && unsafe { pool.release_mapping(claim.handle, owner) }
                .map_err(|_| Error::FrameUnavailable)?
                != 0
        {
            return Err(Error::VerificationFailed);
        }
        if pool
            .release_claim_reference(claim.handle, owner)
            .map_err(|_| Error::FrameUnavailable)?
            != 0
        {
            return Err(Error::VerificationFailed);
        }
        let ticket = pool
            .begin_quarantine(claim.handle, owner)
            .map_err(|_| Error::FrameUnavailable)?;
        unsafe { crate::root::zero_quarantined_span(pool, ticket, owner) }
            .map_err(|_| Error::FrameUnavailable)?;
    }
    unsafe {
        FIRST_CLAIM = None;
        SECOND_CLAIM = None;
        PROCESS_TABLE_CLAIMS = [None; 6];
    }
    MAPPED.store(false, Ordering::Release);
    Ok(())
}

/// Remove both bootstrap process data mappings, invalidate their local
/// translations, and recycle the frames through the zero-before-reuse path.
///
/// # Safety
/// The kernel root must be active on the sole CPU with interrupts masked.
/// Neither process may be executing or concurrently inspected.
pub unsafe fn teardown_private_pages(pool: &sorveth_frames::FramePool<256>) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if !MAPPED.load(Ordering::Acquire) {
            return Err(Error::NotMapped);
        }
        let kernel = crate::root::kernel_root_physical().ok_or(Error::KernelUnavailable)?;
        let active: u64;
        let flags: u64;
        asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        if active & ADDRESS_MASK != kernel || flags & (1 << 9) != 0 {
            return Err(Error::KernelUnavailable);
        }
        let pages_before = pool
            .status()
            .map_err(|_| Error::FrameUnavailable)?
            .available_pages;
        let claims_before = pool.claim_count().map_err(|_| Error::FrameUnavailable)?;

        let claim_a = unsafe { FIRST_CLAIM }.ok_or(Error::FrameUnavailable)?;
        let claim_b = unsafe { SECOND_CLAIM }.ok_or(Error::FrameUnavailable)?;
        let table_claims = unsafe { PROCESS_TABLE_CLAIMS };
        let tables = process_table_frames().ok_or(Error::PageTableStorageUnavailable)?;
        let owner_a = sorveth_frames::FrameOwner::PROCESS_FIRST_DATA;
        let owner_b = sorveth_frames::FrameOwner::PROCESS_SECOND_DATA;
        let record_a = pool
            .claim_record_at(claim_a.handle.slot() as usize)
            .map_err(|_| Error::FrameUnavailable)?
            .ok_or(Error::FrameUnavailable)?;
        let record_b = pool
            .claim_record_at(claim_b.handle.slot() as usize)
            .map_err(|_| Error::FrameUnavailable)?
            .ok_or(Error::FrameUnavailable)?;
        if record_a.generation() != claim_a.handle.generation()
            || record_b.generation() != claim_b.handle.generation()
            || record_a.owner() != owner_a
            || record_b.owner() != owner_b
            || record_a.span() != claim_a.span
            || record_b.span() != claim_b.span
            || record_a.references() != 1
            || record_b.references() != 1
            || record_a.mappings() != 1
            || record_b.mappings() != 1
            || record_a.is_quarantined()
            || record_b.is_quarantined()
            || checked_process_root(Process::First).is_none()
            || checked_process_root(Process::Second).is_none()
        {
            return Err(Error::VerificationFailed);
        }
        for claim in table_claims.into_iter().flatten() {
            let record = pool
                .claim_record_at(claim.handle.slot() as usize)
                .map_err(|_| Error::FrameUnavailable)?
                .ok_or(Error::FrameUnavailable)?;
            if record.generation() != claim.handle.generation()
                || record.owner() != sorveth_frames::FrameOwner::PROCESS_PAGE_TABLES
                || record.span() != claim.span
                || record.references() != 1
                || record.mappings() != 1
                || record.is_quarantined()
            {
                return Err(Error::VerificationFailed);
            }
        }

        let (root_a, slot_a) = process_root(Process::First).ok_or(Error::KernelUnavailable)?;
        let (root_b, slot_b) = process_root(Process::Second).ok_or(Error::KernelUnavailable)?;
        let address_a = user_base(slot_a).ok_or(Error::VerificationFailed)?;
        let address_b = user_base(slot_b).ok_or(Error::VerificationFailed)?;
        let saved_a =
            read_registered_table_word(root_a, slot_a as usize).ok_or(Error::VerificationFailed)?;
        let saved_b =
            read_registered_table_word(root_b, slot_b as usize).ok_or(Error::VerificationFailed)?;

        if write_registered_table_word(root_a, slot_a as usize, 0).is_none() {
            return Err(Error::PageTableStorageUnavailable);
        }
        if write_registered_table_word(root_b, slot_b as usize, 0).is_none() {
            if write_registered_table_word(root_a, slot_a as usize, saved_a).is_some() {
                compiler_fence(Ordering::SeqCst);
                asm!("invlpg [{}]", in(reg) address_a, options(nostack, preserves_flags));
                asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));
            }
            return Err(Error::PageTableStorageUnavailable);
        }
        compiler_fence(Ordering::SeqCst);
        asm!("invlpg [{}]", in(reg) address_a, options(nostack, preserves_flags));
        asm!("invlpg [{}]", in(reg) address_b, options(nostack, preserves_flags));
        // CR3 reload flushes the remaining non-global translations for this
        // single CPU before the mapping ledger references are dropped.
        asm!("mov cr3, {}", in(reg) kernel, options(nostack, preserves_flags));

        for table in tables {
            crate::root::with_physical_window(table, |window| {
                ptr::write_bytes(window, 0, 4096);
            })
            .map_err(|_| Error::PageTableStorageUnavailable)?;
        }
        if read_registered_table_word(root_a, slot_a as usize) != Some(0)
            || read_registered_table_word(root_b, slot_b as usize) != Some(0)
        {
            return Err(Error::VerificationFailed);
        }

        if unsafe { pool.release_mapping(claim_a.handle, owner_a) }
            .map_err(|_| Error::FrameUnavailable)?
            != 0
            || unsafe { pool.release_mapping(claim_b.handle, owner_b) }
                .map_err(|_| Error::FrameUnavailable)?
                != 0
        {
            return Err(Error::VerificationFailed);
        }
        if pool
            .release_claim_reference(claim_a.handle, owner_a)
            .map_err(|_| Error::FrameUnavailable)?
            != 0
            || pool
                .release_claim_reference(claim_b.handle, owner_b)
                .map_err(|_| Error::FrameUnavailable)?
                != 0
        {
            return Err(Error::VerificationFailed);
        }
        let ticket_a = pool
            .begin_quarantine(claim_a.handle, owner_a)
            .map_err(|_| Error::FrameUnavailable)?;
        let ticket_b = pool
            .begin_quarantine(claim_b.handle, owner_b)
            .map_err(|_| Error::FrameUnavailable)?;
        unsafe { crate::root::zero_quarantined_span(pool, ticket_a, owner_a) }
            .map_err(|_| Error::FrameUnavailable)?;
        unsafe { crate::root::zero_quarantined_span(pool, ticket_b, owner_b) }
            .map_err(|_| Error::FrameUnavailable)?;

        for claim in table_claims.into_iter().flatten() {
            let owner = sorveth_frames::FrameOwner::PROCESS_PAGE_TABLES;
            if unsafe { pool.release_mapping(claim.handle, owner) }
                .map_err(|_| Error::FrameUnavailable)?
                != 0
            {
                return Err(Error::VerificationFailed);
            }
            if pool
                .release_claim_reference(claim.handle, owner)
                .map_err(|_| Error::FrameUnavailable)?
                != 0
            {
                return Err(Error::VerificationFailed);
            }
            let ticket = pool
                .begin_quarantine(claim.handle, owner)
                .map_err(|_| Error::FrameUnavailable)?;
            unsafe { crate::root::zero_quarantined_span(pool, ticket, owner) }
                .map_err(|_| Error::FrameUnavailable)?;
        }
        if pool
            .status()
            .map_err(|_| Error::FrameUnavailable)?
            .available_pages
            != pages_before
                .checked_add(8)
                .ok_or(Error::VerificationFailed)?
            || pool.claim_count().map_err(|_| Error::FrameUnavailable)?
                != claims_before
                    .checked_sub(8)
                    .ok_or(Error::VerificationFailed)?
        {
            return Err(Error::VerificationFailed);
        }

        unsafe {
            FIRST_CLAIM = None;
            SECOND_CLAIM = None;
            PROCESS_TABLE_CLAIMS = [None; 6];
        }
        MAPPED.store(false, Ordering::Release);
        RECLAIMED_ONCE.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = pool;
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn owned_page_table_reader_rejects_foreign_unaligned_and_cross_page_entries() {
        let owned = [0x1000, 0x2000, 0x3000, 0x4000];
        assert!(approved_table_entry(&owned, 0x1000));
        assert!(approved_table_entry(&owned, 0x1ff8));
        assert!(approved_table_entry(&owned, 0x4008));
        assert!(!approved_table_entry(&owned, 0x5000));
        assert!(!approved_table_entry(&owned, 0x1001));
        assert!(!approved_table_entry(&owned, 0x1fff));
        assert!(!approved_table_entry(&owned, u64::MAX));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn registered_table_word_policy_rejects_foreign_frames_and_oob_indices() {
        let allowed = [
            0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000,
        ];
        assert!(registered_table_word_allowed(0x1000, 0, &allowed));
        assert!(registered_table_word_allowed(0x9000, 511, &allowed));
        assert!(!registered_table_word_allowed(0x1000, 512, &allowed));
        assert!(!registered_table_word_allowed(0x1001, 0, &allowed));
        assert!(!registered_table_word_allowed(0, 0, &allowed));
        assert!(!registered_table_word_allowed(0xa000, 0, &allowed));
        assert!(!registered_table_word_allowed(u64::MAX, 0, &allowed));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn audit_allows_cpu_accessed_dirty_bits_but_rejects_permission_drift() {
        let ancestor = 0x1234_5000 | USER_TABLE_FLAGS;
        assert!(entry_matches(ancestor, ancestor, false));
        assert!(entry_matches(ancestor | ACCESSED, ancestor, false));
        assert!(!entry_matches(ancestor | DIRTY, ancestor, false));
        assert!(!entry_matches(ancestor & !USER, ancestor, false));
        assert!(!entry_matches(ancestor & !WRITE, ancestor, false));

        let leaf = 0x5678_9000 | USER_DATA_FLAGS;
        assert!(entry_matches(leaf | ACCESSED | DIRTY, leaf, true));
        assert!(!entry_matches(leaf & !USER, leaf, true));
        assert!(!entry_matches(leaf & !WRITE, leaf, true));
        assert!(!entry_matches(leaf & !NO_EXECUTE, leaf, true));
        assert!(!entry_matches(leaf ^ 0x1000, leaf, true));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn private_data_mapping_has_user_read_write_but_never_execute() {
        assert_eq!(USER_DATA_FLAGS & USER, USER);
        assert_eq!(USER_DATA_FLAGS & WRITE, WRITE);
        assert_eq!(USER_DATA_FLAGS & PRESENT, PRESENT);
        assert_ne!(USER_DATA_FLAGS & NO_EXECUTE, 0);
        assert_eq!(USER_TABLE_FLAGS & NO_EXECUTE, 0);
        assert_eq!(user_base(0), None);
        assert_eq!(user_base(256), None);
        assert_eq!(user_base(255), Some(255u64 << 39));
        assert_eq!(user_base(254), Some(254u64 << 39));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn inherited_user_bit_is_removed_and_absent_entries_zeroed() {
        assert_eq!(supervisor_entry(0x1007), 0x1003);
        assert_eq!(supervisor_entry(0x2007 | 1 << 63), 0x2003 | 1 << 63);
        assert_eq!(supervisor_entry(0xffe), 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn process_slots_must_be_distinct_lower_half_and_empty() {
        let mut pml4 = [1u64; 512];
        pml4[0] = 0;
        pml4[255] = 0;
        pml4[254] = 0;
        assert_eq!(vacant_slots(|i| pml4[i]), Some((255, 254)));
        pml4[254] = 1;
        assert_eq!(vacant_slots(|i| pml4[i]), None);
        pml4[253] = 0;
        assert_eq!(vacant_slots(|i| pml4[i]), Some((255, 253)));
    }
}
