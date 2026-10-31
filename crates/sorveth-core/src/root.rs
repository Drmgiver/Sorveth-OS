//! M1-B2 / M2-K.1a: owned PML4 plus transitional high-half frame window.
//!
//! Only supported for the x86-64 UEFI identity-mapped QEMU bootstrap.
//! The backing page is 4096-byte aligned and permanently retained in the
//! loader image. CR3 is changed only after translation/identity checks.
//! One independent high-half supervisor NX page is mapped through private
//! PDPT/PD/PT tables; the remaining lower levels still belong to firmware.
//! This is NOT yet a complete independent address space or user isolation.

use sorveth_frames::{FrameOwner, FramePool};

#[cfg(target_arch = "x86_64")]
use core::{
    ptr,
    sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedArchitecture,
    FirmwareTablesNotIdentityMapped,
    NewRootNotIdentityMapped,
    InvalidRoot,
    RootAlreadyInstalled,
    VerificationFailed,
    NoFreeVirtualSlot,
    PrivateTablesNotIdentityMapped,
    TestFrameNotIdentityMapped,
    FrameUnavailable,
    NxUnsupported,
    RootNotInstalled,
    ScratchAddressUnavailable,
    PhysicalWindowInvalid,
    PhysicalWindowBusy,
    WrongCpuContext,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct RootPage([u64; 512]);

#[cfg(target_arch = "x86_64")]
static mut SORVETH_ROOT: RootPage = RootPage([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SORVETH_PDPT: RootPage = RootPage([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SORVETH_PD: RootPage = RootPage([0; 512]);
#[cfg(target_arch = "x86_64")]
static mut SORVETH_PT: RootPage = RootPage([0; 512]);
/// Four statically retained Sorveth-owned bootstrap paging frames.
/// Their initial virtual addresses are verified identity addresses in QEMU;
/// this is an inventory hook, not an interface for physical memory writes.
#[cfg(target_arch = "x86_64")]
pub(crate) fn bootstrap_owned_table_frames() -> [u64; 4] {
    [
        ptr::addr_of!(SORVETH_ROOT) as u64,
        ptr::addr_of!(SORVETH_PDPT) as u64,
        ptr::addr_of!(SORVETH_PD) as u64,
        ptr::addr_of!(SORVETH_PT) as u64,
    ]
}

#[cfg(target_arch = "x86_64")]
static ACTIVE_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static UNMAPPED_TEST: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static PRIVATE_BASE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static NEXT_PRIVATE_PAGE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
const PHYSICAL_WINDOW_INDEX: usize = 511;
// Reserve the preceding upper-half leaf for direct kernel access to its own
// private PT page. The leaf itself is not user accessible.
#[cfg(target_arch = "x86_64")]
const PRIVATE_PT_ALIAS_INDEX: usize = 510;
#[cfg(target_arch = "x86_64")]
static PHYSICAL_WINDOW_BUSY: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(target_arch = "x86_64")]
const PRESENT: u64 = 1;
#[cfg(target_arch = "x86_64")]
const HUGE: u64 = 1 << 7;
#[cfg(target_arch = "x86_64")]
const WRITE: u64 = 1 << 1;
#[cfg(target_arch = "x86_64")]
const NO_EXECUTE: u64 = 1 << 63;
#[cfg(target_arch = "x86_64")]
const TEST_WORD: u64 = 0x53_4f_52_56_45_54_48_21; // "SORVETH!"

/// Resolve a canonical x86-64 virtual address using 4-level paging.
/// The closure receives *physical* addresses of page-table entries; it must
/// provide a safe read of those entries. This does not dereference physical
/// memory itself and can be unit tested with synthetic page tables.
#[cfg(target_arch = "x86_64")]
fn translate<F>(root: u64, virtual_address: u64, mut read: F) -> Option<u64>
where
    F: FnMut(u64) -> Option<u64>,
{
    if !(virtual_address < 0x0000_8000_0000_0000 || virtual_address >= 0xffff_8000_0000_0000) {
        return None;
    }
    if root == 0 || root & 4095 != 0 {
        return None;
    }
    let mut table = root;
    for shift in [39u32, 30, 21, 12] {
        let index = (virtual_address >> shift) & 511;
        let entry_address = table.checked_add(index * 8)?;
        let entry = read(entry_address)?;
        if entry & PRESENT == 0 {
            return None;
        }
        if shift == 30 || shift == 21 {
            if entry & HUGE != 0 {
                let offset_mask = (1u64 << shift) - 1;
                let base = (entry & ADDRESS_MASK) & !offset_mask;
                return Some(base | (virtual_address & offset_mask));
            }
        } else if shift == 39 && entry & HUGE != 0 {
            return None;
        }
        if shift == 12 {
            return Some((entry & ADDRESS_MASK) | (virtual_address & 4095));
        }
        table = entry & ADDRESS_MASK;
        if table == 0 {
            return None;
        }
    }
    None
}

/// In this QEMU-only bootstrap, OVMF is expected to identity-map page-table
/// memory. Accessing physical table addresses as pointers is unsafe on
/// machines without that direct map. Do not use on bare metal without an
/// independently validated physical-memory window and fault handler.
#[cfg(target_arch = "x86_64")]
unsafe fn inherited_translate(root: u64, address: u64) -> Option<u64> {
    translate(root, address, |phys| {
        if phys == 0 || phys & 7 != 0 {
            return None;
        }
        Some(ptr::read_volatile(phys as *const u64))
    })
}

#[cfg(target_arch = "x86_64")]
unsafe fn enable_nxe() -> bool {
    // NX PTEs are legal only if CPUID advertises NX and IA32_EFER.NXE is set.
    // Changing EFER is restricted to this privileged x86-64 QEMU bootstrap.
    if core::arch::x86_64::__cpuid(0x8000_0000).eax < 0x8000_0001
        || core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 20) == 0
    {
        return false;
    }
    let low: u32;
    let high: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") 0xc000_0080u32,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags),
    );
    if low & (1 << 11) == 0 {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xc000_0080u32,
            in("eax") (low | (1 << 11)),
            in("edx") high,
            options(nostack, preserves_flags),
        );
    }
    let verified: u32;
    let high_again: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") 0xc000_0080u32,
        out("eax") verified,
        out("edx") high_again,
        options(nomem, nostack, preserves_flags),
    );
    let _ = high_again;
    verified & (1 << 11) != 0
}

/// Activate a distinct PML4 page retaining every firmware leaf mapping.
///
/// # Safety
/// Caller must run at ring 0 on a single CPU after UEFI ExitBootServices,
/// with x86-64 4-level paging and OVMF's identity map of physical table RAM.
/// This procedure checks both the old and new root's identity mapping,
/// but cannot recover from an inaccessible inherited CR3 page. QEMU only.
pub unsafe fn install(inherited_root: u64, pool: &FramePool<256>) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if ACTIVE_ROOT.load(Ordering::Acquire) != 0 {
            return Err(Error::RootAlreadyInstalled);
        }
        if inherited_root == 0 || inherited_root & 4095 != 0 {
            return Err(Error::InvalidRoot);
        }
        let fresh_root = ptr::addr_of_mut!(SORVETH_ROOT).cast::<u64>() as u64;
        if fresh_root & 4095 != 0 || fresh_root == inherited_root {
            return Err(Error::InvalidRoot);
        }
        if inherited_translate(inherited_root, inherited_root) != Some(inherited_root) {
            return Err(Error::FirmwareTablesNotIdentityMapped);
        }
        if inherited_translate(inherited_root, fresh_root) != Some(fresh_root) {
            return Err(Error::NewRootNotIdentityMapped);
        }
        let source = inherited_root as *const u64;
        let dest = fresh_root as *mut u64;
        ptr::copy_nonoverlapping(source, dest, 512);
        for i in 0..512 {
            if ptr::read_volatile(source.add(i)) != ptr::read_volatile(dest.add(i)) {
                return Err(Error::VerificationFailed);
            }
        }
        // Install the first Sorveth-owned *subtree* in an otherwise unused
        // upper-half PML4 slot. Neither the new table pages nor the scratch
        // page are released: this is a permanent bootstrap test mapping.
        let pdpt = ptr::addr_of_mut!(SORVETH_PDPT).cast::<u64>() as u64;
        let pd = ptr::addr_of_mut!(SORVETH_PD).cast::<u64>() as u64;
        let pt = ptr::addr_of_mut!(SORVETH_PT).cast::<u64>() as u64;
        for table in [pdpt, pd, pt] {
            if table & 4095 != 0 || inherited_translate(inherited_root, table) != Some(table) {
                return Err(Error::PrivateTablesNotIdentityMapped);
            }
        }
        let slot = match (256usize..512)
            .rev()
            .find(|&index| ptr::read_volatile(source.add(index)) & PRESENT == 0)
        {
            Some(index) => index,
            None => return Err(Error::NoFreeVirtualSlot),
        };
        // Claim an actual *conventional* frame from the locked ownership
        // ledger. The original firmware mapping must identity-map it before
        // we can safely clear its contents at this stage.
        let scratch = pool
            .claim_unmapped_for(1, FrameOwner::ROOT_BOOTSTRAP)
            .map_err(|_| Error::FrameUnavailable)?
            .span;
        if inherited_translate(inherited_root, scratch.start) != Some(scratch.start) {
            return Err(Error::TestFrameNotIdentityMapped);
        }
        if !enable_nxe() {
            return Err(Error::NxUnsupported);
        }
        ptr::write_bytes(scratch.start as *mut u8, 0, 4096);
        ptr::write_bytes(pdpt as *mut u8, 0, 4096);
        ptr::write_bytes(pd as *mut u8, 0, 4096);
        ptr::write_bytes(pt as *mut u8, 0, 4096);

        ptr::write_volatile(pdpt as *mut u64, pd | PRESENT | WRITE);
        ptr::write_volatile(pd as *mut u64, pt | PRESENT | WRITE);
        ptr::write_volatile(pt as *mut u64, scratch.start | PRESENT | WRITE | NO_EXECUTE);
        // Self-alias for editing this PT through Sorveth's own upper-half
        // page tables instead of via its inherited identity address.
        ptr::write_volatile(
            (pt as *mut u64).add(PRIVATE_PT_ALIAS_INDEX),
            pt | PRESENT | WRITE | NO_EXECUTE,
        );
        ptr::write_volatile(dest.add(slot), pdpt | PRESENT | WRITE);
        let high_address = 0xffff_0000_0000_0000u64 | ((slot as u64) << 39);

        compiler_fence(Ordering::SeqCst);
        // PML4 reload flushes non-global entries. The previous mappings
        // remain intact and a private supervisor-only NX page is added.
        core::arch::asm!("mov cr3, {}", in(reg) fresh_root, options(nostack, preserves_flags));
        compiler_fence(Ordering::SeqCst);
        let observed: u64;
        core::arch::asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
        if observed & ADDRESS_MASK != fresh_root {
            return Err(Error::VerificationFailed);
        }
        // Prove the high-half address really resolves through Sorveth-owned
        // PML4/PDPT/PD/PT frames, to the claimed physical scratch frame.
        ptr::write_volatile(high_address as *mut u64, TEST_WORD);
        if ptr::read_volatile(scratch.start as *const u64) != TEST_WORD {
            return Err(Error::VerificationFailed);
        }
        if translate(fresh_root, high_address, |phys| {
            Some(ptr::read_volatile(phys as *const u64))
        }) != Some(scratch.start)
        {
            return Err(Error::VerificationFailed);
        }
        let pt_alias = high_address + PRIVATE_PT_ALIAS_INDEX as u64 * 4096;
        let self_entry = ptr::read_volatile((pt_alias as *const u64).add(PRIVATE_PT_ALIAS_INDEX));
        // Hardware may set Accessed/Dirty; address, USER denial and W^X
        // protection must remain identical to the installed self-alias.
        let immutable_bits = ADDRESS_MASK | PRESENT | WRITE | NO_EXECUTE | (1 << 2);
        if self_entry & immutable_bits != pt | PRESENT | WRITE | NO_EXECUTE
            || ptr::read_volatile(pt_alias as *const u64) & ADDRESS_MASK != scratch.start
            || translate(fresh_root, pt_alias, |phys| {
                Some(ptr::read_volatile(phys as *const u64))
            }) != Some(pt)
        {
            return Err(Error::VerificationFailed);
        }
        // PT index 1 is untouched (non-present). Retain this canonical
        // address solely for a controlled fault-handler acceptance test.
        UNMAPPED_TEST.store(high_address + 4096, Ordering::Release);
        PRIVATE_BASE.store(high_address, Ordering::Release);
        NEXT_PRIVATE_PAGE.store(2, Ordering::Release);
        ACTIVE_ROOT.store(fresh_root, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = inherited_root;
        let _ = pool;
        Err(Error::UnsupportedArchitecture)
    }
}

#[cfg(target_arch = "x86_64")]
fn valid_physical_window_frame(frame: u64) -> bool {
    frame != 0 && frame & 4095 == 0 && frame & !ADDRESS_MASK == 0
}

#[cfg(target_arch = "x86_64")]
struct PhysicalWindowGuard {
    pte: *mut u64,
    address: u64,
}
#[cfg(target_arch = "x86_64")]
impl Drop for PhysicalWindowGuard {
    fn drop(&mut self) {
        unsafe {
            ptr::write_volatile(self.pte, 0);
            compiler_fence(Ordering::SeqCst);
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) self.address,
                options(nostack, preserves_flags),
            );
        }
        PHYSICAL_WINDOW_BUSY.store(false, Ordering::Release);
    }
}

/// Temporarily access an owned physical frame through Sorveth's high-half PT.
/// The PT entry is changed through its own supervisor RW/NX virtual alias,
/// not through the inherited identity address for the paging frame.
///
/// # Safety
/// The caller owns the complete frame, is on the only CPU with IRQs masked and
/// kernel CR3 loaded, and does not retain the visitor pointer or change CR3.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn with_physical_window<R>(
    frame: u64,
    visit: impl FnOnce(*mut u8) -> R,
) -> Result<R, Error> {
    if !valid_physical_window_frame(frame) {
        return Err(Error::PhysicalWindowInvalid);
    }
    let root = ACTIVE_ROOT.load(Ordering::Acquire);
    let base = PRIVATE_BASE.load(Ordering::Acquire);
    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if root == 0 || base == 0 || active & ADDRESS_MASK != root || flags & (1 << 9) != 0 {
        return Err(Error::WrongCpuContext);
    }
    if PHYSICAL_WINDOW_BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::PhysicalWindowBusy);
    }
    let pte = (base + PRIVATE_PT_ALIAS_INDEX as u64 * 4096) as *mut u64;
    let pte = pte.add(PHYSICAL_WINDOW_INDEX);
    if ptr::read_volatile(pte) != 0 {
        PHYSICAL_WINDOW_BUSY.store(false, Ordering::Release);
        return Err(Error::PhysicalWindowBusy);
    }
    let address = base + PHYSICAL_WINDOW_INDEX as u64 * 4096;
    ptr::write_volatile(pte, frame | PRESENT | WRITE | NO_EXECUTE);
    compiler_fence(Ordering::SeqCst);
    core::arch::asm!(
        "invlpg [{}]",
        in(reg) address,
        options(nostack, preserves_flags),
    );
    let guard = PhysicalWindowGuard { pte, address };
    let result = visit(address as *mut u8);
    drop(guard);
    Ok(result)
}

/// Read a firmware-inherited supervisor page-table entry through the owned
/// high-half window, after verifying that its table frame still has the
/// trusted bootstrap identity mapping. This is a TRANSITIONAL inventory
/// reader: it cannot be used after inherited supervisor mappings are removed.
///
/// # Safety
/// Kernel CR3 active on the single bootstrap CPU with IRQs disabled.
/// The firmware table ancestry must remain immutable during the read.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_bootstrap_supervisor_entry(address: u64) -> Option<u64> {
    let page = address & !4095;
    if page == 0 || address & 7 != 0 || address - page > 4088 {
        return None;
    }
    let kernel_root = kernel_root_physical()?;
    if inherited_translate(kernel_root, page) != Some(page) {
        return None;
    }
    with_physical_window(page, |window| {
        ptr::read_volatile(window.add((address - page) as usize) as *const u64)
    })
    .ok()
}

/// Copy one identity-mapped inherited page-table page through Sorveth's
/// temporary frame window. Validating the identity mapping once per page
/// keeps bounded ancestry inventory practical without exposing a physical
/// pointer to its caller.
///
/// # Safety
/// Kernel CR3 active on the single bootstrap CPU with IRQs disabled; the
/// inherited page-table page is immutable for the duration of the copy.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_bootstrap_supervisor_table(frame: u64, entries: &mut [u64; 512]) -> bool {
    if frame == 0 || frame & 4095 != 0 || frame & !ADDRESS_MASK != 0 {
        return false;
    }
    let Some(kernel_root) = kernel_root_physical() else {
        return false;
    };
    if inherited_translate(kernel_root, frame) != Some(frame) {
        return false;
    }
    with_physical_window(frame, |window| {
        for (index, entry) in entries.iter_mut().enumerate() {
            *entry = ptr::read_volatile(window.add(index * 8).cast::<u64>());
        }
    })
    .is_ok()
}

/// Claim, zero, and map one additional supervisor-only NX 4 KiB page inside
/// Sorveth's private 2 MiB upper-half bootstrap window. Slot one is reserved
/// as an intentionally absent page for the controlled #PF acceptance test.
///
/// This is **not** a general heap: only one CPU may call it, and pages
/// are never reclaimed. The owned PT alias and frame window avoid direct
/// physical address dereferences in this method, but other boot paths
/// still rely on inherited firmware page tables.
pub fn claim_kernel_scratch(pool: &FramePool<256>) -> Result<u64, Error> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if !active() {
            return Err(Error::RootNotInstalled);
        }
        let slot = NEXT_PRIVATE_PAGE.load(Ordering::Acquire);
        if !(2..PRIVATE_PT_ALIAS_INDEX as u64).contains(&slot) {
            return Err(Error::NoFreeVirtualSlot);
        }
        let physical = pool
            .claim_unmapped_for(1, FrameOwner::KERNEL_SCRATCH)
            .map_err(|_| Error::FrameUnavailable)?
            .span
            .start;
        let root = ACTIVE_ROOT.load(Ordering::Acquire);
        // K.1a: access this newly claimed frame through the Sorveth-owned
        // high-half window instead of dereferencing a physical address.
        with_physical_window(physical, |window| ptr::write_bytes(window, 0, 4096))?;
        let base = PRIVATE_BASE.load(Ordering::Acquire);
        let pte = (base + PRIVATE_PT_ALIAS_INDEX as u64 * 4096) as *mut u64;
        let pte = pte.add(slot as usize);
        if ptr::read_volatile(pte) != 0 {
            return Err(Error::VerificationFailed);
        }
        ptr::write_volatile(pte, physical | PRESENT | WRITE | NO_EXECUTE);
        let virtual_address = PRIVATE_BASE
            .load(Ordering::Acquire)
            .checked_add(slot * 4096)
            .ok_or(Error::ScratchAddressUnavailable)?;
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virtual_address,
            options(nostack, preserves_flags),
        );
        // A distinct address and a distinct physical claim are required.
        const SENTINEL: u64 = 0x53_4f_52_56_4d_41_50_21;
        ptr::write_volatile(virtual_address as *mut u64, SENTINEL ^ slot);
        let observed =
            with_physical_window(physical, |window| ptr::read_volatile(window as *const u64))?;
        if observed != (SENTINEL ^ slot)
            || translate(root, virtual_address, |address| {
                Some(ptr::read_volatile(address as *const u64))
            }) != Some(physical)
            || ptr::read_volatile(
                ((base + PRIVATE_PT_ALIAS_INDEX as u64 * 4096) as *const u64)
                    .add(PHYSICAL_WINDOW_INDEX),
            ) != 0
        {
            return Err(Error::VerificationFailed);
        }
        NEXT_PRIVATE_PAGE.store(slot + 1, Ordering::Release);
        Ok(virtual_address)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = pool;
        Err(Error::UnsupportedArchitecture)
    }
}

/// Number of 4 KiB Sorveth-owned mappings in the initial private PT.
/// Excludes the deliberately missing fault-test page at index 1.
pub fn private_pages() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let next = NEXT_PRIVATE_PAGE.load(Ordering::Acquire);
        if next >= 2 {
            next - 1
        } else {
            0
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[cfg(feature = "qemu-fault")]
pub fn deliberate_fault_address() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let address = UNMAPPED_TEST.load(Ordering::Acquire);
        if address == 0 {
            None
        } else {
            Some(address)
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// The active Sorveth-owned bootstrap PML4 physical address.
#[cfg(target_arch = "x86_64")]
pub(crate) fn kernel_root_physical() -> Option<u64> {
    let root = ACTIVE_ROOT.load(Ordering::Acquire);
    if root == 0 {
        None
    } else {
        Some(root)
    }
}

/// Permanently activate an independently built candidate for a dedicated
/// QEMU acceptance image. The candidate root page must still be reachable
/// by the currently active Sorveth root, and interrupts must remain masked.
///
/// # Safety
/// The caller has completely audited the candidate's live code, data, stack,
/// CPU tables, frame window and supervisor leaves. Failure after the CR3
/// write is fatal; this path is compiled only for QEMU acceptance builds.
#[cfg(all(target_arch = "x86_64", feature = "qemu-independent-root"))]
pub(crate) unsafe fn activate_independent_root(candidate: u64) -> Result<(), Error> {
    let current = ACTIVE_ROOT.load(Ordering::Acquire);
    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if current == 0
        || active & ADDRESS_MASK != current
        || flags & (1 << 9) != 0
        || candidate == current
        || !valid_physical_window_frame(candidate)
        || inherited_translate(current, candidate) != Some(candidate)
    {
        return Err(Error::WrongCpuContext);
    }

    core::arch::asm!("mov cr3, {}", in(reg) candidate, options(nostack, preserves_flags));
    let observed: u64;
    core::arch::asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
    if observed & ADDRESS_MASK != candidate {
        return Err(Error::VerificationFailed);
    }
    ACTIVE_ROOT.store(candidate, Ordering::Release);
    Ok(())
}

/// First supervisor-only private high-half page.
#[cfg(target_arch = "x86_64")]
pub(crate) fn kernel_private_address() -> Option<u64> {
    let address = PRIVATE_BASE.load(Ordering::Acquire);
    if address == 0 {
        None
    } else {
        Some(address)
    }
}

/// A verified 4-KiB leaf retained for the independent supervisor mapping plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateWindowMapping {
    pub virtual_page: u64,
    pub physical_page: u64,
    pub writable: bool,
    pub executable: bool,
}

/// Summary and bounded snapshot of the idle private high-half frame window.
/// The fixed capacity covers all single-page claims in the 256-entry allocator
/// ledger plus the page-table self-alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateWindowEvidence {
    pub base: u64,
    pub mapped_pages: u64,
    pub first_virtual_page: u64,
    pub last_virtual_page: u64,
    pub mappings: [Option<PrivateWindowMapping>; 257],
    pub mapping_count: usize,
}

/// Audit failure codes keep the boot diagnostic compact and stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateWindowAuditFailure {
    CpuContext,
    BaseAddress,
    PageTableAlias,
    SelfAliasEntry,
    PhysicalWindowEntry,
    GuardEntry,
    LeafPermissions,
    UnownedFrame,
    DuplicateFrame,
    PageCount,
}

impl PrivateWindowAuditFailure {
    pub(crate) const fn code(self) -> u64 {
        match self {
            Self::CpuContext => 1,
            Self::BaseAddress => 2,
            Self::PageTableAlias => 3,
            Self::SelfAliasEntry => 4,
            Self::PhysicalWindowEntry => 9,
            Self::GuardEntry => 10,
            Self::LeafPermissions => 5,
            Self::UnownedFrame => 6,
            Self::DuplicateFrame => 7,
            Self::PageCount => 8,
        }
    }
}

/// Audit every present private-window leaf. Slot 1 remains the guard page,
/// slot 510 is the page-table self-alias, and slot 511 must be empty while
/// the temporary physical-frame window is idle.
///
/// # Safety
/// One CPU, kernel CR3 active, IF=0, no concurrent frame claims or PTE edits.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn audit_private_window(
    pool: &FramePool<256>,
) -> Result<PrivateWindowEvidence, PrivateWindowAuditFailure> {
    use PrivateWindowAuditFailure as Failure;

    let root = kernel_root_physical().ok_or(Failure::CpuContext)?;
    let base = kernel_private_address().ok_or(Failure::CpuContext)?;
    let active: u64;
    let flags: u64;
    core::arch::asm!("mov {}, cr3", out(reg) active, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    if active & ADDRESS_MASK != root || flags & (1 << 9) != 0 {
        return Err(Failure::CpuContext);
    }
    if base & 4095 != 0 || base >> 39 & 511 < 256 {
        return Err(Failure::BaseAddress);
    }

    let table_alias = base + PRIVATE_PT_ALIAS_INDEX as u64 * 4096;
    let table_frame = ptr::addr_of!(SORVETH_PT) as u64;
    if table_frame & 4095 != 0
        || !identity_mapped(table_frame)
        || translate(root, table_alias, |address| {
            Some(ptr::read_volatile(address as *const u64))
        }) != Some(table_frame)
    {
        return Err(Failure::PageTableAlias);
    }

    let entries = table_alias as *const u64;
    let self_entry = ptr::read_volatile(entries.add(PRIVATE_PT_ALIAS_INDEX));
    let immutable_self_mask = ADDRESS_MASK | PRESENT | WRITE | NO_EXECUTE;
    let expected_self_entry = table_frame | PRESENT | WRITE | NO_EXECUTE;
    if self_entry & immutable_self_mask != expected_self_entry {
        return Err(Failure::SelfAliasEntry);
    }
    if ptr::read_volatile(entries.add(PHYSICAL_WINDOW_INDEX)) != 0 {
        return Err(Failure::PhysicalWindowEntry);
    }
    if ptr::read_volatile(entries.add(1)) != 0 {
        return Err(Failure::GuardEntry);
    }

    let allowed = ADDRESS_MASK | PRESENT | WRITE | NO_EXECUTE | (1 << 5) | (1 << 6);
    let mut count = 0u64;
    let mut first = 0;
    let mut last = 0;
    let mut mappings = [None; 257];
    let mut mapping_count = 0usize;
    for slot in 0..PRIVATE_PT_ALIAS_INDEX {
        if slot == 1 {
            continue;
        }
        let entry = ptr::read_volatile(entries.add(slot));
        if entry & PRESENT == 0 {
            if entry != 0 {
                return Err(Failure::LeafPermissions);
            }
            continue;
        }
        if entry & !allowed != 0
            || entry & (PRESENT | WRITE | NO_EXECUTE) != PRESENT | WRITE | NO_EXECUTE
        {
            return Err(Failure::LeafPermissions);
        }
        let physical = entry & ADDRESS_MASK;
        if physical == 0 || !pool.owns_frame(physical).unwrap_or(false) {
            return Err(Failure::UnownedFrame);
        }
        for prior in 0..slot {
            if prior == 1 {
                continue;
            }
            let prior_entry = ptr::read_volatile(entries.add(prior));
            if prior_entry & PRESENT != 0 && prior_entry & ADDRESS_MASK == physical {
                return Err(Failure::DuplicateFrame);
            }
        }
        let virtual_page = base + slot as u64 * 4096;
        mappings[mapping_count] = Some(PrivateWindowMapping {
            virtual_page,
            physical_page: physical,
            writable: true,
            executable: false,
        });
        mapping_count += 1;
        if count == 0 {
            first = virtual_page;
        }
        last = virtual_page;
        count += 1;
    }

    if count == 0 || count != private_pages() || mapping_count >= mappings.len() {
        return Err(Failure::PageCount);
    }
    mappings[mapping_count] = Some(PrivateWindowMapping {
        virtual_page: table_alias,
        physical_page: table_frame,
        writable: true,
        executable: false,
    });
    mapping_count += 1;
    Ok(PrivateWindowEvidence {
        base,
        mapped_pages: count,
        first_virtual_page: first,
        last_virtual_page: last,
        mappings,
        mapping_count,
    })
}

/// The bootstrap can only use static PML4 pages as CR3 if their physical
/// addresses remain accessible through OVMF's verified identity mapping.
#[cfg(target_arch = "x86_64")]
pub(crate) fn identity_mapped(address: u64) -> bool {
    match kernel_root_physical() {
        Some(root) => unsafe { inherited_translate(root, address) == Some(address) },
        None => false,
    }
}

pub fn active() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        ACTIVE_ROOT.load(Ordering::Acquire) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(all(feature = "qemu-user", target_arch = "x86_64"))]
static mut USER_PDPT: RootPage = RootPage([0; 512]);
#[cfg(all(feature = "qemu-user", target_arch = "x86_64"))]
static mut USER_PD: RootPage = RootPage([0; 512]);
#[cfg(all(feature = "qemu-user", target_arch = "x86_64"))]
static mut USER_PT: RootPage = RootPage([0; 512]);

/// Bounded, allocation-free machine-code emitter for the test-only ring-3
/// stub. Every expected result is compared *inside* user mode. A mismatch
/// loops forever and cannot produce the QEMU success marker.
#[cfg(feature = "qemu-user")]
struct ProbeProgram {
    bytes: [u8; 2048],
    len: usize,
}

#[cfg(feature = "qemu-user")]
impl ProbeProgram {
    const fn new() -> Self {
        Self {
            bytes: [0; 2048],
            len: 0,
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(Error::VerificationFailed)?;
        if end > self.bytes.len() {
            return Err(Error::VerificationFailed);
        }
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn set_rax(&mut self, value: u32) -> Result<(), Error> {
        self.emit(&[0xb8])?;
        self.emit(&value.to_le_bytes())
    }

    fn set_rdx(&mut self, value: u64) -> Result<(), Error> {
        self.emit(&[0x48, 0xba])?;
        self.emit(&value.to_le_bytes())
    }

    #[cfg(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b"))]
    fn set_r8(&mut self, value: u64) -> Result<(), Error> {
        self.emit(&[0x49, 0xb8])?;
        self.emit(&value.to_le_bytes())
    }

    #[cfg(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b"))]
    fn set_r9(&mut self, value: u64) -> Result<(), Error> {
        self.emit(&[0x49, 0xb9])?;
        self.emit(&value.to_le_bytes())
    }

    fn int80(&mut self) -> Result<(), Error> {
        self.emit(&[0xcd, 0x80])
    }

    fn expect_rax(&mut self, value: u32) -> Result<(), Error> {
        self.emit(&[0x3d])?;
        self.emit(&value.to_le_bytes())?;
        self.emit(&[0x75, 0xfe]) // jne to this instruction: fail closed
    }

    fn trap(&mut self, number: u32, reply: u32) -> Result<(), Error> {
        self.set_rax(number)?;
        self.int80()?;
        self.expect_rax(reply)
    }
}

#[cfg(feature = "qemu-user")]
fn build_probe(allowed: u64, foreign: u64, protected: u64) -> Result<ProbeProgram, Error> {
    use sorveth_broker::{REPLY_DENIED, SYS_RESOURCE_READ, SYS_RESOURCE_WRITE};
    let mut program = ProbeProgram::new();
    program.trap(7, 0x5356_5246)?; // first legacy test handshake
    program.set_rax(8)?; // second legacy handshake returns 0
    program.int80()?;

    program.set_rdx(allowed)?;
    program.trap(
        SYS_RESOURCE_READ as u32,
        crate::user::RESOURCE_PROBE_VALUE as u32,
    )?;
    program.trap(SYS_RESOURCE_WRITE as u32, REPLY_DENIED as u32)?;
    program.set_rdx(0)?;
    program.trap(SYS_RESOURCE_READ as u32, REPLY_DENIED as u32)?;
    program.set_rdx(foreign)?;
    program.trap(SYS_RESOURCE_READ as u32, REPLY_DENIED as u32)?;

    program.emit(&[0x48, 0xb8])?; // movabs rax, protected high-half address
    program.emit(&protected.to_le_bytes())?;
    program.emit(&[0x48, 0x8b, 0x00, 0xeb, 0xfe])?; // read then spin
    Ok(program)
}

/// Dedicated ring-3 syscall acceptance program. The trusted kernel
/// chooses this process and its capability handles; the program can only
/// submit numeric arguments, never a TaskId, Process ID or CR3 root.
#[cfg(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b"))]
fn build_transfer_probe(read: u64, foreign: u64) -> Result<ProbeProgram, Error> {
    use crate::transfer::{
        COPY_DENIED, COPY_IN_OK, COPY_OUT_OK, SYS_COMPLETE, SYS_COPY_IN, SYS_COPY_OUT,
    };

    let own = crate::process_roots::mapped_page(crate::transfer::owner())
        .ok_or(Error::VerificationFailed)?;
    let other = crate::process_roots::mapped_page(crate::transfer::other())
        .ok_or(Error::VerificationFailed)?;
    let write = crate::transfer::write_handle().ok_or(Error::VerificationFailed)?;
    let mut program = ProbeProgram::new();

    // Each call supplies a user capability in RDX, a user virtual pointer
    // in R8 and a length in R9. The fifth efiapi gateway argument receives
    // the saved R9 value. The kernel obtains the caller identity from CR3.
    let mut call = |number: u64, handle: u64, pointer: u64, len: u64, reply: u64| {
        program.set_rdx(handle)?;
        program.set_r8(pointer)?;
        program.set_r9(len)?;
        program.trap(number as u32, reply as u32)
    };
    // Phase order mirrors the kernel's integrity-checked test table.
    // Every request is an actual ring-3 INT80 instruction.
    call(SYS_COPY_IN, read, own.virtual_address, 8, COPY_IN_OK)?;
    call(SYS_COPY_IN, read, other.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_OUT, read, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_OUT, foreign, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, 0, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, read, own.virtual_address, 0, COPY_DENIED)?;
    call(
        SYS_COPY_OUT,
        write,
        own.virtual_address + 4095,
        2,
        COPY_DENIED,
    )?;
    call(SYS_COPY_OUT, write, other.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, write, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, u64::MAX, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, read, 0, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, read, u64::MAX, 8, COPY_DENIED)?;
    call(SYS_COPY_OUT, write, 0xffff_8000_0000_0000, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, read, 0x0000_7fff_ffff_fffc, 8, COPY_DENIED)?;
    call(SYS_COPY_IN, read, own.virtual_address, 65537, COPY_DENIED)?;
    call(SYS_COPY_OUT, write, own.virtual_address, 0, COPY_DENIED)?;

    // Authorized write, followed by *additional* unauthorized writes.
    // The kernel checks a whole-page digest on every INT80, so none of
    // these denials may tamper with any byte of either process frame.
    call(SYS_COPY_OUT, write, own.virtual_address, 8, COPY_OUT_OK)?;
    call(SYS_COPY_OUT, read, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_OUT, foreign, own.virtual_address, 8, COPY_DENIED)?;
    call(SYS_COPY_OUT, write, other.virtual_address, 8, COPY_DENIED)?;
    call(0x7f, write, own.virtual_address, 8, COPY_DENIED)?;

    // Proof from actual CPL3 instructions that the process sees the bytes
    // written by the kernel. A mismatch loops without reaching completion.
    program.emit(&[0x48, 0xb8])?; // movabs rax, own data virtual address
    program.emit(&own.virtual_address.to_le_bytes())?;
    program.emit(&[0x48, 0x8b, 0x08])?; // mov rcx,[rax]
    program.emit(&[0x48, 0xba])?; // movabs rdx, expected data
    program.emit(&u64::from_le_bytes(crate::transfer::pattern()).to_le_bytes())?;
    program.emit(&[0x48, 0x39, 0xd1, 0x75, 0xfe])?; // cmp rcx,rdx; jne self

    // The completion INT80 verifies source/destination content and restores
    // the process's original data before allowing QEMU's debug exit.
    program.set_rdx(0)?;
    program.set_r8(own.virtual_address)?;
    program.set_r9(8)?;
    program.trap(SYS_COMPLETE as u32, 0)?;
    program.emit(&[0xeb, 0xfe])?; // no uncontrolled return to unknown memory
    Ok(program)
}

/// Test-only CPL3 program: prove own memory read then fault on foreign
/// private user address. Any incorrect own-page value loops in ring 3.
#[cfg(any(feature = "qemu-isolate-a", feature = "qemu-isolate-b"))]
fn build_isolation_probe() -> Result<ProbeProgram, Error> {
    let own = crate::process_roots::mapped_page(crate::isolation::owner())
        .ok_or(Error::VerificationFailed)?;
    let foreign = crate::process_roots::mapped_page(crate::isolation::foreign())
        .ok_or(Error::VerificationFailed)?;
    if own.virtual_address == foreign.virtual_address
        || own.physical_address == foreign.physical_address
    {
        return Err(Error::VerificationFailed);
    }
    // Expected contents are read via the owned supervisor frame alias.
    // The test frame was populated by the real M2-I.3 CR3 switches.
    let expected =
        unsafe { crate::process_roots::read_process_frame_word(crate::isolation::owner()) }
            .ok_or(Error::VerificationFailed)?;
    let mut program = ProbeProgram::new();
    program.emit(&[0x48, 0xb8])?; // movabs rax, own virtual address
    program.emit(&own.virtual_address.to_le_bytes())?;
    program.emit(&[0x48, 0x8b, 0x08])?; // mov rcx, [rax]
    program.emit(&[0x48, 0xba])?; // movabs rdx, expected
    program.emit(&expected.to_le_bytes())?;
    program.emit(&[0x48, 0x39, 0xd1, 0x75, 0xfe])?; // cmp rcx,rdx; jne self
    program.trap(
        crate::isolation::SIGNAL as u32,
        crate::isolation::REPLY as u32,
    )?;
    program.emit(&[0x48, 0xb8])?; // movabs rax, foreign virtual address
    program.emit(&foreign.virtual_address.to_le_bytes())?;
    program.emit(&[0x48, 0x8b, 0x00, 0xeb, 0xfe])?; // mov rax,[rax]; spin
    Ok(program)
}

#[cfg(feature = "qemu-user")]
pub struct UserProbe {
    pub entry: u64,
    pub stack: u64,
}

/// Isolated from all existing high-half kernel mappings. This builds a new
/// USER=1 four-level subtree in an unused *lower canonical* PML4 slot.
///
/// Only used by the QEMU privilege-transition acceptance test. The actual
/// machine-code probe consists of MOV EAX,7; INT80; CMP EAX,magic; JNE loop;
/// MOV EAX,8; INT80. It cannot call Rust, UEFI, or arbitrary kernel services.
#[cfg(feature = "qemu-user")]
pub fn prepare_user_probe(
    pool: &FramePool<256>,
    read_handle: u64,
    foreign_handle: u64,
) -> Result<UserProbe, Error> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        const U: u64 = 1 << 2;
        // The test-only program runs a task-owned capability read and
        // probes denied WRITE, forged and foreign-task handles before
        // attempting the existing supervisor-memory protection check.
        let protected = PRIVATE_BASE.load(Ordering::Acquire);
        if protected == 0 {
            return Err(Error::VerificationFailed);
        }
        #[cfg(any(feature = "qemu-isolate-a", feature = "qemu-isolate-b"))]
        let code_bytes = build_isolation_probe()?;
        #[cfg(any(feature = "qemu-transfer-a", feature = "qemu-transfer-b"))]
        let code_bytes = build_transfer_probe(read_handle, foreign_handle)?;
        #[cfg(not(any(
            feature = "qemu-isolate-a",
            feature = "qemu-isolate-b",
            feature = "qemu-transfer-a",
            feature = "qemu-transfer-b"
        )))]
        let code_bytes = build_probe(read_handle, foreign_handle, protected)?;
        let root = ACTIVE_ROOT.load(Ordering::Acquire);
        if root == 0 {
            return Err(Error::RootNotInstalled);
        }
        // In isolation images do not collide with process A/B data slots.
        #[cfg(any(
            feature = "qemu-isolate-a",
            feature = "qemu-isolate-b",
            feature = "qemu-transfer-a",
            feature = "qemu-transfer-b"
        ))]
        let avoided = [
            crate::process_roots::process_root(crate::process_roots::Process::First)
                .ok_or(Error::VerificationFailed)?
                .1 as usize,
            crate::process_roots::process_root(crate::process_roots::Process::Second)
                .ok_or(Error::VerificationFailed)?
                .1 as usize,
        ];
        #[cfg(not(any(
            feature = "qemu-isolate-a",
            feature = "qemu-isolate-b",
            feature = "qemu-transfer-a",
            feature = "qemu-transfer-b"
        )))]
        let avoided = [0usize; 2];
        let slot = with_physical_window(root, |window| {
            let entries = window as *const u64;
            (1usize..256).rev().find(|&i| {
                ptr::read_volatile(entries.add(i)) & PRESENT == 0 && !avoided.contains(&i)
            })
        })?
        .ok_or(Error::NoFreeVirtualSlot)?;
        let pdpt = ptr::addr_of_mut!(USER_PDPT).cast::<u64>() as u64;
        let pd = ptr::addr_of_mut!(USER_PD).cast::<u64>() as u64;
        let pt = ptr::addr_of_mut!(USER_PT).cast::<u64>() as u64;
        for table in [pdpt, pd, pt] {
            if table & 4095 != 0 || inherited_translate(root, table) != Some(table) {
                return Err(Error::PrivateTablesNotIdentityMapped);
            }
        }

        let code = pool
            .claim_unmapped_for(1, FrameOwner::USER_PROBE_CODE)
            .map_err(|_| Error::FrameUnavailable)?
            .span
            .start;
        let stack = pool
            .claim_unmapped_for(1, FrameOwner::USER_PROBE_STACK)
            .map_err(|_| Error::FrameUnavailable)?
            .span
            .start;
        if code == stack
            || !valid_physical_window_frame(code)
            || !valid_physical_window_frame(stack)
        {
            return Err(Error::FrameUnavailable);
        }
        // Both frames are permanent claims in the physical frame ledger.
        // Initialize code and stack via the kernel-owned supervisor window,
        // without requiring identity mappings of either data frame.
        with_physical_window(code, |window| {
            ptr::write_bytes(window, 0, 4096);
            ptr::copy_nonoverlapping(code_bytes.bytes.as_ptr(), window, code_bytes.len);
        })?;
        with_physical_window(stack, |window| ptr::write_bytes(window, 0, 4096))?;
        for table in [pdpt, pd, pt] {
            with_physical_window(table, |window| ptr::write_bytes(window, 0, 4096))?;
        }

        with_physical_window(pdpt, |window| {
            ptr::write_volatile(window as *mut u64, pd | PRESENT | WRITE | U);
        })?;
        with_physical_window(pd, |window| {
            ptr::write_volatile(window as *mut u64, pt | PRESENT | WRITE | U);
        })?;
        with_physical_window(pt, |window| {
            let entries = window as *mut u64;
            ptr::write_volatile(entries, code | PRESENT | U);
            ptr::write_volatile(entries.add(1), stack | PRESENT | WRITE | U | NO_EXECUTE);
        })?;
        with_physical_window(root, |window| {
            ptr::write_volatile((window as *mut u64).add(slot), pdpt | PRESENT | WRITE | U);
        })?;
        let entry = (slot as u64) << 39;
        let user_stack = entry + 8192 - 16;
        core::arch::asm!("invlpg [{}]", in(reg) entry, options(nostack, preserves_flags));
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) (entry + 4096),
            options(nostack, preserves_flags),
        );
        // Read back the actual four-level translation through only the
        // newly registered test paging frames. A malformed PTE cannot
        // redirect the verifier to an arbitrary physical memory address.
        let mut read_entry = |address: u64| {
            let page = address & !4095;
            if address & 7 != 0 || ![root, pdpt, pd, pt].contains(&page) {
                return None;
            }
            with_physical_window(page, |window| {
                ptr::read_volatile(window.add((address - page) as usize) as *const u64)
            })
            .ok()
        };
        if translate(root, entry, &mut read_entry) != Some(code)
            || translate(root, entry + 4096, &mut read_entry) != Some(stack)
        {
            return Err(Error::VerificationFailed);
        }
        Ok(UserProbe {
            entry,
            stack: user_stack,
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (pool, read_handle, foreign_handle);
        Err(Error::UnsupportedArchitecture)
    }
}

#[cfg(feature = "qemu-user")]
pub fn protected_kernel_address() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let address = PRIVATE_BASE.load(Ordering::Acquire);
        if address != 0 {
            Some(address)
        } else {
            None
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    #[test]
    fn reserved_window_accepts_only_aligned_physical_frames() {
        assert!(valid_physical_window_frame(0x1000));
        assert!(valid_physical_window_frame(0x1000_0000));
        assert!(!valid_physical_window_frame(0));
        assert!(!valid_physical_window_frame(0x1001));
        assert!(!valid_physical_window_frame(0xffff_8000_0000_0000));
        assert_eq!(PHYSICAL_WINDOW_INDEX, 511);
        assert_eq!(PRIVATE_PT_ALIAS_INDEX, 510);
        assert!(PRIVATE_PT_ALIAS_INDEX < PHYSICAL_WINDOW_INDEX);
    }

    #[test]
    fn translates_a_synthetic_four_level_page() {
        // PML4 @0x1000 -> PDPT @0x2000 -> PD @0x3000 -> PT @0x4000.
        let result = translate(0x1000, 0x1234, |address| match address {
            0x1000 => Some(0x2003),
            0x2000 => Some(0x3003),
            0x3000 => Some(0x4003),
            0x4008 => Some(0x9003),
            _ => None,
        });
        assert_eq!(result, Some(0x9234));
        assert_eq!(translate(0x1000, 0x1234, |_| None), None);
        assert_eq!(translate(0x1000, 0x0000_8000_0000_0000, |_| Some(1)), None);
    }

    #[test]
    fn handles_2m_and_1g_huge_pages() {
        let two_meg = translate(0x1000, 0x20_1234, |address| match address {
            0x1000 => Some(0x2003),
            0x2000 => Some(0x3003),
            0x3008 => Some(0x40_0083),
            _ => None,
        });
        assert_eq!(two_meg, Some(0x40_1234));

        let one_gig = translate(0x1000, 0x4000_1234, |address| match address {
            0x1000 => Some(0x2003),
            0x2008 => Some(0x8000_0083),
            _ => None,
        });
        assert_eq!(one_gig, Some(0x8000_1234));
    }
}
