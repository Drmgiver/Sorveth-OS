//! M1-B2: Sorveth-owned PML4 root with inherited lower-level mappings.
//!
//! Only supported for the x86-64 UEFI identity-mapped QEMU bootstrap.
//! The backing page is 4096-byte aligned and permanently retained in the
//! loader image. CR3 is changed only after translation/identity checks.
//! One independent high-half supervisor NX page is mapped through private
//! PDPT/PD/PT tables; the remaining lower levels still belong to firmware.
//! This is NOT yet a complete independent address space or user isolation.

use sorveth_frames::FramePool;

#[cfg(target_arch = "x86_64")]
use core::{
    ptr,
    sync::atomic::{compiler_fence, AtomicU64, Ordering},
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
#[cfg(target_arch = "x86_64")]
static ACTIVE_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static UNMAPPED_TEST: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static PRIVATE_BASE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static NEXT_PRIVATE_PAGE: AtomicU64 = AtomicU64::new(0);

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
            .claim_unmapped(1)
            .map_err(|_| Error::FrameUnavailable)?;
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

/// Claim, zero, and map one additional supervisor-only NX 4 KiB page inside
/// Sorveth's private 2 MiB upper-half bootstrap window. Slot one is reserved
/// as an intentionally absent page for the controlled #PF acceptance test.
///
/// This is **not** a general heap: only one CPU may call it, the inherited
/// firmware identity map must still cover the physical frame, and pages are
/// never reclaimed. A future mapper will remove these constraints.
pub fn claim_kernel_scratch(pool: &FramePool<256>) -> Result<u64, Error> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if !active() {
            return Err(Error::RootNotInstalled);
        }
        let slot = NEXT_PRIVATE_PAGE.load(Ordering::Acquire);
        if !(2..512).contains(&slot) {
            return Err(Error::NoFreeVirtualSlot);
        }
        let physical = pool
            .claim_unmapped(1)
            .map_err(|_| Error::FrameUnavailable)?
            .start;
        let root = ACTIVE_ROOT.load(Ordering::Acquire);
        if inherited_translate(root, physical) != Some(physical) {
            return Err(Error::TestFrameNotIdentityMapped);
        }
        // Physical memory is accessible through OVMF's identity map here.
        // Zero before exposing the page at its new virtual address.
        ptr::write_bytes(physical as *mut u8, 0, 4096);
        let pte = ptr::addr_of_mut!(SORVETH_PT)
            .cast::<u64>()
            .add(slot as usize);
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
        if ptr::read_volatile(physical as *const u64) != (SENTINEL ^ slot)
            || translate(root, virtual_address, |address| {
                Some(ptr::read_volatile(address as *const u64))
            }) != Some(physical)
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
pub fn prepare_user_probe(pool: &FramePool<256>) -> Result<UserProbe, Error> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        const U: u64 = 1 << 2;
        const CODE: [u8; 23] = [
            0xb8, 7, 0, 0, 0, 0xcd, 0x80, 0x3d, 0x46, 0x52, 0x56, 0x53,
            0x75, 0xfe, 0xb8, 8, 0, 0, 0, 0xcd, 0x80, 0xeb, 0xfe,
        ];
        let root = ACTIVE_ROOT.load(Ordering::Acquire);
        if root == 0 {
            return Err(Error::RootNotInstalled);
        }
        let pml4 = root as *mut u64;
        let slot = match (1usize..256)
            .rev()
            .find(|&i| ptr::read_volatile(pml4.add(i)) & PRESENT == 0)
        {
            Some(i) => i,
            None => return Err(Error::NoFreeVirtualSlot),
        };
        let pdpt = ptr::addr_of_mut!(USER_PDPT).cast::<u64>() as u64;
        let pd = ptr::addr_of_mut!(USER_PD).cast::<u64>() as u64;
        let pt = ptr::addr_of_mut!(USER_PT).cast::<u64>() as u64;
        for table in [pdpt, pd, pt] {
            if table & 4095 != 0 || inherited_translate(root, table) != Some(table) {
                return Err(Error::PrivateTablesNotIdentityMapped);
            }
        }

        let code = pool
            .claim_unmapped(1)
            .map_err(|_| Error::FrameUnavailable)?
            .start;
        let stack = pool
            .claim_unmapped(1)
            .map_err(|_| Error::FrameUnavailable)?
            .start;
        if code == stack
            || inherited_translate(root, code) != Some(code)
            || inherited_translate(root, stack) != Some(stack)
        {
            return Err(Error::TestFrameNotIdentityMapped);
        }
        ptr::write_bytes(code as *mut u8, 0, 4096);
        ptr::write_bytes(stack as *mut u8, 0, 4096);
        ptr::copy_nonoverlapping(CODE.as_ptr(), code as *mut u8, CODE.len());
        ptr::write_bytes(pdpt as *mut u8, 0, 4096);
        ptr::write_bytes(pd as *mut u8, 0, 4096);
        ptr::write_bytes(pt as *mut u8, 0, 4096);

        ptr::write_volatile(pdpt as *mut u64, pd | PRESENT | WRITE | U);
        ptr::write_volatile(pd as *mut u64, pt | PRESENT | WRITE | U);
        ptr::write_volatile(pt as *mut u64, code | PRESENT | U);
        ptr::write_volatile(
            (pt as *mut u64).add(1),
            stack | PRESENT | WRITE | U | NO_EXECUTE,
        );
        ptr::write_volatile(pml4.add(slot), pdpt | PRESENT | WRITE | U);
        let entry = (slot as u64) << 39;
        let user_stack = entry + 8192 - 16;
        core::arch::asm!("invlpg [{}]", in(reg) entry, options(nostack, preserves_flags));
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) (entry + 4096),
            options(nostack, preserves_flags),
        );
        if translate(root, entry, |address| {
            Some(ptr::read_volatile(address as *const u64))
        }) != Some(code)
            || translate(root, entry + 4096, |address| {
                Some(ptr::read_volatile(address as *const u64))
            }) != Some(stack)
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
        let _ = pool;
        Err(Error::UnsupportedArchitecture)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
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
