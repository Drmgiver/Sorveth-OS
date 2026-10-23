//! M1-B2: Sorveth-owned PML4 root with inherited lower-level mappings.
//!
//! Only supported for the x86-64 UEFI identity-mapped QEMU bootstrap.
//! The backing page is 4096-byte aligned and permanently retained in the
//! loader image. CR3 is changed only after translation/identity checks.
//! All lower paging levels continue to belong to firmware, so this is NOT
//! a complete independent address space or user isolation.

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
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
struct RootPage([u64; 512]);

#[cfg(target_arch = "x86_64")]
static mut SORVETH_ROOT: RootPage = RootPage([0; 512]);
#[cfg(target_arch = "x86_64")]
static ACTIVE_ROOT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(target_arch = "x86_64")]
const PRESENT: u64 = 1;
#[cfg(target_arch = "x86_64")]
const HUGE: u64 = 1 << 7;

/// Resolve a canonical x86-64 virtual address using 4-level paging.
/// The closure receives *physical* addresses of page-table entries; it must
/// provide a safe read of those entries. This does not dereference physical
/// memory itself and can be unit tested with synthetic page tables.
#[cfg(target_arch = "x86_64")]
fn translate<F>(root: u64, virtual_address: u64, mut read: F) -> Option<u64>
where
    F: FnMut(u64) -> Option<u64>,
{
    if !(virtual_address < 0x0000_8000_0000_0000
        || virtual_address >= 0xffff_8000_0000_0000)
    {
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

/// Activate a distinct PML4 page retaining every firmware leaf mapping.
///
/// # Safety
/// Caller must run at ring 0 on a single CPU after UEFI ExitBootServices,
/// with x86-64 4-level paging and OVMF's identity map of physical table RAM.
/// This procedure checks both the old and new root's identity mapping,
/// but cannot recover from an inaccessible inherited CR3 page. QEMU only.
pub unsafe fn install(inherited_root: u64) -> Result<(), Error> {
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
        compiler_fence(Ordering::SeqCst);
        // Switching the top-level root flushes non-global TLB entries. All
        // existing mappings are retained by the copied PML4 entries.
        core::arch::asm!("mov cr3, {}", in(reg) fresh_root, options(nostack, preserves_flags));
        compiler_fence(Ordering::SeqCst);
        let observed: u64;
        core::arch::asm!("mov {}, cr3", out(reg) observed, options(nomem, nostack, preserves_flags));
        if observed & ADDRESS_MASK != fresh_root {
            return Err(Error::VerificationFailed);
        }
        ACTIVE_ROOT.store(fresh_root, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = inherited_root;
        Err(Error::UnsupportedArchitecture)
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
