//! M1-F: private x86-64 TSS and emergency fault stacks.
//!
//! Copy the currently active flat UEFI GDT into Sorveth-owned storage,
//! append a 64-bit available-TSS descriptor, load GDTR/TR, and configure
//! IST1 for page faults and IST2 for double faults. Interrupts remain masked.
//! No context switching or ring-3 stacks are implemented.

#[cfg(target_arch = "x86_64")]
use core::{
    arch::asm,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    ExistingGdtInvalid,
    TssNotLoaded,
    AlreadyInstalled,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    privilege_stacks: [u64; 3],
    reserved1: u64,
    interrupt_stacks: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_bitmap_offset: u16,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct EmergencyStack([u8; 32 * 1024]);

#[cfg(target_arch = "x86_64")]
static mut PAGE_FAULT_STACK: EmergencyStack = EmergencyStack([0; 32 * 1024]);
#[cfg(target_arch = "x86_64")]
static mut DOUBLE_FAULT_STACK: EmergencyStack = EmergencyStack([0; 32 * 1024]);

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct OwnedGdt([u64; 256]);

#[cfg(target_arch = "x86_64")]
static mut GDT: OwnedGdt = OwnedGdt([0; 256]);
#[cfg(target_arch = "x86_64")]
static mut TSS: TaskStateSegment = TaskStateSegment {
    reserved0: 0,
    privilege_stacks: [0; 3],
    reserved1: 0,
    interrupt_stacks: [0; 7],
    reserved2: 0,
    reserved3: 0,
    io_bitmap_offset: 104,
};
#[cfg(target_arch = "x86_64")]
static LOADED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
fn tss_descriptor(base: u64, limit: u64) -> (u64, u64) {
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89u64 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

/// # Safety
/// Must run in ring 0 on one CPU after UEFI ExitBootServices, while the
/// inherited GDT is still accessible and maskable interrupts are disabled.
/// Retaining the inherited segment descriptors is intentional at this stage.
pub unsafe fn install() -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    {
        if LOADED.load(Ordering::Acquire) {
            return Err(Error::AlreadyInstalled);
        }
        let mut old = DescriptorTablePointer { limit: 0, base: 0 };
        asm!("sgdt [{}]", in(reg) &mut old, options(nostack, preserves_flags));
        let old_size = old.limit as usize + 1;
        let old_base = old.base;
        let selector: u16;
        asm!("mov ax, cs", out("ax") selector, options(nomem, nostack, preserves_flags));
        if old_base == 0
            || old_size < 24
            || old_size % 8 != 0
            || old_size + 16 > core::mem::size_of::<OwnedGdt>()
            || (selector as usize & !7) >= old_size
        {
            return Err(Error::ExistingGdtInvalid);
        }
        // Preserve the current code/data descriptors, so the CPU can
        // continue using its current CS, SS, DS, etc. after LGDT.
        let base = ptr::addr_of_mut!(GDT).cast::<u8>();
        ptr::copy_nonoverlapping(old_base as *const u8, base, old_size);

        let pf = ptr::addr_of_mut!(PAGE_FAULT_STACK).cast::<u8>() as u64
            + core::mem::size_of::<EmergencyStack>() as u64;
        let df = ptr::addr_of_mut!(DOUBLE_FAULT_STACK).cast::<u8>() as u64
            + core::mem::size_of::<EmergencyStack>() as u64;
        let tss = TaskStateSegment {
            reserved0: 0,
            privilege_stacks: [0; 3],
            reserved1: 0,
            interrupt_stacks: [pf, df, 0, 0, 0, 0, 0],
            reserved2: 0,
            reserved3: 0,
            io_bitmap_offset: core::mem::size_of::<TaskStateSegment>() as u16,
        };
        ptr::write(ptr::addr_of_mut!(TSS), tss);

        let tss_base = ptr::addr_of!(TSS) as u64;
        let (low, high) = tss_descriptor(
            tss_base,
            (core::mem::size_of::<TaskStateSegment>() - 1) as u64,
        );
        let slot = old_size / 8;
        let gdt = ptr::addr_of_mut!(GDT).cast::<u64>();
        ptr::write(gdt.add(slot), low);
        ptr::write(gdt.add(slot + 1), high);
        let gdtr = DescriptorTablePointer {
            limit: (old_size + 16 - 1) as u16,
            base: gdt as u64,
        };
        asm!("lgdt [{}]", in(reg) &gdtr, options(readonly, nostack));
        let tss_selector = old_size as u16;
        asm!("ltr ax", in("ax") tss_selector, options(nostack, preserves_flags));
        let loaded: u16;
        asm!("str ax", out("ax") loaded, options(nomem, nostack, preserves_flags));
        if loaded != tss_selector {
            return Err(Error::TssNotLoaded);
        }
        LOADED.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(Error::Unsupported)
    }
}

pub fn ready() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        LOADED.load(Ordering::Acquire)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Called only from the #PF Rust entry to prove that the CPU chose IST1.
pub fn running_on_page_fault_ist() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if !ready() {
            return false;
        }
        let rsp: u64;
        unsafe {
            asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
        }
        let base = ptr::addr_of!(PAGE_FAULT_STACK) as u64;
        base < rsp && rsp < base + core::mem::size_of::<EmergencyStack>() as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn tss_and_16_byte_descriptor_binary_layout() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(core::mem::size_of::<super::TaskStateSegment>(), 104);
            assert_eq!(core::mem::size_of::<super::DescriptorTablePointer>(), 10);
            let base = 0x1234_5678_9abc_def0u64;
            let (low, high) = super::tss_descriptor(base, 103);
            assert_eq!((low >> 40) & 0xff, 0x89);
            assert_eq!(low & 0xffff, 103);
            assert_eq!(
                (low >> 16 & 0x00ff_ffff)
                    | (((low >> 56) & 0xff) << 24)
                    | (high << 32),
                base
            );
        }
    }
}
