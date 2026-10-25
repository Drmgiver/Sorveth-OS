//! Early x86-64 exception table. Interrupts remain disabled: no IRQs,
//! scheduling, TSS/IST or privilege transitions exist yet.
//!
//! The IDT vectors installed here are synchronous #BP, #GP and #PF. Every
//! unexpected fault emits serial diagnostics and halts. The #BP handler
//! preserves volatile registers and returns through iretq, so it can be
//! exercised by the automated QEMU boot test.

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

#[cfg(target_arch = "x86_64")]
impl Gate {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: u64, selector: u16) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            ist: 0,
            attributes: 0x8e, // present 64-bit interrupt gate, DPL 0
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    #[cfg(test)]
    fn address(self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_middle as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct Descriptor {
    limit: u16,
    base: u64,
}

#[cfg(target_arch = "x86_64")]
static mut IDT: [Gate; 256] = [Gate::EMPTY; 256];
#[cfg(target_arch = "x86_64")]
static BREAKPOINT_HITS: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.global sorveth_exception_breakpoint_entry
sorveth_exception_breakpoint_entry:
    push rbx
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rbx, rsp
    and rsp, -16
    sub rsp, 32
    call sorveth_exception_breakpoint_rust
    mov rsp, rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    pop rbx
    iretq

.global sorveth_exception_page_fault_entry
sorveth_exception_page_fault_entry:
    push rbx
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rbx, rsp
    mov rcx, cr2
    mov rdx, [rbx + 64]
    and rsp, -16
    sub rsp, 32
    call sorveth_exception_page_fault_rust
    cli
1:
    hlt
    jmp 1b

.global sorveth_exception_general_protection_entry
sorveth_exception_general_protection_entry:
    push rbx
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rbx, rsp
    mov rcx, [rbx + 64]
    and rsp, -16
    sub rsp, 32
    call sorveth_exception_general_protection_rust
    cli
2:
    hlt
    jmp 2b

.global sorveth_exception_double_fault_entry
sorveth_exception_double_fault_entry:
    push rbx
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rbx, rsp
    mov rcx, [rbx + 64]
    and rsp, -16
    sub rsp, 32
    call sorveth_exception_double_fault_rust
    cli
3:
    hlt
    jmp 3b
"#
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn sorveth_exception_breakpoint_entry();
    fn sorveth_exception_page_fault_entry();
    fn sorveth_exception_general_protection_entry();
    fn sorveth_exception_double_fault_entry();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedArchitecture,
}

pub fn install() -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // No external IRQs may arrive until an actual scheduler/IRQ system
        // is designed. This must run before the intentional int3 probe.
        core::arch::asm!("cli", options(nomem, nostack));
        let selector: u16;
        core::arch::asm!(
            "mov ax, cs",
            out("ax") selector,
            options(nomem, nostack, preserves_flags)
        );
        IDT[3] = Gate::new(sorveth_exception_breakpoint_entry as usize as u64, selector);
        IDT[13] = Gate::new(
            sorveth_exception_general_protection_entry as usize as u64,
            selector,
        );
        IDT[14] = Gate::new(sorveth_exception_page_fault_entry as usize as u64, selector);
        let descriptor = Descriptor {
            limit: (core::mem::size_of::<[Gate; 256]>() - 1) as u16,
            base: core::ptr::addr_of!(IDT) as u64,
        };
        core::arch::asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack));
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(Error::UnsupportedArchitecture)
    }
}

/// Once TR holds Sorveth's own TSS, direct #PF to IST1 and #DF to IST2.
/// The current IDT lives in permanent statically allocated kernel memory.
/// IRQs are still disabled; no user/kernel transitions occur.
pub fn enable_fault_stacks() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if !crate::tss::ready() {
            return false;
        }
        let selector = IDT[14].selector;
        IDT[14].ist = 1;
        let mut df = Gate::new(
            sorveth_exception_double_fault_entry as usize as u64,
            selector,
        );
        df.ist = 2;
        IDT[8] = df;
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

pub fn breakpoint_roundtrip() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let before = BREAKPOINT_HITS.load(Ordering::SeqCst);
        unsafe {
            core::arch::asm!("int3", options(nomem, nostack));
        }
        BREAKPOINT_HITS.load(Ordering::SeqCst) == before + 1
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "efiapi" fn sorveth_exception_breakpoint_rust() {
    BREAKPOINT_HITS.fetch_add(1, Ordering::SeqCst);
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "efiapi" fn sorveth_exception_page_fault_rust(address: u64, error: u64) -> ! {
    crate::serial::write_line("SORVETH EXCEPTION: PAGE FAULT");
    if crate::tss::running_on_page_fault_ist() {
        crate::serial::write_line("Sorveth page fault IST1: active");
    } else {
        crate::serial::write_line("FATAL: page fault did not enter emergency IST1 stack");
        halt_fault();
    }
    crate::serial::write("Fault address (CR2): ");
    crate::serial::write_hex_u64(address);
    crate::serial::write_line("");
    crate::serial::write("Page fault error code: ");
    crate::serial::write_hex_u64(error);
    crate::serial::write_line("");
    #[cfg(feature = "qemu-fault")]
    {
        if crate::root::deliberate_fault_address() == Some(address) {
            crate::serial::write_line("SORVETH CONTROLLED PAGE FAULT: verified");
            unsafe {
                core::arch::asm!(
                    "out dx, al",
                    in("dx") 0xf4u16,
                    in("al") 0x10u8,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
    }
    #[cfg(feature = "qemu-user")]
    {
        // P=1, W=0, U=1: privilege-protected supervisor mapping.
        // This must be a protection failure, not merely an absent page.
        if USER_TRAP_PHASE.load(Ordering::Acquire) == 2
            && crate::root::protected_kernel_address() == Some(address)
            && (error & 0x7) == 0x5
        {
            crate::serial::write_line("SORVETH USER KERNEL-MEMORY DENIAL: verified");
            unsafe {
                core::arch::asm!(
                    "out dx, al",
                    in("dx") 0xf4u16,
                    in("al") 0x10u8,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
    }
    halt_fault()
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "efiapi" fn sorveth_exception_general_protection_rust(error: u64) -> ! {
    crate::serial::write_line("SORVETH EXCEPTION: GENERAL PROTECTION");
    crate::serial::write("GP error code: ");
    crate::serial::write_hex_u64(error);
    crate::serial::write_line("");
    halt_fault()
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "efiapi" fn sorveth_exception_double_fault_rust(error: u64) -> ! {
    crate::serial::write_line("SORVETH EXCEPTION: DOUBLE FAULT");
    crate::serial::write("Double-fault error code: ");
    crate::serial::write_hex_u64(error);
    crate::serial::write_line("");
    halt_fault()
}

#[cfg(target_arch = "x86_64")]
fn halt_fault() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", options(nomem, nostack));
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_and_descriptor_match_x86_idt_binary_layout() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(core::mem::size_of::<Gate>(), 16);
            assert_eq!(core::mem::size_of::<Descriptor>(), 10);
            let entry = Gate::new(0x1234_5678_90ab_cdef, 0x08);
            assert_eq!(entry.address(), 0x1234_5678_90ab_cdef);
            assert_eq!(entry.attributes, 0x8e);
        }
    }
}

#[cfg(all(target_arch = "x86_64", feature = "qemu-user"))]
static USER_TRAP_PHASE: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_arch = "x86_64", feature = "qemu-user"))]
core::arch::global_asm!(
    r#"
.global sorveth_user_int80_entry
sorveth_user_int80_entry:
    push rbx
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rbx, rsp
    mov rcx, [rbx + 48]
    mov rdx, [rbx + 72]
    and rsp, -16
    sub rsp, 32
    call sorveth_user_int80_rust
    mov [rbx + 48], rax
    mov rsp, rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    pop rbx
    iretq
"#
);

#[cfg(all(target_arch = "x86_64", feature = "qemu-user"))]
extern "C" {
    fn sorveth_user_int80_entry();
}

#[cfg(feature = "qemu-user")]
pub fn install_user_gateway() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if !crate::tss::ready() {
            return false;
        }
        let kernel_code = IDT[3].selector;
        if kernel_code == 0 {
            return false;
        }
        let mut gate = Gate::new(sorveth_user_int80_entry as usize as u64, kernel_code);
        gate.attributes = 0xee; // present interrupt gate, DPL3
        IDT[0x80] = gate;
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// The ring-3 probe must execute two separate INT 0x80 instructions.
/// The first trap returns a known RAX value to user code. The second can
/// occur only if IRETQ returned to the unprivileged instruction stream.
#[cfg(all(target_arch = "x86_64", feature = "qemu-user"))]
#[no_mangle]
pub extern "efiapi" fn sorveth_user_int80_rust(number: u64, caller_cs: u64) -> u64 {
    if caller_cs & 3 != 3 {
        crate::serial::write_line("FATAL: ring-3 trap came from wrong privilege");
        halt_fault();
    }
    if number == 7 && USER_TRAP_PHASE.load(Ordering::Acquire) == 0 {
        USER_TRAP_PHASE.store(1, Ordering::Release);
        crate::serial::write_line("Sorveth ring-3 syscall: entered kernel from user mode");
        return 0x5356_5246;
    }
    if number == 8 && USER_TRAP_PHASE.load(Ordering::Acquire) == 1 {
        USER_TRAP_PHASE.store(2, Ordering::Release);
        crate::serial::write_line("SORVETH RING3 ROUNDTRIP: verified");
        return 0;
    }
    crate::serial::write_line("FATAL: invalid ring-3 syscall probe sequence");
    halt_fault()
}
