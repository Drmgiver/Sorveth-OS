//! Test-only x86-64 transition to an explicitly mapped ring-3 code page.
//! No normal kernel image enters this path. The unprivileged probe invokes
//! INT 0x80 twice, and the kernel's test handler exits QEMU after the second.

/// # Safety
/// Requires a loaded ring-3 GDT/TSS, valid user-executable page, user stack,
/// and DPL3 INT80 handler. This is the QEMU-only acceptance path.
pub unsafe fn enter(entry: u64, stack: u64, user_cs: u16, user_ss: u16) -> ! {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "push {ss}",
        "push {stack}",
        "pushfq",
        "push {cs}",
        "push {entry}",
        "iretq",
        ss = in(reg) user_ss as u64,
        stack = in(reg) stack,
        cs = in(reg) user_cs as u64,
        entry = in(reg) entry,
        options(noreturn),
    );
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (entry, stack, user_cs, user_ss);
        loop {
            core::hint::spin_loop();
        }
    }
}
