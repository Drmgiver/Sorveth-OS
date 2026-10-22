//! Early x86 UART COM1 driver; serial port is set up before the first write.
//! Production drivers will move to isolated userspace services.

#[cfg(target_arch = "x86_64")]
mod uart {
    const COM1: u16 = 0x3f8;

    #[inline]
    unsafe fn out(port: u16, data: u8) {
        core::arch::asm!("out dx, al", in("dx") port, in("al") data,
            options(nomem, nostack, preserves_flags));
    }
    #[inline]
    unsafe fn input(port: u16) -> u8 {
        let value: u8;
        core::arch::asm!("in al, dx", in("dx") port, out("al") value,
            options(nomem, nostack, preserves_flags));
        value
    }
    pub fn init() {
        unsafe {
            out(COM1 + 1, 0x00); // disable interrupts
            out(COM1 + 3, 0x80); // DLAB
            out(COM1, 0x03); // divisor 3: 38400 baud
            out(COM1 + 1, 0x00);
            out(COM1 + 3, 0x03); // 8N1
            out(COM1 + 2, 0xC7); // enable FIFO
            out(COM1 + 4, 0x0B); // modem control
        }
    }
    pub fn put(byte: u8) {
        // Bounded wait: kernel must never hang solely due to missing UART.
        let mut attempts = 0;
        while attempts < 100_000 {
            if unsafe { input(COM1 + 5) } & 0x20 != 0 {
                unsafe {
                    out(COM1, byte);
                }
                return;
            }
            attempts += 1;
        }
    }
}

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    uart::init();
}
pub fn write_line(msg: &str) {
    #[cfg(target_arch = "x86_64")]
    {
        for byte in msg.bytes() {
            uart::put(byte);
        }
        uart::put(b'\r');
        uart::put(b'\n');
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = msg;
}
