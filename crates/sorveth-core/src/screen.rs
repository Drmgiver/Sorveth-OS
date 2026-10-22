//! Minimal software-rendered native framebuffer splash after firmware exit.
//! Direct memory writes are intentional only for this early boot experiment.

use sorveth_abi::{FramebufferInfo, PIXEL_BGR};

struct Canvas<'a> { fb: &'a FramebufferInfo }

impl Canvas<'_> {
    fn pixel(&self, x: u32, y: u32, rgb: u32) {
        if x >= self.fb.width || y >= self.fb.height { return; }
        let byte_offset = ((y as u64 * self.fb.pixels_per_scanline as u64) + x as u64) * 4;
        if byte_offset + 4 > self.fb.size_bytes { return; }
        let red = (rgb >> 16) & 0xff;
        let green = (rgb >> 8) & 0xff;
        let blue = rgb & 0xff;
        let packed = if self.fb.pixel_format == PIXEL_BGR {
            (red << 16) | (green << 8) | blue
        } else {
            (blue << 16) | (green << 8) | red
        };
        // Safety: bootloader checks framebuffer bounds, geometry and format.
        // The inherited firmware identity mapping must still be active here.
        unsafe {
            ((self.fb.address + byte_offset) as *mut u32).write_volatile(packed);
        }
    }

    fn rect(&self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let end_y = y.saturating_add(h).min(self.fb.height);
        let end_x = x.saturating_add(w).min(self.fb.width);
        for py in y.min(self.fb.height)..end_y {
            for px in x.min(self.fb.width)..end_x { self.pixel(px, py, color); }
        }
    }

    fn glyph(&self, x: u32, y: u32, ch: u8, scale: u32, color: u32) {
        let glyph = bitmap(ch);
        for (row, mask) in glyph.iter().enumerate() {
            for col in 0..5 {
                if (*mask & (1u8 << (4 - col))) != 0 {
                    self.rect(x + col * scale, y + row as u32 * scale, scale, scale, color);
                }
            }
        }
    }

    fn text(&self, x: u32, y: u32, text: &str, scale: u32, color: u32) {
        for (n, ch) in text.bytes().enumerate() {
            let advance = (n as u32).saturating_mul(6).saturating_mul(scale);
            self.glyph(x.saturating_add(advance), y, ch, scale, color);
        }
    }
}

pub fn paint(fb: &FramebufferInfo) {
    if !fb.is_usable() { return; }
    let c = Canvas { fb };
    c.rect(0, 0, fb.width, fb.height, 0x101827);
    let margin = fb.width / 12;
    let upper = fb.height / 4;
    let scale = if fb.width >= 960 { 7 } else if fb.width >= 640 { 5 } else { 3 };
    c.rect(margin, upper.saturating_sub(24), 108, 6, 0x49DFC2);
    c.text(margin, upper, "SORVETH OS", scale, 0xF2F8FF);
    let lower = upper.saturating_add(70 * scale / 5);
    c.text(margin, lower, "CORE ONLINE", 2, 0x49DFC2);
    let strip_y = fb.height.saturating_sub(58);
    c.rect(0, strip_y, fb.width, 2, 0x30445F);
    c.text(margin, strip_y.saturating_add(16), "MILESTONE 0", 2, 0xD1DCE8);
}

fn bitmap(c: u8) -> [u8; 7] {
    // Five-bit rows, seven rows per glyph. Enough for the boot milestone.
    match c {
        b'A' => [14,17,17,31,17,17,17],
        b'C' => [14,17,16,16,16,17,14],
        b'E' => [31,16,16,30,16,16,31],
        b'I' => [31,4,4,4,4,4,31],
        b'L' => [16,16,16,16,16,16,31],
        b'M' => [17,27,21,21,17,17,17],
        b'N' => [17,25,21,19,17,17,17],
        b'O' => [14,17,17,17,17,17,14],
        b'R' => [30,17,17,30,20,18,17],
        b'S' => [15,16,16,14,1,1,30],
        b'T' => [31,4,4,4,4,4,4],
        b'X' => [17,17,10,4,10,17,17],
        b'0' => [14,17,19,21,25,17,14],
        b' ' => [0,0,0,0,0,0,0],
        _ => [0,0,0,0,0,0,0],
    }
}
