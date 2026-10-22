#![no_std]

//! Versioned loader-to-kernel handoff contract.
//! This is NOT yet a stable userspace syscall ABI.

/// Update this whenever the layout of [`BootInfo`] changes incompatibly.
pub const BOOT_PROTOCOL_VERSION: u32 = 1;

pub const PIXEL_RGB: u32 = 0;
pub const PIXEL_BGR: u32 = 1;
pub const PIXEL_UNAVAILABLE: u32 = u32::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FramebufferInfo {
    /// Physical address under the identity mappings inherited from firmware.
    pub address: u64,
    pub size_bytes: u64,
    pub width: u32,
    pub height: u32,
    pub pixels_per_scanline: u32,
    /// UEFI GOP pixel format: 0=RGB, 1=BGR; other formats cannot be rendered.
    pub pixel_format: u32,
}

impl FramebufferInfo {
    pub const fn unavailable() -> Self {
        Self {
            address: 0,
            size_bytes: 0,
            width: 0,
            height: 0,
            pixels_per_scanline: 0,
            pixel_format: PIXEL_UNAVAILABLE,
        }
    }

    pub fn is_usable(&self) -> bool {
        if self.address == 0
            || self.width == 0
            || self.height == 0
            || self.width > self.pixels_per_scanline
            || !(self.pixel_format == PIXEL_RGB || self.pixel_format == PIXEL_BGR)
        {
            return false;
        }
        if self.address.checked_add(self.size_bytes).is_none() {
            return false;
        }
        let final_pixel = (self.height as u64 - 1)
            .checked_mul(self.pixels_per_scanline as u64)
            .and_then(|v| v.checked_add(self.width as u64));
        match final_pixel.and_then(|n| n.checked_mul(4)) {
            Some(required) => required <= self.size_bytes,
            None => false,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    pub protocol_version: u32,
    pub reserved: u32,
    pub framebuffer: FramebufferInfo,
    /// Address and size of UEFI memory descriptors captured just before ExitBootServices.
    pub memory_map_address: u64,
    pub memory_map_size: u64,
    pub memory_descriptor_size: u64,
    pub memory_descriptor_version: u32,
    pub reserved2: u32,
}

impl BootInfo {
    pub fn is_valid(&self) -> bool {
        self.protocol_version == BOOT_PROTOCOL_VERSION
            && self.memory_map_address != 0
            && self.memory_descriptor_size >= 40
            && self.memory_map_size >= self.memory_descriptor_size as u64
            && self.memory_map_size % self.memory_descriptor_size as u64 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graphics_rejects_truncated_framebuffer() {
        let mut f = FramebufferInfo {
            address: 0x100000,
            size_bytes: 640 * 480 * 4,
            width: 640,
            height: 480,
            pixels_per_scanline: 640,
            pixel_format: PIXEL_BGR,
        };
        assert!(f.is_usable());
        f.size_bytes -= 4;
        assert!(!f.is_usable());
    }
}
