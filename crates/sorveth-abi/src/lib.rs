#![no_std]

//! Versioned loader-to-kernel handoff contract.
//! This is NOT yet a stable userspace syscall ABI.

/// Update this whenever the layout of [`BootInfo`] changes incompatibly.
pub const BOOT_PROTOCOL_VERSION: u32 = 2;

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
    /// Trusted UEFI Loaded Image Protocol extent; image bytes remain retained.
    /// Physical/virtual identity is transitional and must be audited by Core.
    pub image_base: u64,
    pub image_size: u64,
}

impl BootInfo {
    pub fn is_valid(&self) -> bool {
        self.protocol_version == BOOT_PROTOCOL_VERSION
            && self.memory_map_address != 0
            && self.memory_descriptor_size >= 40
            && self.memory_map_size >= self.memory_descriptor_size as u64
            && self.memory_map_size % self.memory_descriptor_size as u64 == 0
            && self.image_base != 0
            && self.image_base & 4095 == 0
            && (4096..=128 * 1024 * 1024).contains(&self.image_size)
            && self.image_base.checked_add(self.image_size).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_handoff_is_bounded_and_versioned() {
        assert_eq!(core::mem::size_of::<BootInfo>(), 88);
        let mut info = BootInfo {
            protocol_version: BOOT_PROTOCOL_VERSION,
            reserved: 0,
            framebuffer: FramebufferInfo::unavailable(),
            memory_map_address: 0x3000,
            memory_map_size: 48,
            memory_descriptor_size: 48,
            memory_descriptor_version: 1,
            reserved2: 0,
            image_base: 0x20_0000,
            image_size: 0x30000,
        };
        assert!(info.is_valid());
        info.image_base += 1;
        assert!(!info.is_valid());
        info.image_base -= 1;
        info.image_size = 0;
        assert!(!info.is_valid());
        info.image_size = 0x30000;
        info.protocol_version -= 1;
        assert!(!info.is_valid());
    }

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
