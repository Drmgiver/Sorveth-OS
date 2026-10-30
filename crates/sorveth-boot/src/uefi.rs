//! Minimal x86-64 UEFI ABI surface. Each layout requires verification against
//! UEFI 2.x; we deliberately avoid exposing arbitrary BootServices calls.
use core::ffi::c_void;

pub type Status = usize;
pub const EFI_SUCCESS: Status = 0;
pub const EFI_INVALID_PARAMETER: Status = (1usize << (usize::BITS - 1)) | 2;
pub const EFI_BUFFER_TOO_SMALL: Status = (1usize << (usize::BITS - 1)) | 5;
pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct TextOutputProtocol {
    pub reset: usize,
    pub output_string: extern "efiapi" fn(*mut TextOutputProtocol, *const u16) -> Status,
    // Remaining members are not needed by this bootstrap stage.
}

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// EFI_LOADED_IMAGE_PROTOCOL_GUID from UEFI specification chapter 9.
pub const LOADED_IMAGE_GUID: Guid = Guid {
    data1: 0x5b1b_31a1,
    data2: 0x9562,
    data3: 0x11d2,
    data4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const LOADED_IMAGE_REVISION: u32 = 0x1000;

/// Only read fixed fields through ImageSize. The UEFI owner retains this
/// protocol until ExitBootServices; kernel receives copied scalar metadata.
#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: *mut c_void,
    pub system_table: *mut SystemTable,
    pub device_handle: *mut c_void,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

pub const GOP_GUID: Guid = Guid {
    data1: 0x9042_a9de,
    data2: 0x23dc,
    data3: 0x4a38,
    data4: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};

#[repr(C)]
pub struct Gop {
    pub query_mode: usize,
    pub set_mode: usize,
    pub blt: usize,
    pub mode: *mut GopMode,
}

#[repr(C)]
pub struct GopMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *mut GopModeInfo,
    pub size_of_info: usize,
    pub framebuffer_base: u64,
    pub framebuffer_size: usize,
}

#[repr(C)]
pub struct GopModeInfo {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: [u32; 4],
    pub pixels_per_scanline: u32,
}

#[repr(C)]
pub struct BootServices {
    pub header: TableHeader,
    // Offsets 24..56: service pointers 0 through 3.
    _raise_tpl: usize,
    _restore_tpl: usize,
    _allocate_pages: usize,
    _free_pages: usize,
    // Pointer #4 / offset 56.
    pub get_memory_map:
        extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    _allocate_pool: usize, // #5
    _free_pool: usize,     // #6
    _unused_7_through_15: [usize; 9],
    // Pointer #16 / offset 152, obtained before GetMemoryMap/ExitBootServices.
    pub handle_protocol:
        extern "efiapi" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Status,
    _unused_17_through_25: [usize; 9],
    // Pointer #26 / offset 232.
    pub exit_boot_services: extern "efiapi" fn(*mut c_void, usize) -> Status,
    _unused_27_through_36: [usize; 10],
    // Pointer #37 / offset 320.
    pub locate_protocol: extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
}

#[repr(C)]
pub struct SystemTable {
    pub header: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: *mut c_void,
    pub con_in: *mut c_void,
    pub console_out_handle: *mut c_void,
    pub con_out: *mut TextOutputProtocol,
    pub standard_error_handle: *mut c_void,
    pub std_err: *mut TextOutputProtocol,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut c_void,
}

/// UEFI text output is for loader diagnostics ONLY (before ExitBootServices).
pub unsafe fn write_line(st: *mut SystemTable, message: &str) {
    let console = (*st).con_out;
    if console.is_null() {
        return;
    }
    let mut buf = [0u16; 128];
    let mut used = 0usize;
    for ch in message.bytes().chain([b'\r', b'\n']) {
        if used == buf.len() - 1 {
            buf[used] = 0;
            ((*console).output_string)(console, buf.as_ptr());
            used = 0;
        }
        buf[used] = ch as u16;
        used += 1;
    }
    buf[used] = 0;
    ((*console).output_string)(console, buf.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loaded_image_and_boot_services_abi_layouts() {
        assert_eq!(core::mem::offset_of!(LoadedImage, image_base), 64);
        assert_eq!(core::mem::offset_of!(LoadedImage, image_size), 72);
        assert_eq!(core::mem::offset_of!(BootServices, handle_protocol), 152);
        assert_eq!(core::mem::offset_of!(BootServices, exit_boot_services), 232);
        assert_eq!(core::mem::offset_of!(BootServices, locate_protocol), 320);
    }
}
