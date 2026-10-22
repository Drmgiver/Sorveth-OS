#![no_std]
#![no_main]

//! Firmware-facing UEFI loader. After ExitBootServices succeeds, execution
//! enters sorveth_core::kernel_main without making further firmware calls.

mod uefi;

use sorveth_abi::{BootInfo, FramebufferInfo, BOOT_PROTOCOL_VERSION};
use core::{ffi::c_void, ptr};
use uefi::{BootServices, Status, SystemTable};

const MAP_BUFFER_CAPACITY: usize = 128 * 1024;
#[repr(align(16))]
struct MapBuffer([u8; MAP_BUFFER_CAPACITY]);
static mut MEMORY_MAP: MapBuffer = MapBuffer([0u8; MAP_BUFFER_CAPACITY]);

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: *mut c_void, system_table: *mut SystemTable)
    -> Status
{
    if system_table.is_null() || image_handle.is_null() {
        return uefi::EFI_INVALID_PARAMETER;
    }
    unsafe {
        let st = &*system_table;
        if st.header.signature != uefi::EFI_SYSTEM_TABLE_SIGNATURE
            || st.boot_services.is_null()
        {
            return uefi::EFI_INVALID_PARAMETER;
        }
        let bs = &*st.boot_services;
        uefi::write_line(system_table, "SORVETH BOOT / UEFI x86-64");
        uefi::write_line(system_table, "Locating native framebuffer...");
        let fb = detect_framebuffer(bs);
        if fb.is_usable() {
            uefi::write_line(system_table, "GOP framebuffer ready");
        } else {
            uefi::write_line(system_table, "GOP unavailable; serial-only kernel output");
        }
        uefi::write_line(system_table, "Exiting firmware boot services...");

        // No console operations, allocations, protocol calls or other actions
        // that can mutate the UEFI memory map between the following two calls.
        // A changed map key is retried with GetMemoryMap + ExitBootServices only.
        for _ in 0..4 {
            let mut size = MAP_BUFFER_CAPACITY;
            let mut key = 0usize;
            let mut descriptor_size = 0usize;
            let mut descriptor_version = 0u32;
            let buffer = ptr::addr_of_mut!(MEMORY_MAP.0).cast::<u8>();
            let status = (bs.get_memory_map)(
                &mut size, buffer, &mut key, &mut descriptor_size, &mut descriptor_version
            );
            if status != uefi::EFI_SUCCESS { return status; }
            let info = BootInfo {
                protocol_version: BOOT_PROTOCOL_VERSION,
                reserved: 0,
                framebuffer: fb,
                memory_map_address: buffer as u64,
                memory_map_size: size as u64,
                memory_descriptor_size: descriptor_size as u64,
                memory_descriptor_version: descriptor_version,
                reserved2: 0,
            };
            let exit_status = (bs.exit_boot_services)(image_handle, key);
            if exit_status == uefi::EFI_SUCCESS {
                // Ownership of the machine has transferred from firmware.
                // Sorveth Core runs independently of UEFI boot services.
                sorveth_core::kernel_main(&info);
            }
            if exit_status != uefi::EFI_INVALID_PARAMETER {
                return exit_status;
            }
        }
        uefi::EFI_INVALID_PARAMETER
    }
}

unsafe fn detect_framebuffer(bs: &BootServices) -> FramebufferInfo {
    let mut interface: *mut c_void = ptr::null_mut();
    let rc = (bs.locate_protocol)(&uefi::GOP_GUID, ptr::null_mut(), &mut interface);
    if rc != uefi::EFI_SUCCESS || interface.is_null() {
        return FramebufferInfo::unavailable();
    }
    let gop = &*(interface.cast::<uefi::Gop>());
    if gop.mode.is_null() { return FramebufferInfo::unavailable(); }
    let mode = &*gop.mode;
    if mode.info.is_null() || mode.size_of_info < core::mem::size_of::<uefi::GopModeInfo>() {
        return FramebufferInfo::unavailable();
    }
    let mi = &*mode.info;
    let fb = FramebufferInfo {
        address: mode.framebuffer_base,
        size_bytes: mode.framebuffer_size as u64,
        width: mi.horizontal_resolution,
        height: mi.vertical_resolution,
        pixels_per_scanline: mi.pixels_per_scanline,
        pixel_format: mi.pixel_format,
    };
    if fb.is_usable() { fb } else { FramebufferInfo::unavailable() }
}

#[panic_handler]
fn panic(_panic: &core::panic::PanicInfo<'_>) -> ! {
    loop { core::hint::spin_loop(); }
}
