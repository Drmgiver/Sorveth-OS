/* Independent C check of the UEFI x86-64 struct offsets in uefi.rs. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
typedef struct { uint64_t sig; uint32_t revision,size,crc,reserved; } hdr_t;
typedef struct {
  hdr_t header;
  uintptr_t raise, restore, alloc_pages, free_pages, get_memory_map, alloc_pool, free_pool;
  uintptr_t rest7_25[19], exit_boot_services, rest27_36[10], locate_protocol;
} bs_t;
typedef struct {
  hdr_t header;
  uint16_t *firmware_vendor;
  uint32_t firmware_revision;
  void *console_in_handle,*con_in,*console_out_handle,*con_out;
  void *standard_error_handle,*std_err,*runtime_services,*boot_services;
  uintptr_t num_config_entries;
  void *config_table;
} st_t;
typedef struct { uint32_t version, width, height, pixel_format; uint32_t mask[4]; uint32_t stride; } gop_mode_info_t;
typedef struct {
  uint32_t max_mode, mode; gop_mode_info_t *info;
  uintptr_t size_of_info; uint64_t framebuffer_base; uintptr_t framebuffer_size;
} gop_mode_t;
typedef struct {
  uint32_t type, padding;
  uint64_t physical_start, virtual_start, number_of_pages, attribute;
} efi_memory_descriptor_t;
typedef struct {
  uint64_t address, size_bytes;
  uint32_t width, height, stride, pixel_format;
} sorveth_framebuffer_t;
typedef struct {
  uint32_t version, reserved;
  sorveth_framebuffer_t framebuffer;
  uint64_t memory_map_address, memory_map_size, descriptor_size;
  uint32_t descriptor_version, reserved2;
} sorveth_boot_info_t;
_Static_assert(sizeof(efi_memory_descriptor_t)==40, "EFI memory descriptor minimum size");
_Static_assert(offsetof(efi_memory_descriptor_t, physical_start)==8, "EFI physical start offset");
_Static_assert(offsetof(efi_memory_descriptor_t, number_of_pages)==24, "EFI page count offset");
_Static_assert(sizeof(sorveth_framebuffer_t)==32, "Sorveth framebuffer layout");
_Static_assert(offsetof(sorveth_boot_info_t, memory_map_address)==40, "Sorveth map offset");
_Static_assert(sizeof(sorveth_boot_info_t)==72, "Sorveth boot info layout");
_Static_assert(sizeof(void*)==8, "this test is for x86-64");
_Static_assert(sizeof(hdr_t)==24, "UEFI header size");
_Static_assert(offsetof(bs_t, get_memory_map)==56, "GetMemoryMap offset");
_Static_assert(offsetof(bs_t, exit_boot_services)==232, "ExitBootServices offset");
_Static_assert(offsetof(bs_t, locate_protocol)==320, "LocateProtocol offset");
_Static_assert(offsetof(st_t, con_out)==64, "ConsoleOut offset");
_Static_assert(offsetof(st_t, boot_services)==96, "BootServices offset");
_Static_assert(sizeof(st_t)==120, "SystemTable prefix size");
_Static_assert(sizeof(gop_mode_info_t)==36, "GOP mode info size");
_Static_assert(offsetof(gop_mode_t, framebuffer_base)==24, "GOP framebuffer base");
int main(void) { puts("UEFI x86-64 ABI layout reference: PASS"); return 0; }
