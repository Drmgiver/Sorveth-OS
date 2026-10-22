# Sorveth OS development roadmap

Status as of 2026-10-22. Each milestone is accepted only on observable evidence.

| Phase | Deliverable | Acceptance gate | State |
|---|---|---|---|
| M0-A | Source bootstrap | UEFI loader, freestanding kernel, ABI, capability prototype, memory map validation, host tests | Authored, validation incomplete |
| M0-B | First actual boot | Cross-build EFI; QEMU boots; COM1 shows native post-firmware output; framebuffer draws | CI smoke test authored, not executed |
| M1 | Memory/CPU foundation | UEFI memory map parser, own frame allocator, new page tables, IDT, timer, exceptions, dedicated kernel stack | Parser and bootstrap frame-planner diagnostic authored, uncompiled; durable allocator/CPU pending |
| M2 | Real microkernel separation | User-mode process, kernel syscalls, message IPC, scheduler and capability-checked mediation | Pending |
| M3 | User-space system services | Separate storage/input/display driver services and initial resource persistence | Pending |
| M4 | Sorveth Space desktop | Window manager, compositor, keyboard/mouse, native resource explorer, desktop runs without AI | Pending |
| M5 | Native app platform | Manifests, action contracts, editable resources, Forge, Atlas, Frame, Script | Pending |
| M6 | Sorveth Mind | Local model adapters, explicit broker, sandboxed builder, approval/verifier, full off switch | Pending |
| M7 | Daily-computing expansion | Networking, browser path, audio, USB, updates, expanded hardware coverage, security hardening | Pending |

## Next implementation sequence

1. On a machine with Rust/QEMU, compile `sorveth-boot` for the official UEFI target.
   Fix compiler and linker issues; preserve reproducible logs.
2. Boot with OVMF; check that `ExitBootServices` succeeds and serial output comes
   from `sorveth_core::kernel_main`, not UEFI text output. Check GOP splash.
3. Execute the authored QEMU debug-exit smoke test in CI, fix any compiler/boot
   failures, and add a serial-observable panic/exception facility.
4. Cross-build and host-test `sorveth-frames`; audit its reservations and then
   retain it as the first persistent kernel allocator. Reserve all loader/kernel,
   framebuffer, ACPI, runtime and MMIO physical regions before frame use.
5. Install owned x86-64 page tables and a dedicated kernel stack before moving
   beyond the handoff. Add IDT/exception handlers and basic timer interrupts.
6. Separate the kernel image from the EFI loader and build a verified ELF loader;
   then implement first isolated ring-3 task, minimal syscalls and IPC.

## Gate rules

- Source authored != compiled.
- Compiled != successfully booted.
- Boots under UEFI != independent native kernel (post-ExitBootServices is required).
- Capability handles in a struct != enforced inter-process capability security.
- A splash screen != a window server or usable desktop.
- A model demo != safe OS-level AI integration.

Known hazards: raw UEFI ABI layouts require audits; identity framebuffer mappings are
only a bootstrap assumption; fixed map buffers can be too small on some machines;
no memory allocator or real CPU protection exists yet. Early code is emulator-only,
not suitable for bare-metal use or handling personal data.
