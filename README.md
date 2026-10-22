# Sorveth OS

**An independent, local-first, AI-optional, user-owned operating system.**

Sorveth OS is a **from-scratch operating system project**, not a Linux distribution,
not a Wine/Windows compatibility environment, and not a conventional OS with a
chatbot glued on top. Its core principles are user ownership, understandable native
software, explicit capabilities, portability, and useful computing with AI fully off.

This repository is the **initial engineering baseline, dated 2026-10-22**. It
contains real early-stage source code, not a complete OS. This bootstrap milestone
is designed to run Rust kernel code without UEFI boot services after a firmware handoff. It
**does not yet** provide task isolation, a scheduler, IPC, filesystem, drivers,
resource editing, a desktop, or AI.

## Subsystems we are building

| System | Role | State |
|---|---|---|
| Sorveth Core | Independent Rust microkernel and capability protection | Bootstrap only |
| Sorveth Space | Original project/activity desktop with windows/files/menus | Architecture defined |
| Sorveth Vault | Portable structured resource/data environment | Architecture defined |
| Sorveth Mind | Optional local-first OS agent, broker and native app builder | Architecture defined |
| Sorveth Forge | Native code / app creation tooling | Planned |
| Sorveth Atlas / Frame / Script | Resource explorer / media tools / automation | Planned |

## Repository layout

- `crates/sorveth-abi`: typed versioned bootloader-to-kernel handoff.
- `crates/sorveth-cap`: `no_std`, fixed-capacity capabilities with least-rights derivation,
  generations to reject stale handles, and recursive descendant revocation.
- `crates/sorveth-memory`: allocation-free, checked UEFI memory-descriptor reader and
  conventional-page summary.
- `crates/sorveth-frames`: no-heap physical-frame ownership planner with checked
  reservations, overlap rejection and contiguous allocation. Early kernel entry
  now audits the map and proves two disjoint frame claims; this remains a
  non-persistent diagnostic, not a production memory manager or new page tables.
- `crates/sorveth-boot`: small x86-64 UEFI loader. Obtains GOP and the final memory map,
  calls `ExitBootServices`, then transfers control to Sorveth Core.
- `crates/sorveth-core`: freestanding Rust kernel entry, x86 serial trace and direct
  framebuffer splash. After handoff it makes no firmware boot-service calls.
- `docs`: implementation decisions, architecture, security rules, roadmap.
- `scripts`: local build, checks, and QEMU boot command.
- `.github/workflows`: cross-build and host tests for a future dedicated repository.

## Build and run (Linux development host)

Prerequisites: stable Rust with rustup/cargo, C compiler, QEMU x86-64 and OVMF
(UEFI firmware). Example package names vary by distribution.

```sh
rustup target add x86_64-unknown-uefi
./scripts/check.sh
./scripts/run-qemu.sh
```

For a fully automated milestone gate on a host with the toolchain installed,
run `./scripts/smoke-qemu.sh`. This builds a dedicated smoke-test EFI image,
checks serial markers emitted *after* firmware exit, and requires the QEMU
`isa-debug-exit` device to return success. The GitHub Actions workflow runs this test on pushes. Each smoke-test run
preserves serial and QEMU diagnostics in the `sorveth-qemu-diagnostics` Actions
artifact, including when boot fails. Locally, set `SORVETH_QEMU_ARTIFACT_DIR`
to an output directory to keep the same evidence. Until a real run passes,
boot success must not be claimed.

The QEMU script detects commonly installed OVMF images; override with
`OVMF_CODE=/path/to/OVMF_CODE.fd` and `OVMF_VARS=/path/to/OVMF_VARS.fd` as needed.
For serial-only operation, run `./scripts/run-qemu.sh --headless`.
The script compiles a PE32+ `sorveth-boot.efi` image and places it at
`esp/EFI/BOOT/BOOTX64.EFI` for the emulated UEFI firmware.

After a successful boot, QEMU COM1 should print messages including:

```text
SORVETH OS / Sorveth Core
Native kernel execution: EFI boot services exited
Boot protocol v1: OK
UEFI physical memory map: validated
Physical frame planner: validated (no mappings written)
Capability table: initialized
SORVETH CORE ONLINE / end of milestone 0
```

If GOP supports RGB/BGR 32-bit linear framebuffer access, the display should show
a Sorveth OS startup splash after the firmware handoff. The CPU deliberately halts
when this smoke test finishes; it is not a working desktop.

## Test status (2026-10-22)

- **Passed:** C/x86-64 UEFI ABI layout reference test (`./scripts/check-layout.sh`).
- **Authored but not executed:** Rust capability, memory-parser, frame-planner and boot-protocol unit tests; a bootstrap physical-frame diagnostic; an automated QEMU/OVMF smoke test with a test-only debug-exit device.
- **Not yet verified:** Rust cross-build, QEMU/OVMF boot and on-screen splash; the automated boot test cannot run in the current environment.
- **Reason:** The authoring environment lacks Rust/cargo and QEMU, with no network
  package access. Do not report M0 as boot-tested until both pass.
- **Not implemented:** production/installed physical or virtual memory manager, own page tables, user processes, actual
  kernel-enforced capability isolation, services, filesystems, networking, desktop,
  AI, and general-purpose application support.

See the authoritative [Sorveth Product Constitution](docs/SORVETH_VISION.md),
[implementation roadmap](docs/ROADMAP.md), [architecture](docs/ARCHITECTURE.md)
and [security model](docs/SECURITY.md) for the design and engineering gates.

## License and contributions

Copyright 2026 Sorveth OS contributors. GNU GPL v3.0 (`LICENSE`). Design discussions,
changes, and new user-facing resources should preserve the project's ownership,
portability, permission and no-AI-required principles.