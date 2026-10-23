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
- `crates/sorveth-frames`: a permanent locked ledger for conventional-memory
  physical frame claims, with checked reservations and overlap rejection. Its
  physical claims are unmapped until an address is explicitly installed.
- `crates/sorveth-paging`: no-heap 4 KiB mapping policy (W^X, canonicality,
  privilege separation, overlap validation) and read-only CPU paging audit.
- `crates/sorveth-boot`: small x86-64 UEFI loader. Obtains GOP and the final memory map,
  calls `ExitBootServices`, then transfers control to Sorveth Core.
- `crates/sorveth-core`: freestanding Rust kernel entry, serial diagnostic monitor,
  owned top-level x86-64 PML4 transition, and direct framebuffer splash.
  Sorveth builds one private PDPT/PD/PT subtree and maps a claimed, zeroed
  supervisor-only NX scratch page. Most inherited firmware mappings remain
  shared. After handoff it makes no firmware boot-service calls. The monitor
  is a privileged bootstrap tool, not a userspace terminal.
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

The CI acceptance tests run on GitHub Actions:
- `./scripts/smoke-qemu.sh` builds an instrumented EFI image, verifies serial
  markers emitted after UEFI ExitBootServices, and requires a test-only QEMU
  debug-exit status.
- `bash scripts/smoke-monitor-qemu.sh` builds the *normal* EFI image, boots it
  in QEMU, sends commands over a serial socket, and validates their answers.
- Rust unit tests cover the capability system, memory parser, frame planner,
  and kernel monitor line editor. Successful commits and passing CI are tracked
  separately; inspect the current Actions run before declaring a milestone.
The `sorveth-qemu-diagnostics` artifact saves emulator logs on failures.
To preserve logs locally, set `SORVETH_QEMU_ARTIFACT_DIR` to a directory.

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
Persistent physical frame ledger: installed (unmapped)
Sorveth PML4 root: active (firmware lower levels shared)
Sorveth private supervisor NX mapping: verified
Capability table: initialized
SORVETH CORE ONLINE / end of milestone 0
```

On a normal boot, Sorveth then enters its **interactive serial kernel monitor**:
```text
Sorveth bootstrap monitor v0.1
Type help for available commands.
sorveth> help
Commands: help status memory paging caps halt
sorveth> 
```
The `status`, `memory`, `paging`, and `caps` commands inspect bootstrap
state; `halt` halts the CPU. Sorveth now creates and switches to a distinct
PML4 root and a single private high-half supervisor mapping. Most of the
subordinate firmware paging tables are still shared, so this is **not** an
isolated address space. Input is line-buffered, supports backspace and CR/LF,
and rejects
overlong commands. QEMU's `-serial stdio` connects the prompt to a terminal.
The special first-boot smoke-test binary deliberately exits QEMU instead.

A supported GOP framebuffer receives a basic startup splash. Neither the splash
nor this privileged monitor is a desktop, user process, or proper terminal.

## Test status (2026-10-22)

- **Verified in GitHub Actions:** Rust tests, UEFI cross-build, ABI offsets,
  rustfmt, native post-firmware QEMU boot and an interactive monitor session.
- **Verified hardware transition in QEMU:** a new Sorveth PML4 root was
  loaded through CR3, and a separate 4 KiB supervisor-only NX mapping was
  exercised by writing through the new high virtual address and reading back
  the claimed physical page. This uses an OVMF-provided identity mapping
  to access paging structures during bootstrap.
- **Not implemented:** fully private address spaces, page faults/IDT, proper
  kernel stacks, user-mode tasks, scheduler, IPC, native driver services,
  filesystem, networking, desktop, and Sorveth Mind. Physical machines have
  not been tested; this bootstrap is **QEMU-only**.

See the authoritative [Sorveth Product Constitution](docs/SORVETH_VISION.md),
[implementation roadmap](docs/ROADMAP.md), [architecture](docs/ARCHITECTURE.md)
and [security model](docs/SECURITY.md) for the design and engineering gates.

## License and contributions

Copyright 2026 Sorveth OS contributors. GNU GPL v3.0 (`LICENSE`). Design discussions,
changes, and new user-facing resources should preserve the project's ownership,
portability, permission and no-AI-required principles.