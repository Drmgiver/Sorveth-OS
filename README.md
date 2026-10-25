# Sorveth OS

**An independent, local-first, AI-optional, user-owned operating system project.**

Sorveth is an original Rust x86-64 operating-system effort: not Linux, a
distribution, or a Windows compatibility layer. Its planned native desktop,
resource environment and application platform are designed for human control
and portability, whether or not Sorveth Mind (its optional AI component)
is enabled. The code is GPL-3.0-only.

> **Development status (October 24, 2026): early microkernel engineering,
> not a complete or safe daily-use OS.** Only QEMU/OVMF boot and controlled
> verification programs have been tested. Do **not** boot this on real
> hardware or entrust personal data to it.

## Verified milestones

| Area | What actual QEMU/host tests demonstrate | Boundary |
|---|---|---|
| M0: independent startup | Rust UEFI loader exits firmware boot services and executes Sorveth Core, serial monitor responds to commands | No general drivers, filesystem, desktop |
| M1: kernel foundations | Persistent physical frame ledger; CR3 switch to an owned PML4; private 4 KiB supervisor mappings; x86 IDT, TSS/IST fault stacks, controlled page fault; dedicated kernel stack | Most memory mappings still inherited from OVMF, single CPU |
| M2-A/B: kernel coordination | Capability-gated bounded IPC; generation-safe task registry and runnable selection | Trusted kernel data structures, no userspace ownership yet |
| M2-C: message wakeups | Authorized send wakes a parked receiver with reserved dequeue and revocation rules | Kernel-internal only |
| M2-D/E: real context switching | Native x86-64 kernel context saves and resumes, then two separate kernel workers run in A-B-A-B scheduler order | Cooperative, ring 0, no preemption or complete extended register state |
| M2-F/G: tested user boundary | A **test-only** ring-3 program calls INT 0x80 twice and then attempts a supervisor-only memory read; the CPU generates the expected user-mode protection #PF | One hardcoded probe, shared address space | 
| M2-H: task-scoped syscall prototype | Kernel-owned task identity authorizes register-only resource READ/WRITE; QEMU rejects readonly WRITE, forged tokens and another task's handle | Still one hardcoded probe; no generic syscalls, user pointers or separate task address spaces |

The ring-3 test also deliberately attempts to read a supervisor-only kernel
page. QEMU verified the hardware #PF, CR2 address and user-mode
protection-violation bits. This establishes one concrete privilege boundary,
not complete process isolation.

The task-scoped syscall/protection tests and previous acceptance gates passed in
[GitHub Actions run 40163063162](https://github.com/Drmgiver/Sorveth-OS/actions/runs/40163063162).
Source commits, builds, boot tests and hardware support are **separate** claims.

## What Sorveth is building

| Subsystem | Intended role | Current state |
|---|---|---|
| **Sorveth Core** | Capability-based microkernel, memory protection, processes, IPC | Partial native kernel + controlled ring-3 probe |
| **Sorveth Space** | Original project/activity desktop, windowing, input | Design only |
| **Sorveth Vault** | User-owned structured resources and portable storage | Design only |
| **Sorveth Forge** | Native app creation and editing tools | Planned |
| **Sorveth Atlas / Frame / Script** | Resource exploration, media tools and automation | Planned |
| **Sorveth Mind** | Optional local AI orchestration and app generation | Design only |

## Repository structure

- `crates/sorveth-boot` — independent x86-64 UEFI handoff.
- `crates/sorveth-abi` — typed versioned loader/kernel interface.
- `crates/sorveth-core` — Rust kernel, owned-stack and page-table tests,
  synchronous fault handlers, TSS and serial monitor; experimental
  Win64-ABI kernel fiber and ring-3 trap routines.
- `crates/sorveth-memory`, `sorveth-frames`, `sorveth-paging` —
  checked firmware map accounting, persistent frame claims and 4 KiB
  virtual-mapping policy.
- `crates/sorveth-cap` — derivable, revocable capability handles.
- `crates/sorveth-ipc` — bounded copy-only message mailboxes.
- `crates/sorveth-task` — generation-safe runnable/blocked task registry.
- `crates/sorveth-exchange` — capability-checked mailbox parking and wakeups.
- `crates/sorveth-broker` — no-heap syscall resource authority checks,
  binding opaque handles to kernel-selected generation-safe task identities.
- `docs` — product architecture, engineering decisions, constraints and roadmap.
- `scripts`, `.github/workflows` — test and QEMU boot infrastructure.

## Build and test on a Linux development host

Requires Rust/cargo, the `x86_64-unknown-uefi` target, QEMU x86-64 and
OVMF UEFI firmware. These are development and emulator tests only.

```sh
rustup target add x86_64-unknown-uefi
./scripts/check.sh
./scripts/smoke-qemu.sh
bash scripts/smoke-monitor-qemu.sh
```

`smoke-qemu.sh` builds three independent EFI test images:

1. **`qemu-smoke`** — post-ExitBootServices native kernel boot, physical
   memory validation, context switching, then a test-only QEMU debug exit.
2. **`qemu-fault`** — deliberately accesses a private unmapped page and
   requires Sorveth's own #PF handler, CR2/error-code diagnostics and IST1 stack.
3. **`qemu-user`** — enters CPL3 using an explicitly mapped user-executable
   machine-code stub and user NX stack. It proves INT 0x80 roundtrips,
   task-owned capability READ authorization and denial of forged/foreign
   handles and unauthorized WRITE. The stub then reads a supervisor-only
   kernel address and must trigger a controlled user-mode protection #PF
   on IST1.

`smoke-monitor-qemu.sh` boots the **normal** kernel and sends commands
to the polling serial monitor, verifying the live replies. Use
`SORVETH_QEMU_ARTIFACT_DIR` to preserve emulator logs. On normal startup:

```text
Sorveth bootstrap monitor v0.1
Type help for available commands.
sorveth> help
Commands: help status memory paging caps halt
sorveth>
```

The monitor is a privileged diagnostic interface, not a shell for an
isolated user process.

## Next engineering gates

The next task is to turn the ring-3 prototype into per-task address spaces
and a defensive copy-in/copy-out mechanism for bounded user buffers, followed
by syscall lifecycle and scheduling. The current INT 0x80 dispatch is still
**test-only**, register-only and not a generally usable syscall interface.

Only after memory independence, process containment, services, security and
hardware coverage are verified will Sorveth be considered an operating system
that other people should run. No physical-hardware test has yet occurred.

See [the roadmap](docs/ROADMAP.md),
[architecture](docs/ARCHITECTURE.md),
[security model](docs/SECURITY.md), and
[Sorveth Product Constitution](docs/SORVETH_VISION.md).

## License

Copyright 2026 Sorveth OS contributors.
GNU GPL v3.0 (`GPL-3.0-only`). Native software should preserve user
ownership, portability, explicit capabilities and a fully usable AI-off mode.
