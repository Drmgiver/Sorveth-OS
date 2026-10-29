# Sorveth OS

**An independent, local-first, AI-optional, user-owned operating system project.**

Sorveth is an original Rust x86-64 operating-system effort: not Linux, a
distribution, or a Windows compatibility layer. Its planned native desktop,
resource environment and application platform are designed for human control
and portability, whether or not Sorveth Mind (its optional AI component)
is enabled. The code is GPL-3.0-only.

> **Development status (October 29, 2026): early microkernel engineering,
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
| M2-H: task-scoped syscall prototype | Kernel-owned task identity authorizes register-only READ/WRITE and denies forged/foreign tokens | Hardcoded QEMU probe |
| M2-I: isolated experimental process roots | Distinct A/B CR3 roots, per-process user frames, bidirectional ring-3 foreign-memory denial and task-root lifecycle checks | Static permanent test mappings, nonpreemptive bootstrap |
| M2-J: bounded user-memory syscall proof | Audited user page walks, capability-gated copy-in/out and 22 real ring-3 INT80 probes per process with whole-frame integrity checks | Exactly eight bytes per syscall in current test ABI; not general user memory or production process lifecycle |
| M2-K.1 (partial): owned supervisor frame access | Private high-half frame window, process page/root auditing, scheduler checks, copy-in/out integrity, PML4 construction and ring-3 program/table initialization through owned aliases | Early kernel executable/stack/IDT/TSS and lower-level supervisor paging still inherit OVMF mappings |

The ring-3 test also deliberately attempts to read a supervisor-only kernel
page. QEMU verified the hardware #PF, CR2 address and user-mode
protection-violation bits. This establishes one concrete privilege boundary,
not complete process isolation.

The latest accepted kernel changes passed host and QEMU tests in
[GitHub Actions run 40918371037](https://github.com/Drmgiver/Sorveth-OS/actions/runs/40918371037).
Earlier milestone evidence remains in the development log.
Source commits, builds, boot tests and hardware support are **separate** claims.

## What Sorveth is building

| Subsystem | Intended role | Current state |
|---|---|---|
| **Sorveth Core** | Capability-based microkernel, memory protection, processes, IPC | Early kernel and controlled A/B ring-3 process, copy and security probes; no general process runtime |
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

`smoke-qemu.sh` builds seven independent EFI test images:

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

The other four test images, `qemu-isolate-a`, `qemu-isolate-b`,
`qemu-transfer-a` and `qemu-transfer-b`, exercise A/B process-memory
denial and capability-secured user-buffer syscalls. Their QEMU outcomes
are verified independently before the test suite passes.

The monitor is a privileged diagnostic interface, not a shell for an
isolated user process.

## Next engineering gates

M2-I/J have proved isolated, task-bound A/B memory operations within the
single-core bootstrap. Work now proceeds through **M2-K**: remove firmware-
identity dependencies, implement safe dynamic frame lifetime/reclamation,
process creation/teardown, broader buffer operations and fault recovery.
The current INT 0x80 memory-copy ABI remains **test-only** and limited to
eight-byte transfers. See [the active K plan](docs/M2-K-PLAN.md).

Only after memory independence, process containment, services, security and
hardware coverage are verified will Sorveth be considered an operating system
that other people should run. No physical-hardware test has yet occurred.

See [the supervisor mapping transition plan](docs/M2-K1D-SUPERVISOR-TRANSITION.md),
[the roadmap](docs/ROADMAP.md),
[architecture](docs/ARCHITECTURE.md),
[security model](docs/SECURITY.md), and
[Sorveth Product Constitution](docs/SORVETH_VISION.md).

## License

Copyright 2026 Sorveth OS contributors.
GNU GPL v3.0 (`GPL-3.0-only`). Native software should preserve user
ownership, portability, explicit capabilities and a fully usable AI-off mode.
