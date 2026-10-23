# Sorveth OS development roadmap

Status as of 2026-10-22. Each milestone is accepted only on observable evidence.

| Phase | Deliverable | Acceptance gate | State |
|---|---|---|---|
| M0-A | Source bootstrap | UEFI loader, freestanding kernel, ABI, capability prototype, memory map validation, host tests | Verified in CI |
| M0-B | First boot | EFI cross-build, QEMU reaches kernel after ExitBootServices, debug-exit signal | Verified in QEMU CI |
| M0-C | Interactive monitor | COM1 input, bounded editor, five built-in commands, QEMU-driven replies | Verified in QEMU CI |
| M1 | Memory/CPU foundation | Persistent frame allocation, page tables, IDT, interrupts, dedicated stack | M1-A/B1/B2 boot tests verified in QEMU; most firmware leaf mappings still shared, IDT/process isolation pending |
| M2 | Real microkernel separation | User-mode process, kernel syscalls, message IPC, scheduler and capability-checked mediation | Pending |
| M3 | User-space system services | Separate storage/input/display driver services and initial resource persistence | Pending |
| M4 | Sorveth Space desktop | Window manager, compositor, keyboard/mouse, native resource explorer, desktop runs without AI | Pending |
| M5 | Native app platform | Manifests, action contracts, editable resources, Forge, Atlas, Frame, Script | Pending |
| M6 | Sorveth Mind | Local model adapters, explicit broker, sandboxed builder, approval/verifier, full off switch | Pending |
| M7 | Daily-computing expansion | Networking, browser path, audio, USB, updates, expanded hardware coverage, security hardening | Pending |

## Next implementation sequence

1. Extend the private mapping proof into safely managed physical/virtual
   memory; remove assumptions that a firmware identity map is available.
2. Install the x86-64 IDT and deterministic exception/page-fault diagnostics.
3. Establish a dedicated kernel stack, replace inherited firmware mappings,
   and validate controlled mapping changes and TLB invalidation.
4. Implement a ring-3 user task and basic scheduling/system calls.
5. Add capability-checked IPC and move services outside ring 0.
6. Preserve QEMU boot and real interactive monitor acceptance at every step.

M0 evidence: [passing GitHub Actions run 39874178796](https://github.com/Drmgiver/Sorveth-OS/actions/runs/39874178796).
The framebuffer has not been visually validated, and there has been no
bare-metal hardware test.

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


## M1-A — Physical frame ledger boundaries

The first retained ledger accepts only UEFI ConventionalMemory, explicitly excludes
the boot descriptor buffer, BootInfo, and visible framebuffer ranges, and cannot
be reset after installation. All claims are one-way and are **not yet usable RAM**
without an owned mapping and zeroing. No firmware runtime, loader or device memory
is reclaimed. Native drivers, userspace memory, paging and page reclamation remain
blocked until later acceptance tests prove isolation and controlled ownership.

## M1-B, phase 1 — Paging policy and firmware CR3 audit

Sorveth's allocation-free `sorveth-paging` module plans 4 KiB kernel/user
mappings, rejects writable+executable pages, noncanonical addresses,
inappropriate privilege halves, overlaps, and unapproved physical aliases.
A privileged read-only CR0/CR3/CR4 audit verifies the inherited four-level
paging configuration on actual QEMU boots. It **does not** inspect or replace
firmware page tables, change CR3, allocate or zero page-table frames, enable
NXE or enforce new hardware protections. Sorveth-owned tables and tested
CR3 transitions remain the next phase of M1-B.

**M1-B phase 1 acceptance:** [GitHub Actions run 39881282684](https://github.com/Drmgiver/Sorveth-OS/actions/runs/39881282684)
passed host Rust unit tests, UEFI build, ABI checks, rustfmt, post-firmware
native boot, and the interactive monitor test with the inherited paging audit.
This does not establish owned page-table installation or physical hardware support.

## M1-B, phase 2 — Sorveth top-level PML4 and CR3 transition

Sorveth now builds a distinct, page-aligned PML4 root from the inherited UEFI
PML4 entries. The transition checks identity translation for the current
firmware root and Sorveth's page, copies all 512 entries, checks the clone,
changes CR3, reads it back and logs the result **after** the transition.
The monitor's `paging` command reports this state. Automated QEMU tests
must confirm the post-switch marker and interactive command responses.

**Scope restriction:** the initial PML4 switch preserves the inherited
firmware mappings. The next section documents one independently created
high-half mapping with Sorveth-owned lower-level tables. All *other*
lower-level mappings remain firmware-owned and shared. No ring-3 isolation,
page fault handler, general RAM mapping facility, or safe physical-hardware
boot is claimed. The QEMU bootstrap still uses the OVMF identity map to
access and initialize physical paging frames.

### M1-B2 private 4-KiB mapping acceptance

The kernel now claims a conventional-memory physical frame from its retained
ledger, verifies the firmware identity window, zeroes that frame, and creates
fresh 4-KiB-aligned page-table pages for a previously absent higher-half slot.
Sorveth installs a supervisor-only writable, NX scratch mapping using its own
PML4/PDPT/PD/PT entries; it checks CPU NX support and enables EFER.NXE.
After writing CR3, Sorveth writes through the *new high virtual address* and
verifies the result through the claimed physical page. The QEMU integration
test requires the post-switch proof and the interactive paging command.

**Still experimental:** this private mapping is a bootstrap proof, not a
general-purpose virtual-memory allocator. The rest of the inherited tables
are shared; hardware page faults and fully isolated processes are still
unimplemented. No physical hardware boot is authorized.


## M1-C — Owned x86-64 synchronous-exception table

Sorveth installs a 256-entry interrupt descriptor table (IDT), with a
tested reversible breakpoint (#BP) handler and fatal page-fault (#PF) and
general-protection (#GP) reporters. The breakpoint wrapper preserves the
volatile registers, meets the UEFI x64 ABI stack/shadow-space requirements,
and returns using IRETQ. The read-only kernel console survives the test.

A dedicated QEMU fault-test image can read the deliberately *unmapped*
second page of the private high-half page table. The #PF handler prints
the fault address and error code before issuing QEMU's test-only success
exit, without resuming a faulting instruction. This is never done in a
normal boot.

Only synchronous faults are supported: hardware IRQs stay masked (CLI),
IST/TSS dedicated exception stacks, robust double-fault handling, timers,
SMP, unprivileged ring-3 tasks and recoverable page faults remain pending.

## M1-D — Restricted private kernel page allocation

A monotonic bootstrap mapper now claims and zeroes two additional conventional
frames from the permanent frame ledger. It installs supervisor-only NX PTEs in
Sorveth's private page table, invalidates TLB translations with INVLPG,
and verifies access through the high virtual addresses against their physical
frames. The first page is the original bootstrap proof, index 1 stays
unmapped for controlled fault testing, and the monitor reports three mapped
private pages. Both normal and fault-test QEMU boots verify the marker.

This is **not** a production heap or general virtual-memory manager: it still
requires the inherited OVMF identity mapping to initialize physical pages.
There is no reclamation, sharing, SMP serialization or user-mode access yet.

## M1-E — Dedicated kernel execution stack

The bootstrap kernel now switches irrevocably from the UEFI-provided stack to
a statically retained, 128 KiB, 4 KiB-aligned Sorveth-owned stack. The handoff
sets x64 calling-convention alignment and shadow space, then invokes a
non-returning kernel continuation. It reads RSP to verify the new stack bounds.
Normal QEMU boot, the interactive monitor, and the page-fault test all require
proof after the transition; deliberate faults run on the new stack.

Limitations: this is one global bootstrap stack inside the EFI image, without
guard pages, per-thread stacks, privilege switching, or IST/double-fault
protection. It is not a general-purpose scheduler stack.

## M1-F — Emergency exception stacks with TSS/IST

Sorveth now copies the inherited GDT descriptors into permanent kernel-owned
memory, appends a 64-bit TSS descriptor, loads GDTR and TR, then routes page
faults to a separate IST1 stack and double faults to IST2. This reserves two
32 KiB emergency stacks outside the ordinary 128 KiB kernel execution stack.
The QEMU page-fault image verifies that the page-fault callback's RSP is
inside IST1, before printing CR2/error-code diagnostics and the test marker.

This is early QEMU-only exception isolation: GDT code/data descriptors remain
inherited, both emergency stacks are statically allocated and unguarded,
and interrupt masking continues. No scheduler, IRQ dispatch, TSS RSP0 for
ring-3 privilege transitions, or recoverable page-fault process exists.

## M2-A — Internal capability-gated IPC queue

A `sorveth-ipc` no_std crate implements fixed-size endpoints with bounded
message payloads, FIFO delivery, backpressure, optional irreversible close,
and separate SEND/READ/MANAGE authorization via the capability table.
Handles for another endpoint or object kind cannot access the queue.
Derived handles respect attenuated rights; revoked and stale handles fail
before mutating queue state. Rust regression tests cover overflow, wraparound,
authorization, payload limits, revocation and endpoint closure.

The trusted kernel boot now creates an endpoint, derives SEND/READ handles,
roundtrips an owned message, revokes its root authority and verifies that
the now-stale handles are rejected; QEMU smoke tests require the marker.

**Important limit:** no userspace address space, syscall dispatcher, blocking
wait queues or scheduler exists yet, so this is not enforceable cross-process
IPC. It is the narrow transport and authorization primitive to build upon.
