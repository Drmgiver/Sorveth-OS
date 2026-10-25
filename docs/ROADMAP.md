# Sorveth OS development roadmap

Status as of 2026-10-22. Each milestone is accepted only on observable evidence.

| Phase | Deliverable | Acceptance gate | State |
|---|---|---|---|
| M0-A | Source bootstrap | UEFI loader, freestanding kernel, ABI, capability prototype, memory map validation, host tests | Verified in CI |
| M0-B | First boot | EFI cross-build, QEMU reaches kernel after ExitBootServices, debug-exit signal | Verified in QEMU CI |
| M0-C | Interactive monitor | COM1 input, bounded editor, five built-in commands, QEMU-driven replies | Verified in QEMU CI |
| M1 | Memory/CPU foundation | Persistent frame allocation, page tables, IDT, interrupts, dedicated stack | Frame ledger, owned PML4/private pages, IDT/TSS/IST and dedicated stack verified in QEMU; most firmware mappings remain shared |
| M2 | Real microkernel separation | User-mode process, kernel syscalls, message IPC, scheduler and capability-checked mediation | M2-A..H verified in QEMU/host prototypes; independent user address spaces and production syscalls pending |
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

## M2-B — Generation-safe task registry and runnable selection

A `sorveth-task` no_std crate now tracks bounded task identities, runnable
and blocked states, fair circular selection, explicit wake/block transitions,
and generation changes on task exit. Host tests require fairness, stale ID
rejection, no scheduling of blocked slots, duplicate-object prevention,
and exhaustion behavior. The trusted kernel bootstrap exercises the registry
with two simulated tasks and publishes a serial marker in QEMU.

**Not yet multitasking:** no task has registers, a private stack, a page
table, CPU execution, timers or syscalls. The scheduler chooses *identities*,
not an actual process to run. This is groundwork for a future switcher.

## M2-C — Capability-gated IPC receiver parking and wakeup

The kernel-owned `sorveth-exchange` component composes an endpoint mailbox
with the generation-safe task registry. A receiver with READ authority can
park when the queue is empty; it becomes non-runnable. A *successful*
capability-authorized SEND wakes that task and preserves a dequeue reservation
so another task cannot steal its message. Unauthorized sends/receives and
queue overflow cannot create spurious wakeups. Revoked receive authority
releases the reservation without consuming queued data; cancellation and
task exit clear parked state. Tests exercise these races deterministically.

This is a **task-state and delivery handshake**, not actual CPU multitasking.
It still executes only in the privileged bootstrap and has neither ring-3
tasks, saved CPU contexts, hardware scheduling nor user-visible system calls.

## M2-D — Native cooperative x86 kernel context switching

Sorveth's x86-64 bootstrap contains a restricted assembly context switcher
that saves/restores the EFI/Windows-x64 ABI's nonvolatile general registers,
XMM6-XMM15, and RSP. A statically allocated 64 KiB worker stack is initialized
with an ABI-aligned synthetic return frame. A separate worker runs, yields to
the kernel stack, resumes from its saved continuation, and yields a second
time. Normal QEMU boot, fault-test boot and interactive monitor acceptance
all require the post-switch serial proof.

**Restricted scope:** this is one controlled ring-0 cooperative experiment.
The CPU still uses one address space; no actual scheduler-driven tasks,
time slicing, extended x87/AVX context, FPU per-task ownership, user privilege
isolation or ring-3 entry are implemented. This switcher must not yet be used
to run arbitrary workloads.

## M2-E — Scheduler-directed cooperative kernel workers

Sorveth tests two independent 64-KiB kernel worker stacks and saved Win64
register contexts. Its existing generation-safe Scheduler selects worker A,
worker B, then A and B again. Each resumes at its own suspended instruction
rather than restarting. The bootstrap rejects any incorrect order or
unexpected continuation; both QEMU modes and interactive boot require
an `A B A B` serial acceptance marker.

These workers are still explicitly controlled, privileged test functions.
There is no timer IRQ, preemption, independent address space, userspace code,
blocking syscall entry or complete floating-point/AVX context handling.


## M2-F — Experimental ring-3 INT80 privilege boundary

A dedicated \`qemu-user\` EFI image (never a normal boot) installs ring-3
code/data GDT selectors, a TSS RSP0 trap stack, and a DPL3 INT80 IDT gate.
Sorveth allocates two fresh physical frames and maps a read-only executable
machine-code stub and a writable NX stack in an unused lower-canonical
user-address subtree (U/S=1 at every paging level). It enters CPL3 via
IRETQ. The stub issues INT80, checks the returned RAX token in user mode,
then issues INT80 again; only the second successful trap exits QEMU.

**This is a test-only user transition, not a process service:** the stub
cannot perform general syscalls; its frame mappings still rely on OVMF's
bootstrap identity window for setup. There is no ELF loader, capability
table in userspace, process lifecycle, pointer validation, process-specific
CR3 switching, IRQ preemption or recoverable error handling.

## Immediate engineering sequence after M2-F

1. Convert the ring-3 proof into a separately tracked task with private
   address-space ownership and guaranteed kernel-only mappings.
2. Implement a small syscall ABI with explicit capability-table ownership,
   untrusted-pointer checks, bounded copy-in/out and rejection of forged handles.
3. Preserve the demonstrated scheduler-controlled kernel context switches,
   adding user register/extended-state save and TSS RSP0 lifecycle semantics.
4. Add scheduler/interrupt integration and process exit/fault recovery without
   allowing one faulty task to bring down the kernel.
5. Continue native storage, input, display and resource services, then Sorveth
   Space, application tooling and eventually optional Sorveth Mind.

**M2-F acceptance:** [successful GitHub Actions run 40160414357](https://github.com/Drmgiver/Sorveth-OS/actions/runs/40160414357).
This verifies a controlled QEMU CPL3 entry and two trap transitions, **not**
a complete, secure, general-purpose userspace or bare-metal support.



## M2-G — User-mode supervisor-memory denial test

The qemu-user stub now returns from its second INT80 as well, then tries to
read the existing high-half Sorveth supervisor-only private scratch page.
The controlled acceptance test requires a real x86 #PF on IST1 with
CR2 equal to that page and error-code bits P=1, W=0, U=1 (0x5).
Only that exact fault sequence signals the emulator's success exit.
If user code can read the page, faults for another reason, or cannot return
from the kernel trap, the image must not report success.

This checks a concrete hardware-enforced user/supervisor boundary, but it
does not yet establish a complete hostile-code sandbox or a task-specific
kernel/user address-space strategy.

**M2-G acceptance:** [passing GitHub Actions run 40160674706](https://github.com/Drmgiver/Sorveth-OS/actions/runs/40160674706), including the test-only ring-3 supervisor-memory denial and all earlier emulator acceptance gates.

## M2-H — Task-bound capability checks across a ring-3 syscall trap

The `sorveth-broker` no-heap crate binds global capability handles to
generation-safe task identities selected by the **kernel**, not user registers.
Kernel-only grant/derive/revoke and task-exit operations enforce ownership.
Its bounded, pointer-free resource READ/WRITE ABI returns a scalar in RAX.
The same numeric handle cannot grant authority to a different task, and a
task with READ authority cannot WRITE.

The qemu-user image presents a READ-only handle in RDX. Its ring-3 stub
first reads a test resource successfully, then verifies that a WRITE
attempt, a zero forged token and another task's valid WRITE token are all
denied. Every expected result is compared **in ring 3**; a mismatch
cannot reach the final protected-kernel-page fault or debug-exit marker.
Only then does the previous hardware supervisor-memory-denial test run.

**Boundary:** one hardcoded identity in the privileged QEMU bootstrap,
not an independent process scheduler or generic system call ABI. No
user pointers are passed, so copy-in/out and invalid-address handling
remain unimplemented. Per-process CR3, task lifetimes, real services,
preemption and hardware support are also pending.

**M2-H acceptance:** [successful GitHub Actions run 40163063162](https://github.com/Drmgiver/Sorveth-OS/actions/runs/40163063162), including Rust host unit tests, UEFI compilation, code-format checks, native QEMU boot, deliberate page fault, serial monitor and real ring-3 authorization/denial checks. The implementation is not production userspace.
