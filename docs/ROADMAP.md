# Sorveth OS development roadmap

Status as of 2026-10-22. Each milestone is accepted only on observable evidence.

| Phase | Deliverable | Acceptance gate | State |
|---|---|---|---|
| M0-A | Source bootstrap | UEFI loader, freestanding kernel, ABI, capability prototype, memory map validation, host tests | Verified in CI |
| M0-B | First boot | EFI cross-build, QEMU reaches kernel after ExitBootServices, debug-exit signal | Verified in QEMU CI |
| M0-C | Interactive monitor | COM1 input, bounded editor, five built-in commands, QEMU-driven replies | Verified in QEMU CI |
| M1 | Memory/CPU foundation | Persistent frame allocation, page tables, IDT, interrupts, dedicated stack | M1-A/B1 verified; M1-B2 owned PML4 root under verification, firmware leaf mappings remain shared |
| M2 | Real microkernel separation | User-mode process, kernel syscalls, message IPC, scheduler and capability-checked mediation | Pending |
| M3 | User-space system services | Separate storage/input/display driver services and initial resource persistence | Pending |
| M4 | Sorveth Space desktop | Window manager, compositor, keyboard/mouse, native resource explorer, desktop runs without AI | Pending |
| M5 | Native app platform | Manifests, action contracts, editable resources, Forge, Atlas, Frame, Script | Pending |
| M6 | Sorveth Mind | Local model adapters, explicit broker, sandboxed builder, approval/verifier, full off switch | Pending |
| M7 | Daily-computing expansion | Networking, browser path, audio, USB, updates, expanded hardware coverage, security hardening | Pending |

## Next implementation sequence

1. Install a persistent frame allocator with verified lifetime and explicit
   reservations for loader, kernel, runtime, framebuffer and device memory.
2. Establish owned kernel stack/page-table mappings and validate page faults.
3. Install an x86-64 IDT and controlled exception diagnostics, then timers.
4. Implement the first user-mode task, basic scheduling and system calls.
5. Implement capability-checked IPC and move services out of ring 0.
6. Preserve automated QEMU boot and interactive-monitor acceptance tests.

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

**Scope restriction:** this is a new Sorveth-owned *top-level* table only.
All subordinate page tables and memory permissions are still inherited,
shared and firmware-defined. No copied private lower levels, NXE enforcement,
ring-3 isolation, page fault handlers, RAM zeroing, or safe physical-hardware
boot is claimed. The bootstrap currently assumes an OVMF/QEMU identity map
for reading page table frames. The next phase must eliminate that reliance
with a tested physical-memory access window and privately owned subtrees,
then install controlled exceptions before widening hardware support.

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
