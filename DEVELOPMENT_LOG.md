# Development log

## 2026-10-22 — Repository inception and M0-A

- Recovered architectural commitments for Sorveth Core, Space, Mind and Vault.
- Created independent MIT-licensed Rust workspace with `sorveth-abi`, `sorveth-cap`,
  `sorveth-boot` and `sorveth-core`.
- Authored UEFI entry point, graphics protocol lookup, final memory map capture,
  firmware exit, native COM1 serial and direct framebuffer splash.
- Added early capabilities with rights attenuation, parent-aware cascading
  revocation, stale-handle generations and Rust tests.
- Authored security, architecture, implementation roadmap, build scripts and
  GitHub Actions compilation workflow.
- Ran the C UEFI x86-64 ABI offset test: PASS.
- Rust compilation, unit tests and QEMU boot are PENDING: toolchains unavailable
  in this authoring runtime. Do not upgrade this result to "working boot".
- GitHub repository NOT created or updated: the connected account currently exposes
  only a different project (`OSTen`), which must remain untouched. Source delivered
  as a separate self-contained archive instead.

## 2026-10-22 — M0 hardening (second development pass)

- Added `sorveth-memory`: no-allocator UEFI memory-map parser supporting extended
  memory-descriptor strides, overflow/alignment checks, and counting only
  conventional firmware pages as immediately allocatable.
- Sorveth Core now rejects invalid memory-map metadata before continuing the
  bootstrap sequence. This is validation only; no physical allocator exists.
- Added regression tests for memory-map framing, page counts, misalignment,
  and overflowing physical ranges. Added C layout assertions for the UEFI
  memory descriptor and Sorveth boot structures.
- Added QEMU smoke-build feature and `scripts/smoke-qemu.sh`: a boot gate
  checking the debug-exit status and expected post-UEFI serial markers.
  Wired the smoke gate into GitHub Actions; no Sorveth remote exists yet.
- Verification in this environment: native C UEFI layout check and shell
  syntax checks passed. Rust and QEMU remain **unavailable here**, and
  compilation, unit tests, framebuffer output and boot are **not verified**.
- Routine implementation, test authoring, debugging and technical decisions
  are the development lead's responsibility, not the project's sponsor's.

## 2026-10-22 — AI-directed product constitution

- Recorded explicit delegation of both product direction and engineering.
- Adopted `docs/SORVETH_VISION.md` as the authoritative product specification: native
  sovereign computing, typed actions, portable Vault, optional Mind, honest release
  gates and accessible Space. No user testing or corrective implementation assigned.
- Added ADR 0003 on decision authority and ADR 0004 on shared typed native actions.
- This is architectural definition; it is not a claim that desktop, app platform,
  OS rollback or AI components are implemented yet.

## 2026-10-22 — Physical-frame accounting prototype

- Added `sorveth-frames`, an allocation-free `no_std` physical frame planner that
  uses only UEFI conventional pages, rejects overlapping conventional/reserved
  ranges, supports pre-allocation reservations, and hands out distinct contiguous
  spans. No release/reuse until zeroing and lifetime tracking exist.
- Added tests for disjoint frames, reserved gaps, split capacity, allocation
  closure, malformed maps and exhausting regions; included them in check/CI.
- This is *not* the kernel's installed memory allocator, does not map or zero
  RAM, and requires Rust compilation/test execution before acceptance.

## 2026-10-22 — Autonomous development rule and kernel frame-planner integration

- Accepted ADR 0005: Sorveth's AI lead makes product and engineering decisions.
  Human intervention is reserved for irreducible authorization or access;
  the sponsor does not handle debugging, tests, toolchains or design.
- Wired `sorveth-frames` into early `sorveth-core` startup: validates the physical
  map, accounts for available conventional regions, claims two disjoint frames,
  and emits a serial marker. It does not map or access the physical pages and
  is **not** a persistent installed memory manager.
- Fixed a reservation-state bug: an unsuccessful allocation attempt no longer
  prevents subsequent reservations. Added a regression test for the failure
  and subsequent successful allocations.
- Expanded the QEMU boot smoke check to require the frame-planner marker.
- Verification here: C layout PASS, shell syntax PASS, git diff whitespace
  PASS. Rust compiler, cargo and QEMU not installed; local DNS is unavailable;
  Rust tests, Rust cross-build and actual emulator boot are still unverified.
- No changes to OSTen or any remotely hosted repository.

## 2026-10-22 — Project renamed to Sorveth OS

- Adopted the distinct public name **Sorveth OS** and documented the identity
  decision in ADR 0006 after checking targeted web and GitHub repository results.
- Renamed all six Rust crates, module identifiers/imports, UEFI splash and boot
  banners, CI jobs/artifact names, scripts, documentation and package references.
- Retained the historical commit chain; the original name may appear in old Git
  commit messages, but the current working tree uses Sorveth exclusively except
  for the migration decision record.
- Public GitHub repository remains uncreated. Only the new repository name
  `Drmgiver/Sorveth-OS` is approved for publication. OSTen remains untouched.
- Compilation and emulator-boot test status remains unchanged (unverified).

## 2026-10-22 — First public repository preparation

- Confirmed the separate `Drmgiver/Sorveth-OS` GitHub repository exists.
- Adopted GNU GPL v3.0 to match the owner-selected public repository license; corrected the old initial MIT-licensed template.
- Updated CI formatting to check formatting without modifying the checkout.
 
## 2026-10-22 — Verified QEMU boot and interactive CLI

- Published the independent GPLv3 project at Drmgiver/Sorveth-OS.
- Automated GitHub Actions verified unit tests, UEFI x86-64 cross-build,
  x86-64 ABI checks, formatting, and post-ExitBootServices kernel execution.
- Fixed the formatting-only CI errors after reading actual runner logs.
- Implemented a no-heap polling COM1 kernel monitor with help, status, memory,
  caps and halt commands; unit-tested its line editing and input limits.
- Added an emulator integration test that sends real serial commands into the
  *normal* Sorveth kernel and verifies the replies.
- Evidence: https://github.com/Drmgiver/Sorveth-OS/actions/runs/39874178796
  Both CI jobs passed, including separate firmware boot and interactive input.
- This is a **privileged bootstrap monitor**, not an isolated user shell.
  Native physical-memory mappings, scheduler, IPC, ring-3 execution, drivers,
  filesystem and desktop remain unimplemented. No physical-hardware test.

## 2026-10-22 — M1-B phase 1: paging policy and inherited CPU audit

- Added GPLv3 `sorveth-paging` no_std crate with allocation-free 4 KiB
  mapping plans, virtual/physical overlap rejection, physical alias rejection,
  W^X validation, canonical address checks, kernel/user address separation,
  and PTE encoding for *future* installers.
- Added an x86-64 privileged read-only CR0/CR3/CR4 audit. It validates
  inherited four-level paging after UEFI ExitBootServices, without changing
  live mappings, dereferencing firmware tables, or switching CR3.
- Wired it into early kernel boot. Both emulator acceptance tests require
  the paging audit marker. Added host unit tests and format checks in CI.
- Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/39881282684
  Both CI jobs passed; this is **not** a claim of kernel-owned page tables.
- Next: zero and map claimed page-table frames, build a minimal safe
  Sorveth-owned root, retain firmware handoff essentials, and perform a
  carefully validated CR3 transition in QEMU. No hardware testing yet.

## 2026-10-22 — M1-B2: CR3 ownership and first live private mapping

- Authored and boot-tested a distinct 4-KiB-aligned Sorveth PML4 root.
  Validated the inherited OVMF identity mapping, copied the 512 original
  entries, switched CR3, read it back, and retained the interactive monitor.
- Added three aligned, private paging-structure pages (PDPT, PD, PT) in an
  unused supervisor-space slot. Claimed a conventional physical frame from
  the permanent frame ledger, verified its bootstrap identity mapping,
  zeroed it, and installed a supervisor-only NX mapping through the subtree.
- Enabled EFER.NXE on CPUID-supported x86-64 and tested a real read/write
  through Sorveth's high virtual address to the claimed physical frame.
- Expanded both QEMU test paths and the interactive `paging` command
  to require evidence produced *after* the CR3 switch and private mapping.
- Successfully exercised the live mapping and interactive QEMU monitor in
  GitHub Actions run 39882574952. Build formatting required an additional
  correction; verification of the fully corrected run must be checked
  separately.
- Limitations: other lower-level tables remain shared with firmware, so
  this is not an isolated address space, secure heap allocator or complete
  virtual memory manager. No exception handler, user mode, or real-hardware
  boot exists yet.

## 2026-10-24 — Verified M2-C through M2-F kernel milestones

- **M2-C / kernel exchange:** combined the bounded capability-gated mailbox
  with the generation-safe task registry. Empty authorized receives park
  a task; a successful authorized send wakes it and reserves delivery.
  Tests cover unauthorized sends, revocation, queue saturation,
  cancelled/exited waiters and fairness of reserved messages.
  Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40159627068
- **M2-D / CPU-context handoff:** added x86-64 Win64-ABI register/RSP
  preservation, with nonvolatile XMM6-XMM15, plus a separate 64 KiB kernel
  worker stack. The live worker yields/resumes twice in QEMU.
  Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40159855488
- **M2-E / scheduler-directed workers:** connected the task registry's
  round-robin selection to two real worker execution contexts. QEMU
  requires worker order A-B-A-B with separate saved continuations.
  Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40160028585
- **M2-F / ring-3 test-only probe:** added a separately built qemu-user image
  with CPL3 flat code/data descriptors, TSS RSP0, a separate DPL3 INT80
  IDT gate and two physical frames mapped into a fresh lower-canonical
  user-executable/RW-NX subtree. A raw machine-code stub entered via IRETQ,
  invoked INT80, received a known result through IRETQ to user mode, and
  issued a second INT80. The final kernel handler signalled the test-only
  QEMU debug-exit path. Both CI jobs passed.
  Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40160414357

**Security and completeness limits:** all these milestones are QEMU-only
prototypes. Kernel workers run privileged; ring-3 probe is hardcoded and
shares most system mappings with the kernel, not a fully isolated process.
There are no task-scoped syscall handles, external-interrupt preemption,
user-pointer validation, independent per-process CR3, full SIMD state
management or userland services yet. No physical-hardware verification.


## 2026-10-24 — M2-G: verified ring-3 supervisor-memory denial

- Extended the qemu-user probe: after completing two INT80/IretQ roundtrips,
  it deliberately attempts to read Sorveth's existing supervisor-only
  high-half private scratch mapping from CPL3.
- The x86-64 page fault handler requires CR2 to identify that exact address,
  a valid IST1 emergency fault stack, and error bits P=1, W=0, U=1.
  Only that protection-fault sequence emits the test-only success marker
  and exits QEMU. An absent-page fault or unexpected trap cannot pass.
- Fully verified both CI jobs: host Rust tests, Rust UEFI build, formatting,
  normal QEMU boot, kernel fault probe, ring-3 memory-denial test and live
  serial-monitor commands.
- Evidence: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40160674706

This proves one actual hardware-mediated user/supervisor protection rule,
not a complete process sandbox. Normal boot remains privileged monitor mode;
the ring-3 test is confined to the qemu-user build. Independent user address
spaces, task-scoped syscalls, pointer validation and fault recovery remain
future milestones.

## 2026-10-24 — M2-H: task-owned capability syscall prototype

- Added the `sorveth-broker` no_std crate with a fixed-capacity global
  capability table, per-token task ownership and generation-safe task IDs.
  Kernel-only grant, attenuation, revocation and task retirement are
  separate from the small register-only syscall dispatcher.
- Extended the qemu-user INT80 entry to pass syscall number, saved CPL3
  selector, opaque handle and scalar argument to the privileged Rust handler.
  The current task ID is selected from kernel-owned bootstrap state, never
  accepted as a caller-provided register.
- The unprivileged executable page checks an authorized resource READ,
  denial of WRITE via READ-only authority, denial of a zero forged token and
  denial of another task's valid WRITE token. Only after all tests match
  their expected register results does the earlier supervisor-memory
  protection #PF test execute.
- CI verified full Rust host/unit tests and a real QEMU ring-3 security
  integration test; normal QEMU boot, explicit fault probe and the serial
  monitor also pass.
- Evidence: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40163063162

Limits: there is still just one hardcoded unprivileged test program, not
separately scheduled address spaces or a public userspace ABI. The
broker receives no pointers, so no safe copy-in/out, page pinning or
user fault recovery exists. The loader still depends on firmware identity
mappings and no physical hardware has been tested. Next engineering target:
per-task page tables and bounded validated user memory transfers.


## 2026-10-28 — M2-I.2 process-private user data mapping

- Added independent PDPT/PD/PT pages for each experimental process root.
- Claimed two distinct conventional physical frames through Sorveth's
  persistent ownership ledger and zeroed them before mapping.
- Installed distinct USER RW/NX leaf mappings behind separate
  lower-canonical PML4 slots; cross-process slots remain absent.
- Integrated a CR3-driven virtual-memory write/read check with restoration
  of the kernel root and verification of both physical sentinel values.
- Preserved normal boot, serial monitor, deliberate #PF and hardcoded
  ring-3 tests as mandatory acceptance checks.

**Not yet a user-process security proof:** memory access tests execute
under kernel privilege. Future milestones must run separate ring-3 contexts,
prove user-to-user denial, and replace firmware inherited memory assumptions.


## 2026-10-28 — M2-I.3 scheduler-directed CR3 switching

- Added a task-to-Process registry with generation-safe ownership,
  duplicate-process rejection, blocked-task selection and stale-ID tests.
- Kernel selects A-B-A-B in the established Scheduler and loads the
  corresponding independent physical CR3 root for each selected task.
- QEMU reads/writes the task's own private USER RW/NX page and confirms
  the untouched foreign frame and absent foreign PML4 slot.
- Restores Sorveth's kernel CR3 between each task selection and checks
  preserved values when reselecting the same process.
- This is *not yet independent ring-3 task execution*, preemption or a
  complete process security boundary; shared supervisor lower tables
  are still inherited from the OVMF bootstrap.


## 2026-10-28 — M2-I.4 CPL3 bidirectional process-memory probes

Added two test-only UEFI build features to prove process A can access
its own private data from ring 3 but cannot read B's data address, and
vice versa. Each run attaches a restricted unprivileged test-code/stack
subtree only to the selected process CR3. The program validates its
own page contents before entering the kernel via INT80, then attempts
a foreign-page read which must trigger a precise nonpresent user-read
#PF (PFEC=0x4) at CR2 with the expected CR3 and an active IST1 stack.
The existing normal boot, intentional fault, ring-3 capability syscall
and interactive monitor checks remain acceptance requirements.

Only deterministic proof, not general task execution or process-lifetime
management; M2-I.5 remains the integration/hardening target.


## 2026-10-29 — M2-I.5 task/root ownership and lifecycle hardening

- Added generation-checked, Ready-only task authorization of process roots.
- Added private page-table ownership audits before CR3 changes, checking
  Sorveth-owned intermediate tables, leaf permissions, exact physical
  frames and absent foreign/kernel user mappings.
- Added a restricted CR3 guard that restores Sorveth's kernel root on
  normal return, including error paths.
- Added live QEMU negative acceptance tests for blocked, retired and stale
  task generations, a deliberately damaged inactive PML4 user mapping,
  restored page-table contents, and rejection after final retirement.
- Preserved the regular kernel boot, deliberate fault, task-scoped syscall,
  bidirectional ring-3 hardware isolation and interactive monitor tests.

Scope remains restricted to the verified single-CPU OVMF/QEMU bootstrap;
this is not a production userspace scheduler or a general lifetime manager.


## 2026-10-29 — M2-J.1 numeric user-buffer policy

- Introduced a reusable no_std user_range module in sorveth-paging.
- Rejected the null page, zero lengths, >64 KiB requests, u64 wraparound,
  noncanonical kernel addresses and crossings of the user/kernel boundary.
- Exposed first/last 4-KiB pages in private-field validated range records,
  for later process-specific page-table checks.
- Added thorough host unit tests and a serial boot policy self-check.
- Required the policy marker in all existing QEMU and monitor modes.
- Did not add any pointer dereferencing, process permission lookups,
  general page-table access or copying. Those require M2-J.2–J.4.


## 2026-10-29 — M2-J.2 process-owned user-page walking

- Added allocation-free read-only four-level page-table traversal with
  bounded results and checked USER, PRESENT and WRITE permission paths.
- Prevented callback reads of unchecked physical addresses by restricting
  QEMU integration to kernel-audited process root and table-frame whitelist.
- Tested mapped private data, foreign process slots, unmapped adjacent
  pages and a range requiring all pages to pass before acceptance.
- Added synthetic multi-page and permission-negative host tests.
- Preserved the prior QEMU boot, #PF, ring-3 and monitor regressions.

The returned mapping is a snapshot only. M2-J.3 must add copying and
ensure user mappings and physical frames cannot change during transfer.


## 2026-10-29 — M2-J.3 bounded copy from user process data

- Added allocation-free copy policy for all-page ownership preflight,
  scatter-copy of validated page spans and destination preservation on
  any validation error.
- Added kernel-only copy_from_process bounded by M2-J.1/M2-J.2 virtual
  range and permission validation and existing M2-I.5 process-owned roots.
- Enforced selected-process physical frame allowlist and full-frame
  identity mapping before copying from physical memory into a kernel
  buffer. Verified the kernel CR3 and disabled maskable interrupts.
- Added host tests of two-page scatter, rejected second frame, wrong
  destination length, and exact end-of-page access.
- Added QEMU acceptance tests for A/B copied bytes, offset reads,
  foreign-process denial, unmapped-page crossing, null/overflow/zero,
  and unchanged kernel/user memory on rejection.
- Preserved normal boot, controlled faults, ring-3 capability/isolation
  tests and interactive monitor acceptance.

Scope remains narrow: one 4-KiB permanently allocated data frame per
process under single-core, nonpreemptive, identity-mapped QEMU bootstrap.
No general user buffer lifetime tracking, page pinning or syscall copy-in.
