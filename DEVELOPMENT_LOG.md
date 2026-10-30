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


## 2026-10-29 — M2-J.4 bounded writable user-memory copy-out

- Added no_std, bounded copy-to-resolved transfer that checks all
  destination pages before writing any user byte, with multi-page,
  wrong-length and last-byte host tests.
- Added kernel-only copy_to_process using numeric user-range checking,
  a process-owned four-level WRITE page-table walk, fixed private-frame
  ownership, verified identity mapping and kernel CR3 checks.
- Added real QEMU writes into A and B and copy-in readback, followed
  by restoration of the exact original process data.
- Denied foreign/unmapped/kernel/null/overflow/zero-length destinations,
  and verified rejection of a temporarily read-only private leaf
  without changing the user's memory.
- Preserved the existing boot, fault, ring-3 capability/isolation and
  interactive kernel monitor smoke acceptance.

Only the two permanent 4-KiB QEMU private data frames are supported by
the kernel bridge. Dynamic address-space lifetime management,
user-facing system calls and fault recovery remain subsequent work.


## 2026-10-29 — M2-J.5 experimental ring-3 memory syscall integration

- Added kernel-owned memory capability grants with exact object/task
  binding, distinct READ/WRITE rights, and stale/blocked task denial.
- Added two QEMU-only transfer variants, executing actual INT80 calls in
  CPL3 under process A/B's independent page-table roots.
- Extended the gateway to receive user R9 length as the fifth EFI ABI
  argument while retaining legacy syscall behavior.
- On each syscall, checked the active root, determined caller identity
  from saved kernel state, authorized the memory capability, used kernel
  CR3 for the existing copy helpers, then restored the caller root.
- Added successful copy-in/copy-out and ring-3 data readback, plus
  rights, foreign token, forged token, foreign pointer, zero length
  and unmapped page-crossing denial before debug exit.
- Preserved prior QEMU normal boot, deliberate fault, capability,
  A/B user hardware isolation, and interactive monitor regressions.

This is a bounded experimental syscall proof rather than a general
concurrent userspace ABI; J.6 remains the final validation milestone.


## 2026-10-29 — M2-J.6 full-frame/capability hardening acceptance

- Expanded the separate QEMU process A/B ring-3 syscall probes to
  22 actual INT80 requests, including malicious addresses, forged
  tokens, wrong rights, excessive and zero lengths, foreign memory,
  an unknown operation and denied writes after a valid write.
- Added a trusted-kernel pre/post checksum of *every byte* of both
  permanent user data pages on each syscall, with a predicted post-
  write image and final verification of restored original contents.
- Rechecked capability availability and foreign-handle denial and
  audited the registered process roots on every syscall.
- Required the additional full-frame/capability integrity marker
  from **both** process A and process B QEMU images before acceptance.
- Documented single-core, permanent-frames, identity-map and
  test-only eight-byte ABI restrictions; no claims of general-purpose
  user memory support or concurrent lifetime-safe copying.
- Preserved all existing M2-I/J, fault, ring-3 and interactive monitor
  regressions as mandatory acceptance gates.

M2-J complete only as a controlled QEMU bootstrap demonstration.


## 2026-10-29 — M2-K.1a/b: kernel-owned frame access and PTE walking

- Introduced a reserved supervisor-only high-half frame window (PT entry
  511) for ledger-owned physical pages, with single-CPU/IF=0/kernel-CR3
  checks, scoped teardown and TLB invalidation.
- Migrated additional kernel scratch-frame initialization, bounded
  process copy-in/out, process-frame initialization and A/B read-only
  user-page walking to the owned window. The walker admits only known
  process-owned page-table frames, not PTE-supplied arbitrary addresses.
- Migrated ring-3 transfer-test frame checksums and data-word reads to
  the owned window, retaining full 4096-byte pre/post checks per syscall.
- Preserved all previous normal boot, fault, ring-3, A/B isolation,
  memory-syscall and monitor checks.
- Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40825974582
  and https://github.com/Drmgiver/Sorveth-OS/actions/runs/40826311604

## 2026-10-29 — M2-K.1c incremental private page-table self-alias

- Reserved PT entry 510 as a permanent supervisor-only RW/NX mapping of
  Sorveth's own private paging-table frame. PT entry 511 remains the
  transient frame window, and both slots are excluded from scratch claims.
- The window and scratch allocator now edit PTEs through the verified
  high-half self-alias instead of the physical identity pointer.
- Verified PT-frame translation, USER denial and mapping flags under
  the active Sorveth CR3; all earlier QEMU and source gates pass.
- Verified: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40826861153

**Not accepted:** full M2-K.1, firmware-independent kernel paging,
dynamic physical-frame reclamation, full process lifecycle, general user
buffer ABI or physical hardware. The remaining inherited mappings must be
replaced and separately proven before any release claim.


## 2026-10-29 — M2-K.1c registered page-table audit and construction

- M2-I.5 address-space validation now inspects static registered kernel,
  process PML4, PDPT, PD and PT entries via the scoped Sorveth-owned
  physical frame window. A strict nine-frame whitelist and per-frame
  index bounds deny arbitrary PTE-derived table pointers.
- Existing foreign-slot checks, PTE permission audits, A/D-bit rules,
  task identity generation checks, stale-root tests and deliberate
  corruption denial remain mandatory.
- M2-I.2 private process paging construction now zeros six static
  paging frames and installs all eight process table links through the
  same high-half window, rather than raw physical-pointer writes.
- QEMU emits mandatory verification markers after the real process
  isolation and scheduler tests. All host and QEMU checks passed.
- Accepted test run for audit:
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40905890138
- Accepted test run for construction:
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40906547145

**Remaining K.1 work:** physical-to-virtual bootstrap conversion and the
rest of firmware-dependent supervisor root/table initialization and CPU
kernel mappings, followed by an explicit no-inherited-mapping test mode.
Both K.1c increments remain single-core, nonpreemptive, QEMU-specific;
not full general process creation or safe page reclamation.


## 2026-10-29 — M2-K.1d incremental owned root, probe and denial paths

- Cloned both test process PML4 roots using an owned high-half frame
  window, with a full 512-entry supervisor-only snapshot, absent-slot
  selection and readback verification. Previously direct physical root
  pointers have been eliminated from this process-root construction path.
- Migrated QEMU ring-3 probe PML4 attachment to registered-table reads
  and writes, requiring both process A/B isolation and syscall transfer
  test images to demonstrate the new path.
- Migrated the M2-J.4 controlled read-only PTE tamper, restoration and
  data-integrity check onto Sorveth-owned frame aliases. All negative
  access checks and earlier QEMU acceptance markers remain mandatory.
- Accepted host/QEMU evidence:
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40913347669
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40913856622
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40914232264

**M2-K.1d is not complete.** Kernel code, stacks, IDT/TSS handlers,
firmware-provided lower-level supervisor mappings and some bootstrap
address-space checks still require inherited OVMF mappings. No claim
of dynamically allocated/reclaimed frames, general process lifecycle,
SMP, preemption or real-hardware acceptance is made here.


## 2026-10-29 — M2-K.1d scheduler/copy/loader identity-access reduction

- Replaced direct physical PML4/frame reads in the M2-I.3 scheduler
  switching probe with registered frame-window accesses. The A-B-A-B
  proof still performs actual user-virtual CPU reads/writes under each
  selected independent process CR3 root.
- Contained the M2-I.5 deliberately corrupted USER permission test in
  a registered-root writer that restores and re-audits the original entry,
  with no exposed raw physical root pointer.
- Migrated M2-J.3/J.4 positive/negative copy-in/out verification of both
  4-KiB process data frames, including the last-byte boundary, to bounded
  Sorveth-owned frame-window reads; no direct physical identity reads
  remain in those test functions.
- Migrated the QEMU ring-3 test loader's root slot search, generated code
  page, user stack, test PDPT/PD/PT construction and translation checks to
  owned-window accesses. Page-table traversal admits only the four known
  bootstrap test table frames. The two ledger-claimed code/stack frames
  no longer need physical identity mappings for initial contents.
- Preserved all normal boot, deliberate fault, legacy ring-3, bidirectional
  cross-process denial, A/B 22-INT80 syscall and interactive monitor checks.
- Accepted code and main-branch CI evidence:
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40916862711
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40917416388
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40918197260
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40918371037

**Scope:** all of these are controlled single-core QEMU bootstrap probes.
The kernel executable, kernel/IST stacks, CPU descriptor tables, memory
map and remaining firmware-inherited supervisor paging still require
independent mapping. M2-K.1d is not complete, nor is M2-K.2 frame reuse.
See docs/M2-K1D-SUPERVISOR-TRANSITION.md for the next acceptance gates.


## 2026-10-29 — M2-K.1d read-only supervisor survival inventories

- Added a host-tested, allocation-free x86-64 four-level page walker with
  effective USER/WRITE/NX checks, canonical address validation and aligned
  1-GiB/2-MiB/4-KiB leaf handling. A read-only bootstrap reader accesses
  inherited paging frames through the Sorveth-owned supervisor window,
  **after** validating their existing firmware identity mappings.
- Under real QEMU kernel CR3, checked kernel/serial/exception executable
  addresses, the full kernel/worker/IST stacks, optional ring-3 trap stack,
  current RSP, active IDTR/GDTR table buffers and TSS. Missing mappings,
  user exposure, non-writable critical stacks, or NX executable targets
  fail closed. Legacy writable+executable pages are counted, not mistaken
  for an already hardened W^X kernel.
- Added early boot-handoff validation for mapped BootInfo and every page
  of the retained UEFI memory-descriptor buffer. When the GOP framebuffer
  is usable, the audit checks presence/write access at its boundaries,
  without treating the MMIO device as normal RAM or reading its pixels.
- All seven QEMU images must report both new K.1d mapping-audit markers,
  in addition to prior host, normal/fault, ring-3, A/B isolation, A/B
  memory-copy and interactive monitor acceptance criteria.
- Verified branch CI for runtime inventory:
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40931953610
- Verified branch CI for boot-data inventory:
  https://github.com/Drmgiver/Sorveth-OS/actions/runs/40932702573

**Still not complete:** no firmware-independent executable/data/stack
mapping tables are constructed or activated by this step. The reader
itself depends on the original identity mapping to validate inherited
paging-table frames. Descriptor ownership, section-level W^X permissions,
physical-backing manifest and a separate no-inherited-table CR3 smoke
mode are the next prerequisites. M2-K.2 reclamation is also pending.


## 2026-10-29 — M2-K.1d physical backing and paging provenance

- Added a no-heap, 192-entry maximum physical-backing manifest on the
  dedicated kernel stack. Its records track current virtual and physical
  4-KiB pages, effective WRITE/NX, UEFI descriptor type and category.
- Covered sampled kernel/exception code, all permanent kernel/worker/IST
  and optional ring-3 trap stack pages, CPU GDT/IDT/TSS, frame ledger,
  retained BootInfo, UEFI map buffer and optional framebuffer endpoints.
- Copied BootInfo into retained kernel static memory before abandoning
  the EFI entry stack; the UEFI descriptor buffer remains loader-owned.
- Failed closed for missing/conflicting critical descriptor coverage,
  critical conventional/MMIO backing, incorrect effective permissions,
  mismatched page aliases and an overflowing manifest.
- Device-framebuffer descriptors can be absent; that limitation is counted
  separately rather than equated with ordinary RAM or frame ownership.
- Added provenance proof for Sorveth's four static bootstrap paging frames:
  PML4, private PDPT, private PD and private PT. All four must be separately
  manifested with properly aligned backing and supervisor write access.
- Kept the complete QEMU smoke suite, A/B fault/isolation/copy tests,
  interactive monitor and host tests as mandatory acceptance gates.

Evidence:
- https://github.com/Drmgiver/Sorveth-OS/actions/runs/40942697712
- https://github.com/Drmgiver/Sorveth-OS/actions/runs/40943212370

**Not yet an independent CR3:** the manifest is captured and checked
synchronously; it is not persistent authority for reclaiming or mapping
frames. UEFI descriptor type is provenance, not a Sorveth ownership token.
Full linked-image code/data coverage, physical page ownership and alias
policy, device cache attributes, new page tables and a verified transition
without borrowed OVMF ancestry remain to be implemented. M2-K.1d open.


## 2026-10-30 — M2-K.1d independent PE-image paging and temporary CR3 proof

- The current UEFI image backing scan and strict PE32+ section classifier
  became inputs to a **new and independent** (not firmware-PML4-cloned)
  image-only PML4, PDPT, PD and bounded 4-KiB PT hierarchy.
- Explicit leaf permissions: supervisor-only read/execute for PE code,
  writable+NX for data, read-only+NX for headers/read-only sections,
  absent mappings for unknown gaps. 1-GiB region crossings, untrusted
  static table frames and PT budget overruns fail closed.
- Independently walked every planned image page through an allowlisted
  physical-frame reader using Sorveth's high-half window and verified
  exact physical identity, USER=0 and effective WRITE/NX permissions.
- After switching to the **dedicated in-image kernel stack**, briefly
  loaded the image-only candidate into hardware CR3 in one bounded x86-64
  assembly sequence, read back active CR3 and stack memory, then restored
  the old root before any further Rust calls or frame-window activity.
- All seven QEMU variants passed the added mandatory serial acceptance
  markers and continued their original tests. No persistent new CR3, IRQ
  handler under the new root, user-task switch or frame reclamation was
  attempted during this stage.

Verified source and host/QEMU CI:
- https://github.com/Drmgiver/Sorveth-OS/actions/runs/41004595369
- https://github.com/Drmgiver/Sorveth-OS/actions/runs/41005015817

**M2-K.1d remains partial:** the newly constructed PE-only root deliberately
lacks the general frame window, dynamic mappings, non-image kernel state,
robust device mapping/caching, reserved loader stack lifetimes and all
shared supervisor coverage required for a permanently independent kernel
and A/B process roots. The temporary CR3 proof is a narrow hardware
checkpoint, NOT a completed standalone kernel address space.


## 2026-10-30 — M2-K.1e bounded supervisor survival mapping plan

- Added a bounded planner that validates manifest pages within the PE image against the parsed W^X section map and emits explicit non-image supervisor mappings when present.
- The planner rejects noncanonical/unaligned addresses, image backing mismatches, unclassified image pages, unsupported external backing, rights escalation and physical aliases. Framebuffer endpoint samples are deliberately deferred until cache attributes are specified.
- Across the seven QEMU variants, the bounded manifest has 77–86 image-resident supervisor records and two deferred framebuffer endpoint records per run, leaving zero non-image RAM mappings to add. This exposed the next inventory gap: Sorveth's private high-half frame-window subtree and allocator-owned scratch mappings are not represented yet.
- No new page tables were installed and CR3 behavior is unchanged. Host checks, UEFI cross-build, formatting and QEMU acceptance passed: https://github.com/Drmgiver/Sorveth-OS/actions/runs/41006241220

M2-K.1 remains partial. Next work is to inventory and ownership-check the private high-half mappings before extending the independent-root plan.


## 2026-10-30 — M2-K.1f private high-half frame-window ownership

- The physical allocator now records each irreversible claimed span and exposes bounded ownership queries through the persistent frame pool.
- Added a fail-closed walk of Sorveth's private high-half PT. It verifies the PT self-alias, an absent guard slot, an idle/absent temporary physical-window slot, supervisor RW/NX permissions, unique physical backing, and allocator ownership of every present scratch page.
- The boot path requires the ownership audit marker. This does not install the high-half subtree in the independent image root and does not change CR3.
- The next step is to add these audited aliases and owned scratch pages to the independent-root plan, then verify the expanded inactive root.

M2-K.1 remains partial; no dynamic frame reclamation or persistent independent root is claimed.


## 2026-10-30 — M2-K.1g high-half mappings added to the inactive plan

- Extended the private-window ownership audit to snapshot every verified RW/NX leaf, including the page-table self-alias, in a bounded fixed-capacity record.
- Added a planner step for the high-half leaves. Scratch frames must be absent from the captured manifest; the self-alias is accepted only if the PE image section policy already allows the same physical page to be writable and non-executable.
- All seven QEMU variants reported four private-window plan records: three allocator-claimed scratch pages and the PT self-alias. The planner remains inactive; no new ancestry or CR3 transition is installed.
- Host tests, UEFI cross-build, formatting and QEMU acceptance passed: https://github.com/Drmgiver/Sorveth-OS/actions/runs/41008183127

M2-K.1 remains partial. Next is to construct and walk the owned high-half page-table subtree while it remains inactive; inherited firmware mappings and full supervisor coverage are still required.


## 2026-10-30 — M2-K.1h inactive owned high-half hierarchy

- Added a separate static PDPT/PD/PT branch to the independent PE-image candidate hierarchy; the active Sorveth root and its page tables remain unchanged.
- The candidate self-alias points to its own PT frame. The three claimed scratch mappings are copied with audited RW/NX rights, then each planned translation is walked through the restricted physical-frame reader.
- The guard page and transient frame-window slot are verified absent. All seven QEMU variants passed the new hierarchy marker; no CR3 switch to the expanded candidate occurred.
- Host checks, UEFI cross-build, formatting and QEMU acceptance passed: https://github.com/Drmgiver/Sorveth-OS/actions/runs/41009221778

M2-K.1 remains partial. The candidate still lacks the complete non-image supervisor survival set and device cache policy required for a persistent independent root.


## 2026-10-30 — M2-K.1i inactive UC framebuffer mapping

- Added a page-rounded, bounded GOP framebuffer range to the supervisor plan, backed by the trusted framebuffer handoff and its audited endpoint samples.
- The candidate accepts only identity-mapped supervisor-writable framebuffer pages with no conflicting RAM/firmware descriptor type. It verifies CPU PAT support and requires IA32_PAT entry 3 to be UC before using PCD+PWT leaves.
- Candidate PTE cache bits are read through Sorveth's frame window and checked alongside supervisor, writable, NX and identity-translation properties. All seven QEMU variants verified 1,000 framebuffer pages plus the four private-window mappings.
- No candidate CR3 was activated. Other non-image supervisor mappings are not yet supported by this builder. Host checks, UEFI cross-build, formatting and QEMU acceptance passed: https://github.com/Drmgiver/Sorveth-OS/actions/runs/41010104216

M2-K.1 remains partial; the inactive candidate still needs generalized non-image mapping coverage and a complete supervisor survival audit before any persistent CR3 transition.


## 2026-10-30 — M2-K.1j generalized inactive supervisor mappings

- Generalized the candidate hierarchy to accept all verified planner mappings, including mappings that require additional PML4/PDPT/PD branches. New tables come from a bounded pool in writable, identity-mapped PE pages.
- The candidate now fails closed on pool exhaustion, untrusted table frames, huge-page collisions, and occupied leaf entries, then walks every planned mapping and checks translation and permissions. The private-window self-alias remains rebound to the candidate's own PT; framebuffer UC validation remains in place.
- The candidate remains inactive. This does not establish complete runtime survival coverage or authorize a persistent CR3 transition.


## 2026-10-30 — M2-K.1k candidate survival coverage and temporary activation

- The expanded candidate now walks every record in the captured runtime survival manifest. PE pages use the section W^X policy, non-image pages must match the plan, and device endpoints must lie in the verified UC framebuffer range.
- Added a second atomic CR3 probe after candidate construction. It briefly executes and reads the owned stack under the expanded candidate, then restores the inherited Sorveth root before returning to Rust. The earlier PE-only probe remains as a separate checkpoint.
- The full candidate is never kept active. This verifies the captured bootstrap survival set, not all dynamic or future kernel dependencies.


## 2026-10-30 — M2-K.1l candidate frame-window lifecycle probe

- Added a candidate-only temporary physical-window probe using one allocator-owned RW/NX scratch frame. It saves and restores the frame's original word, reads a sentinel through candidate slot 511, clears the PTE through the candidate's self-alias, invalidates the TLB entry, and restores the original CR3 in the same assembly block.
- The QEMU acceptance matrix now requires the lifecycle marker. The active Sorveth root is never modified by this probe; it does not prove general or concurrent frame-window operation.

## 2026-10-30 — M2-K.1m sequential candidate frame-window remapping

- Expanded the candidate probe to use two distinct writable NX frames and two different sentinels. Under one candidate CR3 activation, it reads frame one, clears and invalidates slot 511, maps frame two into the same slot, reads its sentinel, then clears and invalidates before restoring the original CR3.
- After returning to the Sorveth root, the kernel verifies slot 511 is empty and restores both original frame words. All QEMU acceptance variants require the new marker.
- This exercises sequential reuse and stale-translation control in the candidate. It does not prove concurrent use, frame reclamation, or a complete runtime survival inventory.

## 2026-10-30 — M2-K.1n candidate window collision denial

- Added an occupied-slot probe before the successful K.1m remap. It stages a valid candidate-only PTE, calls the regular probe path, and requires `WindowCollision` with the PTE unchanged and the original kernel CR3 still active before clearing the staged entry.
- The normal two-frame remap then runs, and all QEMU acceptance variants require the collision-denial marker.
- This exercises the collision preflight on the single bootstrap CPU; it is not a concurrent-use or fault-recovery guarantee.

## 2026-10-30 — M2-K.1o process-root supervisor mapping coverage

- After constructing both scheduler roots, the kernel now walks every external mapping in the verified supervisor plan through each root, checking physical backing, supervisor-only access, and the write/execute rights the plan requires. The framebuffer endpoints are checked in both roots as well.
- Every QEMU boot variant requires the new marker before process user pages and task scheduling proceed.
- This confirms planned bootstrap dependencies remain reachable through the process roots, which still inherit firmware page-table ancestry. It does not prove complete dynamic mapping coverage.
