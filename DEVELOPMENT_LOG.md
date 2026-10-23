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
