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