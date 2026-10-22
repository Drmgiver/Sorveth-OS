# ADR 0001 — Rust, UEFI x86-64 and proof-first kernel bootstrap

**Status:** Accepted for prototype, 2026-10-22.

- Choose Rust `no_std` for Sorveth Core, not a Linux base or hobby fork.
- Start on x86-64 with UEFI and QEMU/OVMF. Add ARM64 after portability work.
- Ship the minimum UEFI OS loader that calls `ExitBootServices`, passes a
  versioned handoff struct, and jumps into firmware-independent Rust code.
- Use COM1 serial and a GOP-provided framebuffer as initial observable proofs.
  Both are temporary drivers; firmware GOP does not replace native display work.
- Keep allocator-free capability logic as a separately testable Rust library.
- Prefer no third-party dependencies in the first bootstrap; audit raw UEFI
  declarations carefully. Replace hand-coded ABI with vetted bindings when useful.
- Keep distinct acceptance criteria for source, cross-compilation, and boot.

**Consequence:** The kernel and bootloader are linked together in this initial EFI
binary. Moving to a separately loaded ELF kernel, owned paging and user-space
isolation is mandatory before claiming a real microkernel.
