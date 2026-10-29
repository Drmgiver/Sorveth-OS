# M2-K.1d — Replace inherited supervisor mappings

Status: **Open** (2026-10-29). This file describes acceptance criteria, not
features that have already been implemented.

## Verified stepping stones

Sorveth already owns its top-level PML4, a high-half private page subtree,
a transient physical-frame access window and self-mapped private PT. The
controlled A/B process trees, user-data checks, scheduler corruption tests,
copy-in/out integrity probes and generated ring-3 test-code/stack paging
builder now use registered supervisor aliases rather than dereferencing
untrusted physical frame addresses. Current real kernel execution still
depends on OVMF-inherited lower-level supervisor table mappings.

## The survival set that an independent kernel CR3 must cover

The replacement root must explicitly map and protect these regions before
the CPU ever loads it:

1. **Executable kernel image**: instruction pages and relevant branch targets,
   including serial error/panic handlers, with USER=0, WRITE=0 and execute
   allowed. Identify actual physical backing and relocation rules; do not
   assume every virtual address is an identical physical address.
2. **Kernel static data and metadata**: writable and read-only sections,
   capability/task/scheduler state and the persistent physical frame ledger.
   Writable data must be non-executable; prevent unintended physical aliases.
3. **Current and future stacks**: the active Rust stack, kernel-fiber stacks,
   the ring-3 trap stack, page-fault and double-fault IST stacks, with
   supervisor permissions and intentional guard gaps where feasible.
4. **CPU tables and exception machinery**: live GDT, TSS, IDT and their
   referenced targets and IST pointers must remain mapped at exactly the
   same virtual addresses across the CR3 transition.
5. **Boot handoff data**: the validated BootInfo, the UEFI memory descriptor
   buffer and any still-referenced loader allocations. Check their ownership
   and lifetime; firmware runtime/ACPI/MMIO regions must not be mistaken for
   ordinary conventional memory available for reclaiming.
6. **Diagnostics and optional devices**: the serial console and QEMU debug
   exit must remain usable to prove success or failure. An optional
   framebuffer must be explicitly mapped only when accessed, using suitable
   device caching attributes. Do not blindly map all MMIO as normal RAM.
7. **Paging structures and window**: new Sorveth-owned PML4/PDPT/PD/PT
   frames, safe physical-table access aliases and root-independent kernel
   shared mappings needed by both A/B process CR3 contexts.

## Migration and verification sequence

- **Inventory**: derive virtual-to-physical mappings for the above survival
  set from proven boot metadata and CPU page-table state. Explicitly reject
  unrecognized table frames, unsupported huge-page modes and conflicting
  permissions. Do not dereference physical addresses from untrusted entries.
- **Owned construction**: allocate and zero ledger-claimed page-table frames,
  build a supervisor-only hierarchy, and audit every ancestor/leaf's USER,
  WRITE, NX, physical range and overlap policy. Preserve mandatory machine
  state without copying inherited entries wholesale.
- **Controlled transition**: with one CPU and maskable interrupts off, load
  the owned root in a dedicated QEMU mode, immediately prove live stack,
  code, IDT/TSS and serial access, and restore or fail closed if possible.
  Do not enable preemption or frame reclamation at this stage.
- **Inherited-table removal**: explicitly remove OVMF lower-level table
  references from the new kernel and process roots. Verify by independent
  page walks that active translations do not traverse firmware-owned table
  frames; a mere new PML4 pointing at old PDPTs is insufficient.
- **Regression gate**: host unit tests and all normal/fault/legacy ring-3,
  A/B hardware isolation, A/B 22-call memory syscall, and interactive
  monitor QEMU checks must pass. Add deliberate missing/USER/writable-
  executable mapping negatives and ensure no false success marker.

## Not accepted yet

A bare-metal boot, multi-core operation, safe page reclamation, a generic
process loader, a preemptive scheduler or general user buffers. These are
separate M2-K/L tasks. Do not advance K.1d from an ownership-less
identity-map clone or from tests that only see a serial marker before the
new CR3 is loaded.
