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


## Runtime survival mapping inventory (M2-K.1d staged checkpoint)

The x86-64 bootstrap now includes a **read-only** four-level supervisor
page walker, with host tests covering missing entries, USER exposure,
ancestor NX/WRITE reduction, canonical address rejection and aligned
2-MiB huge-page handling. After IDT/TSS installation and the permanent
kernel-stack transfer, it walks every 4-KiB address of the kernel stack,
worker stack, page-fault and double-fault IST stacks, and (when compiled)
the ring-3 trap stack; it also audits the active RSP, CPU GDTR/IDTR
ranges, TSS, serial/kernel code and all four exception entry points.

Every page-table read uses Sorveth's transient high-half window, but the
**firmware-inherited identity mapping is still needed to validate each
lower-level table frame before borrowing it**. This is an inventory proof,
not a new mapping and not an independent root. The audit rejects absent
or effectively USER-accessible critical pages, non-writable stacks and
non-executable code. It counts legacy writable+executable leaf mappings
as technical debt rather than incorrectly pretending OVMF already supplies
a W^X kernel image. The normal/fault/ring-3/isolation/transfer QEMU gates
require an audit marker before the kernel proceeds.

**Next:** record the actual backing physical pages and ownership for each
sample; partition executable/readonly/writable sections and protected
stack guard regions; construct independent supervisor tables from verified
physical frame claims, then transition and prove no inherited table
ancestry under a separate QEMU mode. Audit success by itself is not K.1d
completion.


## Additional boot handoff mapping gate (verified checkpoint)

After the IDT/TSS installation, but before starting arbitrary kernel
scratch tests, Sorveth audits its live BootInfo address range and every
4-KiB page of the retained UEFI memory descriptor buffer. It also
validates the boundary mappings of the framebuffer, when usable, without
reading device memory as RAM. These pointers were separately reserved
in the original physical frame ledger. Invalid/null, arithmetic-overflow,
noncanonical, absent or effectively user-accessible addresses are denied;
framebuffer endpoints additionally require write permission.

QEMU acceptance requires this proof and the later code/stack/GDT/IDT/TSS
survival audit in all supported smoke variants. Both are **read-only**
firmware-transition inventories. They do not pin every backing page,
construct replacement supervisor mappings, remove firmware ancestry or
assert a secure W^X layout. A verified physical-backing/ownership manifest
is the next engineering requirement, followed by an independent page-table
builder and a separate root-transition QEMU mode.

Evidence: Actions runs 40931953610 and 40932702573.


## Bounded physical-backing and UEFI-provenance manifest (K.1d incremental)

On Sorveth's permanent 128-KiB kernel stack, the loader handoff data is
first copied into retained kernel storage. A bounded, allocation-free
manifest then records **distinct 4-KiB virtual/physical page pairs** for
sampled kernel/exception code, every kernel/worker/IST and optional ring-3
trap stack page, active GDT/IDT/TSS, persistent frame-ledger storage,
the retained BootInfo copy, all descriptor-buffer pages, and the first
and last framebuffer device pages when usable.

Each entry is resolved by an actual four-level page walk through the
already audited, temporary Sorveth-owned access window; it is tagged
with the UEFI descriptor memory type and effective WRITE/NX permissions.
Missing physical descriptors, duplicate physical aliases, inconsistent
UEFI descriptor coverage, accidental USER exposure and unrecognized
critical memory types fail closed. Firmware framebuffer pages may be
missing from ordinary descriptor coverage; this is explicitly counted,
**not** treated as conventional RAM. Legacy writable+executable mappings
remain visible as debt. These checks do not confer ownership of a UEFI
loader/boot-services page, guarantee W^X, or prove a complete image map.

The manifest is a *runtime test inventory*, consumed synchronously and
not yet a persistent authoritative page-ownership database. The code image
is represented by critical execution samples, not every executable page.
Therefore it must not be fed directly into a replacement-CR3 installer.

The full QEMU suite requires a dedicated manifest proof marker before
native context switches. A future stage must capture the entire linked
image layout and all required page-table ancestry, retain the validated
metadata, reconcile ownership with actual frame claims, then construct
a fully Sorveth-owned replacement supervisor hierarchy.


### Bootstrap paging frames included in provenance (incremental)

The kernel manifest now also proves the physical backing, 4-KiB alignment,
accessible writable supervisor mappings and UEFI loader/boot-services
provenance for all four statically retained Sorveth paging frames: its
PML4, private PDPT, private PD and private PT. These four records must be
present as distinct pages (no hidden aliases), and a dedicated QEMU success
marker is required across every smoke variant. This remains a bootstrap
inventory, not a page-table ownership transfer or an independent CR3.


## UEFI Loaded Image handoff and complete image-page backing audit

**Implemented increment (M2-K.1d, 2026-10-29):** The loader retrieves
EFI_LOADED_IMAGE_PROTOCOL for its actual image handle *before* the final
GetMemoryMap / ExitBootServices pair. The pointer-free metadata passed to
Sorveth Core via boot protocol v2 includes a bounded, page-aligned image
base and image allocation size. The ABI has host tests for validation and
the required UEFI offsets. No firmware call occurs after ExitBootServices.

Core walks **every 4-KiB page** in that entire allocation using its
transitional read-only four-level page-table walker. Every page must be
present, effectively supervisor-only, identity-backed under this QEMU
bootstrap, and covered by one loader/boot-services UEFI memory descriptor.
The walk counts currently writable, executable and writable+executable
pages without silently claiming modern W^X permissions. The scan is
bounded at 32 MiB for the current QEMU bootstrap and does not retain a
per-page record; it runs alongside the smaller 192-record critical-object
manifest. The full QEMU suite requires a dedicated image-scan marker.

This closes the **current PE image extent/backing *inventory*** gap, not
the section-permission or independent paging construction gap. Next is
strict PE32+ section parsing and page-by-page desired W^X policy, plus
classification of image gaps and actual physical ownership. No inherited
supervisor tables have yet been replaced or reclaimed.


## Strict PE32+ section permission inventory (K.1d next increment)

After validating the complete image's physical backing, Sorveth parses
the first bounded 4-KiB of its actual in-memory PE32+ AMD64 image.
The parser checks the DOS/PE signatures, AMD64 machine ID, optional header
bounds and PE32+ magic, 4-KiB section alignment, total image size,
section-table bounds and RVA ranges. A section may be executable **or**
writable, but never both. Overlapping or out-of-range section pages
are rejected; unknown pages between sections remain **unclassified** and
must not be granted guessed permissions during an independent CR3 build.

The runtime audit counts header/read-only, executable, writable and
unclassified pages, and QEMU requires a separate proof marker. It does
**not** yet change any PTE, nor establish a complete, installed W^X kernel.
It proves that a desired permission plan can be derived from verified PE
section metadata, separately from the inherited firmware's RWX mapping.
