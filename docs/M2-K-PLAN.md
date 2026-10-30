# M2-K — Managed kernel memory and process lifetime

This is the implementation plan after the **CI-verified M2-J.6** controlled
ring-3 memory-copy proof. Milestones are only complete when both host tests
and all QEMU security/monitor gates pass on the accepted commit.

## K.1: Replace firmware-provided physical-memory access

- K.1a: implement a kernel-owned high-half *temporary frame window* used by
  two early scratch-page claims; preserve existing boot tests.
- K.1b: migrate bounded process-frame reads/writes and owned paging-table
  access to explicit trusted high-half mappings, without relying on direct
  physical pointer dereferences.
- K.1c: build and validate Sorveth-owned supervisor mapping ancestry for
  active kernel execution, rejecting accidental user exposure and unsafe
  physical aliases. Audit critical code, stacks, kernel data and framebuffer
  requirements before discontinuing inherited firmware mappings.
- K.1d: remove inherited mappings in a dedicated QEMU verification mode;
  check working monitor, exceptions, independent process roots, copy tests
  and all existing ring-3 negative cases before enabling broadly.

## K.2: Physical frame allocation and reclamation

Add explicit reference/owner records, zero-on-reuse, quarantine for active
CPU mappings, transactional allocation and no premature reclamation.
Validation includes exhaustion, double release, stale generation, and frame
alias/reuse tests. Never release runtime/loader or active paging frames.

## K.3: Process address-space lifecycle

Implement creation, owned mapping installation, guarded stacks and teardown,
with rollback on partial failure. Reject stale identities and foreign roots.
No process may retain a mapping to a reclaimed frame.

## K.4: Generalized bounded copy-in/copy-out

Replace the current fixed eight-byte ring-3 test-only transfer with a
documented bounded buffer ABI, stable mapping lifetimes, full preflight of
all pages and recoverable faults. Preserve capability/task authorization.

## K.5: Full security/regression acceptance

Run deterministic QEMU negative and forced-failure tests in both A/B process
directions, plus normal boot, deliberate faults, ring-3 protection, IPC,
monitor interaction and host tests. Refuse to claim SMP, physical hardware,
or an arbitrary-user-program ABI without separate acceptance evidence.

## Current implementation status

**K.1a verified:** the final PT slot of the Sorveth-owned private high-half
subtree is reserved for a temporary RW/NX physical frame alias. The scoped
guard requires kernel CR3 and interrupts disabled, rejects invalid and
nested use, invalidates the TLB before access, then unmaps on return.
Two early scratch claims no longer dereference their physical frame
addresses through firmware's identity map.

**Still pending:** completion of K.1b–d, all of K.2–K.5, production process scheduling,
page reclamation, and safe arbitrary user mappings. The root's initial
PML4 setup, existing page-table pointers and other kernel accesses still
rely on inherited OVMF identity mappings. This is not an independent
kernel memory subsystem yet.


### K.1b intermediate checkpoint: user-copy frame access

The M2-J.3/J.4 kernel copy helpers now map the specific process-owned data
frame through the scoped high-half window for both directions, rather than
casting the PTE-resolved physical data address into a kernel pointer.
Existing full-range page-walk/ownership preflight remains before any writes;
only the current one-frame permanent process pages are supported. QEMU must
check the new marker in every ordinary boot and the existing A/B ring-3
memory-syscall and denial runs. This does **not** yet migrate page-table
walking, process creation or test setup off inherited firmware mappings.


### K.1b checkpoint: process-owned page-table reads and frame initialization

The bounded M2-J.2 user page walker now only admits aligned entries inside
four known process-owned table frames, and reads those entries through the
scoped Sorveth-owned high-half window. The kernel does not dereference a
PTE-derived physical pointer directly. The two process data frames are also
zeroed through the same window at creation and their final physical values
are checked via that window after restoring the kernel CR3.

Normal, deliberate-fault, ring-3, A/B isolation, A/B transfer and interactive
monitor acceptance must continue to pass; the new marker is emitted only
on the verified post-process-walk boot path.

**Not yet migrated:** initial PML4/static table setup and ownership audits
still access identity-mapped memory; current processes retain permanent
one-page data mappings. Firmware identity mappings cannot yet be removed.


### K.1b checkpoint: QEMU full-frame integrity no longer uses identity pointers

The test-only M2-J.6 ring-3 memory gateway now calculates its 4096-byte
integrity checksums, records original frame words, and performs final
restoration/foreign-frame checks through the same owned temporary high-half
mapping used for ordinary kernel copy operations. An inaccessible mapping
fails closed and cannot report the previous success marker. Both QEMU A/B
transfer images must report an additional K.1b integrity marker.

These remain permanent test frames on one CPU. This is not a production
integrity mechanism, a proof of race-safe copying, or full removal of OVMF
identity mappings used by other initialization and audit paths.


### K.1c intermediate checkpoint: kernel PT self-alias

The existing Sorveth-owned 2-MiB supervisor-only high-half subtree now
reserves entry 510 to map its own 4-KiB PT frame RW/NX. The transient
physical-frame window continues to occupy entry 511. The root setup
verifies the new alias resolves to precisely the known PT frame and that
the alias cannot be accessed as a USER mapping. The window and scratch
page allocator now modify their PTEs through this high-half alias,
without casting the PT's physical address into a live kernel pointer.
Both reserved slots are excluded from ordinary scratch allocations.

This is not a recursively mapped general paging hierarchy. Boot setup,
most static/firmware root audits, and other inherited supervisor mappings
still need a later K.1c/d migration before they can be safely removed.


### K.1c intermediate checkpoint: process-root audit through registered owned tables

The M2-I.5 trusted address-space audit now reads all needed kernel/root
PML4 entries and four ancestor/leaf entries per process through the
single-page high-half physical window. Before the kernel accesses a
physical table entry, a fixed allowlist admits only the kernel PML4,
both known process PML4 frames, and the six static Sorveth-owned PDPT/
PD/PT frames. Entry indices must be 0–511 and frames must be page aligned.
Failed window mappings and unauthorized table addresses fail closed.

The existing page-table ownership, permission, foreign-slot, CPU A/D-bit
policy and stale task/capability negative tests remain mandatory.
The new boot marker follows the actual task-lifecycle corruption test,
so this code path is exercised rather than simply built.

**Still needed for K.1:** static table construction/teardown, other
scheduler/bootstrap physical table accesses and all firmware supervisor
mapping inheritance. These tables are still initialized under a verified
OVMF identity map; the audit now uses Sorveth's owned alias but this
alone does not make initial paging independent of firmware.


### K.1c intermediate checkpoint: construct private paging trees via owned aliases

During M2-I.2 private page setup, Sorveth now zeroes all six registered
PDPT/PD/PT pages through its own temporary high-half frame window.
It writes the eight private paging entries (the two data leaves, four
ancestor links, and two process PML4 root slots) using the same fixed,
registered-table whitelist and temporary window as the audit reader.
The initial empty-slot checks and final A/B ownership/permission audit
also use the registered high-half reader, avoiding raw physical table
pointer casts during this portion of process mapping installation.

Firmware identity mappings remain necessary for early static frame address
validation and existing root/stack and supervisor boot mappings. These
changes are single-core, nonpreemptive, permanently backed bootstrap
experiments, not general concurrent address-space creation.


### K.1c acceptance update — audited and constructed private paging trees

The registered process address-space audit and both private paging-tree
installation paths have been migrated to the Sorveth-owned high-half
physical window. CI has verified the mapping-permission tamper tests,
normal/fault QEMU boot, both process isolation directions, both 22-call
ring-3 memory-transfer images and the interactive serial monitor.

Evidence: Actions runs 40905890138 and 40906547145 (both passed).

Pending for K.1d is real removal of firmware mapping inheritance, including
provisioning supervisor kernel executable/data, stacks, interrupts, memory
map, framebuffer and all CPU-required mappings through kernel-owned tables.
Do not infer that switching the user-table builder removes those remaining
bootstrap dependencies; the owned frame window itself still needs the
initial Sorveth private supervisor subtree installed during handoff.


### K.1d incremental checkpoint — owned PML4 cloning and verification

The two bootstrap process PML4 roots are now constructed by snapshotting
the active kernel PML4 through Sorveth's owned high-half physical window,
sanitizing all present supervisor entries, and writing/verifying each full
512-entry process root through the same temporary window. All vacant-slot,
foreign-slot, supervisor USER-bit and CR3-switch tests remain required.
The physical root frames themselves are statically allocated; this is not
new process allocation or a production loader. QEMU verifies the new root
clone marker in normal, intentional fault and legacy ring-3 modes, plus
the existing isolation/transfer/monitor acceptance tests.

**Remaining K.1d blocker:** kernel code/stack, IDT/TSS handlers and early
boot data still execute through supervisor mappings inherited from OVMF.
This commit does not unmap inherited firmware tables, reclaim them or
establish a fully independent kernel CR3 hierarchy. Those need a separate,
carefully staged mapping-audit and switched-root QEMU proof.


### K.1d incremental checkpoint — isolated ring-3 probe PML4 attachments

The QEMU-only process probe-attachment path now audits the kernel source
PML4 slot, selected process destination slot, foreign process slot and
cross-process private slots using the registered high-half table reader.
Only after all ownership/permission checks pass does it install the
selected test probe's PML4 slot using the registered high-half table
writer, then verify the exact entry. Neither the destination nor the
source is dereferenced as an identity-mapped physical pointer.

The A/B ring-3 isolation and 22-call transfer variants must emit the
new proof marker before loading their selected process CR3; they
continue to test forbidden cross-process accesses and unauthorized
user-memory operations. The test probe still borrows a kernel test-code
subtree, and the general-purpose userspace loader does not exist.


### K.1d incremental checkpoint — read-only PTE tamper denial uses owned aliases

The M2-J.4 negative mapping test now retrieves the inactive process's
registered PT leaf entry through the owned frame window, changes only
its write permission using the registered-table writer, and restores
the original PTE before concluding the check. The process data-word
integrity comparison also uses an owned temporary high-half alias,
not the physical identity-mapped address. QEMU must require a separate
marker after both A/B write-denial probes complete successfully.

These controlled mutations are serialized on the single bootstrap CPU;
this does not provide dynamic process mapping teardown or concurrent
lifetime protection. Additional legacy scheduler/bootstrap inspection
paths still rely on OVMF identity mappings.


### K.1d incremental checkpoint — owned scheduler/negative-root physical access

The M2-I.3 scheduler address-space switching test no longer reads the
PML4 entries or either process data frame through raw identity-mapped
physical pointers. Trusted process-root lookup accepts only the two
kernel-registered process PML4 frames; process first-word checks use
Sorveth's transient supervisor-only high-half frame mapping. The
A-B-A-B CPU-visible user-virtual memory writes remain intentional
proofs that switching actual CR3 roots changes the mapped address space.

The M2-I.5 stale-task/damaged-root negative test now temporarily clears
USER permission on only the registered selected process root PML4 entry,
using the high-half writer, calls the authorization-denial predicate,
then restores and verifies the original entry and trusted process-root
audit. The caller receives no physical table pointer. QEMU requires a
new marker after these real scheduler/negative tests, in all supported
boot variants. Unmapped/faulting kernel pointers and inherited supervisor
code/stack/IDT memory are not yet removed; K.1d is still incomplete.


### K.1d intermediate checkpoint — owned-memory copy verification

The controlled M2-J.3/4 kernel copy-in and copy-out tests now use
Sorveth's registered, kernel-owned frame alias for all first-word and
final-page-byte integrity observations of both process frames. Test code
no longer casts a physical process-frame address into a pointer, even
for the intentionally rejected writes and cross-page copy attempts.
A bounded read for one requested byte rejects offsets beyond the fixed
4-KiB process test frame. The exact positive and negative transfers
still exercise the original audited user-memory copy routines, with
both A/B cases checked before the new QEMU success marker is printed.

This does not address dynamic data-frame pinning, multiple user pages,
preemption or removing inherited supervisor code and stack mappings.


### K.1d incremental checkpoint — owned ring-3 test loader mappings

The QEMU-only ring-3 program builder now finds its unused kernel PML4
slot by reading the registered root through Sorveth's high-half window.
It zeros its two *ledger-claimed* 4-KiB code/stack frames and populates
the generated program bytes through the owned window, with no direct
physical frame pointer or requirement that OVMF identity map those frames.
Its three static test paging-table frames are also initialized and linked
through the owned window. The new USER PML4 entry is installed and both
code/stack translations verified by a 4-level page walk that accepts only
the four known root/PDPT/PD/PT frames. Foreign PTE-derived physical
addresses cannot expand this verification whitelist.

The legacy ring-3 probe, A/B hardware-isolation probes, and both 22-call
memory-syscall probes must report a dedicated post-construction marker.
The static test paging-table frames continue to be identity-validated
at their early bootstrap physical addresses. This is not a general
process loader, and active kernel code/stack/IDT mapping independence
remains a separate K.1d acceptance target.


### K.1d checkpoint: scheduler, copy and ring-3 loader owned mappings

CI-verified: scheduler-owned PML4/data checks and negative test restoration,
both bounded copy-integrity suites, and construction/translation of the
ring-3 code/stack/table test subtree via Sorveth's owned frame window.
Main verification: https://github.com/Drmgiver/Sorveth-OS/actions/runs/40918371037

**K.1d remains open.** Next: the explicit supervisor mapping inventory,
ownership and permissions for kernel executable, data, stacks, IDT/TSS,
boot information, serial console and optional framebuffer; a separately
QEMU-validated replacement kernel root that can drop all inherited OVMF
lower-level tables. See M2-K1D-SUPERVISOR-TRANSITION.md.


### K.1d read-only runtime survival audit

Implemented a fail-closed, x86-64 supervisor page-walk audit of live
kernel/serial/exception execution, GDTR/IDTR/TSS metadata and all pages
of the kernel, worker and IST stacks (plus ring-3 trap stack when present).
It uses an owned temporary high-half mapping for table reads but still
preflights borrowed firmware table frames through inherited identity
translation; no inherited page tables are removed by this checkpoint.
The audit additionally counts legacy writable+executable kernel pages
as remaining migration debt instead of claiming W^X is already complete.


### K.1d verified boot handoff inventory

Read-only QEMU inventory now covers mapped BootInfo, all UEFI descriptor
buffer pages, and (if available) writable framebuffer boundaries, as
well as code/stack/IDT/TSS survival mappings. Accepted evidence:
https://github.com/Drmgiver/Sorveth-OS/actions/runs/40932702573

This is not an independently mapped kernel. Mapping ownership and the
replacement root still require separate implementation and QEMU proof.


### K.1d physical backing provenance (bounded manifest)

The kernel now captures a bounded, zero-heap 4-KiB page manifest for
critical supervisor code samples, all active/worker/fault/trap stacks,
CPU descriptor tables, persistent frame ledger and retained boot handoff.
Each page records its actual translated backing and UEFI type; overlaps,
unsafe conventional/MMIO types for kernel data, USER exposure and missing
mapping evidence fail closed. The device-framebuffer exception remains
marked explicitly as potentially unclassified. This is a runtime proof,
not an owner ledger or an installable full-image mapping plan.


### K.1d accepted physical-backing and owned table provenance

Bounded, fail-closed runtime manifest checks current 4-KiB virtual/physical
backing and UEFI provenance for critical kernel regions. A second dedicated
QEMU gate verifies that all four static Sorveth-owned root/private paging
frames have distinct, writable, aligned, classified backing. Host tests and
all normal/fault/ring-3/isolation/transfer/monitor QEMU checks passed.
Evidence: Actions 40942697712 and 40943212370.

The manifest does **not** establish full-image sections, page lifetime,
concurrent mapping safety, usable device caching or a firmware-independent
supervisor hierarchy. Remaining before the K.1d switch: complete section
coverage, retention/ownership semantics, W^X permissions, explicit
physical table construction and a separate no-inherited-table QEMU mode.


### K.1d current complete image backing coverage

UEFI's Loaded Image protocol supplies the actual base/size in boot ABI
v2, prior to exiting boot services. The kernel walks every page of this
bounded image and verifies identity-backed supervisor page translations
and loader/boot-services physical provenance. Legacy W+X is explicitly
counted. This is image *backing* coverage, not a PE section permissions
plan and not a new independent CR3. Dedicated QEMU marker required.


### K.1d explicit inactive image-only page table construction

Sorveth constructs a separate, statically retained PML4/PDPT/PD and
limited 4-KiB PT subtree for a PE image limited to one 1-GiB region.
Every section leaf is W^X or absent, with USER disabled; an independent
walk verifies effective permissions and exact physical identity of each
mapped image page. CR3 stays on the existing, shared-firmware kernel
root. This milestone is explicitly NOT an independent supervisor CR3.


### K.1d verified temporary hardware CR3 transition via independent image tables

On the dedicated Sorveth kernel stack, an atomic assembly sequence saved
the old CR3, executed briefly through the independently built W^X PE-image
root, verified CR3 and stack access, then restored the original CR3.
The remaining boot and all QEMU fault, ring-3, isolation, transfer and
monitor variants continued normally, with a required success marker.
Accepted evidence: Actions 41004595369 and 41005015817.

The image-only root is NOT permanently installed and intentionally does
not cover dynamic memory, the high-half frame window, optional MMIO or
all kernel subsystems. Next: build and verify independent mappings for
the supervisor survival set beyond the PE allocation, then adopt the
new root persistently under a separate negative-tested QEMU mode.


### K.1e bounded supervisor survival mapping plan

A new allocation-free planner consumes the verified critical-page manifest and the validated PE section layout. It checks manifest pages inside the image against the section W^X policy and emits explicit target mappings for backed non-image supervisor pages. It rejects noncanonical or unaligned addresses, image aliases, unclassified image pages, unsupported UEFI backing, permission escalation and physical aliases. Framebuffer endpoints remain deferred because their cache policy is not specified.

Across the seven QEMU variants, the manifest reports 77–86 image-resident supervisor records and two deferred framebuffer endpoint records per run. Therefore the non-image mapping list is validly empty; this result exposed that the bounded manifest still omits Sorveth's high-half frame-window subtree and its allocator-owned scratch mappings. The planner is not a page-table builder and no CR3 is changed. Host checks, UEFI cross-build, formatting and QEMU acceptance passed in [run 41006241220](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41006241220).

**Next:** inventory the private high-half subtree and its claimed frame ownership, then extend the plan to cover those mappings before constructing a broader independent supervisor root. Dynamic frames and framebuffer cache attributes remain separate gates.


### K.1f private high-half frame-window ownership audit

The frame allocator now retains a bounded ledger of every irreversible allocation claim. The private high-half audit walks Sorveth's existing PT, verifies the self-alias points to the owned table, requires the guard and transient physical-window slots to be absent, and checks that every present supervisor RW/NX scratch leaf maps a distinct page in the allocator's claim ledger. This is an inventory and ownership proof only; it does not copy the high-half subtree into the independent image root or activate that root.

The QEMU gate requires the audit marker across all variants. Next: feed the verified self-alias and scratch mappings into the independent-root plan, preserving ownership and permission checks, then test that expanded root while it remains inactive.
