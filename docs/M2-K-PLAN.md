Warning: truncated output (original token count: 9172)
Total output lines: 659

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

**K.1d accepted:** the Sorveth-owned candidate root remained active through
the full normal, deliberate-fault, ring-3, A/B isolation, A/B copy-transfer,
and interactive-monitor matrices. Host tests, UEFI cross-build, native ABI
layout, formatting, normal-root QEMU, and independent-root QEMU all passed on
the accepted `10a64f4` commit. CI evidence: [feature run
41111097984](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41111097984)
and [main run
41222147869](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41222147869).

**K.2a accepted:** allocation spans have explicit subsystem owners,
generation-bound handles, and checked logical reference counts. Host tests
cover wrong owners, stale generations, double release, overflow, and the fact
that dropping the final reference does not free physical pages. Evidence:
[feature run
41222639055](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41222639055)
and [main run
41222759256](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41222759256).

**K.2b accepted:** allocation records also track mapping references and can
enter quarantine only after owner and mapping counts reach zero. This is
ledger state only; page-table teardown, real TLB invalidation, zeroing, and
allocator reuse remain blocked until the kernel connects and tests those
operations in order. Evidence: [feature run
41223134856](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41223134856)
and [main run
41223296700](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41223296700).

**K.2c accepted:** each persistent allocation-backed bootstrap leaf
mapping records one mapping reference before its PTE becomes visible: the
root bootstrap page, kernel scratch pages, process A/B data pages, and user
probe code/stack pages. These mappings remain permanent and pinned. The
temporary physical-window alias remains scoped to a caller that holds the
owner reference and is not counted in the mapping ledger. This closes known
persistent-map accounting gaps for the fixed, single-CPU bootstrap paths;
it does not yet implement unmapping, TLB shootdown, zero-before-reuse, or
frame recycling. Evidence: [feature run
41223698875](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41223698875)
and [main run
41223828017](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41223828017).

**K.2d next:** implement real teardown and recycling for a claim only after
all recorded mappings are removed and the relevant CPU translations are
invalidated. Zero the quarantined span through the owned physical window,
then transactionally return its range and advance the claim-slot generation.
The first reclaim path must operate only on claims proven unmapped; firmware,
runtime, active page-table, and permanent bootstrap frames remain pinned.

**Still pending:** K.2d–K.5, production process scheduling, general physical
page reclamation, and safe arbitrary user mappings. K.1's independent root is
a QEMU-verified bootstrap mapping set, not yet a production memory manager.


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


### K.1d checkpoint: scheduler, copy and ring-3 loade…172 tokens truncated… runtime survival audit

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

The QEMU gate requires the audit marker across all variants.


### K.1g audited high-half mappings added to the candidate plan

The private-window audit now returns a bounded snapshot of every present
RW/NX leaf, including the PT self-alias, alongside allocator ownership proof.
The supervisor planner adds those leaves to its inactive plan. It checks
canonical/aligned addresses, collisions with existing planned mappings,
allocator-backed leaves against the captured manifest, and the self-alias
against the PE image's existing section permissions so a writable alias
cannot make code or read-only image data writable. In the current seven QEMU
variants this contributes four records: three claimed scratch pages and the
self-alias.

This expands the candidate mapping inventory only. It does not build the
upper-half page-table ancestry, install the plan, remove inherited mappings,
or establish a persistent independent supervisor root. Dynamic frame lifetime
and framebuffer cache attributes remain open gates. Host checks, UEFI
cross-build, formatting and QEMU passed in [run 41008183127](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41008183127).

### K.1h inactive owned high-half hierarchy construction and walk

The image-only candidate now gains a separate Sorveth-owned PDPT/PD/PT branch
for the planned high-half mappings. It does not borrow the active root's
tables. The page-table self-alias is rebound to the candidate PT frame itself;
the three allocator-owned scratch leaves retain their audited physical backing
and RW/NX permissions. Each planned leaf is walked through the restricted
physical-frame reader, and the guard and transient-window slots must remain
unmapped.

The branch is added only to the inactive candidate. CR3 is not changed, and
this is not yet a complete supervisor root: the planner currently accepts
only the four private-window records, while non-image supervisor state,
framebuffer cache policy and all remaining survival mappings are still
outstanding. Host checks, UEFI cross-build, formatting and all seven QEMU
variants passed in [run 41009221778](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41009221778).

### K.1i inactive framebuffer mapping with verified UC cache policy

The candidate planner derives the full page-rounded GOP framebuffer range
from the trusted handoff, requires matching identity-mapped endpoint samples,
rejects overlap with the loaded image or planned RAM pages, and limits the
range to 64 MiB. Before construction, the kernel checks every framebuffer page
for a supervisor-writable identity mapping and rejects conflicting UEFI
backing types.

The candidate uses 4-KiB supervisor RW/NX leaves with PCD and PWT set, which
select IA32_PAT entry 3 when the PAT bit is clear. The builder confirms PAT
support and verifies entry 3 is UC before adding the leaves. It then checks
the exact PTE cache bits through the Sorveth frame window and verifies the
candidate walk. Across all seven QEMU variants, 1,000 framebuffer pages and
the four private-window leaves passed. The expanded candidate remains
inactive; this does not establish coverage for other non-image manifest
mappings or justify a persistent CR3 transition. See the
[Intel Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
for PAT selection and memory-type rules.

Host checks, UEFI cross-build, formatting and QEMU passed in
[run 41010104216](https://github.com/Drmgiver/Sorveth-OS/actions/runs/41010104216).

**Next:** verify planned supervisor dependencies through both process roots
and inventory their shared inherited page-table ancestry. Persistent CR3
migration remains blocked on general dynamic mapping lifecycle and complete
runtime dependency coverage.




### K.1j generalized inactive supervisor candidate mappings

The candidate now accepts additional planner leaves outside the private
high-half window. It allocates required PDPT, PD, and PT pages from a bounded
PE-resident pool, checking that each frame is identity-mapped and classified
writable before use. Existing image, private-window, and UC framebuffer
subtrees remain owned candidate branches. Every planner mapping is re-walked
through the restricted physical-frame reader and checked for supervisor
access, exact physical backing, and the planned writable/executable rights.
Table-pool exhaustion, collisions, huge-page ancestry, or an untrusted table
frame fail closed. The candidate remains inactive; this does not prove that
the bounded manifest includes every runtime dependency or permit a persistent
CR3 transition.


### K.1k candidate survival-manifest audit and temporary CR3 probe

After building the expanded inactive candidate, the kernel now checks every
record in the captured survival manifest against candidate translations and
effective supervisor permissions. Image records follow the strict PE section
policy, non-image records must match the compiled plan, and framebuffer
endpoints must fall within the fully mapped UC range. The boot path then
briefly activates the expanded candidate on Sorveth's owned stack, reads CR3
and a stack word in one assembly sequence, and restores the prior root before
returning to Rust. QEMU must observe both the manifest-coverage marker and the
CR3 restoration marker. This proves the captured boot survival set can execute
through the candidate; it does not establish complete dynamic runtime
coverage or leave the candidate active.


### K.1l temporary candidate physical-window lifecycle

After the K.1k manifest walk, the kernel selects an allocator-owned writable
NX scratch page and saves its first word. It writes a sentinel through the
current Sorveth physical window, installs a candidate-only PTE in the expanded
root's previously empty slot 511, then briefly activates that root. One atomic
assembly sequence invalidates the alias, reads the sentinel, clears the PTE
through the candidate's PT self-alias, invalidates it again, and restores the
old CR3. Back on the original root, the kernel verifies the candidate PTE is
empty and restores the scratch word. Every QEMU boot variant must report this
marker. This probes one temporary mapping lifecycle; it does not make the
window concurrent, reclaimable, or ready for persistent root migration.


### K.1m sequential candidate physical-window remapping

The K.1l probe now uses two distinct allocator-owned writable NX frames.
While the candidate CR3 is active in one assembly block, it reads a unique
sentinel from the first frame, clears slot 511 through the candidate PT
self-alias and invalidates the address, then installs the second frame in
the same slot, invalidates and reads its different sentinel, clears the PTE,
invalidates again, and restores the original CR3. Back on the original root,
the kernel verifies the slot is empty and restores both original frame words.
Every QEMU acceptance variant requires the new marker. This tests sequential
slot reuse and stale-translation control; it still does not prove concurrent
window use, reclamation, or full survival-manifest coverage.


### K.1n occupied candidate physical-window slot denial

Before the successful remapping probe, the kernel writes a known valid PTE
into the candidate-only slot 511 and calls the normal probe path. The path
must return `WindowCollision` before changing the candidate PTE, touching the
sentinel frames, or activating the candidate root. The caller verifies the
entry is unchanged and kernel CR3 remains active, then clears the staged PTE
and runs the K.1m two-frame probe. Every QEMU variant requires the denial
marker. This checks the collision preflight in one bootstrap context; it is
not a concurrency or fault-recovery proof.


### K.1o planned supervisor mapping coverage in process roots

After the two scheduler roots are cloned, the kernel walks every external
supervisor mapping in the verified candidate plan through both roots, checking
physical backing, supervisor access, and all write/execute rights required by
the plan. It also checks both framebuffer endpoints for identity backing,
supervisor access, and write permission. All QEMU variants require the new
marker before user pages or tasks are installed. This proves the current
process roots can supply the planned bootstrap dependencies; it does not
remove their inherited firmware page-table ancestry or verify every
unplanned dynamic mapping.


### K.1p inherited page-table ancestry inventory

Before user mappings are added, both scheduler roots are traversed through
their reachable four-level page tables. A bounded deduplication inventory
counts unique table frames, notes which frames are shared by both roots, and
records UEFI descriptor types for each frame. Every table frame must remain
identity-readable through the current kernel root and have exactly one
covering descriptor; malformed entries or capacity exhaustion stop boot.
Descriptor types are provenance only, not evidence of Sorveth ownership.
This inventories the current ancestry and does not replace inherited tables
or prove that their mappings are safe to retain in a future independent root.


### K.1q process-root clone and shared-ancestry invariant

The ancestry audit first compares both process PML4 pages against the active
kernel PML4 after clearing USER on each present kernel entry and zeroing absent
entries. It then verifies that the two process roots are the only table frames
not shared across both trees, and that every shared table is reached at the
same paging levels in both roots. This runs before process-private user
subtrees are attached. It detects accidental divergence in the current clone
model; it does not make the inherited lower-level tables owned or independent.


### K.1r owned candidate ancestry and persistent QEMU mode

The expanded candidate is now walked as a complete page-table graph. Every
reachable table frame must be in the writable portion of Sorveth's PE image,
have loader/boot-services descriptor provenance, be reachable through the
restricted candidate table set, and contain no USER entries or huge-page
ancestry. A feature-gated QEMU image then activates this candidate as the
kernel root and updates the trusted active-root record before process roots
are created. The dedicated CI job runs the full normal, fault, ring-3, A/B
isolation, A/B transfer and monitor acceptance suites with that root active.

Accepted K.1d: host policy tests deny missing, USER and writable-executable
leaves, candidate construction checks every required plan mapping, and the
independent candidate remained active through all required QEMU suites. The
full acceptance evidence is recorded in the current implementation status.


### K.2a owner and reference records

Each claimed allocation span now carries a stable owner identity, generation,
and checked logical reference count. Handles reject a mismatched generation,
wrong owner, reference underflow, and count overflow. Dropping the final
reference retires the logical record but leaves the physical span permanently
reserved. This first K.2 step adds accounting only; it does not make a frame
reclaimable, zero-on-reuse, or safe to detach from an active mapping.


### K.2b mapping references and quarantine state

Allocation records now count mapped references independently from owner
references. A final owner release prevents new mappings, while existing
mapping references continue to keep the frame recognized as owned. The record
can enter quarantine only after both counts are zero. This checkpoint does
not yet modify a PTE, perform a TLB invalidation, zero memory, or return a
frame to a free range; those remain explicit gates before any physical reuse.
