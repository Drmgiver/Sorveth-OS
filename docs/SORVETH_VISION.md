# Sorveth OS — Product Constitution

**Version:** 1.0 (2026-10-22)  
**Status:** Authoritative product direction; requirements, not claims of implemented functionality.

## The question Sorveth answers

What operating system should we build if we are free to design the entire computing
experience anew, while accepting the security, reliability, performance, and
interoperability constraints of real hardware?

**Answer:** Sorveth is an operating system where a person owns the computer, their
software, and their data; work is organized around what they are doing rather than
where a file happened to be saved; every application is understandable and
composable; and an optional local-first intelligence can help turn intentions into
safe, inspectable actions. It must also excel at ordinary manual computing.

"Perfect" is a direction tested against explicit outcomes, not a claim that a
universal optimum exists. Sorveth favors controllability, reliability, predictable
behavior and accessibility over novelty for its own sake.

## Non-negotiable product laws

1. **Human sovereignty.** No account, payment, cloud dependency or AI model is
   needed to boot, configure, use or administer the core OS. Everything essential
   continues to work with the network disconnected and Sorveth Mind disabled.
2. **Native, independent foundation.** Sorveth Core is our own Rust, capability-based
   microkernel. The core computing experience does not depend on Linux, Windows,
   Wine, a web browser runtime or remote execution. Compatibility may be provided
   later as a compartmentalized convenience, never as the platform foundation.
3. **Least authority by construction.** Programs and AI receive narrowly scoped,
   revocable capabilities. Reading, modifying, executing, publishing and deleting
   are distinct authorities. A request cannot silently escalate its own privileges.
4. **Portable ownership.** Ordinary files remain first-class. Structured Sorveth
   resources, app source and user-created data have documented formats, export
   paths and meaningful APIs. The OS does not hold personal data hostage.
5. **Editable presentation.** System and native app resources—including labels,
   icons, layouts, themes and documentation—are accessible as non-executable,
   editable resources. Editing these does not grant execution or administrative
   authority. Program logic is versioned separately.
6. **AI as an optional guest, not a master.** Sorveth Mind runs outside the kernel,
   cannot bypass capability checks, may be fully disabled, and never receives
   permanent machine-wide permission. Local models are the default; cloud use
   requires a clear, specific choice.
7. **Visible consequences.** Mutating operations have intelligible scopes and
   effects. Destructive or high-impact actions require authorization, and the
   system records where a requested operation actually came from.
8. **Recoverable changes.** System updates and installs must be transactional with
   a supported rollback/recovery path. User data backup remains user-controllable;
   no hidden copies or mandatory proprietary backup service.
9. **Open development.** The platform is open source and its native standards are
   royalty-free and documented. Security claims require published tests and threat
   modeling, not branding.
10. **Usability without magic.** Keyboard, mouse, touch where supported, files,
    windows, accessibility and discoverable settings work without prompts or
    conversational interfaces. Advanced users can inspect and automate the same
    underlying actions exposed to beginners.

## The distinctive desktop: Sorveth Space

The primary organizational primitive is a **Space**: a person-defined context for
work (a project, a creative task, an activity or simply the regular desktop).
A Space groups windows, related resources, running applications and a recoverable
activity trail. Spaces are optional: the familiar file explorer, application
launcher, overlapping windows and desktop remain immediately available.

Sorveth Space is a native compositor/window-server environment with native input and
accessibility services. Rendering, multimedia, accessibility, keyboard layouts,
display configuration and window placement are system services, not responsibilities
forced onto each application. No UI must depend on AI-generated code to appear.

## The data environment: Sorveth Vault

Vault is not a compulsory proprietary filesystem. It is a **portable resource
layer** above ordinary filesystem objects, indexed metadata, typed documents,
app settings and links between resources. Every resource must be addressable and
exportable without running Sorveth Mind. Indexes are regenerable, and dropping them
must not destroy user content. Search has a deterministic, non-AI path.

## The application model: Native Sorveth Works

Native applications declare, in a versioned manifest:

- their identity, provenance, supported ABI and requested capabilities;
- typed actions with documented inputs, outputs, side effects and reversibility;
- portable non-executable presentation assets and translations;
- source, user data export and import paths;
- failure behavior and permissions needed to automate an action.

Human UI interaction and automation invoke the **same underlying actions**. The
platform supplies a permission broker, structured audit receipts, normal app
sandboxing and unified dialogs. Apps cannot assert that a generated action is
safe merely because a model wrote it.

Foundational Works: **Atlas** (resources, files, search, inspector), **Forge**
(native app editing and building), **Frame** (visual/media creation), and
**Script** (automation and repeatable workflows). The exact app names are not a
technical security dependency.

## The intelligence layer: Sorveth Mind

Mind comprises a pluggable intent interpreter, planner, capability broker,
executor, test/verifier and inspectable user-owned memory. It is an application
and service, never an alternate privileged kernel. Planning and execution remain
separate; model text is untrusted input. Actions must resolve to a manifest-defined
capability, and high-impact actions must be confirmed using deterministic policy,
not the model's own interpretation of its permissions.

A Mind-created native app produces **source code, manifests and user-editable
resources** in a project owned by the user. It must be buildable without relying
on the original model. Generated code begins with no ambient authority; it is
built, tested and exercised in a sandbox before being eligible for permissions.

AI mode states: **Off** (no model loaded or inference), **Local** (approved local
model), and **Connected** (explicitly configured remote provider and scoped
network grants). Switching Off cannot disable files, windows, applications,
accessibility or administration.

## Engineering decisions fixed for the initial platform

- Rust `no_std` core with separate user-space servers and drivers.
- x86-64 UEFI + QEMU/OVMF as the first test target; ARM64 after kernel/driver
  interfaces stop depending on x86-specific assumptions.
- Capability handles, mediated IPC, isolated address spaces, timer/exception
  handling and frame ownership **before** running any untrusted user process.
- Initial filesystem support and a local persistent store **before** AI features.
- A native compositor, resource explorer and app execution path **before** Mind.
- No network account creation during first boot. Telemetry opt-in only.
- Explicit updates with cryptographic integrity, staging and rollback before
  calling the system safe for ordinary installations.
- Hardware support expands only behind tested driver and regression gates.

## Product acceptance tests (future release gates)

Sorveth is not fit for end users until each is demonstrated on actual supported
hardware (not inferred from a screenshot or a successful VM boot):

1. A fresh install boots, logs in, opens apps, saves data and restarts offline.
2. A user can disable/never install Mind and still use every essential OS service.
3. An untrusted process cannot read another process's address space or obtain
   an undeclared device/data capability; revocation takes effect.
4. A user can edit visible resources, package app source/data, export Vault data
   and re-import it without cloud credentials.
5. Failed app and OS updates preserve user data and allow documented recovery.
6. Keyboard-only and assistive-technology navigation cover core workflows.
7. CPU, memory, boot latency, disk integrity, crash recovery and responsiveness
   have published baselines on defined hardware profiles.
8. AI-created applications are reproducibly buildable and cannot assume runtime
   model access or evade sandboxing.

## Authority and scope

The AI development lead selects architecture, product behavior, implementation,
test coverage and priorities. The human requester is **not** assigned debugging,
manual emulator operation or specification-writing. Deliverables are source,
reproducible test evidence and plain-language progress reports, with remaining
limitations stated accurately. Development runs during active work sessions or
through explicitly configured infrastructure; it does not continue autonomously
between conversations without a scheduled/external mechanism.
