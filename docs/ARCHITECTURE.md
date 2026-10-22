# Sorveth OS architecture (living specification)

## Product contract

Sorveth OS is an original native computing environment. Software and data belong to
users. AI is a replaceable service, never a mandatory intermediary between a person
and their operating system. Native applications should declare data/resources,
commands, permissions, UI actions and user-editable presentation resources using
portable documented formats. Sorveth Space is an original desktop, not a copy of any
existing DE, but everyday mouse/keyboard, windows, drag-and-drop, files and shortcuts
remain expected.

## Layer model

```text
Human / keyboard / pointing / accessibility
         |
Sorveth Space <----> native apps: Atlas, Forge, Frame, Script, and third-party
         |                  |
         +------ native action + resource contracts ------+
         |                                                |
    Sorveth Vault <--> policy broker <--> Sorveth Mind (optional)
         |             |               planner / builder / verifier
         +---------- services ----------------------------+
              graphics, input, storage, USB, network, sound
                           |
               user-space capability IPC
                           |
       SORVETH CORE: IPC, tasks, scheduling, memory, capabilities
                           |
     x86-64 UEFI boot -> native kernel -> hardware (ARM64 later)
```

Core remains minimal: address spaces, threads, IPC, scheduling, interrupts, frame
ownership and capability enforcement. Drivers, graphics, storage and network stacks
belong outside the kernel when the necessary primitive isolation exists. Sorveth Mind
runs as a user-space agent subject to exactly the same capability rules as everyone
else, with an additional broker for sensitive operations.

## Sorveth Core

Implementation language: Rust. Bootstrap: x86-64/UEFI. Future architecture: ARM64.
Capability objects include tasks, endpoints, memory and resources. User processes
will receive opaque handles to granted capabilities, not ambient kernel authority.
Derived handles may only reduce rights. Revocation must invalidate descendants.
A process requesting a capability beyond its grant gets an explicit denial.

**Implemented today:** an early boot handoff and an in-kernel fixed-size capability
*data structure*. It is not yet a security boundary because there are no isolated
user processes or system calls. Before running any untrusted code, establish rings,
page tables, address-space switching, syscall entry, interrupt handling, per-process
capability tables and IPC mediation.

## Sorveth Vault

A resource is a documented, typed value with user-controlled data and separate
non-executable presentation assets. Planned interfaces: enumeration, structured
editing, metadata, import/export and capability-scoped references. Ordinary files
continue to exist; resources are an additional first-class organizational model,
not a vendor lock-in. Editable non-executable UI text, icons, layouts, menu labels,
and themes must not be buried in opaque application binaries. The OS's own user-
facing resources eventually follow this contract too.

## Sorveth Space

Spaces are project/activity containers, each exposing related data, running apps,
windows, tasks and a history of permitted actions. Desktop remains usable by
traditional direct manipulation; an AI-generated interface is never a requirement.
Windowing, compositor, HiDPI, multiple displays and accessibility will be
implemented on top of native graphics/input services—not firmware protocols.

## Native app contract

Planned portable manifest:

- identity, version, provenance, supported ABI versions;
- declared actions with typed input/output schemas;
- requested data, hardware and service capabilities;
- editable user-facing resource bundle, separated from executable code;
- exportable source and user-controlled app data;
- optional signatures to establish provenance (not automatic trust).

Atlas is envisioned as a native explorer of files and structured resources; Forge
as native development/build tools; Frame as a visual/media app; Script as native
automation. These descriptions are provisional until their contracts are tested.

## Sorveth Mind

Optional, local-first interchangeable model interface with cloud providers allowed
only by explicit user selection. Modules: interpreter, planner, broker, builder,
executor, verifier, and user-owned memory. Mind works via declarative native app
actions and capabilities, not global UI scraping or unrestricted shell privileges.
Generated source belongs to its user, compiles into ordinary native apps, is tested
inside an isolated sandbox, and cannot touch sensitive real data before approval.
With Mind absent or disabled, the desktop and apps remain fully functional.

## Hardware roadmap

First emulator baseline: QEMU x86-64 with OVMF, framebuffer and serial. After memory,
interrupts, IPC and task isolation: storage (NVMe/AHCI), USB/HID and input, networking,
GPU/display, audio, Wi-Fi/Bluetooth, webcams/controllers, power management,
HiDPI/multi-monitor, and ARM64. Drivers need actual test hardware later. Do not
promise "runs on everything" on the strength of an emulator demo.
