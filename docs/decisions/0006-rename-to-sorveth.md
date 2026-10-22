# ADR 0006 — Adopt the Sorveth OS identity

**Status:** Accepted
**Date:** 2026-10-22

## Context

The project's original working name, Axiom OS, was found to have multiple
preexisting uses in operating-system projects. A distinct name was necessary
before publishing the repository as an independent public project.

## Decision

The project is named **Sorveth OS** (pronounced SOR-veth). The product family is
Sorveth Core, Sorveth Space, Sorveth Vault, Sorveth Mind, Sorveth Forge and the
native applications. Software packages, source paths, boot banners, automated
checks and new documentation use the Sorveth name and `sorveth-` prefix.

The name was checked with targeted web queries and GitHub repository search on
2026-10-22; those searches did not reveal an existing Sorveth OS. This is not a
comprehensive global name or trademark clearance.

The original project's Git history is retained intact. Previous commits may
use the former working name; they are historical records rather than active
product nomenclature. This project remains entirely separate from OSTen.

## Consequences

- The proposed repository name is `Drmgiver/Sorveth-OS`.
- The old `Axiom-OS` repository name must not be used for publication.
- Documentation links, CI commands and import paths must all use Sorveth.
- This is a brand rename only; architecture and user-ownership principles do
  not change.
