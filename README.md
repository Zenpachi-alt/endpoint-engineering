# Endpoint Engineering

Scripts, payloads, and reference artifacts for endpoint management engineering —
Microsoft Intune, Windows Autopilot, and Microsoft Graph.

Everything here is written to be readable and reusable on its own: each unit of
work carries its own README, its prerequisites, and the permissions it needs.
The repo grows one tested artifact at a time rather than in bulk.

## Repository structure

Content is organised by domain and platform, not by file type. A script lives
with the payload, detection logic, and documentation that belong to it.

| Path | Contains |
| --- | --- |
| `Templates/` | Starting points for new scripts and artifacts. |
| `Intune/Windows/` | Remediations, platform scripts, configuration profiles, applications, compliance policies. |
| `Intune/Windows/Autopilot/` | Hardware hash handling, deployment profiles, Enrollment Status Page configuration. |
| `Intune/macOS/` | macOS equivalents. |
| `Graph/` | Microsoft Graph tooling not tied to a single Intune feature — authentication patterns, tenant reporting, bulk operations. |

Folders are created by the first file that belongs in them, so not every path
above exists yet.

## Scripts by area

| Area | Script | Purpose |
| --- | --- | --- |
| — | _Nothing published yet._ | — |

## Conventions

Repository-wide conventions — naming, error handling, required documentation,
and the rule against committing real tenant identifiers — are in
[CLAUDE.md](CLAUDE.md).

## Disclaimer

These scripts are provided as-is, with no warranty. Test in a lab or pilot ring
before running anything against production devices.
