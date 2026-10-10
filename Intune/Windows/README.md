# Windows

Scripts for Windows endpoints: remediation packages Intune delivers, and
technician tools that run on the device itself.

| Folder | Contains |
| --- | --- |
| `Autopilot/` | Hardware hash collection for Windows Autopilot registration. |
| `PolicySource/` | Where each policy setting on the device comes from - Group Policy, Intune, both or neither - and which one is in effect. |
| `Remediations/` | Remediation packages: one detection and remediation script pair per folder. |

Folders are created by the first file that belongs in them.

## Two kinds of thing live here

**Delivered by Intune** — remediations and platform scripts, run by the
management extension as SYSTEM, with no user present and no console to write to.
These follow the exit code contract in `Templates/Remediation/README.md`, write
one short line to STDOUT, and put everything else in the log.

**Run by a person on the device** — technician tools used during OOBE or at a
desk, launched from removable media or a support share. These have a console, so
they may prompt, report progress, and use an exit code that means what the
script says it means rather than what Intune expects.

The difference matters because the exit code contract is Intune's, not ours.
Reusing `1` for "issue found" in a tool nobody runs through the management
extension makes a failure look like a finding. Each script's `.NOTES` states
which kind it is.
