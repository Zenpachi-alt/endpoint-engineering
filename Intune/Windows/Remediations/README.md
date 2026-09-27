# Remediations

Intune remediation packages for Windows. Each folder is one package: a
detection script, the remediation script that runs when detection exits `1`,
and a README with the Intune settings the pair needs.

| Package | Finds | Fixes |
| --- | --- | --- |
| [`BitLockerKeyEscrow/`](BitLockerKeyEscrow/) | BitLocker recovery passwords on OS and fixed data volumes with no evidence of backup to Entra ID. | Backs up each one, and counts it only when Windows' event 845 confirms it. Never adds or rotates a protector. |
| [`ComponentRepairSource/`](ComponentRepairSource/) | Where DISM would get repair files, and the devices where it has none. The pre-flight check for SystemFileHealth. | Nothing: detection only. Exit `1` lists the devices at risk. |
| [`SystemFileHealth/`](SystemFileHealth/) | Corrupt system files, and a component store Windows has flagged as corrupt. | SFC, then DISM only when SFC cannot finish, then SFC again. TimeGuard limits the heavy scans. |

Every package starts from [`Templates/Remediation/`](../../../Templates/Remediation/)
and keeps its exit code contract: a detection that cannot tell exits `2`, never
`1`, so a broken check can never start a repair. Packages with heavy checks use
the TimeGuard block described in the same place.

The contract is tested, not only promised. Every detection script here is
checked for the structure that keeps it, and each package's `*.Tests.ps1` runs
its scripts as the Intune management extension does, with stand-ins for the
parts that touch the device, in every situation they handle.
[Tests](../../../Templates/Remediation/README.md#tests) describes the harness.
