# Remediations

Intune remediation packages for Windows. Each folder is one package: a
detection script, the remediation script that runs when detection exits `1`,
and a README with the Intune settings the pair needs.

| Package | Finds | Fixes |
| --- | --- | --- |
| [`ComponentRepairSource/`](ComponentRepairSource/) | Where DISM would get repair files, and the devices where it has none. The pre-flight check for SystemFileHealth. | Nothing: detection only. Exit `1` lists the devices at risk. |
| [`SystemFileHealth/`](SystemFileHealth/) | Corrupt system files, and a component store Windows has flagged as corrupt. | SFC, then DISM only when SFC cannot finish, then SFC again. TimeGuard limits the heavy scans. |

Every package starts from [`Templates/Remediation/`](../../../Templates/Remediation/)
and keeps its exit code contract: a detection that cannot tell exits `2`, never
`1`, so a broken check can never start a repair. Packages with heavy checks use
the TimeGuard block described in the same place.
