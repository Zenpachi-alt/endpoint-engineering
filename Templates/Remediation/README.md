# Remediation template pair

Starting point for an Intune remediation script package: a detection script and
the remediation script that runs when detection reports an issue.

| File | Role |
| --- | --- |
| `Test-ExampleSetting.ps1` | Detection. Read-only. Decides whether the issue is present. |
| `Repair-ExampleSetting.ps1` | Remediation. Makes the change and verifies it. |

## How to use

1. Copy the folder into the domain folder the unit belongs to, for example
   `Intune/Windows/Remediations/<Setting>/`.
2. Rename both scripts after the setting: `Test-<Noun>.ps1` and
   `Repair-<Noun>.ps1`. Keep the pair in one folder with its own `README.md`.
3. Replace the `#region Detect`, `#region Repair`, and `#region Verify` blocks.
   Everything outside those regions — logging, exit codes, error handling — is
   the part worth keeping.
4. Update comment-based help, including `.NOTES`, before committing.

## Exit codes

The management extension only distinguishes `1` from everything else:

| Script | Code | Meaning |
| --- | --- | --- |
| Detection | `0` | Issue not found. Remediation does not run. |
| Detection | `1` | Issue found. Remediation runs. |
| Detection | `2` | Detection failed. Remediation does **not** run; the failure is visible in the script output. |
| Remediation | `0` | Succeeded. |
| Remediation | `1` | Failed. Intune retries on the configured schedule. |

Exit code `2` in the detection script exists so a broken detection cannot be
mistaken for a detected issue. An unhandled terminating error in PowerShell
exits with `1`, which would silently trigger the remediation on every device the
package is assigned to — so the template catches everything and exits
deliberately.

## Constraints these templates are written around

- **No modules.** Only what ships with Windows. The scripts run before, and
  independently of, anything installed on the device.
- **Windows PowerShell 5.1.** PowerShell 7 is not present on a stock device.
- **SYSTEM context**, unless the setting is genuinely per-user. Set *Run this
  script using the logged-on credentials* to **No**.
- **32-bit host by default.** *Run script in 64-bit PowerShell* defaults to
  **No**, so registry and file system calls are redirected to `WOW6432Node` and
  `SysWOW64` on 64-bit devices. Both scripts log which host they ran in, and
  both must be configured the same way.
- **2048 characters of output.** Intune keeps only the tail of STDOUT, so each
  script writes exactly one short result line there. Detail goes to the log.
- **UTF-8 encoding**, and UTF-8 *without* BOM when *Enforce script signature
  check* is enabled. Keeping the files ASCII-only avoids the question entirely.
- **Logging to disk.** `%ProgramData%\EndpointEngineering\Logs\<script>.log`,
  rotated to a single `.old` copy. A logging failure is reported but never fails
  the run.

## Licensing and permissions

Remediations require Intune plus Windows Enterprise E3/E5, Windows Education
A3/A5, or Windows VDA per user. Creating and assigning packages needs the
Intune *Device configurations* permissions; the first use in a tenant needs an
Intune Administrator to confirm licensing.

## Reference

- [Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)
- [Use PowerShell scripts on Windows devices in Intune](https://learn.microsoft.com/intune/device-management/tools/run-powershell-scripts-windows)
