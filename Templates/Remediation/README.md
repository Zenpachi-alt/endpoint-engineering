# Remediation template pair

Starting point for an Intune remediation script package: a detection script and
the remediation script that runs when detection reports an issue.

| File | Role |
| --- | --- |
| `Test-ExampleSetting.ps1` | Detection. Read-only. Decides whether the issue is present. |
| `Repair-ExampleSetting.ps1` | Remediation. Makes the change and verifies it. |
| `TimeGuard.ps1` | Optional block for packages with heavy checks. Not deployed; its region is pasted into both scripts. See [TimeGuard](#timeguard-limiting-heavy-work). |

## How to use

1. Copy the folder into the domain folder the unit belongs to, for example
   `Intune/Windows/Remediations/<Setting>/`.
2. Rename both scripts after the setting: `Test-<Noun>.ps1` and
   `Repair-<Noun>.ps1`. Keep the pair in one folder with its own `README.md`.
3. Replace the `#region Detect`, `#region Repair`, and `#region Verify` blocks.
   Everything outside those regions — logging, exit codes, error handling — is
   the part worth keeping.
4. If the check or the repair is heavy, add TimeGuard (below).
5. Update comment-based help, including `.NOTES`, before committing.

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

## TimeGuard: limiting heavy work

Intune's schedule says when a package is due, not how often it runs. Missed runs
catch up as soon as the device is online, policy is read again after every
restart and sign-in, and **Run remediation** ignores the schedule entirely. For
a registry check that doesn't matter. For SFC, DISM or a full disk scan it does.

TimeGuard makes the scripts keep a minimum interval themselves.
[`TimeGuard.ps1`](TimeGuard.ps1) holds the canonical `#region TimeGuard` block.
Endpoint scripts cannot depend on a module, so the region is pasted unchanged
into both scripts of a package; the version on the `#region` line records which
copy it came from.

### The rules

| | Detection | Remediation |
| --- | --- | --- |
| Guard | On. Skips while `LastDetection` is younger than the interval — unless `LastRemediation` is newer. | Optional; off by default (`TimeGuardIntervalDays = 0`). |
| When it skips | Exit `0`, and one stable line: `Skipped by TimeGuard: last full check <date> UTC.` | Exit `1` — the repair was not attempted — and `Skipped by TimeGuard: last repair <date> UTC.` |
| Records its timestamp | When the heavy work starts. | When the heavy work starts. |
| Takes the run back | When the heavy work refused to start (a restart is pending, say), by restoring the previous value. | Never. |

The work always runs when the guard is off, when there is no timestamp or it
cannot be parsed, when it is more than five minutes in the future (the clock was
wrong when it was written), or when TimeGuard's registry key cannot be read at
all. The guard limits how often the work runs; it must never be the reason it
does not.

Why each rule is there:

- **A newer remediation lets detection through.** Straight after a remediation,
  Intune runs detection again to confirm the fix. A guard that looked only at
  the age of the last check would skip that run, exit `0`, and Intune would
  report the device fixed whether it was or not.
- **Timestamps are written when the work starts.** A run the management
  extension stops part-way would otherwise never be recorded, and the heavy work
  would restart on every trigger.
- **A skip never writes.** If it did, the window would slide forward with every
  trigger and the work would never run again.
- **The remediation never takes its run back**, because its timestamp is what
  lets the next detection through. If a repair could not start because a restart
  is pending, the first detection after the restart is still a real check.
- **The skip line does not change between real runs.** Intune reports a device
  again whenever its output changes; a countdown would make every device report
  on every run.

### State

`HKLM\SOFTWARE\EndpointEngineering\TimeGuard\<TimeGuardName>`, always in the
64-bit registry view, so a 32-bit and a 64-bit host read the same key. The
values `LastDetection` and `LastRemediation` are UTC timestamps in round-trip
format (`2026-09-22T12:00:00.0000000Z`), readable in regedit.

To force a full run on a device, delete the key.

### Adding it to a package

1. Paste the region from `TimeGuard.ps1` into both scripts, unchanged.
2. Give both scripts a `TimeGuardName` parameter, with the same value in each,
   and a `TimeGuardIntervalDays` parameter.
3. In the detection, before the heavy work:

   ```powershell
   $nowUtc = [datetime]::UtcNow
   $previousCheck = Get-TimeGuardValue -Name $TimeGuardName -ValueName 'LastDetection'
   $lastRemediation = Get-TimeGuardValue -Name $TimeGuardName -ValueName 'LastRemediation'
   $guard = Get-TimeGuardDecision -Now $nowUtc -LastRun $previousCheck `
       -LastRemediation $lastRemediation -IntervalDays $TimeGuardIntervalDays

   if (-not $guard.Run) {
       # Write the stable skip line and exit 0.
   }

   Set-TimeGuardValue -Name $TimeGuardName -ValueName 'LastDetection' `
       -Value $nowUtc.ToString('o', [cultureinfo]::InvariantCulture)
   ```

4. In the remediation, the same with `LastRemediation`, without the
   `-LastRemediation` argument, and exit `1` on a skip.
5. Wrap the TimeGuard calls in `try`/`catch`, and let the work run if they fail.

[`SystemFileHealth`](../../Intune/Windows/Remediations/SystemFileHealth/) is
the reference implementation. `Get-TimeGuardDecision` reads no state, so its
rules can be checked without a device by dot-sourcing `TimeGuard.ps1`.

## Licensing and permissions

Remediations require Intune plus Windows Enterprise E3/E5, Windows Education
A3/A5, or Windows VDA per user. Creating and assigning packages needs the
Intune *Device configurations* permissions; the first use in a tenant needs an
Intune Administrator to confirm licensing.

## Reference

- [Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)
- [Use PowerShell scripts on Windows devices in Intune](https://learn.microsoft.com/intune/device-management/tools/run-powershell-scripts-windows)
