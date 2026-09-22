# SystemFileHealth

Remediation package that finds and repairs corrupt Windows system files. The
heavy scan runs at most once per TimeGuard interval, however often Intune starts
the package.

| File | Role |
| --- | --- |
| `Test-SystemFileHealth.ps1` | Detection: `sfc /verifyonly`, plus DISM `CheckHealth`, which reads in seconds whether Windows has flagged the component store. |
| `Repair-SystemFileHealth.ps1` | Remediation: SFC; DISM only when SFC cannot finish; then SFC again. |

## How it works

**Detection** reports an issue (exit `1`) when SFC finds integrity violations or
the component store is flagged.

**Remediation:**

1. `sfc /scannow`. If SFC repairs everything and the store is not flagged, it
   stops here. DISM is the slowest step, and most devices never need it.
2. If SFC could not repair some files, or the store is flagged: DISM
   `RestoreHealth`. DISM repairs the component store — the source SFC copies
   good files *from* — not the system files themselves.
3. If SFC was the reason DISM ran: `sfc /scannow` again, now with a healthy
   source.

Microsoft's manual procedure runs DISM first. Running SFC first reaches the same
result and skips DISM wherever SFC alone is enough.

## Intune settings

| Setting | Value |
| --- | --- |
| Detection script file | `Test-SystemFileHealth.ps1` |
| Remediation script file | `Repair-SystemFileHealth.ps1` |
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No, unless the scripts are signed |
| Run script in 64-bit PowerShell | **Yes.** DISM cannot service a running 64-bit Windows from 32-bit PowerShell; both scripts stop with a message saying so. |
| Schedule | Recurring. TimeGuard, not the schedule, sets the minimum gap between scans. |

Intune passes no parameters, so a setting such as the interval is changed in the
script's `param` block before upload.

## TimeGuard

- Detection skips the scan while the last full check is less than **30 days**
  old (`TimeGuardIntervalDays`), unless a remediation has started since.
- The remediation's own guard is **off** (`TimeGuardIntervalDays = 0`).
- The schedule is how often Intune asks; the guard is the minimum gap between
  scans. With a schedule shorter than the guard, a device is scanned about once
  per interval and catches up soon after being offline. With a schedule longer
  than the guard, the guard only catches the runs Intune makes outside the
  schedule.
- To force a full check on a device, delete
  `HKLM\SOFTWARE\EndpointEngineering\TimeGuard\SystemFileHealth`.

The rules, and the reason for each, are in
[`Templates/Remediation/README.md`](../../../../Templates/Remediation/README.md#timeguard-limiting-heavy-work).

## The repair source DISM needs

DISM `RestoreHealth` fetches replacement files, and on a managed device where
they come from is decided by the policy *Specify settings for optional component
installation and component repair* (Computer Configuration > Administrative
Templates > System). It writes to
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing`:

| Value | Meaning |
| --- | --- |
| `RepairContentServerSource` = `2` | Contact Windows Update directly for repair content, even where WSUS is configured for servicing. Normal servicing still goes through WSUS. |
| `LocalSourcePath` | Paths searched first, separated by `;`. A folder, or a WIM given as `wim:\\SERVER-001\share\file.wim:1`, patched to the same level as the device. |

A device pointed at WSUS with neither value set is the one that fails with
`0x800F081F`. Reading that key across the fleet predicts those failures before
the DISM branch is ever reached, which is worth doing first: the branch only
runs for the devices SFC alone could not fix.

Two wrinkles:

- On Windows 10 2004 through Windows 11 21H2, setting *Specify source service
  for specific classes of Windows Updates* to WSUS for feature or quality
  updates stops the repair content downloading even when this policy says
  Windows Update.
- Windows 11 22H2 and later get Features on Demand and language packs from WSUS
  itself, through on-premises UUP. Whether corruption repair content follows the
  same path is worth testing rather than assuming.

## Rolling it out

SFC is the well-travelled path. The DISM branch runs only where SFC could not
finish, so it sees little traffic and deserves a pilot.

1. **Check the repair source first**, across the devices you plan to assign, as
   described above. Devices pointed at WSUS with neither `RepairContentServerSource`
   nor `LocalSourcePath` are the ones where DISM will fail. A detection-only
   script package is a convenient way to collect that: Intune keeps each
   device's output line and exports the lot to CSV.
2. **Assign to a pilot group**, with the schedule you intend to use.
3. **Watch the report** for `Remediation failed: DISM` (no repair source),
   `Not repaired: ... waiting for a restart` (expected on some devices; the
   first check after the restart verifies them), and `Detection failed: SFC
   result not recognised` (a device installed in another language).
4. **Force a re-check** on a device by deleting its TimeGuard key, rather than
   waiting out the interval.
5. **Broaden the assignment** once the DISM branch has run on real devices and
   the report says what you expect.

## What the report shows

Each script writes one line, which Intune shows in the device status report.

| Script | Exit | Line starts with | Meaning |
| --- | --- | --- | --- |
| Detection | `0` | `Healthy:` | No integrity violations; store not flagged. |
| Detection | `0` | `Skipped by TimeGuard:` | Scanned within the interval, so not scanned this time. |
| Detection | `1` | `Issue found:` | Says what was found. The remediation runs. |
| Detection | `2` | `Not checked:` | A repair is waiting for a restart. The first detection after it is a real check. |
| Detection | `2` | `Detection failed:` | Wrong host, no administrator rights, SFC failed, or an SFC message the script does not recognise. |
| Remediation | `0` | `Remediated:` | Says what fixed it, and whether DISM was needed. |
| Remediation | `1` | `Not repaired:` | A repair is waiting for a restart. |
| Remediation | `1` | `Remediation failed:` | Says which step failed and which log to read. |
| Remediation | `1` | `Skipped by TimeGuard:` | Only when the optional remediation guard is on. |

## Logs

| Log | Holds |
| --- | --- |
| `%ProgramData%\EndpointEngineering\Logs\Test-SystemFileHealth.log` | Every detection, including TimeGuard's reason and the end of SFC's output. |
| `%ProgramData%\EndpointEngineering\Logs\Repair-SystemFileHealth.log` | Every remediation step. |
| `%windir%\Logs\CBS\CBS.log` | SFC's detail. Search for `[SR]`; `Cannot repair member file` names the files SFC could not fix. |
| `%windir%\Logs\DISM\dism.log` | DISM's detail. |

## Limitations

- **English only.** SFC's result is read from its closing message, which under
  SYSTEM is in the language Windows was installed in. On any other language no
  message matches, and the scripts report `result not recognised` rather than
  guess. Reading the `[SR]` entries in `CBS.log`, which are not translated,
  would remove the limit.
- **DISM needs a repair source:** Windows Update, or the source set by the
  policy *Specify settings for optional component installation and component
  repair*. Without either, it fails with `0x800F081F`.
- **No restarts.** A repair that needs one is reported, and the first detection
  after the restart verifies it.
- **Run time.** SFC, then DISM, then SFC again can take a long time. Microsoft
  documents a 30-minute limit for platform scripts but none for remediations. If
  the management extension stops the remediation part-way, TimeGuard has already
  recorded the attempt, so it is not restarted on every trigger.
- **Detection writes one thing:** its own TimeGuard timestamp.

## Licensing and permissions

Remediations require Intune plus Windows Enterprise E3/E5, Windows Education
A3/A5, or Windows VDA per user. Creating and assigning the package needs the
Intune *Device configurations* permissions. On the device, both scripts run as
SYSTEM, which has the administrator rights SFC and DISM require.

## Reference

- [Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)
- [sfc command](https://learn.microsoft.com/windows-server/administration/windows-commands/sfc)
- [Analyze the log file entries that SFC.exe generates](https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/analyze-sfc-program-log-file-entries)
- [Repair a Windows image](https://learn.microsoft.com/windows-hardware/manufacture/desktop/repair-a-windows-image)
- [Repair-WindowsImage](https://learn.microsoft.com/powershell/module/dism/repair-windowsimage)
