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

DISM `RestoreHealth` fetches replacement files. It tries the alternate source
path set by the policy *Specify settings for optional component installation
and component repair* (Computer Configuration > Administrative Templates >
System) first, then Windows Update where that is allowed. The policy writes to
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing`:

| Value | Builds | Meaning |
| --- | --- | --- |
| `LocalSourcePath` | All | Paths tried first, separated by `;`. A folder, or a WIM given as `wim:\\SERVER-001\share\file.wim:1`, patched to the same level as the device. |
| `RepairContentServerSource` = `2` | Before 26100 (Windows 11 24H2) | Download repair content from Windows Update directly, even where WSUS is configured; normal servicing still goes through WSUS. From 24H2 the policy no longer has this option. |

A device that takes its updates from WSUS with neither of these is the one that
fails with `0x800F081F`.
[`ComponentRepairSource`](../ComponentRepairSource/) reports this for every
device, before the DISM branch is ever reached.

What Microsoft documents only in part:

- From Windows 11 22H2, WSUS delivers Features on Demand and language packs
  itself, through on-premises UUP, which is why 24H2 dropped the Windows Update
  options from the policy. Whether WSUS also delivers *corruption repair*
  content is not documented. If the fleet has WSUS-managed devices on 24H2 or
  later, include some in the pilot.
- On Windows 10 2004 through Windows 11 21H2, pointing feature or quality
  updates at WSUS with *Specify source service for specific classes of Windows
  Updates* stops Features on Demand and language packs downloading, even when
  this policy says Windows Update. Whether repair content is affected the same
  way is not documented.

## Rolling it out

SFC is the well-travelled path. The DISM branch runs only where SFC could not
finish, so it sees little traffic and deserves a pilot.

1. **Check the repair source first.** Assign
   [`ComponentRepairSource`](../ComponentRepairSource/) to the devices you plan
   to pilot. Its `WsusOnly` devices, listed under *With issues*, are the ones
   where DISM is likely to fail.
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
