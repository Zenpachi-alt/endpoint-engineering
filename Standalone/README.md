# Standalone

Scripts that run by themselves on a workstation or device and touch neither
Intune nor a tenant: text and log handling, installer inspection, diagnostics,
one-off utilities. Anything delivered through Intune belongs in `Intune/`, and
anything that talks to Graph belongs in `Graph/`.

| Script | Purpose |
| --- | --- |
| `Invoke-TextScrub.ps1` | Replaces identifying values in text with consistent placeholders, and puts them back. |
| `Invoke-TextScrub.Tests.ps1` | Pester tests for it. CI runs them on every push. |
| `Get-InstallerInfo.ps1` | Reads what an Intune Win32 app needs from an MSI, an EXE installer or an `.intunewin` package. |
| `Get-InstallerInfo.Tests.ps1` | Pester tests for it, under Windows PowerShell 5.1 and PowerShell 7. CI runs them on every push. |

## Invoke-TextScrub.ps1

Shares only what the reader needs. Replaces identifiers in a log, an export, a
script or the clipboard with consistent placeholders, so the text still reads
coherently: device 001 failed after user 003 signed in. `-Restore` puts the
real values back into whatever comes back.

Useful wherever data is shared, inside the organisation or out: tickets and
wikis, vendor and Microsoft support cases, approved AI tools, documentation and
training material. Being allowed to share something is not the same as needing
to share all of it; the recipient loses no diagnostic value, only identity.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 7.0 or later. A workstation utility, never deployed through Intune, so not held to 5.1 |
| Modules | None |
| Graph scopes | None |
| Admin consent | Not applicable |
| Licensing | None |
| Role | None. Runs as the signed-in user |
| Platform | Written for Windows. On Linux, `-Clipboard` needs `xclip` |

### Examples

```powershell
# Once: a template config to fill in with your domains, host name patterns and terms
.\Invoke-TextScrub.ps1 -NewConfig

# See what would be replaced, and with what, writing nothing
.\Invoke-TextScrub.ps1 -Path .\IntuneManagementExtension.log -ReportOnly |
    Format-Table Category, Original, Placeholder, Occurrences

# Scrub files; each becomes <name>.scrubbed<ext>
.\Invoke-TextScrub.ps1 -Path .\export.csv, .\error.txt -OutputDirectory C:\Temp\Out

# Scrub the clipboard in place, ready to paste
.\Invoke-TextScrub.ps1 -Clipboard

# Put the real values back into an answer
.\Invoke-TextScrub.ps1 -Path .\Answer.ps1 -Restore
```

### What it replaces

| Category | Example placeholder | Restorable |
| --- | --- | --- |
| Private keys, JWTs, bearer tokens, `password=` style values | `[REDACTED-JWT]`, `[REDACTED]` | No, never stored |
| E-mail addresses and UPNs | `user001@example.com` | Yes |
| GUIDs | `00000000-0000-0000-0000-000000000001` | Yes |
| SIDs, MAC addresses, SHA-1 thumbprints | `S-1-5-21-0-0-0-1001`, `00-00-5E-00-53-01`, `THUMBPRINT-001` | Yes |
| Tenant names in `*.onmicrosoft.com`, `*.sharepoint.com` | `tenant001` | Yes |
| Configured domains, and every host under them | `corp001.example`, `host001.corp001.example` | Yes |
| UNC server names, user profile folders | `SERVER-001`, `C:\Users\USER-001` | Yes |
| Host name patterns, literal terms, extra patterns from config | `DEVICE-001`, `TERM-001`, `SERIAL-001` | Yes |
| ServiceNow-style record numbers | `INC0000001` | Yes |
| IPv4 addresses | `192.0.2.1` | Yes |

Placeholders come from values reserved for documentation (RFC 2606 domains,
RFC 5737 addresses, the RFC 7042 MAC block), so they cannot collide with
anything real. Well-known Microsoft application IDs, such as Microsoft Graph's,
are left readable. The machine name, the signed-in user name and the logon
domain are added to the literal terms unless `-SkipLocalIdentity` is used.

Scrubbing is idempotent: scrubbing scrubbed text changes nothing, and a later
step never rewrites an earlier step's placeholder.

### config.json and map.json stay on the device

Both live in `-DataDirectory`, by default `%LOCALAPPDATA%\TextScrub`.

| File | Holds |
| --- | --- |
| `config.json` | Your domains, host name patterns and literal terms: real values once filled in |
| `map.json` | Every real value and its placeholder. `-Restore` reads it; without it, earlier output cannot be restored |
| `scrub.log` | File names and counts only. Never a value |

The script warns when either file sits inside a git working tree. The map is
saved before any output is written, and replaced atomically, so a failed run
cannot leave behind output that has no map to restore it from.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | The run failed. Nothing is written after the failure |
| `2` | Output was written, but a value already in the map is still in it |

Exit code `2` usually means a value inside a longer token, such as a configured
term `Acme` inside `Acmecorp`, which the word boundaries skip. The warning gives
the line and the placeholder, never the value, because console output is
exactly what gets pasted. The check is a deliberate substring search, so a
short or common term, `user` for example, also matches inside ordinary words
such as `Users`. Keep literal terms distinctive.

### Limits

Regular expressions cannot recognise a person's name in free text, a street
address, or anything the config does not describe. **Read the output before it
leaves the device.**

- IPv6 addresses are not recognised.
- Four-part version numbers match the IPv4 pattern. Use `-SkipIPv4` for text
  full of them.
- MAC and IPv4 placeholders come from documentation ranges holding 256 and 762
  values. A map that needs more stops with an error rather than reusing a
  placeholder; use a separate `-DataDirectory`.
- An 8 MB log with 100,000 identifiers takes under 20 seconds to scrub and a
  few seconds to restore.

### Tests

```powershell
Install-Module Pester -Scope CurrentUser -SkipPublisherCheck   # once; Pester 5.5 or later
Invoke-Pester -Path .\Standalone -Output Detailed
```

The tests build every identifier-shaped value at run time, random GUIDs and a
JWT assembled from parts, so the test file passes
`Tools/Test-SensitiveContent.ps1` like any other file.

## Get-InstallerInfo.ps1

Reads what an Intune Win32 app needs from an installer: product and upgrade
codes, the install context, silent switches, and suggested install, uninstall
and detection settings. Takes an MSI, an EXE installer, or a finished
`.intunewin` package. Read-only: nothing is installed, extracted or run.

When an `.intunewin` is built from an MSI, the Intune portal fills in the
product code by itself. The script is for everything else: checking an
installer before packaging it, MSIs started by a wrapper script, EXE
installers, and the details the portal does not show, such as a per-user
package, cabinets that must travel with the MSI, or whether a new version
removes the old one by itself.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or later. Packaging is often done on a clean virtual machine that has only Windows PowerShell, and nothing here needs 7 |
| Modules | None |
| Graph scopes | None |
| Admin consent | Not applicable |
| Licensing | None |
| Role | None. Runs as the signed-in user |
| Platform | Windows. MSIs are read through `msi.dll`, signatures through Authenticode |
| Language mode | FullLanguage. The script calls .NET directly and compiles a small `msi.dll` wrapper with `Add-Type`, which Constrained Language Mode blocks |

### Examples

```powershell
# Everything the MSI holds that matters to a deployment
.\Get-InstallerInfo.ps1 -Path .\ContosoApp.msi

# Only the suggested Intune settings
.\Get-InstallerInfo.ps1 -Path .\ContosoApp.msi | Select-Object -Property Intune*

# Public properties that can be set on the msiexec command line
(.\Get-InstallerInfo.ps1 -Path .\ContosoApp.msi).PublicProperties

# One line per installer in a folder
Get-ChildItem -Path .\Installers -File | .\Get-InstallerInfo.ps1 |
    Format-Table -Property FileType, ProductName, ProductVersion, InstallerFramework

# What an existing package was built from
.\Get-InstallerInfo.ps1 -Path \SERVER-001\Packages\ContosoApp.intunewin
```

```text
IntuneInstallCommand   : msiexec /i "ContosoApp.msi" /qn /norestart
IntuneUninstallCommand : msiexec /x "{00000000-0000-0000-0000-000000000001}" /qn /norestart
IntuneInstallBehavior  : System
IntuneDetection        : MSI product code {00000000-0000-0000-0000-000000000001}, product
                         version greater than or equal to 24.1.3115
```

The `Intune*` values are starting points to test on a virtual machine, not
settings to paste unread.

### What it reads

The file type is recognised from the file's content, not its extension.

| File | Reads | Main properties |
| --- | --- | --- |
| MSI | The Property table, the summary information, and the Upgrade, Media, File, LaunchCondition, Control and InstallExecuteSequence tables. Opened read-only | `ProductCode`, `UpgradeCode`, `PackageCode`, `ProductVersion`, `Architecture`, `InstallContext`, `RemovesOlderVersions`, `PublicProperties`, `ExternalCabinets`, `LooseFileCount`, `LaunchConditions` |
| EXE | The version resource, the embedded manifest, the file headers, and the first 64 KB after the executable image. Never run | `ProductVersion`, `FileVersion`, `ExecutableArchitecture`, `RequestedExecutionLevel`, `InstallerFramework`, `FrameworkEvidence` |
| `.intunewin` | `Metadata/Detection.xml`, the unencrypted part of the package | `SetupFile`, `ProductCode`, `UpgradeCode`, `MsiExecutionContext`, `ContentSizeBytes`, `ToolVersion` |

Every result also carries `SignatureStatus`, `Signer`, the four `Intune*`
properties and `Notes`.

### How an MSI's install context is decided

| Property table | `InstallContext` | Install behavior | Install command adds |
| --- | --- | --- | --- |
| `ALLUSERS=1` | `PerMachine` | System | |
| `ALLUSERS=2` | `PerMachineWhenElevated` | System | |
| `ALLUSERS=2`, `MSIINSTALLPERUSER=1` | `DualPurposePerUserDefault` | System | `ALLUSERS=1` |
| No `ALLUSERS` | `PerUser` | User | |

Windows Installer ignores `MSIINSTALLPERUSER` unless `ALLUSERS` is 2, and a
per-user install stays per-user when SYSTEM runs it. A per-user package
deployed as System therefore installs into the SYSTEM profile and reports
success, while no user ever sees the app.

### EXE installers

| Framework | Recognised by | Install switches | Uninstall |
| --- | --- | --- | --- |
| WiX Burn | A `.wixburn` section | `/quiet /norestart` | The same file: `/uninstall /quiet /norestart` |
| NSIS | Manifest identity `Nullsoft.NSIS.exehead`, or the NSIS header after the executable | `/S`, case-sensitive | The uninstaller written during install, with `/S` |
| Inno Setup | Manifest identity `JR.Inno.Setup`, Inno Setup data after the executable, or the version comment | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` | `unins000.exe` in the app folder, same switches |
| InstallShield | The word InstallShield in the manifest or version resource, which is weak evidence | `/s /v"/qn"` for Basic MSI projects | Depends on the project type |

The switches are each framework's defaults, which a vendor can change.
`FrameworkEvidence` says what each match rests on, and anything else is
reported as `Unknown`.

`ExecutableArchitecture` is that of the installer itself. Burn, NSIS and Inno
Setup installers are 32-bit even when the app they install is 64-bit. An EXE
carries no product code either, so detection comes from what a test install
writes, such as `DisplayVersion` under the Uninstall registry key.

### .intunewin packages

The Win32 Content Prep Tool writes a ZIP archive: the setup folder, encrypted,
and `Metadata/Detection.xml` in plain text. The XML records the setup file and,
for an MSI, its codes and execution context. It also holds the key that
decrypts the content, so anyone holding an `.intunewin` file can read what is
inside it. The script reads only the identifying fields and never outputs the
key. It refuses an XML file that declares a DTD, because a package can come
from anywhere.

The field names were checked against packages built by version 1.8.7 of the
Content Prep Tool. If a later version renames one, that property comes back
empty rather than failing.

### Warnings

These are written as warnings and kept in `Notes`, because each one makes a
deployment fail:

- a per-user MSI, or a dual-purpose MSI that defaults to per-user
- cabinets in the Media table that are not embedded in the MSI
- files stored uncompressed beside the MSI
- a signature that no longer matches the file (`HashMismatch`)

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every file was read |
| `1` | At least one file could not be read, or the script could not start. Every other file is still read and returned |

### Limits

- Not read: patches (`.msp`), transforms (`.mst`), merge modules (`.msm`),
  MSIX and APPX packages. An MSI wrapped inside an EXE is not extracted.
- Public properties are those with a default in the Property table or set by a
  dialog. A property that only a custom action reads does not appear; the
  vendor's documentation is the source for those.
- A vendor's own bootstrapper is reported as `Unknown`.

### Tests

```powershell
Invoke-Pester -Path .\Standalone\Get-InstallerInfo.Tests.ps1 -Output Detailed
```

No installer is checked in. The tests build every file they read: MSIs through
the Windows Installer COM API, EXEs as hand-assembled PE headers with a
manifest resource, and `.intunewin` packages as ZIP archives holding a
`Detection.xml`. They run under Windows PowerShell 5.1 and PowerShell 7, and
are skipped on other platforms.
