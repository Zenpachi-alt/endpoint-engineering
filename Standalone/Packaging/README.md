# Packaging

Scripts for preparing Intune Win32 apps, run on a packaging workstation or a
test virtual machine. They read installers and the registry, and suggest the
Intune settings that follow from them; nothing here talks to Intune or a
tenant.

| Script | Purpose |
| --- | --- |
| `Get-InstallerInfo.ps1` | What an installer holds: reads an MSI, an EXE installer or an `.intunewin` package. |
| `Get-InstallerInfo.Tests.ps1` | Pester tests for it, under Windows PowerShell 5.1 and PowerShell 7. |
| `Get-UninstallEntry.ps1` | What an installer wrote: reads the Uninstall registry entries, and compares them before and after a test install. |
| `Get-UninstallEntry.Tests.ps1` | Pester tests for it, under Windows PowerShell 5.1 and PowerShell 7. |

The two cover an app from both ends. `Get-InstallerInfo.ps1` reads the file
before anything is installed, which for an MSI is enough to deploy it. An EXE
carries no product code, so its detection rule has to come from what it
writes: install it on a test machine between two runs of
`Get-UninstallEntry.ps1`.

CI runs every test here on each push, under both editions on Windows.

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
.\Get-InstallerInfo.ps1 -Path \\SERVER-001\Packages\ContosoApp.intunewin
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
writes, such as `DisplayVersion` under the Uninstall registry key:
[`Get-UninstallEntry.ps1`](#get-uninstallentryps1) shows exactly that.

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
Invoke-Pester -Path .\Standalone\Packaging\Get-InstallerInfo.Tests.ps1 -Output Detailed
```

No installer is checked in. The tests build every file they read: MSIs through
the Windows Installer COM API, EXEs as hand-assembled PE headers with a
manifest resource, and `.intunewin` packages as ZIP archives holding a
`Detection.xml`. They run under Windows PowerShell 5.1 and PowerShell 7, and
are skipped on other platforms.

## Get-UninstallEntry.ps1

Reads the Uninstall registry entries Windows lists installed apps from, and
turns each into an Intune detection rule, uninstall command and install
behavior. Saves a snapshot before a test install and compares after it, to
show exactly what the installer wrote. Read-only apart from the snapshot file:
nothing is installed, uninstalled or run.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or later, for the same reason as `Get-InstallerInfo.ps1` |
| Modules | None |
| Graph scopes | None |
| Admin consent | Not applicable |
| Licensing | None |
| Role | None. Reading the Uninstall keys needs no elevation. Run it as the user who installs a per-user app: `HKEY_CURRENT_USER` is the hive of whoever runs the script |
| Platform | Windows |

### Examples

```powershell
# Before installing, on a clean test machine
.\Get-UninstallEntry.ps1 -SaveSnapshot .\before.json

# ... install the app ...

# What the install wrote, and the Intune settings for it
.\Get-UninstallEntry.ps1 -CompareSnapshot .\before.json |
    Select-Object -Property Change, DisplayName, DisplayVersion, Intune*

# An app that is already installed
.\Get-UninstallEntry.ps1 -Name '*Contoso*'

# Every installed app, one line each
.\Get-UninstallEntry.ps1 |
    Format-Table -Property DisplayName, DisplayVersion, Scope, RegistryView, Installer
```

```text
Change                 : Added
DisplayName            : Contoso App
DisplayVersion         : 24.1.3115
IntuneInstallBehavior  : System
IntuneUninstallCommand : "C:\Program Files\Contoso\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
IntuneDetection        : Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Contoso
                         App_is1, value DisplayVersion, version comparison, greater than or equal to 24.1.3115,
                         associated with a 32-bit app on 64-bit clients: No
```

### Where it reads

| Registry key | Holds | `RegistryView` |
| --- | --- | --- |
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | 64-bit apps, and every app on 32-bit Windows | `64-bit` |
| `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` | 32-bit apps on 64-bit Windows | `32-bit` |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall` | Apps installed for the signed-in user only | `User` |

Entries without a `DisplayName` are skipped, as Windows skips them.

An Intune registry rule takes the native key path, never `WOW6432Node`: its
"Associated with a 32-bit app on 64-bit clients" switch is what makes Intune
read the 32-bit view. So `RegistryPath` shows where an entry really is, and
`IntuneDetection` gives the path to type into Intune, with the switch.

### What it suggests

| Installer | Recognised by | Uninstall command | Detection |
| --- | --- | --- | --- |
| MSI | `WindowsInstaller` = 1 | `msiexec /x "{ProductCode}" /qn /norestart` | MSI product code and version |
| Inno Setup | Key name ending `_is1` | The uninstaller with `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`; Inno's own `QuietUninstallString` uses `/SILENT`, which shows progress | Registry |
| WiX Burn | `BundleUpgradeCode` | `QuietUninstallString` | Registry; the key is the bundle ID, new for every release |
| Squirrel | `Update.exe --uninstall` | `QuietUninstallString` | Registry, per-user only |
| NSIS | The NSIS manifest inside its uninstaller | The uninstaller with `/S` | Registry |
| Anything else | | `QuietUninstallString`, where there is one | Registry |

Every command quotes the uninstaller's path, which Windows does not always
do: an unquoted path with a space in it would fail as an Intune command. The
registry rule compares `DisplayVersion` as a version where it is one, as a
string where it is not, and checks only that the key exists where there is no
version.

`IntuneInstallBehavior` is `System` for a machine entry and `User` for a
per-user one. Notes say what else to know: a per-user entry, an uninstaller
inside a user profile, whose path Intune cannot build because it does not
expand variables in an uninstall command, an entry hidden by
`SystemComponent`, and an NSIS uninstaller, which returns before it has
finished unless given `_?=<install folder>`.

### Snapshots

`-SaveSnapshot` writes every entry to a JSON file, and `-CompareSnapshot`
returns only the entries added, changed or removed since, with
`ChangedValues` naming what changed. Take both as the same user, since the
per-user entries are that user's. The file holds paths from this machine,
user profile folders included: keep it local.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, including a comparison that found no change, which also writes a warning |
| `1` | The registry or the snapshot could not be read, or the snapshot could not be written |

### Limits

- Only the signed-in user's per-user entries are read, not other users' hives.
- NSIS is recognised from its uninstaller's file; one larger than 8 MB is not
  read.
- The commands are each framework's defaults, which a vendor can change.
  Test them on a virtual machine.

### Tests

```powershell
Invoke-Pester -Path .\Standalone\Packaging\Get-UninstallEntry.Tests.ps1 -Output Detailed
```

The registry reader is tested against a key under
`HKEY_CURRENT_USER\Software\EndpointEngineeringTests`, removed afterwards, and
never against the real Uninstall keys. The end-to-end runs only read those,
and write their snapshots to TestDrive.
