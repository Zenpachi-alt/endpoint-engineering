# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Reads the Uninstall registry entries an installer writes, and turns each
    into an Intune detection rule, uninstall command and install behavior.
    Compares two points in time, to show what a test install added.

.DESCRIPTION
    Read-only, apart from the snapshot file -SaveSnapshot writes. Nothing is
    installed, uninstalled or run.

    Windows lists installed apps from three registry locations, and this
    script reads all three:
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
            64-bit apps, and every app on 32-bit Windows
        HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
            32-bit apps on 64-bit Windows
        HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall
            apps installed for the signed-in user only

    An EXE installer carries no product code, so its detection rule has to
    come from what it writes. On a clean test machine:
        1. .\Get-UninstallEntry.ps1 -SaveSnapshot .\before.json
        2. Install the app.
        3. .\Get-UninstallEntry.ps1 -CompareSnapshot .\before.json
    Step 3 returns only what was added, changed or removed.

    Each entry gets Intune* properties:
        IntuneDetection        an MSI rule for an MSI, otherwise a registry
                               rule on DisplayVersion, with the 32-bit switch
                               set for the view the entry is in
        IntuneUninstallCommand msiexec /x for an MSI; /VERYSILENT for Inno
                               Setup; /S for NSIS; else QuietUninstallString
        IntuneInstallBehavior  System for a machine entry, User for a per-user one

    The installer that wrote an entry is recognised from the entry itself: an
    MSI from WindowsInstaller, Inno Setup from the _is1 key name, WiX Burn
    from BundleUpgradeCode, Squirrel from Update.exe --uninstall. NSIS is
    recognised by reading its uninstaller, which carries the NSIS manifest. An
    uninstaller that cannot be read, such as an app execution alias, leaves its
    entry Unknown, with a warning and a note giving the reason.

    Entries without a DisplayName are skipped, as Windows skips them.

.PARAMETER Name
    Only entries whose DisplayName matches one of these wildcard patterns.

.PARAMETER Publisher
    Only entries whose Publisher matches this wildcard pattern.

.PARAMETER SaveSnapshot
    Write every entry to this JSON file, for -CompareSnapshot after an
    install. The folder must exist. An existing file is replaced.

.PARAMETER CompareSnapshot
    Compare the entries now with a file -SaveSnapshot wrote, and return only
    those added, changed or removed since. Take both as the same user: entries
    under HKEY_CURRENT_USER belong to whoever runs the script.

.EXAMPLE
    .\Get-UninstallEntry.ps1 -Name '*Git*'

    Every entry whose display name contains Git, with Intune settings.

.EXAMPLE
    .\Get-UninstallEntry.ps1 -SaveSnapshot .\before.json
    # install the app
    .\Get-UninstallEntry.ps1 -CompareSnapshot .\before.json | Select-Object -Property Change, DisplayName, Intune*

    What the install wrote, and how to detect and remove it with Intune.

.EXAMPLE
    .\Get-UninstallEntry.ps1 | Format-Table -Property DisplayName, DisplayVersion, Scope, RegistryView, Installer

    Every installed app, one line each.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.1
    Last updated  : 2026-10-12

    PowerShell    : 5.1 or later. Packaging is often done on a clean virtual
                    machine that has only Windows PowerShell, and nothing here
                    needs PowerShell 7.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : None.
    Role required : None. Reading the Uninstall keys needs no elevation.
                    HKEY_CURRENT_USER is the hive of whoever runs the script,
                    so run it as the user who installs a per-user app.

    Platform      : Windows only.

    Exit codes    : 0 success, including a comparison that found no change, and
                      an uninstaller that could not be read.
                    1 the registry or the snapshot could not be read, or the
                      snapshot could not be written.

    Limits        : Only the signed-in user's per-user entries are read, not
                    other users' hives. The snapshot holds paths from this
                    machine, user profile folders included: keep it local.
#>

[CmdletBinding(DefaultParameterSetName = 'List', SupportsShouldProcess, ConfirmImpact = 'Low')]
[OutputType([pscustomobject])]
param (
    [Parameter(Position = 0, ParameterSetName = 'List')]
    [Parameter(ParameterSetName = 'Compare')]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string[]]$Name,

    [Parameter(ParameterSetName = 'List')]
    [Parameter(ParameterSetName = 'Compare')]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string]$Publisher,

    [Parameter(Mandatory, ParameterSetName = 'Save')]
    [ValidateNotNullOrEmpty()]
    [string]$SaveSnapshot,

    [Parameter(Mandatory, ParameterSetName = 'Compare')]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Leaf) { $true }
            else { throw "No snapshot file at '$_'. Write one first with -SaveSnapshot." }
        })]
    [string]$CompareSnapshot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitFailure = 1

function Split-CommandLine {
    # A program path and its arguments, from a command line that may or may not quote the path.
    # Windows writes both: Steam's UninstallString is an unquoted path with spaces in it.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ([Parameter()] [AllowNull()] [AllowEmptyString()] [string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $text = $CommandLine.Trim()
    if ($text.StartsWith('"')) {
        $end = $text.IndexOf('"', 1)
        if ($end -lt 2) { return $null }
        return [pscustomobject]@{ Path = $text.Substring(1, $end - 1); Arguments = $text.Substring($end + 1).Trim() }
    }
    $match = [regex]::Match($text, '^(.+?\.exe)(?=\s|$)(.*)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) { return $null }
    [pscustomobject]@{ Path = $match.Groups[1].Value; Arguments = $match.Groups[2].Value.Trim() }
}

function Join-CommandLine {
    # The path always quoted, so the command still works where the path has spaces.
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)] [string]$Path,
        [Parameter()] [AllowEmptyString()] [string[]]$Argument = @()
    )

    $parts = @('"{0}"' -f $Path) + @($Argument | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $parts -join ' '
}

function Test-NsisUninstaller {
    # An NSIS uninstaller carries the NSIS manifest identity, or the NSIS data header, as plain
    # bytes. Uninstallers are small; a large file is not read.
    [CmdletBinding()]
    [OutputType([bool])]
    param ([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $file = Get-Item -LiteralPath $Path
    if ($file.Length -gt 8MB) { return $false }
    $text = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($file.FullName))
    $text.Contains('Nullsoft.NSIS.exehead') -or $text.Contains('NullsoftInst')
}

function Get-InstallerType {
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory)] [pscustomobject]$Entry)

    if ($Entry.WindowsInstaller) { return 'MSI' }
    if ($Entry.KeyName -like '*_is1') { return 'Inno Setup' }
    if ($Entry.BundleUpgradeCode) { return 'WiX Burn' }
    $uninstaller = Split-CommandLine -CommandLine $Entry.UninstallString
    if ($null -ne $uninstaller) {
        if ((Split-Path -Path $uninstaller.Path -Leaf) -eq 'Update.exe' -and $uninstaller.Arguments -match '--uninstall') {
            return 'Squirrel'
        }
        if (Test-NsisUninstaller -Path $uninstaller.Path) { return 'NSIS' }
    }
    'Unknown'
}

function Read-UninstallKey {
    # Every entry with a DisplayName under one Uninstall key, as plain values: what a
    # snapshot stores, and what two points in time are compared on.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)] [Microsoft.Win32.RegistryHive]$Hive,
        [Parameter(Mandatory)] [Microsoft.Win32.RegistryView]$View,
        [Parameter(Mandatory)] [string]$SubKey,
        [Parameter(Mandatory)] [ValidateSet('Machine', 'User')] [string]$Scope,
        [Parameter(Mandatory)] [ValidateSet('64-bit', '32-bit', 'User')] [string]$RegistryView,
        [Parameter(Mandatory)] [string]$RegistryPath
    )

    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, $View)
    try {
        $uninstall = $base.OpenSubKey($SubKey)
        if ($null -eq $uninstall) { return }
        try {
            foreach ($keyName in $uninstall.GetSubKeyNames()) {
                try {
                    $key = $uninstall.OpenSubKey($keyName)
                }
                catch [System.Security.SecurityException] {
                    Write-Warning ('Cannot read {0}\{1}: {2}' -f $RegistryPath, $keyName, $_.Exception.Message)
                    continue
                }
                # Gone between listing and opening: an install or uninstall is running.
                if ($null -eq $key) { continue }
                try {
                    $displayName = [string]$key.GetValue('DisplayName')
                    if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
                    $bundle = $key.GetValue('BundleUpgradeCode')
                    [pscustomobject]@{
                        Scope                = $Scope
                        RegistryView         = $RegistryView
                        KeyName              = $keyName
                        RegistryPath         = '{0}\{1}' -f $RegistryPath, $keyName
                        DisplayName          = $displayName.Trim()
                        DisplayVersion       = [string]$key.GetValue('DisplayVersion')
                        Publisher            = [string]$key.GetValue('Publisher')
                        InstallDate          = [string]$key.GetValue('InstallDate')
                        InstallLocation      = [string]$key.GetValue('InstallLocation')
                        UninstallString      = [string]$key.GetValue('UninstallString')
                        QuietUninstallString = [string]$key.GetValue('QuietUninstallString')
                        WindowsInstaller     = $key.GetValue('WindowsInstaller') -eq 1
                        SystemComponent      = $key.GetValue('SystemComponent') -eq 1
                        BundleUpgradeCode    = if ($bundle) { @($bundle)[0] } else { '' }
                    }
                }
                finally {
                    $key.Dispose()
                }
            }
        }
        finally {
            $uninstall.Dispose()
        }
    }
    finally {
        $base.Dispose()
    }
}

function Get-UninstallSource {
    # The three places Windows lists apps. On 32-bit Windows there is one machine view.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param ([Parameter(Mandatory)] [bool]$Is64BitWindows)

    $subKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    if ($Is64BitWindows) {
        @{ Hive = 'LocalMachine'; View = 'Registry64'; SubKey = $subKey; Scope = 'Machine'; RegistryView = '64-bit'
            RegistryPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        }
        @{ Hive = 'LocalMachine'; View = 'Registry32'; SubKey = $subKey; Scope = 'Machine'; RegistryView = '32-bit'
            RegistryPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        }
    }
    else {
        @{ Hive = 'LocalMachine'; View = 'Default'; SubKey = $subKey; Scope = 'Machine'; RegistryView = '32-bit'
            RegistryPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        }
    }
    @{ Hive = 'CurrentUser'; View = 'Default'; SubKey = $subKey; Scope = 'User'; RegistryView = 'User'
        RegistryPath = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    }
}

function Test-EntryFilter {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)] [pscustomobject]$Entry,
        [Parameter()] [AllowNull()] [string[]]$Name,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string]$Publisher
    )

    if ($Name -and -not @($Name | Where-Object { $Entry.DisplayName -like $_ })) { return $false }
    if ($Publisher -and $Entry.Publisher -notlike $Publisher) { return $false }
    $true
}

function Compare-UninstallSnapshot {
    # Matched on view and key name: the same key in another view is another app.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Reference,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Difference
    )

    $compared = 'DisplayName', 'DisplayVersion', 'Publisher', 'InstallLocation', 'UninstallString',
    'QuietUninstallString', 'WindowsInstaller', 'SystemComponent'
    $before = @{}
    foreach ($entry in $Reference) { $before['{0}|{1}' -f $entry.RegistryView, $entry.KeyName] = $entry }
    $seen = @{}

    foreach ($entry in $Difference) {
        $id = '{0}|{1}' -f $entry.RegistryView, $entry.KeyName
        $seen[$id] = $true
        if (-not $before.ContainsKey($id)) {
            [pscustomobject]@{ Change = 'Added'; Entry = $entry; ChangedValues = @() }
            continue
        }
        $old = $before[$id]
        $changes = @(foreach ($property in $compared) {
                $was = [string]$old.$property
                $now = [string]$entry.$property
                if ($was -cne $now) { '{0}: {1} -> {2}' -f $property, $was, $now }
            })
        if ($changes.Count -gt 0) {
            [pscustomobject]@{ Change = 'Changed'; Entry = $entry; ChangedValues = $changes }
        }
    }
    foreach ($id in $before.Keys) {
        if (-not $seen.ContainsKey($id)) {
            [pscustomobject]@{ Change = 'Removed'; Entry = $before[$id]; ChangedValues = @() }
        }
    }
}

function Read-UninstallSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ([Parameter(Mandatory)] [string]$Path)

    try {
        # Read as UTF-8, as it was written. Windows PowerShell reads a file without a byte order
        # mark in the system code page, which turns a name like "HWiNFO(R) 64" into another key.
        $file = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
        $snapshot = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "The snapshot at '$Path' is not valid JSON: $($_.Exception.Message)"
    }
    if ($snapshot -isnot [System.Management.Automation.PSCustomObject]) {
        throw "'$Path' is not a snapshot this script wrote. Write one with -SaveSnapshot."
    }
    $names = @($snapshot.PSObject.Properties | ForEach-Object { $_.Name })
    if ($names -notcontains 'Format' -or $snapshot.Format -ne 'UninstallSnapshot' -or
        $names -notcontains 'Version' -or $names -notcontains 'Entries') {
        throw "'$Path' is not a snapshot this script wrote. Write one with -SaveSnapshot."
    }
    if ($snapshot.Version -ne 1) {
        throw "The snapshot at '$Path' has format version $($snapshot.Version); this script reads version 1."
    }
    # Enumerated from a variable: Windows PowerShell would wrap a piped JSON array as one item.
    $entries = $snapshot.Entries
    foreach ($entry in @($entries)) {
        if ($null -ne $entry) { $entry }
    }
}

function ConvertTo-UninstallReport {
    # One entry with the Intune settings it implies, and the notes that go with them.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)] [pscustomobject]$Entry,
        [Parameter()] [AllowNull()] [string]$Change,
        [Parameter()] [AllowEmptyCollection()] [string[]]$ChangedValues = @()
    )

    $notes = [System.Collections.Generic.List[string]]::new()
    try {
        $installer = Get-InstallerType -Entry $Entry
    }
    catch [System.IO.IOException], [System.UnauthorizedAccessException] {
        # Recognising NSIS reads the uninstaller, and not every file opens: an app execution alias
        # under WindowsApps is a reparse point File.ReadAllBytes cannot read. That leaves this one
        # entry unrecognised, not the whole listing unread.
        $installer = 'Unknown'
        # Trimmed: under Windows PowerShell the message ends with a line break.
        $reason = $_.Exception.GetBaseException().Message.Trim()
        Write-Warning ('Cannot read the uninstaller of {0}, so its installer was not recognised: {1}' -f $Entry.DisplayName, $reason)
        $notes.Add(('The uninstaller could not be read, so its installer was not recognised: {0}' -f $reason))
    }
    $productCode = $null
    if ($installer -eq 'MSI' -and $Entry.KeyName -match '^\{[0-9A-Fa-f-]{36}\}$') { $productCode = $Entry.KeyName.ToUpperInvariant() }
    $removed = $Change -eq 'Removed'

    $uninstallCommand = $null
    $detection = $null
    $behavior = $null
    if (-not $removed) {
        $behavior = if ($Entry.Scope -eq 'User') { 'User' } else { 'System' }

        # Detection: an MSI rule where there is a product code, a registry rule on the
        # entry otherwise. Intune takes the native key path; its 32-bit switch picks the view.
        if ($productCode) {
            $detection = 'MSI product code {0}' -f $productCode
            if ($Entry.DisplayVersion) { $detection += ', product version greater than or equal to {0}' -f $Entry.DisplayVersion }
        }
        else {
            $hive = if ($Entry.Scope -eq 'User') { 'HKEY_CURRENT_USER\Software' } else { 'HKEY_LOCAL_MACHINE\SOFTWARE' }
            $keyPath = '{0}\Microsoft\Windows\CurrentVersion\Uninstall\{1}' -f $hive, $Entry.KeyName
            $check32Bit = if ($Entry.RegistryView -eq '32-bit') { 'Yes' } else { 'No' }
            $parsed = $null
            $rule = if (-not $Entry.DisplayVersion) { 'key exists' }
            elseif ([version]::TryParse($Entry.DisplayVersion, [ref]$parsed)) {
                'value DisplayVersion, version comparison, greater than or equal to {0}' -f $Entry.DisplayVersion
            }
            else { 'value DisplayVersion, string comparison, equals {0}' -f $Entry.DisplayVersion }
            $detection = 'Registry: {0}, {1}, associated with a 32-bit app on 64-bit clients: {2}' -f $keyPath, $rule, $check32Bit
        }

        $uninstaller = Split-CommandLine -CommandLine $Entry.UninstallString
        $quiet = Split-CommandLine -CommandLine $Entry.QuietUninstallString
        switch ($installer) {
            'MSI' {
                if ($productCode) { $uninstallCommand = 'msiexec /x "{0}" /qn /norestart' -f $productCode }
            }
            'Inno Setup' {
                if ($uninstaller) {
                    $uninstallCommand = Join-CommandLine -Path $uninstaller.Path -Argument $uninstaller.Arguments, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
                    $notes.Add('Inno Setup''s own QuietUninstallString uses /SILENT, which shows progress; the suggested command uses /VERYSILENT.')
                }
            }
            'NSIS' {
                if ($quiet) { $uninstallCommand = Join-CommandLine -Path $quiet.Path -Argument $quiet.Arguments }
                else { $uninstallCommand = Join-CommandLine -Path $uninstaller.Path -Argument $uninstaller.Arguments, '/S' }
                $notes.Add(('An NSIS uninstaller copies itself to a temporary folder and exits at once, so Intune can check ' +
                        'detection before the uninstall finishes. Adding _?=<install folder> as the last argument makes it wait, ' +
                        'and leaves the uninstaller behind.'))
            }
            default {
                if ($quiet) { $uninstallCommand = Join-CommandLine -Path $quiet.Path -Argument $quiet.Arguments }
            }
        }
        if (-not $uninstallCommand) {
            $notes.Add(('No silent uninstall is known. UninstallString runs the uninstaller with its user interface; ' +
                    'check the vendor''s silent switch.'))
        }
        elseif ($uninstallCommand -match '^"?[A-Za-z]:\\Users\\[^\\]+\\') {
            $notes.Add(('The uninstaller is inside this user''s profile, so its path differs for every user, and Intune ' +
                    'does not expand variables in an uninstall command. Use a script that builds the path from %LOCALAPPDATA%.'))
        }

        if ($Entry.Scope -eq 'User') {
            $notes.Add(('Per-user entry, written for the signed-in user only. Deploy with install behavior User: a rule ' +
                    'under HKEY_CURRENT_USER only detects the app in that user''s context.'))
        }
        if ($Entry.SystemComponent) {
            $notes.Add(('Hidden from Installed apps (SystemComponent=1), usually because a bundle installed it. Detect and ' +
                    'uninstall the visible parent entry instead.'))
        }
        switch ($installer) {
            'WiX Burn' {
                $notes.Add('WiX Burn bundle: the key name is this release''s bundle ID, and changes with every version.')
            }
            'Squirrel' {
                $notes.Add('Squirrel installs per user only, into the user''s profile; it has no install for all users.')
            }
        }
    }

    $report = [ordered]@{}
    if ($Change) {
        $report.Change = $Change
        $report.ChangedValues = @($ChangedValues)
    }
    $report.DisplayName = $Entry.DisplayName
    $report.DisplayVersion = $Entry.DisplayVersion
    $report.Publisher = $Entry.Publisher
    $report.Scope = $Entry.Scope
    $report.RegistryView = $Entry.RegistryView
    $report.Installer = $installer
    $report.ProductCode = $productCode
    $report.Hidden = [bool]$Entry.SystemComponent
    $report.InstallLocation = $Entry.InstallLocation
    $report.InstallDate = $Entry.InstallDate
    $report.UninstallString = $Entry.UninstallString
    $report.QuietUninstallString = $Entry.QuietUninstallString
    $report.RegistryPath = $Entry.RegistryPath
    $report.IntuneInstallBehavior = $behavior
    $report.IntuneUninstallCommand = $uninstallCommand
    $report.IntuneDetection = $detection
    $report.Notes = $notes.ToArray()
    [pscustomobject]$report
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Get-UninstallEntry runs on Windows only: it reads the Windows registry.'
    }

    $current = @(foreach ($source in @(Get-UninstallSource -Is64BitWindows ([Environment]::Is64BitOperatingSystem))) {
            Read-UninstallKey @source
        })

    switch ($PSCmdlet.ParameterSetName) {
        'Save' {
            $target = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($SaveSnapshot)
            $folder = Split-Path -Path $target -Parent
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                throw "The folder '$folder' does not exist."
            }
            if ($PSCmdlet.ShouldProcess($target, ('Save a snapshot of {0} Uninstall entries' -f $current.Count))) {
                $snapshot = [ordered]@{
                    Format  = 'UninstallSnapshot'
                    Version = 1
                    Created = (Get-Date).ToUniversalTime().ToString('o')
                    Entries = $current
                }
                $json = ConvertTo-Json -InputObject $snapshot -Depth 4
                [IO.File]::WriteAllText($target, $json, [System.Text.UTF8Encoding]::new($false))
                Get-Item -LiteralPath $target
            }
        }
        'Compare' {
            $reference = @(Read-UninstallSnapshot -Path $CompareSnapshot)
            $order = @{ Added = 0; Changed = 1; Removed = 2 }
            $changes = @(Compare-UninstallSnapshot -Reference $reference -Difference $current |
                    Where-Object { Test-EntryFilter -Entry $_.Entry -Name $Name -Publisher $Publisher } |
                    Sort-Object -Property { $order[$_.Change] }, { $_.Entry.DisplayName })
            if ($changes.Count -eq 0) {
                Write-Warning ('No Uninstall entry changed since the snapshot. A per-user install only shows for the user ' +
                    'who ran it; take the snapshot and the comparison as that user.')
            }
            foreach ($change in $changes) {
                ConvertTo-UninstallReport -Entry $change.Entry -Change $change.Change -ChangedValues $change.ChangedValues
            }
        }
        default {
            $current | Where-Object { Test-EntryFilter -Entry $_ -Name $Name -Publisher $Publisher } |
                Sort-Object -Property DisplayName |
                ForEach-Object { ConvertTo-UninstallReport -Entry $_ }
        }
    }
    exit $ExitSuccess
}
catch {
    Write-Error -Exception $_.Exception -Message ('Get-UninstallEntry failed: {0}' -f $_.Exception.Message) -ErrorAction Continue
    exit $ExitFailure
}
