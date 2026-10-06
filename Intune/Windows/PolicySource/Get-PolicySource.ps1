# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Shows where each policy setting on this device comes from - Group Policy,
    Intune, both or neither - and which one is in effect.

.DESCRIPTION
    Read-only. Run on the device, elevated, by an administrator tracing a
    setting, or by two teams settling who owns one.

    In a hybrid estate one registry value can be written by a GPO and by an
    Intune policy. Intune writes many settings to the same Policies keys Group
    Policy uses, so a message such as "a Group Policy setting prevents this"
    names the mechanism, not the team. This script reads every local source and
    puts them side by side, one row per registry value:

        Intune (MDM)   PolicyManager: what each enrollment set, which one won,
                       and the registry value each setting maps to.
        Group Policy   The RSoP data Windows logs at every refresh: the applied
                       registry settings, the winning GPO, and the GPOs that
                       lost on precedence.
        GPO cache      Windows' local copy of each applied GPO. A setting a GPO
                       holds that RSoP does not show was not applied.
        Preferences    The local history of Group Policy Preferences registry
                       items.
        Registry       The value Windows reads now.

    Nothing contacts a domain controller or the internet, so the script works
    off the corporate network. gpresult is not used: it needs a domain
    controller and stalls without one.

    Verdicts, most important first:
        Conflict         Group Policy and Intune both apply it, with different
                         values.
        OverriddenByMdm  A GPO sets it, but it was not applied because Intune
                         sets it too (ControlPolicyConflict/MDMWinsOverGP). RSoP
                         and rsop.msc do not show these.
        NotApplied       A GPO sets it, it was not applied, and no Intune
                         setting explains why.
        Both             Both set it. Intune sends an ADMX state (Enabled,
                         Disabled) rather than a value, so the two are not
                         compared.
        Agree            Both set it, to the same value.
        GpOnly           Group Policy only.
        MdmOnly          Intune, or another MDM, only.
        Unclaimed        A value under HKLM\SOFTWARE\Policies that none of the
                         sources claims: a script, an app, another management
                         tool, or a Windows default.

    Settings Windows provisions for itself through PolicyManager - power and
    processor tuning, mostly, hundreds of them - are left out unless
    -IncludeWindowsInternal is given.

.PARAMETER Filter
    Only settings matching one of these wildcard patterns, tried against the
    setting name, the registry path, the Intune setting and the GPO name.

.PARAMETER Verdict
    Only settings with one of these verdicts.

.PARAMETER IncludeWindowsInternal
    Include the settings Windows provisions for itself through PolicyManager.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs. The log holds counts and timings,
    not values.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Get-PolicySource.ps1 -Filter '*FVE*', '*BitLocker*'

    BitLocker settings, wherever they come from. FVE is BitLocker's policy key.

.EXAMPLE
    .\Get-PolicySource.ps1 -Verdict Conflict, OverriddenByMdm, NotApplied

    Only the settings both sides claim, where one of them loses.

.EXAMPLE
    .\Get-PolicySource.ps1 -Filter '*WindowsUpdate*' | Format-List

    Every property of each Windows Update setting, including the note that
    explains the verdict.

.EXAMPLE
    .\Get-PolicySource.ps1 | Export-Csv -Path .\PolicySource.csv -NoTypeInformation

    Everything, as a file for the other team. It holds GPO names and policy
    values from this device; scrub it before it leaves the organisation.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-10-06

    PowerShell    : Windows PowerShell 5.1. It runs on the device, where
                    PowerShell 7 cannot be assumed.
    Kind          : Run by a person on the device, not delivered by Intune, so
                    the remediation exit code contract does not apply.
    Context       : Elevated. RSoP data and the GPO cache are readable by
                    administrators only; the script checks and says so.
    Modules       : None.
    Graph scopes  : None. Nothing leaves the device.
    Admin consent : Not applicable.
    Licensing     : None to run. It reads what Group Policy and an MDM
                    (Microsoft Intune Plan 1 or another) have applied.
    Role required : Local administrator on the device.

    Exit codes    : 0 success, including when no setting matches.
                    1 not elevated, or Intune or Group Policy data could not
                      be read. The reason is on stderr and in the log.

    Limits        : Computer settings only, not user settings. Registry-based
                    policy only: security settings (passwords, user rights,
                    audit) go through a separate engine and are not read.
                    Values of ADMX-backed Intune settings are not compared
                    with Group Policy values. A setting written by a script or
                    an app is Unclaimed only under HKLM\SOFTWARE\Policies.

.LINK
    https://learn.microsoft.com/windows/client-management/mdm/policy-csp-controlpolicyconflict
#>

[CmdletBinding()]
[OutputType([pscustomobject])]
param (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string[]]$Filter,

    [Parameter()]
    [ValidateSet('Conflict', 'OverriddenByMdm', 'NotApplied', 'Both', 'Agree', 'GpOnly', 'MdmOnly', 'Unclaimed')]
    [string[]]$Verdict,

    [Parameter()]
    [switch]$IncludeWindowsInternal,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path -Path $env:ProgramData -ChildPath 'EndpointEngineering\Logs'),

    [Parameter()]
    [ValidateRange(65536, 104857600)]
    [int]$MaxLogSizeBytes = 1048576
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitFailure = 1

$PolicyManagerPath = 'SOFTWARE\Microsoft\PolicyManager'
$PoliciesPath = 'SOFTWARE\Policies'
$GpoCacheDirectory = Join-Path -Path $env:windir -ChildPath 'System32\GroupPolicy\DataStore'
$PreferencesHistoryDirectory = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Group Policy\History'

# Verdicts in the order they are listed: the ones that need a decision first.
$VerdictRank = @{
    Conflict = 0; OverriddenByMdm = 1; NotApplied = 2; Both = 3; Agree = 4; GpOnly = 5; MdmOnly = 6; Unclaimed = 7
}

# Set by Initialize-LogFile. $null means "log to the verbose stream only".
$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path. Returns $null when logging is not possible, so that a
            logging problem never fails a run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$MaxSizeBytes
    )

    try {
        if (-not (Test-Path -LiteralPath $Directory)) {
            $null = New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop
        }

        $path = Join-Path -Path $Directory -ChildPath "$Name.log"

        if (Test-Path -LiteralPath $path) {
            $existing = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($existing.Length -gt $MaxSizeBytes) {
                Move-Item -LiteralPath $path -Destination "$path.old" -Force -ErrorAction Stop
            }
        }

        return $path
    }
    catch {
        Write-Warning "Could not initialise log file in '$Directory': $($_.Exception.Message). Continuing without a log file."
        return $null
    }
}

function Write-LogEntry {
    <#
        .SYNOPSIS
            Appends a timestamped line to the log file and the verbose stream.
            Never writes to the pipeline, which carries the results.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] [PID {2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff zzz', [cultureinfo]::InvariantCulture), $Level, $PID, $Message

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Disable logging rather than fail the run, and say so once.
            $script:LogFile = $null
            Write-Warning "Logging stopped: $($_.Exception.Message)"
        }
    }

    Write-Verbose $line
}

function Test-Elevated {
    <#
        .SYNOPSIS
            True when the current process runs as an administrator.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValueSet {
    <#
        .SYNOPSIS
            Every value of one key below Root, as a hashtable, or $null when the
            key does not exist.

        .DESCRIPTION
            Registry reads go through .NET, not the registry provider. In
            Windows PowerShell 5.1 the provider takes about 100 ms per
            Test-Path or Get-ItemProperty on a PolicyManager key, which over
            hundreds of policies stalls for minutes. .NET also reads a '/' in a
            policy name as part of the key name, where the provider would take
            it as a path separator.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $key = $Root.OpenSubKey($Path)
    if ($null -eq $key) { return $null }

    try {
        $values = @{}
        foreach ($name in $key.GetValueNames()) {
            if ($name) {
                $values[$name] = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        return $values
    }
    finally {
        $key.Dispose()
    }
}

function Get-RegistrySubKeyName {
    <#
        .SYNOPSIS
            Subkey names of one key below Root, or $null when the key does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $key = $Root.OpenSubKey($Path)
    if ($null -eq $key) { return $null }

    try {
        return , $key.GetSubKeyNames()
    }
    finally {
        $key.Dispose()
    }
}

function Get-KeyPath {
    <#
        .SYNOPSIS
            A registry key path without a hive prefix or surrounding backslashes,
            the form PolicyManager, RSoP and Registry.pol files are compared in.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key
    )

    return ($Key.Trim('\') -replace '^(HKEY_LOCAL_MACHINE|HKLM:?|MACHINE)\\', '').TrimEnd('\')
}

function Get-LocationId {
    <#
        .SYNOPSIS
            The case-insensitive identity of one registry value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    return ('{0}|{1}' -f (Get-KeyPath -Key $Key), $ValueName).ToLowerInvariant()
}

function ConvertTo-ValueText {
    <#
        .SYNOPSIS
            A registry value as comparable text: DWORDs and QWORDs unsigned,
            multi-strings joined with '; ', binary data as base64.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    if ($Value -is [int]) { return [string][BitConverter]::ToUInt32([BitConverter]::GetBytes($Value), 0) }
    if ($Value -is [long]) { return [string][BitConverter]::ToUInt64([BitConverter]::GetBytes($Value), 0) }
    if ($Value -is [array]) { return (@($Value) -join '; ') }
    return [string]$Value
}

function ConvertFrom-PolicyValue {
    <#
        .SYNOPSIS
            Policy data stored as raw bytes and a registry type - in RSoP and in
            Registry.pol files - as the same text ConvertTo-ValueText gives for
            the value in the registry.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]$Data,

        [Parameter(Mandatory)]
        [uint32]$Type
    )

    if ($null -eq $Data) { return $null }

    switch ($Type) {
        { $_ -in 1, 2 } {
            return [Text.Encoding]::Unicode.GetString($Data).TrimEnd([char]0)
        }
        7 {
            $parts = [Text.Encoding]::Unicode.GetString($Data).Split([char]0) | Where-Object { $_ -ne '' }
            return (@($parts) -join '; ')
        }
        4 {
            if ($Data.Length -ge 4) { return [string][BitConverter]::ToUInt32($Data, 0) }
        }
        5 {
            if ($Data.Length -ge 4) {
                $copy = $Data[0..3]
                [Array]::Reverse($copy)
                return [string][BitConverter]::ToUInt32([byte[]]$copy, 0)
            }
        }
        11 {
            if ($Data.Length -ge 8) { return [string][BitConverter]::ToUInt64($Data, 0) }
        }
    }

    if ($Data.Length -eq 0) { return '' }
    return [Convert]::ToBase64String($Data)
}

function Get-LiveValue {
    <#
        .SYNOPSIS
            The value Windows reads now, as text, or $null when it is not set.
            A key the caller may not read gives '(not readable)' rather than
            failing the run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Name
    )

    try {
        $handle = $Root.OpenSubKey((Get-KeyPath -Key $Key))
    }
    catch [System.Security.SecurityException] {
        return '(not readable)'
    }
    if ($null -eq $handle) { return $null }

    try {
        return ConvertTo-ValueText -Value $handle.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    finally {
        $handle.Dispose()
    }
}

function Test-AdmxState {
    <#
        .SYNOPSIS
            True when an MDM value is an ADMX state (<enabled/> or <disabled/>)
            rather than a value the registry would hold.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    return [bool]($Value -match '^\s*<(enabled|disabled)\s*/>')
}

function Format-MdmValue {
    <#
        .SYNOPSIS
            An MDM value for display. An ADMX state becomes Enabled or Disabled,
            with any data elements as id=value pairs.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value -match '^\s*<disabled\s*/>') { return 'Disabled' }
    if ($Value -notmatch '^\s*<enabled\s*/>') { return $Value }

    $pairs = foreach ($match in [regex]::Matches($Value, '<data\s+id="([^"]*)"\s+value="([^"]*)"\s*/>')) {
        '{0}={1}' -f $match.Groups[1].Value, $match.Groups[2].Value
    }
    if (@($pairs).Count -eq 0) { return 'Enabled' }
    return 'Enabled: ' + (@($pairs) -join '; ')
}

function Get-EnrollmentSource {
    <#
        .SYNOPSIS
            For each enrollment ID, who it stands for: Intune, another MDM, or
            Windows itself.

        .DESCRIPTION
            PolicyManager records the winning enrollment of each setting. The
            Intune enrollment has ProviderID 'MS DM Server'. Enrollments of type 1
            without a ProviderID are Windows' own: they provision power and
            processor tuning and a few security defaults.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root
    )

    $sources = @{}
    $ids = Get-RegistrySubKeyName -Root $Root -Path 'SOFTWARE\Microsoft\Enrollments'
    if ($null -eq $ids) { return $sources }

    foreach ($id in $ids) {
        $values = Get-RegistryValueSet -Root $Root -Path "SOFTWARE\Microsoft\Enrollments\$id"
        if ($null -eq $values) { continue }

        $provider = [string]$values['ProviderID']
        if ($provider -eq 'MS DM Server') {
            $sources[$id] = [pscustomobject]@{ Label = 'Intune'; Kind = 'Intune' }
        }
        elseif ($provider) {
            $sources[$id] = [pscustomobject]@{ Label = $provider; Kind = 'Other' }
        }
        elseif ($null -ne $values['EnrollmentType']) {
            if ([int]$values['EnrollmentType'] -eq 1) {
                $sources[$id] = [pscustomobject]@{ Label = 'Windows'; Kind = 'Windows' }
            }
            else {
                $sources[$id] = [pscustomobject]@{ Label = ('Windows enrollment type {0}' -f $values['EnrollmentType']); Kind = 'Other' }
            }
        }
    }

    return $sources
}

function Get-AdmxMetadataIndex {
    <#
        .SYNOPSIS
            Where PolicyManager keeps the metadata of each ingested ADMX policy:
            'area|policy' to the key path under AdmxDefault.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root
    )

    $index = @{}
    $base = "$PolicyManagerPath\AdmxDefault"
    $owners = Get-RegistrySubKeyName -Root $Root -Path $base
    if ($null -eq $owners) { return $index }

    foreach ($owner in $owners) {
        $areas = Get-RegistrySubKeyName -Root $Root -Path "$base\$owner"
        if ($null -eq $areas) { continue }
        foreach ($area in $areas) {
            $policies = Get-RegistrySubKeyName -Root $Root -Path "$base\$owner\$area"
            if ($null -eq $policies) { continue }
            foreach ($policy in $policies) {
                $index[('{0}|{1}' -f $area, $policy).ToLowerInvariant()] = "$base\$owner\$area\$policy"
            }
        }
    }

    return $index
}

function Get-MdmPolicy {
    <#
        .SYNOPSIS
            Every device-scope setting in PolicyManager: its value, the winning
            enrollment, and the registry value it maps to.

        .DESCRIPTION
            current\device\<Area> lists each setting. Its value is there, or -
            for a setting stored at its registry location - only in the store of
            the winning enrollment, providers\<id>\default\device\<Area>; the
            current key then holds just <Policy>_ProviderSet and
            <Policy>_WinningProvider.

            The mapping comes from the setting's metadata, in default\<Area>
            for settings built into Windows and in AdmxDefault for ingested
            ADMX: RegKeyPathRedirect and RegValueNameRedirect name the registry
            value the setting writes, and GPBlockingRegKeyPath and
            GPBlockingRegValueName the Group Policy value MDMWinsOverGP blocks.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [hashtable]$Source
    )

    $metadataSuffix = '^(.+)_(ProviderSet|WinningProvider|LastWrite|ADMXInstanceData|Dirty)$'
    $areas = Get-RegistrySubKeyName -Root $Root -Path "$PolicyManagerPath\current\device"
    if ($null -eq $areas) { return }

    $builtIn = @{}
    $defaultAreas = Get-RegistrySubKeyName -Root $Root -Path "$PolicyManagerPath\default"
    if ($null -ne $defaultAreas) {
        foreach ($area in $defaultAreas) { $builtIn[$area] = $true }
    }
    $admxIndex = Get-AdmxMetadataIndex -Root $Root
    $unknown = [pscustomobject]@{ Label = 'Unknown'; Kind = 'Other' }

    foreach ($area in $areas) {
        $values = Get-RegistryValueSet -Root $Root -Path "$PolicyManagerPath\current\device\$area"
        if ($null -eq $values) { continue }

        $names = @{}
        foreach ($name in @($values.Keys)) {
            if ($name -match $metadataSuffix) { $names[$Matches[1]] = $true }
            else { $names[$name] = $true }
        }

        $isBuiltIn = $builtIn.ContainsKey($area)
        foreach ($name in @($names.Keys)) {
            # Metadata with a suffix not listed above is skipped, not taken for a setting.
            $cut = $name.LastIndexOf('_')
            if ($cut -gt 0 -and $names.ContainsKey($name.Substring(0, $cut))) { continue }

            $lookup = ('{0}|{1}' -f $area, $name).ToLowerInvariant()
            $metadata = $null
            if ($isBuiltIn) {
                $metadata = Get-RegistryValueSet -Root $Root -Path "$PolicyManagerPath\default\$area\$name"
            }
            elseif ($admxIndex.ContainsKey($lookup)) {
                $metadata = Get-RegistryValueSet -Root $Root -Path $admxIndex[$lookup]
            }
            if ($null -eq $metadata) { $metadata = @{} }

            $winner = [string]$values["${name}_WinningProvider"]
            $value = $null
            if ($values.ContainsKey($name)) {
                $value = ConvertTo-ValueText -Value $values[$name]
            }
            elseif ($winner) {
                $stored = Get-RegistryValueSet -Root $Root -Path "$PolicyManagerPath\providers\$winner\default\device\$area"
                if ($null -ne $stored -and $stored.ContainsKey($name)) {
                    $value = ConvertTo-ValueText -Value $stored[$name]
                }
            }

            $owner = $unknown
            if ($winner -and $Source.ContainsKey($winner)) { $owner = $Source[$winner] }

            [pscustomobject]@{
                Name          = "$area/$name"
                Value         = $value
                Source        = $owner.Label
                SourceKind    = $owner.Kind
                AdmxBacked    = (-not $isBuiltIn) -or ($area -like 'ADMX_*') -or $metadata.ContainsKey('AdmxMetadataDevice') -or
                    $metadata.ContainsKey('AdmxMetadataBoth') -or $metadata.ContainsKey('AdmxMetadataUser')
                RedirectKey   = [string]$metadata['RegKeyPathRedirect']
                RedirectValue = [string]$metadata['RegValueNameRedirect']
                BlockKey      = [string]$metadata['GPBlockingRegKeyPath']
                BlockValue    = [string]$metadata['GPBlockingRegValueName']
            }
        }
    }
}

function Get-CimValue {
    <#
        .SYNOPSIS
            A property of a CIM instance, or $null when the class has no such
            property, without tripping strict mode.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Instance,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $property = $Instance.CimInstanceProperties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-AppliedGroupPolicy {
    <#
        .SYNOPSIS
            The GPOs and the applied registry settings, from the RSoP data
            Windows logs at every Group Policy refresh.

        .DESCRIPTION
            Entries without a value name create keys, and entries starting with
            ** are instructions (delete a value, a key); neither is a setting.
            Every GPO that took part is returned, with whether it applied.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    $namespace = 'root\rsop\computer'
    $gpos = @{}
    foreach ($gpo in @(Get-CimInstance -Namespace $namespace -ClassName 'RSOP_GPO' -OperationTimeoutSec 120 -ErrorAction Stop)) {
        $id = [string](Get-CimValue -Instance $gpo -Name 'id')
        $guid = [string](Get-CimValue -Instance $gpo -Name 'guidName')
        if (-not $guid -and $id -match '\{[0-9A-Fa-f-]{36}\}') { $guid = $Matches[0] }

        $applied = $true
        foreach ($flag in @(@('enabled', $true), @('filterAllowed', $true), @('accessDenied', $false))) {
            $state = Get-CimValue -Instance $gpo -Name $flag[0]
            if ($null -ne $state -and [bool]$state -ne $flag[1]) { $applied = $false }
        }

        # A domain GPO's id is its directory path; the local GPO's is not. Only domain GPOs are cached.
        $gpos[$id] = [pscustomobject]@{
            Guid    = $guid.ToUpperInvariant()
            Name    = [string](Get-CimValue -Instance $gpo -Name 'name')
            Applied = $applied
            Domain  = $id -like 'cn=*'
        }
    }

    $entries = foreach ($setting in @(Get-CimInstance -Namespace $namespace -ClassName 'RSOP_RegistryPolicySetting' -OperationTimeoutSec 120 -ErrorAction Stop)) {
        $valueName = [string](Get-CimValue -Instance $setting -Name 'valueName')
        if (-not $valueName.Trim() -or $valueName.StartsWith('**')) { continue }

        $gpoId = [string](Get-CimValue -Instance $setting -Name 'GPOID')
        $gpoName = $gpoId
        if ($gpos.ContainsKey($gpoId)) { $gpoName = $gpos[$gpoId].Name }
        $type = Get-CimValue -Instance $setting -Name 'valueType'
        if ($null -eq $type) { $type = 0 }

        [pscustomobject]@{
            Key        = Get-KeyPath -Key ([string](Get-CimValue -Instance $setting -Name 'registryKey'))
            ValueName  = $valueName
            Value      = ConvertFrom-PolicyValue -Data (Get-CimValue -Instance $setting -Name 'value') -Type ([uint32]$type)
            Precedence = [int](Get-CimValue -Instance $setting -Name 'precedence')
            GpoName    = $gpoName
        }
    }

    return [pscustomobject]@{ Gpo = $gpos; Entry = @($entries) }
}

function Read-RegistryPolString {
    <#
        .SYNOPSIS
            One null-terminated UTF-16LE string from a Registry.pol buffer, and
            the position after its terminator.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [Parameter(Mandatory)]
        [int]$Start
    )

    $end = $Start
    while ($end + 1 -lt $Bytes.Length -and ($Bytes[$end] -ne 0 -or $Bytes[$end + 1] -ne 0)) { $end += 2 }
    if ($end + 1 -ge $Bytes.Length) { throw "a string starting at byte $Start has no terminator" }

    return [pscustomobject]@{
        Text = [Text.Encoding]::Unicode.GetString($Bytes, $Start, $end - $Start)
        Next = $end + 2
    }
}

function Assert-RegistryPolCharacter {
    <#
        .SYNOPSIS
            Throws unless the UTF-16LE character at Position is the expected
            delimiter.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [Parameter(Mandatory)]
        [int]$Position,

        [Parameter(Mandatory)]
        [char]$Character
    )

    if ($Position + 1 -ge $Bytes.Length -or $Bytes[$Position] -ne [byte]$Character -or $Bytes[$Position + 1] -ne 0) {
        throw "expected '$Character' at byte $Position"
    }
}

function ConvertFrom-RegistryPol {
    <#
        .SYNOPSIS
            The entries of a Registry.pol file: the PReg header, then
            [key;value;type;size;data] records in UTF-16LE.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Source = 'The file'
    )

    if ($Bytes.Length -lt 8 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x67655250) {
        throw "$Source is not a registry policy file: the PReg signature is missing."
    }

    $position = 8
    try {
        while ($position -lt $Bytes.Length) {
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $position -Character '['
            $key = Read-RegistryPolString -Bytes $Bytes -Start ($position + 2)
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $key.Next -Character ';'
            $name = Read-RegistryPolString -Bytes $Bytes -Start ($key.Next + 2)
            $position = $name.Next
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $position -Character ';'
            if ($position + 14 -gt $Bytes.Length) { throw "the record at byte $position is cut short" }
            $type = [BitConverter]::ToUInt32($Bytes, $position + 2)
            Assert-RegistryPolCharacter -Bytes $Bytes -Position ($position + 6) -Character ';'
            $size = [BitConverter]::ToUInt32($Bytes, $position + 8)
            Assert-RegistryPolCharacter -Bytes $Bytes -Position ($position + 12) -Character ';'
            $position += 14
            if ($position + $size -gt $Bytes.Length) { throw "the data at byte $position runs past the end" }
            $data = New-Object -TypeName byte[] -ArgumentList $size
            [Array]::Copy($Bytes, $position, $data, 0, $size)
            $position += $size
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $position -Character ']'
            $position += 2

            [pscustomobject]@{
                Key       = Get-KeyPath -Key $key.Text
                ValueName = $name.Text
                Type      = $type
                Value     = ConvertFrom-PolicyValue -Data $data -Type $type
            }
        }
    }
    catch {
        throw "$Source is malformed: $($_.Exception.Message)."
    }
}

function Get-GpoCacheEntry {
    <#
        .SYNOPSIS
            The computer registry settings in Windows' local copy of each
            applied GPO.

        .DESCRIPTION
            Windows keeps a copy of each GPO it downloads under
            System32\GroupPolicy\DataStore. Its Machine\Registry.pol holds every
            computer registry setting the GPO makes, including those that were
            not applied: RSoP lists only what was. Copies of GPOs that no longer
            apply are skipped by GUID.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [hashtable]$AppliedGpo
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }

    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -Recurse -Filter 'Registry.pol' -File -ErrorAction Stop)) {
        if ($file.Directory.Name -ne 'Machine') { continue }
        $guid = $file.Directory.Parent.Name.ToUpperInvariant()
        if (-not $AppliedGpo.ContainsKey($guid)) { continue }

        foreach ($entry in @(ConvertFrom-RegistryPol -Bytes ([IO.File]::ReadAllBytes($file.FullName)) -Source "The cached GPO $guid")) {
            if (-not $entry.ValueName.Trim() -or $entry.ValueName.StartsWith('**')) { continue }
            [pscustomobject]@{
                Key       = $entry.Key
                ValueName = $entry.ValueName
                Value     = $entry.Value
                GpoName   = $AppliedGpo[$guid]
            }
        }
    }
}

function ConvertFrom-PreferenceValue {
    <#
        .SYNOPSIS
            A Group Policy Preferences registry value as comparable text. The
            XML holds DWORDs and QWORDs as hexadecimal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Type,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Type -eq 'REG_DWORD' -and $Value -match '^[0-9A-Fa-f]{1,8}$') { return [string][Convert]::ToUInt32($Value, 16) }
    if ($Type -eq 'REG_QWORD' -and $Value -match '^[0-9A-Fa-f]{1,16}$') { return [string][Convert]::ToUInt64($Value, 16) }
    return $Value
}

function Get-PreferenceRegistryItem {
    <#
        .SYNOPSIS
            Computer registry items of Group Policy Preferences, from the
            history Windows keeps for each applied GPO.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [hashtable]$AppliedGpo
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }

    foreach ($folder in @(Get-ChildItem -LiteralPath $Directory -Directory -ErrorAction Stop)) {
        $guid = $folder.Name.ToUpperInvariant()
        if (-not $AppliedGpo.ContainsKey($guid)) { continue }
        $file = Join-Path -Path $folder.FullName -ChildPath 'Machine\Preferences\Registry\Registry.xml'
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }

        $xml = New-Object -TypeName System.Xml.XmlDocument
        $xml.Load($file)
        foreach ($node in $xml.SelectNodes("//*[local-name()='Properties']")) {
            # 'D' deletes the value, so it sets nothing.
            if ($node.GetAttribute('hive') -ne 'HKEY_LOCAL_MACHINE' -or $node.GetAttribute('action') -eq 'D') { continue }
            $name = $node.GetAttribute('name')
            if ($node.GetAttribute('default') -eq '1') { $name = '' }

            [pscustomobject]@{
                Key       = Get-KeyPath -Key $node.GetAttribute('key')
                ValueName = $name
                Value     = ConvertFrom-PreferenceValue -Type $node.GetAttribute('type') -Value $node.GetAttribute('value')
                GpoName   = $AppliedGpo[$guid]
            }
        }
    }
}

function Get-RegistryValueLocation {
    <#
        .SYNOPSIS
            Every value under one key below Root, as Key and ValueName pairs.
            Stops after MaxKeys keys, so a huge tree cannot stall the run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxKeys = 20000
    )

    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    $visited = 0

    while ($pending.Count -gt 0) {
        if ($visited -ge $MaxKeys) {
            Write-Warning "Stopped reading HKLM\$Path after $MaxKeys keys; values below the rest are not checked."
            return
        }
        $current = $pending.Pop()
        try {
            $key = $Root.OpenSubKey($current)
        }
        catch [System.Security.SecurityException] {
            Write-LogEntry -Message "No read access to HKLM\$current; its values are not checked." -Level WARN
            continue
        }
        if ($null -eq $key) { continue }

        try {
            $visited++
            foreach ($name in $key.GetValueNames()) {
                [pscustomobject]@{ Key = $current; ValueName = $name }
            }
            foreach ($sub in $key.GetSubKeyNames()) { $pending.Push("$current\$sub") }
        }
        finally {
            $key.Dispose()
        }
    }
}

function Get-PolicyLocation {
    <#
        .SYNOPSIS
            The record for one registry value in Table, created when missing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Table,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    $id = Get-LocationId -Key $Key -ValueName $ValueName
    if (-not $Table.ContainsKey($id)) {
        $Table[$id] = [pscustomobject]@{
            Key       = Get-KeyPath -Key $Key
            ValueName = $ValueName
            Applied   = [System.Collections.Generic.List[object]]::new()
            Cached    = [System.Collections.Generic.List[object]]::new()
            Preferred = [System.Collections.Generic.List[object]]::new()
            Mdm       = [System.Collections.Generic.List[object]]::new()
        }
    }
    return $Table[$id]
}

function Find-KeyClaim {
    <#
        .SYNOPSIS
            The ADMX-backed MDM settings that write under Key or one of its
            parents, or nothing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Claim,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key
    )

    $path = (Get-KeyPath -Key $Key).ToLowerInvariant()
    while ($path) {
        if ($Claim.ContainsKey($path)) { return $Claim[$path].ToArray() }
        $cut = $path.LastIndexOf('\')
        if ($cut -lt 0) { break }
        $path = $path.Substring(0, $cut)
    }
    # Nothing, not $null: the caller wraps the result in @(), and @($null) holds one item.
    return
}

function ConvertTo-PolicySourceRow {
    <#
        .SYNOPSIS
            One result row, showing the main columns by default.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Property
    )

    $row = [pscustomobject][ordered]@{
        Verdict       = $Property['Verdict']
        Setting       = $Property['Setting']
        LiveValue     = $Property['LiveValue']
        GpValue       = $Property['GpValue']
        Gpo           = $Property['Gpo']
        OverriddenGpo = $Property['OverriddenGpo']
        GpSource      = $Property['GpSource']
        MdmSetting    = $Property['MdmSetting']
        MdmValue      = $Property['MdmValue']
        MdmSource     = $Property['MdmSource']
        MdmSourceKind = $Property['MdmSourceKind']
        RegistryPath  = $Property['RegistryPath']
        Note          = $Property['Note']
    }

    $columns = [string[]]@('Verdict', 'Setting', 'LiveValue', 'GpValue', 'Gpo', 'MdmValue', 'MdmSource')
    $display = New-Object -TypeName System.Management.Automation.PSPropertySet -ArgumentList 'DefaultDisplayPropertySet', $columns
    Add-Member -InputObject $row -MemberType MemberSet -Name PSStandardMembers -ErrorAction Stop `
        -Value ([System.Management.Automation.PSMemberInfo[]]@($display))
    return $row
}

function Resolve-PolicySource {
    <#
        .SYNOPSIS
            Puts every source side by side, one row per registry value, plus a
            row for each MDM setting with no single registry value, and gives
            each a verdict.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Mdm,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$GpApplied,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$GpCached,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Preference,

        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter()]
        [bool]$MdmWinsOverGp
    )

    $locations = @{}
    foreach ($entry in $GpApplied) { (Get-PolicyLocation -Table $locations -Key $entry.Key -ValueName $entry.ValueName).Applied.Add($entry) }
    foreach ($entry in $GpCached) { (Get-PolicyLocation -Table $locations -Key $entry.Key -ValueName $entry.ValueName).Cached.Add($entry) }
    foreach ($entry in $Preference) { (Get-PolicyLocation -Table $locations -Key $entry.Key -ValueName $entry.ValueName).Preferred.Add($entry) }

    $gpKeys = @{}
    foreach ($entry in $GpApplied) { $gpKeys[(Get-KeyPath -Key $entry.Key).ToLowerInvariant()] = $true }

    # Each MDM setting goes to the registry value it writes. The value MDMWinsOverGP
    # blocks is used too, but only where Group Policy has something there.
    $claims = @{}
    $unplaced = [System.Collections.Generic.List[object]]::new()
    foreach ($policy in $Mdm) {
        $placed = $false
        if ($policy.RedirectKey -and $policy.RedirectValue) {
            (Get-PolicyLocation -Table $locations -Key $policy.RedirectKey -ValueName $policy.RedirectValue).Mdm.Add($policy)
            $placed = $true
        }
        if ($policy.BlockKey -and $policy.BlockValue) {
            $id = Get-LocationId -Key $policy.BlockKey -ValueName $policy.BlockValue
            if ($locations.ContainsKey($id)) {
                $location = $locations[$id]
                if (-not $location.Mdm.Contains($policy) -and
                    ($location.Applied.Count + $location.Cached.Count + $location.Preferred.Count) -gt 0) {
                    $location.Mdm.Add($policy)
                    $placed = $true
                }
            }
        }
        if ($policy.AdmxBacked -and $policy.RedirectKey) {
            $claimKey = (Get-KeyPath -Key $policy.RedirectKey).ToLowerInvariant()
            if (-not $claims.ContainsKey($claimKey)) { $claims[$claimKey] = [System.Collections.Generic.List[object]]::new() }
            $claims[$claimKey].Add($policy)
        }
        if (-not $placed) { $unplaced.Add($policy) }
    }

    # Values nobody claims are found by reading what is there.
    foreach ($value in @(Get-RegistryValueLocation -Root $Root -Path $PoliciesPath)) {
        $null = Get-PolicyLocation -Table $locations -Key $value.Key -ValueName $value.ValueName
    }

    $switchState = if ($MdmWinsOverGp) { 'on' } else { 'off' }
    foreach ($location in $locations.Values) {
        $live = Get-LiveValue -Root $Root -Key $location.Key -Name $location.ValueName
        $applied = @($location.Applied | Sort-Object -Property Precedence)
        $cached = $location.Cached.ToArray()
        $preferred = $location.Preferred.ToArray()
        # An external MDM before Windows' own provisioning, when both write one value.
        $mdmPolicies = @($location.Mdm | Sort-Object -Property { $_.SourceKind -eq 'Windows' })
        $notes = [System.Collections.Generic.List[string]]::new()

        $gpValue = $null; $gpo = $null; $gpSource = $null; $overridden = $null
        if ($applied.Count -gt 0) {
            $gpValue = $applied[0].Value
            $gpo = $applied[0].GpoName
            $gpSource = 'Registry policy'
            $losers = @($applied | Select-Object -Skip 1 | ForEach-Object { $_.GpoName } | Select-Object -Unique)
            if ($losers.Count -gt 0) { $overridden = $losers -join '; ' }
        }
        elseif ($preferred.Count -gt 0) {
            $gpValue = $preferred[0].Value
            $gpo = $preferred[0].GpoName
            $gpSource = 'Preferences'
        }
        elseif ($cached.Count -gt 0) {
            $gpValue = $cached[0].Value
            $gpo = (@($cached | ForEach-Object { $_.GpoName } | Select-Object -Unique) -join '; ')
            $gpSource = 'GPO, not applied'
        }
        $gpApplies = $applied.Count -gt 0 -or $preferred.Count -gt 0

        $policy = $null
        if ($mdmPolicies.Count -gt 0) {
            $policy = $mdmPolicies[0]
            if ($mdmPolicies.Count -gt 1) {
                $notes.Add(('{0} MDM settings write this value: {1}.' -f $mdmPolicies.Count, (@($mdmPolicies | ForEach-Object { $_.Name }) -join ', ')))
            }
        }
        $mdmValue = $null
        $admx = $false
        if ($null -ne $policy) {
            $mdmValue = Format-MdmValue -Value $policy.Value
            $admx = Test-AdmxState -Value $policy.Value
        }
        $claimants = @(Find-KeyClaim -Claim $claims -Key $location.Key)
        $keyClaim = $null
        if ($claimants.Count -gt 0) { $keyClaim = (@($claimants | ForEach-Object { $_.Name }) -join '; ') }

        if ($null -ne $policy) {
            if ($gpApplies) {
                if ($admx) {
                    $verdict = 'Both'
                    $notes.Add('Intune sends an ADMX state, not a value, so the two are not compared.')
                }
                elseif ($gpValue -eq $policy.Value) {
                    $verdict = 'Agree'
                }
                else {
                    $verdict = 'Conflict'
                    $holder = 'neither side'
                    if ($live -eq $gpValue) { $holder = 'Group Policy' }
                    elseif ($live -eq $policy.Value) { $holder = $policy.Source }
                    $notes.Add(('The registry holds the value of {0}. MDMWinsOverGP is {1}.' -f $holder, $switchState))
                }
            }
            elseif ($cached.Count -gt 0) {
                $verdict = 'OverriddenByMdm'
                $comparison = if ($admx) { 'Intune sends an ADMX state, so the values are not compared' }
                elseif ($gpValue -eq $policy.Value) { 'both set the same value' }
                else { 'the values differ' }
                $notes.Add(('The GPO sets it, but {0} does and Group Policy did not apply it; {1}. MDMWinsOverGP is {2}.' -f
                        $policy.Source, $comparison, $switchState))
            }
            else {
                $verdict = 'MdmOnly'
                if (-not $admx -and $null -ne $live -and $live -ne $policy.Value) {
                    $notes.Add('The registry holds a different value: something wrote it after the MDM did.')
                }
            }
        }
        elseif ($gpApplies) {
            $verdict = 'GpOnly'
            if ($null -ne $live -and $live -ne $gpValue) {
                $notes.Add('The registry holds a different value: something wrote it after Group Policy did.')
            }
            if ($keyClaim) { $notes.Add(('Intune ADMX settings also write under this key: {0}.' -f $keyClaim)) }
        }
        elseif ($cached.Count -gt 0) {
            if ($keyClaim) {
                $verdict = 'OverriddenByMdm'
                $notes.Add(('The GPO sets it, but Group Policy did not apply it; Intune ADMX settings write under this key: {0}. MDMWinsOverGP is {1}.' -f
                        $keyClaim, $switchState))
            }
            else {
                $verdict = 'NotApplied'
                $notes.Add('The GPO sets it, but Group Policy did not apply it, and no MDM setting writes it. A client-side extension may have failed; check the Group Policy operational log.')
            }
        }
        elseif ($location.Key -like 'SOFTWARE\Policies\Microsoft\Windows\Wireless\*') {
            $verdict = 'GpOnly'
            $gpSource = 'Wireless profile'
            $notes.Add('Written by the Wireless Group Policy extension, which RSoP does not list value by value.')
        }
        elseif ($keyClaim) {
            $verdict = 'MdmOnly'
            $notes.Add(('A value of an Intune ADMX setting that writes under this key: {0}.' -f $keyClaim))
        }
        else {
            $verdict = 'Unclaimed'
            $notes.Add('None of the sources sets it: a script, an app, another management tool, or a Windows default.')
        }

        $valueLabel = if ($location.ValueName) { $location.ValueName } else { '(Default)' }
        $setting = "$($location.Key)\$valueLabel"
        if ($null -ne $policy) { $setting = $policy.Name }

        # A value matched to MDM only through its key is credited to the setting that writes the key.
        $mdmSetting = $null; $mdmSource = $null; $mdmSourceKind = $null
        if ($null -ne $policy) {
            $mdmSetting = (@($mdmPolicies | ForEach-Object { $_.Name }) -join '; ')
            $mdmSource = $policy.Source
            $mdmSourceKind = $policy.SourceKind
        }
        elseif ($claimants.Count -gt 0 -and $verdict -in 'MdmOnly', 'OverriddenByMdm') {
            $mdmSetting = $keyClaim
            $mdmSource = $claimants[0].Source
            $mdmSourceKind = $claimants[0].SourceKind
        }

        ConvertTo-PolicySourceRow -Property @{
            Verdict       = $verdict
            Setting       = $setting
            LiveValue     = $live
            GpValue       = $gpValue
            Gpo           = $gpo
            OverriddenGpo = $overridden
            GpSource      = $gpSource
            MdmSetting    = $mdmSetting
            MdmValue      = $mdmValue
            MdmSource     = $mdmSource
            MdmSourceKind = $mdmSourceKind
            RegistryPath  = "HKLM\$($location.Key)\$valueLabel"
            Note          = $(if ($notes.Count -gt 0) { $notes -join ' ' } else { $null })
        }
    }

    foreach ($policy in $unplaced) {
        $path = $null
        if ($policy.RedirectKey) {
            $path = 'HKLM\' + (Get-KeyPath -Key $policy.RedirectKey)
            $note = 'ADMX-backed: writes one or more values under this key.'
            if ($gpKeys.ContainsKey((Get-KeyPath -Key $policy.RedirectKey).ToLowerInvariant())) {
                $note += ' Group Policy also sets values under this key.'
            }
        }
        else {
            $note = 'No registry value: Windows reads this setting from PolicyManager.'
        }

        ConvertTo-PolicySourceRow -Property @{
            Verdict       = 'MdmOnly'
            Setting       = $policy.Name
            MdmSetting    = $policy.Name
            MdmValue      = Format-MdmValue -Value $policy.Value
            MdmSource     = $policy.Source
            MdmSourceKind = $policy.SourceKind
            RegistryPath  = $path
            Note          = $note
        }
    }
}

function Select-PolicySource {
    <#
        .SYNOPSIS
            The rows the caller asked for, most important verdict first.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Row,

        [Parameter()]
        [AllowNull()]
        [string[]]$Filter,

        [Parameter()]
        [AllowNull()]
        [string[]]$Verdict,

        [Parameter()]
        [switch]$IncludeWindowsInternal
    )

    $selected = foreach ($candidate in $Row) {
        if (-not $IncludeWindowsInternal -and $candidate.Verdict -eq 'MdmOnly' -and $candidate.MdmSourceKind -eq 'Windows') { continue }
        if ($Verdict -and $Verdict -notcontains $candidate.Verdict) { continue }
        if ($Filter) {
            $matched = $false
            foreach ($pattern in $Filter) {
                foreach ($text in @($candidate.Setting, $candidate.RegistryPath, $candidate.MdmSetting, $candidate.Gpo)) {
                    if ($text -and $text -like $pattern) { $matched = $true; break }
                }
                if ($matched) { break }
            }
            if (-not $matched) { continue }
        }
        $candidate
    }

    if ($null -eq $selected) { return }
    @($selected) | Sort-Object -Property @{ Expression = { $VerdictRank[$_.Verdict] } }, Setting
}

$machine = $null
try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Write-LogEntry -Message "Started. PowerShell $($PSVersionTable.PSVersion); host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' })."

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Get-PolicySource runs on Windows only: it reads the Windows registry and RSoP data.'
    }
    if (-not (Test-Elevated)) {
        throw 'Run this from an elevated PowerShell. The Group Policy results (RSoP) and the GPO cache can only be read by an administrator.'
    }

    # The 64-bit view, so a 32-bit PowerShell reads the same keys Windows does.
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading MDM policy'
    $sources = Get-EnrollmentSource -Root $machine
    $mdm = @(Get-MdmPolicy -Root $machine -Source $sources)
    $mdmWinsOverGp = (Get-LiveValue -Root $machine -Key "$PolicyManagerPath\current\device\ControlPolicyConflict" -Name 'MDMWinsOverGP') -eq '1'
    Write-LogEntry -Message ('MDM settings: {0}. MDMWinsOverGP: {1}.' -f $mdm.Count, $mdmWinsOverGp)

    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading Group Policy results'
    # The ADMX policy 'Turn off Resultant Set of Policy logging' sets RSoPLogging to 0.
    if ((Get-LiveValue -Root $machine -Key "$PoliciesPath\Microsoft\Windows\System" -Name 'RSoPLogging') -eq '0') {
        throw ('RSoP logging is turned off on this device (policy "Turn off Resultant Set of Policy logging"), so ' +
            'the applied Group Policy cannot be read. Without it every Group Policy setting would look missing.')
    }
    try {
        $rsop = Get-AppliedGroupPolicy
    }
    catch {
        throw "Could not read the Group Policy results from WMI (root\rsop\computer): $($_.Exception.Message)"
    }
    $appliedGpo = @{}
    foreach ($gpo in $rsop.Gpo.Values) {
        if ($gpo.Applied -and $gpo.Domain -and $gpo.Guid) { $appliedGpo[$gpo.Guid] = $gpo.Name }
    }
    Write-LogEntry -Message ('Applied registry policy entries: {0}; domain GPOs applied: {1}.' -f $rsop.Entry.Count, $appliedGpo.Count)

    # The cache and the Preferences history add to RSoP; without them the run is still useful.
    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading the GPO cache'
    $cached = @()
    if ($appliedGpo.Count -gt 0 -and -not (Test-Path -LiteralPath $GpoCacheDirectory -PathType Container)) {
        Write-Warning ("No GPO cache at $GpoCacheDirectory. Settings a GPO holds but did not apply - OverriddenByMdm " +
            'and NotApplied - cannot be found.')
    }
    try {
        $cached = @(Get-GpoCacheEntry -Directory $GpoCacheDirectory -AppliedGpo $appliedGpo)
    }
    catch {
        Write-Warning "The GPO cache could not be read, so OverriddenByMdm and NotApplied cannot be found: $($_.Exception.Message)"
        Write-LogEntry -Message "GPO cache: $($_.Exception.Message)" -Level WARN
    }
    $preferences = @()
    try {
        $preferences = @(Get-PreferenceRegistryItem -Directory $PreferencesHistoryDirectory -AppliedGpo $appliedGpo)
    }
    catch {
        Write-Warning "The Group Policy Preferences history could not be read, so its registry items show as Unclaimed: $($_.Exception.Message)"
        Write-LogEntry -Message "Preferences history: $($_.Exception.Message)" -Level WARN
    }
    Write-LogEntry -Message ('GPO cache entries: {0}; Preferences registry items: {1}.' -f $cached.Count, $preferences.Count)

    Write-Progress -Activity 'Get-PolicySource' -Status 'Matching the sources'
    $rows = @(Resolve-PolicySource -Mdm $mdm -GpApplied $rsop.Entry -GpCached $cached -Preference $preferences -Root $machine -MdmWinsOverGp $mdmWinsOverGp)
    $result = @(Select-PolicySource -Row $rows -Filter $Filter -Verdict $Verdict -IncludeWindowsInternal:$IncludeWindowsInternal)
    Write-Progress -Activity 'Get-PolicySource' -Completed

    $summary = (@($rows | Group-Object -Property Verdict | Sort-Object -Property { $VerdictRank[$_.Name] } |
                ForEach-Object { '{0} {1}' -f $_.Name, $_.Count }) -join ', ')
    Write-LogEntry -Message ('Finished in {0:N1} s. All settings: {1}. Returned: {2}.' -f $timer.Elapsed.TotalSeconds, $summary, $result.Count)

    $result
    exit $ExitSuccess
}
catch {
    $message = "Get-PolicySource failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber)." -Level ERROR
    Write-Error -Exception $_.Exception -Message $message -ErrorAction Continue
    exit $ExitFailure
}
finally {
    if ($null -ne $machine) { $machine.Dispose() }
}
