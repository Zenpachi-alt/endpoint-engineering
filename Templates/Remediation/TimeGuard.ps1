# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    TimeGuard: limits how often the heavy work in a remediation package runs.

.DESCRIPTION
    This file is neither deployed nor run. It holds the canonical copy of the
    TimeGuard region, which is pasted unchanged into both scripts of a package:
    endpoint-side scripts cannot depend on a module, so a shared block is the
    only way to reuse code between them.

    Dot-source the file to try the functions. Get-TimeGuardDecision reads no
    state, so any combination of times can be tested without a device:

        . .\Templates\Remediation\TimeGuard.ps1
        Get-TimeGuardDecision -Now ([datetime]::UtcNow) -IntervalDays 30 `
            -LastRun '2026-09-01T00:00:00.0000000Z'

    Templates/Remediation/README.md describes the rules and how the detection
    and remediation scripts each call the functions.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-22

    PowerShell    : Windows PowerShell 5.1, like the scripts it is pasted into.
    Context       : Whatever the host script uses. Writing the timestamps needs
                    write access to HKLM, which SYSTEM has.
    Modules       : None.
    Licensing     : None beyond that of the host script.
    Graph scopes  : None.
    Admin consent : Not applicable.
#>

[CmdletBinding()]
param ()

#region TimeGuard 1.0.0 - canonical copy in Templates/Remediation/TimeGuard.ps1
# Paste this region unchanged into both scripts of a package. The rules it
# implements are described in Templates/Remediation/README.md.

function Get-TimeGuardValue {
    <#
        .SYNOPSIS
            Reads one TimeGuard timestamp. Returns $null when the key or the
            value does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('LastDetection', 'LastRemediation')]
        [string]$ValueName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Root = 'SOFTWARE\EndpointEngineering\TimeGuard'
    )

    # The 64-bit view is opened explicitly so that a 32-bit and a 64-bit host
    # read the same key, rather than one of them landing in WOW6432Node.
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        $key = $baseKey.OpenSubKey("$Root\$Name")
        if ($null -eq $key) {
            return $null
        }

        try {
            $value = $key.GetValue($ValueName)
            if ($null -eq $value) {
                return $null
            }

            return [string]$value
        }
        finally {
            $key.Dispose()
        }
    }
    finally {
        $baseKey.Dispose()
    }
}

function Set-TimeGuardValue {
    <#
        .SYNOPSIS
            Writes one TimeGuard timestamp, or removes it when Value is empty.
            Restoring a previous value is how a run that did no heavy work is
            taken back.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('LastDetection', 'LastRemediation')]
        [string]$ValueName,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Root = 'SOFTWARE\EndpointEngineering\TimeGuard'
    )

    $target = "HKLM\$Root\$Name\$ValueName"
    $action = if ($Value) { "Set to '$Value'" } else { 'Remove' }

    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
        return
    }

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        # CreateSubKey opens the key for writing, creating it if necessary.
        $key = $baseKey.CreateSubKey("$Root\$Name")
        if ($null -eq $key) {
            throw "Could not open or create 'HKLM\$Root\$Name'."
        }

        try {
            if ($Value) {
                $key.SetValue($ValueName, $Value, [Microsoft.Win32.RegistryValueKind]::String)
            }
            else {
                $key.DeleteValue($ValueName, $false)
            }
        }
        finally {
            $key.Dispose()
        }
    }
    finally {
        $baseKey.Dispose()
    }
}

function ConvertFrom-TimeGuardValue {
    <#
        .SYNOPSIS
            Parses a stored round-trip ('o') timestamp into UTC. Returns $null
            for anything else, including an empty value.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    $parsed = [datetime]::MinValue
    $isValid = [datetime]::TryParseExact(
        $Value,
        'o',
        [cultureinfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed)

    if (-not $isValid) {
        return $null
    }

    return $parsed.ToUniversalTime()
}

function Get-TimeGuardDecision {
    <#
        .SYNOPSIS
            Decides whether the heavy work runs now, and says why.

        .DESCRIPTION
            Reads no state, so every rule can be tested with any combination
            of times. Returns an object with Run (bool), Reason (string) and
            LastRunUtc (the parsed LastRun, or $null).

            The work runs when the guard is off, when no usable timestamp
            exists, when the stored time is in the future, when a remediation
            started after the last run, or when the interval has elapsed. It
            is skipped only when the last run is recent and nothing has
            happened since. A guard that cannot decide lets the work run: it
            limits how often the work happens and must never stop it.

        .PARAMETER Now
            The current time, normally [datetime]::UtcNow.

        .PARAMETER LastRun
            This script's stored timestamp, as read from the registry.

        .PARAMETER LastRemediation
            The remediation's stored timestamp. Detection passes it so that
            the check Intune makes straight after a remediation always runs;
            the remediation leaves it out.

        .PARAMETER IntervalDays
            Minimum number of days between runs. 0 turns the guard off.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [datetime]$Now,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LastRun,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LastRemediation,

        [Parameter(Mandatory)]
        [ValidateRange(0, 3650)]
        [int]$IntervalDays
    )

    $format = 'yyyy-MM-dd HH:mm'
    $culture = [cultureinfo]::InvariantCulture
    $nowUtc = $Now.ToUniversalTime()
    $lastRunUtc = ConvertFrom-TimeGuardValue -Value $LastRun

    $decision = [pscustomobject]@{
        Run        = $true
        Reason     = ''
        LastRunUtc = $lastRunUtc
    }

    if ($IntervalDays -eq 0) {
        $decision.Reason = 'TimeGuard is off (interval 0 days).'
    }
    elseif ([string]::IsNullOrWhiteSpace($LastRun)) {
        $decision.Reason = 'No previous run is recorded.'
    }
    elseif ($null -eq $lastRunUtc) {
        $decision.Reason = "The recorded time '$LastRun' is not a valid timestamp."
    }
    elseif ($lastRunUtc -gt $nowUtc.AddMinutes(5)) {
        # Five minutes of tolerance absorbs a small clock correction without
        # treating it as a broken timestamp.
        $decision.Reason = "The recorded time $($lastRunUtc.ToString($format, $culture)) UTC is in the future; the clock was probably wrong when it was written."
    }
    else {
        $lastRemediationUtc = ConvertFrom-TimeGuardValue -Value $LastRemediation
        $dueUtc = $lastRunUtc.AddDays($IntervalDays)

        if ($null -ne $lastRemediationUtc -and $lastRemediationUtc -gt $lastRunUtc) {
            $decision.Reason = "A remediation started at $($lastRemediationUtc.ToString($format, $culture)) UTC, after the last run at $($lastRunUtc.ToString($format, $culture)) UTC. Running to verify it."
        }
        elseif ($nowUtc -lt $dueUtc) {
            $decision.Run = $false
            $decision.Reason = "Last run at $($lastRunUtc.ToString($format, $culture)) UTC. Next run due after $($dueUtc.ToString($format, $culture)) UTC."
        }
        else {
            $decision.Reason = "$IntervalDays days or more have passed since the last run at $($lastRunUtc.ToString($format, $culture)) UTC."
        }
    }

    return $decision
}

#endregion TimeGuard
