# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Remediation template for an Intune remediation script package.

.DESCRIPTION
    Copy this file, rename it after the setting it repairs (Repair-<Noun>.ps1),
    and replace the logic in the "Repair" and "Verify" regions. It is the
    counterpart to Test-<Noun>.ps1 and runs only when that script exits 1.

    The script makes the change, then re-checks it. A remediation that reports
    success without verifying is a remediation that silently stops working.

    Contract enforced by the Intune management extension:
      exit 0  Remediation succeeded.
      exit 1  Remediation failed. Intune retries on the configured schedule.

.PARAMETER RegistryPath
    Registry key holding the value to set. Replace with the real key.

.PARAMETER ValueName
    Name of the registry value to set.

.PARAMETER DesiredValue
    Value to write. Must match the expected value in the detection script.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Repair-ExampleSetting.ps1 -WhatIf -Verbose

    Shows what would change without touching the device. Intune never passes
    -WhatIf, so this is for local testing only.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-20

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM (Run this script using the logged-on credentials: No)
    Host          : 32-bit unless "Run script in 64-bit PowerShell" is set to
                    Yes. Must match the detection script, or the two will look
                    at different registry views.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. Keep the file ASCII-only.
    Modules       : None.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None.
    Admin consent : Not applicable.

    Reversibility : State whether this change can be undone, and how. A
                    remediation that runs on every device in a tenant is not the
                    place to discover that it cannot.

.LINK
    https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RegistryPath = 'HKLM:\SOFTWARE\EndpointEngineering\Example',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ValueName = 'ExampleSetting',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [int]$DesiredValue = 1,

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

$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path, or $null if logging is not possible.
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

# Named Write-LogEntry rather than Write-Log: PSScriptAnalyzer reports the
# latter as shadowing a command that exists in some PowerShell profiles, and
# a template should not teach people to override one.
function Write-LogEntry {
    <#
        .SYNOPSIS
            Appends a timestamped line to the log file and the verbose stream.
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

    $line = '{0} [{1}] [PID {2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $PID, $Message

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            $script:LogFile = $null
            Write-Warning "Logging stopped: $($_.Exception.Message)"
        }
    }

    Write-Verbose $line
}

function Write-ResultLine {
    <#
        .SYNOPSIS
            Writes the single STDOUT line Intune surfaces, truncated to the
            2048-character output limit.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    if ($Message.Length -gt 2048) {
        $Message = $Message.Substring(0, 2045) + '...'
    }

    Write-Output $Message
}

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Remediation started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-LogEntry -Message 'Running in a 32-bit host on a 64-bit OS. Registry and file system calls are redirected. The detection script must run in the same host.' -Level WARN
    }

    #region Repair
    # Replace everything in this region with the real change, gated by
    # ShouldProcess so -WhatIf works during local testing.
    if (-not $PSCmdlet.ShouldProcess("$RegistryPath\$ValueName", "Set to '$DesiredValue'")) {
        Write-LogEntry -Message 'ShouldProcess declined. No change made.'
        Write-ResultLine -Message 'No change made (WhatIf or declined confirmation).'
        exit $ExitSuccess
    }

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        Write-LogEntry -Message "Creating key '$RegistryPath'."
        $null = New-Item -Path $RegistryPath -Force -ErrorAction Stop
    }

    Write-LogEntry -Message "Setting '$ValueName' to '$DesiredValue' under '$RegistryPath'."
    $null = New-ItemProperty -LiteralPath $RegistryPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force -ErrorAction Stop
    #endregion

    #region Verify
    # Re-read the state that was just changed. Never report success on the
    # strength of the write alone.
    $actualValue = (Get-Item -LiteralPath $RegistryPath -ErrorAction Stop).GetValue($ValueName)

    if ($actualValue -ne $DesiredValue) {
        throw "Verification failed: '$ValueName' reads back as '$actualValue' after being set to '$DesiredValue'."
    }
    #endregion

    Write-LogEntry -Message "Remediation succeeded. '$ValueName' is $actualValue."
    Write-ResultLine -Message "Remediated: '$ValueName' set to $actualValue."
    exit $ExitSuccess
}
catch {
    $message = "Remediation failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitFailure
}
