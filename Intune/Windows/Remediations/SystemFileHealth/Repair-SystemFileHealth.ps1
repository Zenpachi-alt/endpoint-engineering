# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Repairs corrupt Windows system files with SFC, and uses DISM only when SFC
    cannot finish the job.

.DESCRIPTION
    Remediation script of the SystemFileHealth package. It runs only when
    Test-SystemFileHealth.ps1 exits 1.

      1. 'sfc /scannow'. If SFC repairs everything and the component store is
         not flagged, the script stops here: DISM is the slowest step and most
         devices do not need it.
      2. If SFC could not repair some files, or Windows has flagged the
         component store, 'Repair-WindowsImage -Online -RestoreHealth'. DISM
         repairs the component store - the source SFC copies good files from -
         not the system files themselves.
      3. If SFC was the reason DISM ran, 'sfc /scannow' again, now with a
         healthy source to repair from.

    Microsoft's manual procedure runs DISM first. This order reaches the same
    result and skips DISM wherever SFC alone is enough.

    Verification is part of the sequence: every success rests on SFC's or
    DISM's own report of the state after the repair. Intune then runs the
    detection script, and TimeGuard lets that check through because a
    remediation has started since the last one.

    The script records when it starts in the TimeGuard key, which is what makes
    the next detection a real check. An optional guard (TimeGuardIntervalDays)
    stops repairs repeating within a set number of days; it is off by default.

    The device is never restarted. A repair that needs a restart is reported,
    and the first check after the restart verifies it.

    Contract enforced by the Intune management extension:
      exit 0  Repaired, or nothing left to repair.
      exit 1  Not repaired: the repair failed, was not attempted (TimeGuard, a
              pending restart), or the script failed. Intune retries on the
              configured schedule.

.PARAMETER TimeGuardName
    Name of the TimeGuard key shared with Test-SystemFileHealth.ps1. Both
    scripts must use the same name.

.PARAMETER TimeGuardIntervalDays
    Minimum number of days between repairs. 0, the default, turns the
    remediation guard off. The start of every repair is recorded either way,
    because the detection script needs it.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Repair-SystemFileHealth.ps1 -WhatIf -Verbose

    Checks the host and TimeGuard, then shows what would run, without scanning
    or changing anything - including the TimeGuard timestamp. Intune never
    passes -WhatIf, so this is for local testing only.

.EXAMPLE
    .\Repair-SystemFileHealth.ps1 -Verbose

    Runs the repair from an elevated 64-bit Windows PowerShell and echoes every
    log line to the console.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-23

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM (Run this script using the logged-on credentials:
                    No). SFC and DISM need administrator rights; without them
                    the script exits 1.
    Host          : 64-bit (Run script in 64-bit PowerShell: Yes). Must match
                    the detection script. DISM cannot service a running 64-bit
                    Windows from a 32-bit host.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. The file is ASCII-only.
    Modules       : Dism, which ships with Windows. Nothing to install.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None.
    Admin consent : Not applicable.

    Network       : DISM RestoreHealth downloads replacement files from Windows
                    Update, or from the repair source set by the policy
                    "Specify settings for optional component installation and
                    component repair". With neither reachable it fails with
                    0x800F081F.
    Run time      : SFC alone takes several minutes. SFC, DISM and SFC again
                    can take much longer, and Microsoft does not document a
                    time limit for remediation scripts.
    Reversibility : SFC and DISM replace damaged system files and component
                    store entries with Microsoft's own versions. Individual
                    replacements cannot be undone, and need not be: they
                    restore the state Windows expects. No user data or settings
                    are touched.

.LINK
    https://learn.microsoft.com/intune/device-management/tools/deploy-remediations

.LINK
    https://learn.microsoft.com/windows-hardware/manufacture/desktop/repair-a-windows-image
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$TimeGuardName = 'SystemFileHealth',

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$TimeGuardIntervalDays = 0,

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
# latter as shadowing a command that exists in some PowerShell profiles.
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

    $line = '{0} [{1}] [PID {2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff zzz', [cultureinfo]::InvariantCulture), $Level, $PID, $Message

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

#region SystemFileHealth 1.1.0 - keep identical in Test- and Repair-SystemFileHealth.ps1
function Test-IsElevated {
    <#
        .SYNOPSIS
            True when the process has administrator rights, as SYSTEM does
            under Intune. SFC and DISM refuse to run without them.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SfcResult {
    <#
        .SYNOPSIS
            Names the result that SFC's closing message reports. Returns
            'Unknown' when no known message is present, which callers treat as
            a failure and never as healthy.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Output
    )

    # Reduced to lowercase letters and digits, so line wrapping, punctuation
    # and the NUL padding of SFC's UTF-16 output cannot break a match.
    $normalized = ($Output -replace "`0", '').ToLowerInvariant() -replace '[^\p{L}\p{Nd}]', ''

    # No pattern is contained in another, so the order does not decide the
    # result; [ordered] keeps it predictable should SFC ever print two.
    $patterns = [ordered]@{
        Healthy             = 'windowsresourceprotectiondidnotfindanyintegrityviolations'
        Repaired            = 'windowsresourceprotectionfoundcorruptfilesandsuccessfullyrepairedthem'
        Unrepaired          = 'windowsresourceprotectionfoundcorruptfilesbutwasunabletofixsomeofthem'
        Corrupt             = 'windowsresourceprotectionfoundintegrityviolations'
        PendingRepairReboot = 'thereisasystemrepairpendingwhichrequiresreboottocompleterestart|systemrepairpending.*requiresreboot.*restart'
        Failed              = 'windowsresourceprotectioncouldnotperformtherequestedoperation'
    }

    foreach ($result in $patterns.Keys) {
        if ($normalized -match $patterns[$result]) {
            return $result
        }
    }

    return 'Unknown'
}

function Invoke-SystemFileChecker {
    <#
        .SYNOPSIS
            Runs sfc.exe and returns its exit code, the result its closing
            message reports, and the last lines of its output for the log.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('VerifyOnly', 'ScanNow')]
        [string]$Mode
    )

    $sfcPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\sfc.exe'
    if (-not (Test-Path -LiteralPath $sfcPath)) {
        throw "sfc.exe was not found at '$sfcPath'."
    }

    $argument = '/' + $Mode.ToLowerInvariant()
    Write-LogEntry -Message "Running '$sfcPath $argument'. This takes several minutes."

    # Windows PowerShell 5.1 turns a native command's stderr output into a
    # terminating error under 'Stop'. The call runs under 'Continue' and its
    # exit code and output are judged afterwards instead.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $sfcPath $argument 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }

    # sfc.exe writes UTF-16, which arrives with a NUL after every character.
    $lines = @(($raw -replace "`0", '') -split '[\r\n]+' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ })

    $result = Get-SfcResult -Output ($lines -join ' ')

    # Progress lines ('Verification 97% complete.') would fill the summary and
    # push out the messages that matter. A number followed by a percent sign
    # identifies them in any language.
    $messages = @($lines | Where-Object { $_ -notmatch '\d+\s*%' })

    return [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Summary  = ($messages | Select-Object -Last 6) -join ' | '
    }
}

function Get-ComponentStoreHealth {
    <#
        .SYNOPSIS
            Returns whether Windows has flagged the component store as corrupt
            (DISM CheckHealth): Healthy, Repairable or NonRepairable. Takes
            seconds, because it reads a flag rather than scanning.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Import-Module -Name Dism -ErrorAction Stop
    $image = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
    return [string]$image.ImageHealthState
}
#endregion SystemFileHealth

function Repair-ComponentStore {
    <#
        .SYNOPSIS
            Repairs the component store (DISM RestoreHealth) and returns its
            health afterwards. Never restarts the device.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Import-Module -Name Dism -ErrorAction Stop
    Write-LogEntry -Message 'Running DISM RestoreHealth. This can take a long time and needs Windows Update or a configured repair source.'

    $image = Repair-WindowsImage -Online -RestoreHealth -NoRestart -ErrorAction Stop

    # Read defensively: strict mode fails on a property the object lacks.
    $restartNeeded = $image.PSObject.Properties['RestartNeeded']
    if ($null -ne $restartNeeded -and $restartNeeded.Value) {
        Write-LogEntry -Message 'DISM reports that a restart is needed to finish the repair.' -Level WARN
    }

    return [string]$image.ImageHealthState
}

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Remediation started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-LogEntry -Message 'Running in 32-bit PowerShell on 64-bit Windows, where DISM cannot service the running system. Set "Run script in 64-bit PowerShell" to Yes.' -Level ERROR
        Write-ResultLine -Message 'Remediation failed: running in 32-bit PowerShell. Set "Run script in 64-bit PowerShell" to Yes.'
        exit $ExitFailure
    }

    if (-not (Test-IsElevated)) {
        Write-LogEntry -Message 'Not running with administrator rights, which SFC and DISM require. Under Intune the script runs as SYSTEM and has them.' -Level ERROR
        Write-ResultLine -Message 'Remediation failed: administrator rights are required.'
        exit $ExitFailure
    }

    #region Guard
    $nowUtc = [datetime]::UtcNow
    $guardUsable = $true

    try {
        $previousRepair = Get-TimeGuardValue -Name $TimeGuardName -ValueName 'LastRemediation'
        $guard = Get-TimeGuardDecision -Now $nowUtc -LastRun $previousRepair -IntervalDays $TimeGuardIntervalDays
        Write-LogEntry -Message "TimeGuard: $($guard.Reason)"
    }
    catch {
        $guardUsable = $false
        $guard = [pscustomobject]@{ Run = $true; Reason = ''; LastRunUtc = $null }
        Write-LogEntry -Message "TimeGuard state could not be read, so the repair runs: $($_.Exception.Message)" -Level WARN
    }

    if (-not $guard.Run) {
        # Exit 1, not 0: the repair was not attempted, and 0 would report it
        # as done.
        Write-ResultLine -Message "Skipped by TimeGuard: last repair $($guard.LastRunUtc.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)) UTC."
        exit $ExitFailure
    }
    #endregion

    if (-not $PSCmdlet.ShouldProcess('Windows system files and component store', 'Repair with SFC, and with DISM if SFC cannot finish')) {
        Write-LogEntry -Message 'ShouldProcess declined. Nothing was scanned or changed.'
        Write-ResultLine -Message 'No change made (WhatIf or declined confirmation).'
        exit $ExitSuccess
    }

    #region Repair
    $storeHealth = Get-ComponentStoreHealth
    Write-LogEntry -Message "Component store (DISM CheckHealth): $storeHealth."

    # Recorded before the heavy work, and kept even if SFC then refuses to
    # start: this timestamp is what makes the next detection a real check
    # rather than a TimeGuard skip.
    if ($guardUsable) {
        try {
            Set-TimeGuardValue -Name $TimeGuardName -ValueName 'LastRemediation' -Value $nowUtc.ToString('o', [cultureinfo]::InvariantCulture)
        }
        catch {
            Write-LogEntry -Message "Could not record the TimeGuard timestamp: $($_.Exception.Message)" -Level WARN
        }
    }

    $firstPass = Invoke-SystemFileChecker -Mode ScanNow
    Write-LogEntry -Message "SFC first pass: exit code $($firstPass.ExitCode), result '$($firstPass.Result)'. Output: $($firstPass.Summary)"

    if ($firstPass.Result -eq 'PendingRepairReboot') {
        Write-LogEntry -Message 'A system file repair is waiting for a restart, and SFC cannot run until the device restarts. The first detection after the restart checks again.' -Level WARN
        Write-ResultLine -Message 'Not repaired: a system file repair is waiting for a restart.'
        exit $ExitFailure
    }

    if ($firstPass.Result -eq 'Failed') {
        Write-LogEntry -Message 'SFC could not perform the requested operation. See %windir%\Logs\CBS\CBS.log.' -Level ERROR
        Write-ResultLine -Message 'Remediation failed: SFC could not perform the requested operation.'
        exit $ExitFailure
    }

    if ($firstPass.Result -notin @('Healthy', 'Repaired', 'Unrepaired')) {
        Write-LogEntry -Message "SFC's output did not match a result this script expects ('$($firstPass.Result)'). On a device installed in a language other than English, SFC's messages are translated and cannot be matched." -Level ERROR
        Write-ResultLine -Message 'Remediation failed: SFC result not recognised; see the log.'
        exit $ExitFailure
    }

    $sfcNeedsStore = $firstPass.Result -eq 'Unrepaired'
    $storeFlagged = $storeHealth -ne 'Healthy'
    $sfcOutcome = if ($firstPass.Result -eq 'Repaired') { 'SFC repaired the corrupt files' } else { 'SFC found nothing to repair' }

    if (-not $sfcNeedsStore -and -not $storeFlagged) {
        Write-LogEntry -Message "Remediation succeeded: $sfcOutcome. DISM was not needed."
        Write-ResultLine -Message "Remediated: $sfcOutcome; DISM not needed."
        exit $ExitSuccess
    }

    # DISM repairs the component store that SFC copies good files from; it
    # does not repair the system files themselves.
    $dismReason = if ($sfcNeedsStore) { 'SFC could not repair some files' } else { "the component store is flagged $storeHealth" }
    Write-LogEntry -Message "Running DISM because $dismReason."

    try {
        $storeAfter = Repair-ComponentStore
    }
    catch {
        Write-LogEntry -Message "DISM RestoreHealth failed: $($_.Exception.Message) See %windir%\Logs\DISM\dism.log. 0x800F081F means no repair source was reachable: Windows Update, or the source set by policy." -Level ERROR
        Write-ResultLine -Message 'Remediation failed: DISM could not repair the component store; see dism.log.'
        exit $ExitFailure
    }

    Write-LogEntry -Message "Component store after DISM: $storeAfter."

    if ($storeAfter -ne 'Healthy') {
        Write-ResultLine -Message "Remediation failed: DISM left the component store $storeAfter; see dism.log."
        exit $ExitFailure
    }

    if (-not $sfcNeedsStore) {
        Write-LogEntry -Message "Remediation succeeded: $sfcOutcome, and DISM repaired the flagged component store."
        Write-ResultLine -Message "Remediated: $sfcOutcome; DISM repaired the component store."
        exit $ExitSuccess
    }

    $secondPass = Invoke-SystemFileChecker -Mode ScanNow
    Write-LogEntry -Message "SFC second pass: exit code $($secondPass.ExitCode), result '$($secondPass.Result)'. Output: $($secondPass.Summary)"

    if ($secondPass.Result -in @('Healthy', 'Repaired')) {
        Write-LogEntry -Message 'Remediation succeeded: DISM repaired the component store, then SFC repaired the remaining files.'
        Write-ResultLine -Message 'Remediated: DISM repaired the component store, then SFC repaired the remaining files.'
        exit $ExitSuccess
    }

    Write-LogEntry -Message "SFC reports '$($secondPass.Result)' even after DISM. %windir%\Logs\CBS\CBS.log lists the files it could not repair ('[SR] Cannot repair member file')." -Level ERROR
    Write-ResultLine -Message "Remediation failed: SFC reports '$($secondPass.Result)' after DISM; see CBS.log."
    exit $ExitFailure
    #endregion
}
catch {
    $message = "Remediation failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitFailure
}
