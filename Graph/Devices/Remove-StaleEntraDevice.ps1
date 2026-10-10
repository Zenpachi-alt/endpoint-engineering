# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Finds Microsoft Entra device objects that have not been active for a set
    time, disables them, and deletes them after a grace period: one explicit
    stage per run, and a report by default.

.DESCRIPTION
    Microsoft Entra ID never removes a device object by itself. This script
    cleans up the stale ones in three stages, and does only the stage it is
    asked for:

      Report   The default. Lists every stale device and what would happen to
               it. Writes nothing to the tenant.
      Disable  Disables the candidates, which an administrator can undo, and
               writes a disabled-device file that lists them with the time.
      Delete   Deletes devices from that file, and only from that file, once
               they have been disabled for the grace period.

    DELETING A DEVICE CANNOT BE UNDONE. Microsoft Entra ID has no recycle bin
    for devices, and the BitLocker recovery keys stored on a device object are
    deleted with it. A device deleted by mistake has to be registered or
    joined again, and an encrypted disk whose key went with it is lost.

    A device is stale when its activity timestamp,
    approximateLastSignInDateTime, is more than -StaleAfterDays old. Entra ID
    refreshes that timestamp only once it is 14 days old, give or take 5, so
    -StaleAfterDays cannot be set below 30.

    A stale device is left alone, and reported as Skipped with the reason,
    when it is any of these. None of them can be switched off:

      - a member of the group named by -ExcludeGroupId, directly or through a
        nested group
      - registered with Windows Autopilot: deleting the object breaks the
        next deployment of the device
      - Microsoft Entra hybrid joined: it is removed in on-premises Active
        Directory, and Microsoft Entra Connect would bring it back
      - of a profile type other than RegisteredDevice, such as a Universal
        Print printer, which is cleaned up in its own portal
      - in a restricted management administrative unit
      - still in Intune: retire or delete it there first
      - without an activity timestamp: Entra ID leaves it blank on some
        devices that are in use

    The Delete stage applies the same checks again to every device in the
    file, and also leaves alone a device that was enabled again, that has
    been active, or that holds BitLocker recovery keys in Entra ID. Only the
    last of those can be overridden, with -IncludeDevicesWithRecoveryKey.

    Entra ID does not record when a device was disabled. The disabled-device
    file is that record: keep it, and keep it as the script wrote it. A device
    that is disabled but in no file is reported as AlreadyDisabled and never
    deleted by this script.

    A Disable or Delete run that would change more devices than
    -MaximumDeviceCount changes none of them and fails. The batch is never
    cut down to fit, because which devices were left out would be arbitrary.
    Each run asks for one confirmation for its batch, and every device is
    read again immediately before it is changed.

    Status of each returned record:

      Candidate        Report: -Stage Disable would disable it.
      AlreadyDisabled  Stale, and disabled before this run.
      Skipped          Left alone. Reason says why.
      WouldDisable     Disable, under -WhatIf or with the batch declined.
      Disabled         Disabled by this run, and written to the file.
      InGracePeriod    Delete: disabled for less than -GraceDays.
      Gone             Delete: no device has that object ID any more.
      WouldDelete      Delete, under -WhatIf or with the batch declined.
      Deleted          Deleted by this run.
      Failed           The change failed, or a disabled device could not be
                       written to the file. Reason says which.
      NotAttempted     The batch was over -MaximumDeviceCount, or an earlier
                       device stopped the batch.

    Exit codes:
      0  The run finished. Skipped devices are reported, not failures.
      1  A device is Failed or NotAttempted, or the script itself failed.

.PARAMETER Stage
    Report (the default), Disable or Delete.

.PARAMETER StaleAfterDays
    A device is stale when its activity timestamp is more than this many days
    old. 30 at least; 120 by default. The Delete stage checks it again.

.PARAMETER GraceDays
    Delete stage: how long a device must have been disabled before it is
    deleted. 7 at least; 60 by default.

.PARAMETER DisabledDevicePath
    Delete stage, and mandatory there: one or more disabled-device files
    written by the Disable stage. A device listed more than once counts from
    its latest date.

.PARAMETER ExcludeGroupId
    Object ID of a group whose device members are never disabled or deleted.
    If the group cannot be read, the run stops before anything else happens.

.PARAMETER MaximumDeviceCount
    The most devices one Disable or Delete run may change. A larger batch is
    refused whole. 50 by default.

.PARAMETER IncludeDevicesWithRecoveryKey
    Delete stage: also delete devices that hold BitLocker recovery keys in
    Entra ID. The keys are destroyed with the device.

.PARAMETER OutputPath
    Existing directory for the report and the disabled-device file. Defaults
    to the user's temp directory. Keep it outside this repository: the files
    name real devices.

.PARAMETER TenantId
    Tenant to connect to, as a GUID or a verified domain name. Optional: an
    existing Microsoft Graph session is reused when it matches.

.PARAMETER UseDeviceCode
    Sign in with the device code flow, for hosts where a browser prompt
    cannot open.

.PARAMETER MaximumRetryCount
    Attempts per Graph request, the first included, before giving up on a
    throttled or failing call.

.EXAMPLE
    .\Remove-StaleEntraDevice.ps1 -StaleAfterDays 730 | Where-Object Status -eq 'Candidate' | Format-Table DisplayName, DaysSinceActivity, JoinType, RecoveryKeyCount

    Reports the devices inactive for more than two years that the Disable
    stage would disable. Nothing is written to the tenant.

.EXAMPLE
    .\Remove-StaleEntraDevice.ps1 -Stage Disable -ExcludeGroupId '<GroupId>' -OutputPath C:\Reports -WhatIf

    Shows which devices would be disabled with the default 120 days, leaving
    the members of the exclusion group alone, and changes nothing.

.EXAMPLE
    .\Remove-StaleEntraDevice.ps1 -Stage Disable -ExcludeGroupId '<GroupId>' -OutputPath C:\Reports

    Disables the candidates after one confirmation, and writes
    StaleEntraDevice-Disabled-<timestamp>.csv to C:\Reports.

.EXAMPLE
    .\Remove-StaleEntraDevice.ps1 -Stage Delete -DisabledDevicePath C:\Reports\StaleEntraDevice-Disabled-20260930-101500.csv -ExcludeGroupId '<GroupId>' -OutputPath C:\Reports

    Deletes the devices in the file that have been disabled for 60 days or
    more and are still disabled, inactive, unmanaged and without recovery
    keys. Devices still in their grace period are reported as InGracePeriod.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-30

    PowerShell    : 5.1 or 7. No PowerShell 7 syntax is used.
    Graph scopes  : Device.Read.All (Device.ReadWrite.All, Directory.Read.All
                    or Directory.ReadWrite.All accepted when already granted)
                    DeviceManagementManagedDevices.Read.All
                    (DeviceManagementManagedDevices.ReadWrite.All accepted)
                    BitlockerKey.ReadBasic.All (BitlockerKey.Read.All accepted)
                    With -ExcludeGroupId: GroupMember.Read.All
                    (GroupMember.ReadWrite.All, Group.Read.All,
                    Group.ReadWrite.All, Directory.Read.All or
                    Directory.ReadWrite.All accepted)
                    With -Stage Disable or Delete, unless -WhatIf:
                    Directory.AccessAsUser.All. It is the only delegated
                    scope Graph accepts for changing or deleting a device,
                    and it is broad: the session can do in the directory
                    whatever the signed-in account can.
    Admin consent : Required, for every scope above.
    Licensing     : Microsoft Intune Plan 1, for the list of managed devices.
                    Microsoft Entra ID Free covers the rest.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later.
    Role required : Intune Administrator covers every stage. So does Cloud
                    Device Administrator, which may disable and delete
                    devices and list BitLocker keys, together with an Intune
                    role that can read managed devices. The Report stage
                    needs only the reading half.

    Sign-in       : Disable and Delete need a signed-in user. An app-only
                    session cannot hold Directory.AccessAsUser.All and is
                    refused.

    Recovery keys : Never read. The script requests a scope that cannot
                    return a key and only counts the keys of each device.

    Endpoint      : v1.0.

    Output        : The report and the disabled-device file name real
                    devices. Treat them as tenant data: keep them out of
                    this repository.

.LINK
    https://learn.microsoft.com/entra/identity/devices/manage-stale-devices

.LINK
    https://learn.microsoft.com/graph/api/device-update

.LINK
    https://learn.microsoft.com/graph/api/device-delete

.LINK
    https://learn.microsoft.com/intune/governance/configure-cleanup-rules
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter()]
    [ValidateSet('Report', 'Disable', 'Delete')]
    [string]$Stage = 'Report',

    [Parameter()]
    [ValidateRange(30, 3650)]
    [int]$StaleAfterDays = 120,

    [Parameter()]
    [ValidateRange(7, 3650)]
    [int]$GraceDays = 60,

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Leaf) { $true }
            else { throw "DisabledDevicePath '$_' does not exist or is not a file." }
        })]
    [string[]]$DisabledDevicePath,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ExcludeGroupId,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MaximumDeviceCount = 50,

    [Parameter()]
    [switch]$IncludeDevicesWithRecoveryKey,

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "OutputPath '$_' does not exist or is not a directory." }
        })]
    [string]$OutputPath = [System.IO.Path]::GetTempPath(),

    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

#region Graph module
# Identical in every script under Graph/, like the Graph helpers below. The
# master copy is the one in Templates/Script-Template.ps1, and
# Templates/Script-Template.Tests.ps1 fails while any copy differs.
#
# The module is loaded here rather than declared with '#Requires -Modules',
# which costs a script its exit code. PowerShell loads a module declared that
# way before the script starts, and when the module runs code of its own while
# it loads, as this one does, a script started with -File reports 0 whatever
# it exits with.
#
# -WhatIf and -Confirm are switched off while the module loads, and restored
# after it. A script started with -File runs in the global scope, where a
# module looks up its preferences, so both would reach the Update-TypeData
# calls the module makes as it loads: -WhatIf prints a line for each, ahead of
# the script's own, and -Confirm asks about each, or fails the import where no
# one can answer.
try {
    $GraphModulePreference = $WhatIfPreference, $ConfirmPreference
    $WhatIfPreference = $false
    $ConfirmPreference = 'None'
    # 4>$null, or a run with -Verbose lists every command the module imports.
    Import-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -ErrorAction Stop 4>$null
}
catch {
    Write-Error -Exception $_.Exception -ErrorAction Continue -Message (
        "Microsoft.Graph.Authentication 2.0.0 or later could not be loaded: $($_.Exception.Message) " +
        'If it is not installed, run: Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser')
    exit 1
}
finally {
    $WhatIfPreference, $ConfirmPreference = $GraphModulePreference
}
#endregion Graph module

# Every stage reads the same things. Changing a device needs the one delegated
# scope Graph accepts for it, and it is requested only by a run that changes.
$RequiredScopes = [ordered]@{
    'Device.Read.All'                         = @('Device.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
    'DeviceManagementManagedDevices.Read.All' = @('DeviceManagementManagedDevices.ReadWrite.All')
    'BitlockerKey.ReadBasic.All'              = @('BitlockerKey.Read.All')
}
if ($ExcludeGroupId) {
    $RequiredScopes['GroupMember.Read.All'] = @('GroupMember.ReadWrite.All', 'Group.Read.All', 'Group.ReadWrite.All',
        'Directory.Read.All', 'Directory.ReadWrite.All')
}
if ($Stage -ne 'Report' -and -not $WhatIfPreference) {
    $RequiredScopes['Directory.AccessAsUser.All'] = @()
}

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ConnectionOpenedHere = $false

# How the disabled-device file holds the time a device was disabled, and the
# only form the Delete stage accepts. A spreadsheet that saves the file again
# rewrites dates in its own form; reading 05/10 as the wrong month would
# shorten a grace period, so anything else is refused.
$DisabledDateTimeFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"

# What a device registered with Windows Autopilot carries in physicalIds.
$AutopilotPhysicalIdPrefix = '[ZTDID]'

#region Graph helpers
# Shared by every script under Graph/ and identical in each, so that any one of
# them still runs when copied out on its own. The master copy is the one in
# Templates/Script-Template.ps1: change it there, paste the whole region over
# every other copy, and run Invoke-Pester - Templates/Script-Template.Tests.ps1
# fails while any copy differs. Written for Windows PowerShell 5.1 and for
# Set-StrictMode -Version Latest, so it runs wherever the script does.

function Get-PropertyValue {
    <#
        .SYNOPSIS
            Reads a property that may not exist, without tripping
            Set-StrictMode. Graph omits properties that are null, and v1.0 and
            beta return different sets.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }

    return $property.Value
}

function ConvertFrom-GraphJson {
    <#
        .SYNOPSIS
            Parses a Graph response body, keeping timestamps as the text Graph
            sent wherever ConvertFrom-Json allows it.

        .DESCRIPTION
            Windows PowerShell 5.1 leaves timestamps as strings, and PowerShell
            7.5 does so with -DateKind String. PowerShell 7.0 to 7.4 always turn
            them into DateTime, so code that reads a timestamp accepts either.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Json
    )

    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }

    $parameters = @{ InputObject = $Json; ErrorAction = 'Stop' }
    if ((Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $parameters['DateKind'] = 'String'
    }

    ConvertFrom-Json @parameters
}

function ConvertTo-UtcDateTime {
    <#
        .SYNOPSIS
            Reads a Graph timestamp as a UTC DateTime, or $null when there is
            none.

        .DESCRIPTION
            Accepts the text Graph sent, and the DateTime that PowerShell 7.0
            to 7.4 make of it. Graph sends timestamps in UTC, so text without
            an offset and a DateTime of unspecified kind are read as UTC, never
            as local time. Text that is not a timestamp throws, rather than
            passing for a missing value.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }

    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }

    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
            return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
        }
        return $Value.ToUniversalTime()
    }

    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
        [System.Globalization.DateTimeStyles]::AssumeUniversal
    $parsed = [datetime]::MinValue

    if (-not [datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "'$Value' is not a timestamp. Graph sends ISO 8601 text such as 2026-03-01T10:15:00Z."
    }

    return $parsed
}

function Get-GraphErrorText {
    <#
        .SYNOPSIS
            Turns an error response body into "code: message", or into the
            start of the body when it is not a Graph error object.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Content
    )

    if ([string]::IsNullOrWhiteSpace($Content)) { return 'no response body' }

    try {
        $parsed = ConvertFrom-Json -InputObject $Content -ErrorAction Stop
        $graphError = Get-PropertyValue -InputObject $parsed -Name 'error'
        $code = Get-PropertyValue -InputObject $graphError -Name 'code'
        $message = Get-PropertyValue -InputObject $graphError -Name 'message'
        if ($code -or $message) { return ('{0}: {1}' -f $code, $message) }
    }
    catch {
        Write-Debug "The response body is not a Graph error object: $($_.Exception.Message)"
    }

    if ($Content.Length -gt 300) { return $Content.Substring(0, 300) }
    return $Content
}

function Get-RetryDelaySecond {
    <#
        .SYNOPSIS
            How long to wait before the next attempt: the Retry-After header
            when the service sent one, otherwise exponential backoff with
            jitter, so that parallel runs do not retry in lockstep.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter()]
        [AllowNull()]
        $ResponseHeaders,

        [Parameter(Mandatory)]
        [ValidateRange(1, 100)]
        [int]$Attempt
    )

    if ($null -ne $ResponseHeaders) {
        foreach ($key in @($ResponseHeaders.Keys)) {
            if ($key -ne 'Retry-After') { continue }

            # The value arrives as a string or as a single-element collection.
            # Five minutes is the ceiling, so a bad header cannot stall a run.
            $raw = @($ResponseHeaders[$key])[0]
            $seconds = 0
            if ([int]::TryParse([string]$raw, [ref]$seconds) -and $seconds -gt 0) {
                return [Math]::Min($seconds, 300)
            }
        }
    }

    $backoff = [int][Math]::Min([Math]::Pow(2, $Attempt), 60)
    return $backoff + (Get-Random -Minimum 0 -Maximum 3)
}

function Test-TransientFailure {
    <#
        .SYNOPSIS
            True when a request failed without an answer from Graph - a
            dropped connection, a failed name lookup, a timeout - rather than
            for a reason that would fail again, such as not being signed in.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Exception]$Exception
    )

    # Matched by name: System.Net.Http is not loaded in every Windows
    # PowerShell session, and a type literal for it would fail there.
    $transientType = @(
        'System.Net.Http.HttpRequestException'
        'System.Net.Sockets.SocketException'
        'System.Net.WebException'
        'System.IO.IOException'
        'System.TimeoutException'
        'System.Threading.Tasks.TaskCanceledException'
    )

    for ($current = $Exception; $null -ne $current; $current = $current.InnerException) {
        for ($type = $current.GetType(); $null -ne $type; $type = $type.BaseType) {
            if ($transientType -contains $type.FullName) { return $true }
        }
    }

    return $false
}

function Invoke-GraphRequestWithRetry {
    <#
        .SYNOPSIS
            Sends one Graph request and returns the parsed response, retrying
            throttled and transient failures.

        .DESCRIPTION
            The Graph SDK retries 429, 503 and 504 by itself - three times,
            honouring Retry-After - and then throws, even with
            -SkipHttpErrorCheck. A loop around that one multiplies the attempts
            and never sees the status code, so the SDK's retry is switched off
            for the length of the call and this loop is the only one. The
            previous setting is restored afterwards. The setting is
            process-wide: do not call this from parallel runspaces.

            GET is retried on 429, 500, 502, 503 and 504, and when no response
            arrives at all. POST, PATCH and DELETE are retried only on 429 and
            503, the answers that mean the service did not act on the request:
            retrying after any other failure could repeat a change that had
            already landed.

            A request that still fails throws. Data['StatusCode'] on the
            exception holds the last HTTP status, or 0 when nothing came back.

            Each retry is announced with Write-Warning, or handed to -OnRetry
            instead, for a script that keeps its own log.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [AllowNull()]
        [hashtable]$Body,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5,

        [Parameter()]
        [AllowNull()]
        [scriptblock]$OnRetry
    )

    $retryStatus = if ($Method -eq 'GET') { @(429, 500, 502, 503, 504) } else { @(429, 503) }

    # -WhatIf:$false and -Confirm:$false keep the calling script's -WhatIf or
    # -Confirm from reaching Set-MgRequestContext, which supports ShouldProcess.
    $sdkMaxRetry = (Get-MgRequestContext).MaxRetry
    if ($sdkMaxRetry -ne 0) {
        $null = Set-MgRequestContext -MaxRetry 0 -WhatIf:$false -Confirm:$false
    }

    try {
        $attempt = 0

        while ($true) {
            $attempt++

            $statusCode = 0
            $responseHeaders = $null
            $content = $null
            $failure = $null

            $request = @{
                Method                  = $Method
                Uri                     = $Uri
                OutputType              = 'Json'
                StatusCodeVariable      = 'statusCode'
                ResponseHeadersVariable = 'responseHeaders'
                SkipHttpErrorCheck      = $true
                ErrorAction             = 'Stop'
            }
            if ($Body) { $request['Body'] = $Body }

            try {
                $content = Invoke-MgGraphRequest @request
            }
            catch {
                # Not signed in, a malformed request: repeating it cannot help.
                if (-not (Test-TransientFailure -Exception $_.Exception)) { throw }
                $failure = $_.Exception
            }

            if (-not $failure -and $statusCode -ge 200 -and $statusCode -lt 300) {
                return ConvertFrom-GraphJson -Json $content
            }

            $outcome = if ($failure) { 'No response' } else { "HTTP $statusCode" }
            $canRetry = if ($failure) { $Method -eq 'GET' } else { $retryStatus -contains $statusCode }

            if (-not $canRetry -or $attempt -ge $MaximumAttempt) {
                $detail = if ($failure) { $failure.Message } else { Get-GraphErrorText -Content $content }
                $exception = [System.Exception]::new(
                    "$outcome from $Method $Uri after $attempt attempt(s): $detail", $failure)
                $exception.Data['StatusCode'] = $statusCode
                throw $exception
            }

            $delay = Get-RetryDelaySecond -ResponseHeaders $responseHeaders -Attempt $attempt
            $notice = "$outcome from $Method $Uri. Waiting $delay second(s) before attempt $($attempt + 1) of $MaximumAttempt."
            if ($OnRetry) { & $OnRetry $notice } else { Write-Warning -Message $notice }

            Start-Sleep -Seconds $delay
        }
    }
    finally {
        if ($sdkMaxRetry -ne 0) {
            $null = Set-MgRequestContext -MaxRetry $sdkMaxRetry -WhatIf:$false -Confirm:$false
        }
    }
}

function Get-GraphCollection {
    <#
        .SYNOPSIS
            Reads every page of a Graph collection, following @odata.nextLink
            until the service stops sending one. A script that reads one page
            and stops silently under-reports.

        .DESCRIPTION
            Returns a List even for zero or one item, so Count is always right
            and ConvertTo-Json always writes an array.
    #>
    # The caller receives the List; object[] is the one-element wrapper that
    # 'return , $items' builds to stop the pipeline unrolling it.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]], [object[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5,

        [Parameter()]
        [AllowNull()]
        [scriptblock]$OnRetry
    )

    # ::new(), not New-Object: a List from New-Object, once stored in an object
    # property, makes PowerShell throw "Argument types do not match" in an
    # expression as ordinary as: if ($x.Items) { @($x.Items).Count } else { '' }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0

    while ($next) {
        $page++
        if ($page -gt 1) { Write-Verbose "Reading page $page of $(($Uri -split '\?')[0])." }

        $response = Invoke-GraphRequestWithRetry -Uri $next -MaximumAttempt $MaximumAttempt -OnRetry $OnRetry

        if ($null -eq $response -or $null -eq $response.PSObject.Properties['value']) {
            throw "GET $next returned no 'value' list, so it is not a collection."
        }

        foreach ($item in @($response.value)) { $items.Add($item) }
        $next = Get-PropertyValue -InputObject $response -Name '@odata.nextLink'
    }

    return , $items
}

function Get-MissingGraphScope {
    <#
        .SYNOPSIS
            Returns each required scope that the granted scopes satisfy neither
            directly nor through one of its broader alternatives.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$Scope,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Granted
    )

    foreach ($required in $Scope.Keys) {
        $satisfied = $false

        foreach ($candidate in @(@($required) + @($Scope[$required]))) {
            if ($Granted -contains $candidate) { $satisfied = $true; break }
        }

        if (-not $satisfied) { [string]$required }
    }
}

function Connect-GraphSession {
    <#
        .SYNOPSIS
            Reuses the current Microsoft Graph session when it will do, signs
            in when it will not, and proves the session holds every scope the
            script needs. Returns $true when it signed in, so the script
            disconnects only a session it opened.

        .DESCRIPTION
            -Scope maps each scope the script requests to the broader scopes
            that also satisfy it:

                [ordered]@{
                    'DeviceManagementManagedDevices.Read.All' =
                        @('DeviceManagementManagedDevices.ReadWrite.All')
                }

            Sign-in requests only the keys, the narrowest set. An existing
            session holding a broader alternative is accepted, so an
            administrator who already consented to ReadWrite is not asked to
            consent to Read as well.

            A delegated session for another tenant, or without a needed scope,
            is replaced by a new sign-in. An app-only session is never
            replaced: the function fails and names the permission to grant.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$Scope,

        [Parameter()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [switch]$UseDeviceCode
    )

    $context = Get-MgContext

    if ($context -and $TenantId -and $context.TenantId -ne $TenantId -and
        $context.Account -notlike "*@$TenantId") {
        Write-Verbose "The current Graph session is for tenant '$($context.TenantId)'; signing in to '$TenantId' instead."
        $context = $null
    }

    if ($context) {
        $granted = @($context.Scopes | Where-Object { $_ })
        $missing = @(Get-MissingGraphScope -Scope $Scope -Granted $granted)
        $identity = if ($context.Account) { $context.Account } else { $context.AppName }

        if ($missing.Count -eq 0) {
            Write-Verbose "Reusing the Graph session of '$identity' in tenant '$($context.TenantId)'."
            return $false
        }

        if ([string]$context.AuthType -ne 'Delegated') {
            if ($granted.Count -eq 0) {
                Write-Warning "The $($context.AuthType) Graph session of '$identity' lists no permissions, so they cannot be verified. A missing one will fail as HTTP 403."
                return $false
            }

            throw "The $($context.AuthType) Graph session of '$identity' lacks $($missing -join ', '). Grant the application permission with admin consent, or run Disconnect-MgGraph and rerun the script to sign in as a user."
        }

        Write-Warning "The current Graph session lacks $($missing -join ', '). Signing in again with the scopes this script needs."
    }

    $connectParameters = @{
        Scopes      = [string[]]@($Scope.Keys)
        ErrorAction = 'Stop'
    }
    if ((Get-Command -Name Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) {
        $connectParameters['NoWelcome'] = $true
    }
    if ($TenantId) { $connectParameters['TenantId'] = $TenantId }
    if ($UseDeviceCode) {
        $connectParameters['UseDeviceCode'] = $true
        Write-Verbose 'Starting device code sign-in. A code and a URL follow.'
    }

    $null = Connect-MgGraph @connectParameters

    $context = Get-MgContext
    if (-not $context) { throw 'Connect-MgGraph finished, but no Graph session is available.' }

    # Consent can be partial: sign-in succeeds with whatever was granted.
    $granted = @($context.Scopes | Where-Object { $_ })
    $missing = @(Get-MissingGraphScope -Scope $Scope -Granted $granted)

    if ($missing.Count -gt 0) {
        try {
            $null = Disconnect-MgGraph -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
        }

        throw "Signed in, but consent does not cover $($missing -join ', '). An administrator can grant it for the tenant. Granted: $($granted -join ', ')."
    }

    Write-Verbose "Connected as '$($context.Account)' in tenant '$($context.TenantId)'."
    return $true
}
#endregion Graph helpers

function Read-DisabledDeviceFile {
    <#
        .SYNOPSIS
            Reads the disabled-device files the Disable stage wrote and
            returns one entry per device. Refuses a file it cannot read
            exactly, rather than guessing at an object ID or a date.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Format,

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
        [System.Globalization.DateTimeStyles]::AssumeUniversal
    $entries = [ordered]@{}

    foreach ($file in $Path) {
        $rows = @(Import-Csv -LiteralPath $file -ErrorAction Stop)
        if ($rows.Count -eq 0) { throw "'$file' lists no devices." }

        $columns = @($rows[0].PSObject.Properties.Name)
        foreach ($required in 'ObjectId', 'DisabledDateTime') {
            if ($columns -notcontains $required) {
                throw ("'$file' has no column '$required'. -DisabledDevicePath takes the StaleEntraDevice-Disabled-*.csv " +
                    'file that -Stage Disable wrote, not its report.')
            }
        }

        $line = 1
        foreach ($row in $rows) {
            $line++

            $objectId = ([string]$row.ObjectId).Trim()
            $parsedId = [guid]::Empty
            if (-not [guid]::TryParse($objectId, [ref]$parsedId) -or $parsedId -eq [guid]::Empty) {
                throw "'$file', line $($line): '$objectId' is not a device object ID."
            }

            $text = ([string]$row.DisabledDateTime).Trim()
            $disabled = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($text, $Format, [cultureinfo]::InvariantCulture, $styles, [ref]$disabled)) {
                throw ("'$file', line $($line): DisabledDateTime '$text' is not in the form 2026-03-01T10:15:00Z. Use the " +
                    'file as the script wrote it: a spreadsheet that saves it again rewrites the dates, and a date read ' +
                    'wrongly would shorten the grace period.')
            }
            if ($disabled -gt $Now) {
                throw "'$file', line $($line): DisabledDateTime '$text' is in the future."
            }

            $displayName = ''
            if ($columns -contains 'DisplayName') { $displayName = [string]$row.DisplayName }

            # A device disabled, enabled again by someone and disabled once
            # more is in two files. Its grace period runs from the later date.
            $key = $parsedId.ToString()
            if (-not $entries.Contains($key) -or $disabled -gt $entries[$key].DisabledDateTime) {
                $entries[$key] = [pscustomobject]@{
                    ObjectId         = $key
                    DisplayName      = $displayName
                    DisabledDateTime = $disabled
                }
            }
        }
    }

    foreach ($entry in $entries.Values) { $entry }
}

function Get-ExclusionGroup {
    <#
        .SYNOPSIS
            Reads the exclusion group and the object IDs of everything in it,
            nested groups included. Throws when the group cannot be read: a
            run without its exclusions would not be the run that was asked
            for.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    try {
        $group = Invoke-GraphRequestWithRetry -Uri "$BaseUri/groups/$GroupId`?`$select=id,displayName" -MaximumAttempt $MaximumAttempt
    }
    catch {
        if ($_.Exception.Data.Contains('StatusCode') -and [int]$_.Exception.Data['StatusCode'] -eq 404) {
            throw "No group has the object ID '$GroupId'. Check that it is the exclusion group's object ID, in this tenant. Nothing was changed."
        }
        throw
    }

    $memberIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $members = Get-GraphCollection -Uri "$BaseUri/groups/$GroupId/transitiveMembers?`$select=id&`$top=999" `
        -MaximumAttempt $MaximumAttempt
    foreach ($member in $members) {
        $memberId = [string](Get-PropertyValue -InputObject $member -Name 'id')
        if ($memberId) { $null = $memberIds.Add($memberId) }
    }

    return [pscustomobject]@{
        Id          = $GroupId
        DisplayName = [string](Get-PropertyValue -InputObject $group -Name 'displayName')
        MemberIds   = $memberIds
    }
}

function Get-StaleDeviceData {
    <#
        .SYNOPSIS
            Reads what the decision needs: every Entra device, every Intune
            managed device, and the list of BitLocker recovery keys. Throws
            when any of the three cannot be read, since each one protects
            devices that must be left alone.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    # Every device is read and the stale ones are picked out locally, so that
    # a device left alone can be reported with the reason.
    # isManagementRestricted is returned only when selected.
    $select = 'id,deviceId,displayName,accountEnabled,approximateLastSignInDateTime,trustType,profileType,physicalIds,' +
        'operatingSystem,operatingSystemVersion,isManaged,isManagementRestricted,registrationDateTime'
    $devices = Get-GraphCollection -Uri "$BaseUri/devices?`$select=$select&`$top=999" -MaximumAttempt $MaximumAttempt

    # No query options: managedDevices documents none.
    try {
        $managedDevices = Get-GraphCollection -Uri "$BaseUri/deviceManagement/managedDevices" -MaximumAttempt $MaximumAttempt
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Data.Contains('StatusCode')) { $statusCode = [int]$_.Exception.Data['StatusCode'] }

        if ($statusCode -eq 403) {
            throw ('Listing Intune managed devices was refused (HTTP 403). The signed-in account needs an Intune role that ' +
                'can read managed devices, and the tenant an Intune licence. Without the list, devices that Intune still ' +
                "manages cannot be left alone, so nothing was changed. $($_.Exception.Message)")
        }
        throw
    }

    # Never $select=key: the scope cannot return it, and asking would write an
    # audit record per key. Only the device ID of each key is used.
    try {
        $keys = Get-GraphCollection -Uri "$BaseUri/informationProtection/bitlocker/recoveryKeys" -MaximumAttempt $MaximumAttempt
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Data.Contains('StatusCode')) { $statusCode = [int]$_.Exception.Data['StatusCode'] }

        if ($statusCode -eq 403) {
            throw ('Listing BitLocker recovery keys was refused (HTTP 403). The signed-in account needs an Entra role that ' +
                'may list keys, such as Cloud Device Administrator or Intune Administrator. Without the list, devices ' +
                "that hold a key cannot be left alone, so nothing was changed. $($_.Exception.Message)")
        }
        throw
    }

    return [pscustomobject]@{
        Devices        = $devices
        ManagedDevices = $managedDevices
        Keys           = $keys
    }
}

function ConvertTo-JoinType {
    <#
        .SYNOPSIS
            Names a trust type the way the admin center does.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TrustType
    )

    switch ($TrustType) {
        'ServerAd' { return 'Microsoft Entra hybrid joined' }
        'AzureAd' { return 'Microsoft Entra joined' }
        'Workplace' { return 'Microsoft Entra registered' }
        default { return '' }
    }
}

function Get-DeviceFact {
    <#
        .SYNOPSIS
            Joins each Entra device to its Intune records, its recovery keys
            and the exclusion group, and lists the reasons it must be left
            alone. Reads no state, so every case can be tested without a
            tenant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Device,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ManagedDevice,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Key,

        [Parameter()]
        [AllowNull()]
        [System.Collections.Generic.HashSet[string]]$ExcludedId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$AutopilotPrefix = '[ZTDID]',

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    # Intune's records by Entra device ID, compared without regard to case.
    $intune = @{}
    foreach ($item in $ManagedDevice) {
        $entraId = [string](Get-PropertyValue -InputObject $item -Name 'azureADDeviceId')
        if (-not $entraId) { continue }

        $lookup = $entraId.ToLowerInvariant()
        if (-not $intune.ContainsKey($lookup)) {
            $intune[$lookup] = [pscustomobject]@{ LastSync = $null }
        }

        $sync = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'lastSyncDateTime')
        if ($sync -and ($null -eq $intune[$lookup].LastSync -or $sync -gt $intune[$lookup].LastSync)) {
            $intune[$lookup].LastSync = $sync
        }
    }

    $keyCount = @{}
    foreach ($item in $Key) {
        $entraId = [string](Get-PropertyValue -InputObject $item -Name 'deviceId')
        if (-not $entraId) { continue }

        $lookup = $entraId.ToLowerInvariant()
        $keyCount[$lookup] = 1 + [int]$keyCount[$lookup]
    }

    foreach ($item in $Device) {
        $objectId = [string](Get-PropertyValue -InputObject $item -Name 'id')
        $deviceId = [string](Get-PropertyValue -InputObject $item -Name 'deviceId')
        $lookup = $deviceId.ToLowerInvariant()
        $accountEnabled = Get-PropertyValue -InputObject $item -Name 'accountEnabled'
        $trust = [string](Get-PropertyValue -InputObject $item -Name 'trustType')
        $profileType = [string](Get-PropertyValue -InputObject $item -Name 'profileType')

        $signIn = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'approximateLastSignInDateTime')
        $daysSinceActivity = $null
        if ($signIn) { $daysSinceActivity = [int][Math]::Floor(($Now - $signIn).TotalDays) }

        $autopilot = $false
        foreach ($physicalId in @(Get-PropertyValue -InputObject $item -Name 'physicalIds')) {
            if ($physicalId -and ([string]$physicalId).StartsWith($AutopilotPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $autopilot = $true
                break
            }
        }

        $excluded = $null -ne $ExcludedId -and $ExcludedId.Contains($objectId)

        $intuneRecord = $null
        if ($deviceId -and $intune.ContainsKey($lookup)) { $intuneRecord = $intune[$lookup] }

        $keys = 0
        if ($deviceId -and $keyCount.ContainsKey($lookup)) { $keys = [int]$keyCount[$lookup] }

        $guards = [System.Collections.Generic.List[string]]::new()
        if ($excluded) {
            if ($accountEnabled -eq $false) { $guards.Add('in the exclusion group, and disabled: enable it again if it is in use') }
            else { $guards.Add('in the exclusion group') }
        }
        if ($autopilot) { $guards.Add('registered with Windows Autopilot') }
        if ($trust -eq 'ServerAd') { $guards.Add('Microsoft Entra hybrid joined, so it is removed in on-premises Active Directory') }
        if ($profileType -and $profileType -ne 'RegisteredDevice') { $guards.Add("profile type $profileType") }
        if ((Get-PropertyValue -InputObject $item -Name 'isManagementRestricted') -eq $true) {
            $guards.Add('in a restricted management administrative unit')
        }
        if ($intuneRecord) {
            if ($intuneRecord.LastSync) {
                $guards.Add("still in Intune, last synced $([int][Math]::Floor(($Now - $intuneRecord.LastSync).TotalDays)) day(s) ago")
            }
            else {
                $guards.Add('still in Intune, never synced')
            }
        }
        if (-not $signIn) { $guards.Add('no activity timestamp') }

        [pscustomobject]@{
            ObjectId                      = $objectId
            DeviceId                      = $deviceId
            DisplayName                   = Get-PropertyValue -InputObject $item -Name 'displayName'
            AccountEnabled                = $accountEnabled
            TrustType                     = $trust
            JoinType                      = ConvertTo-JoinType -TrustType $trust
            OperatingSystem               = Get-PropertyValue -InputObject $item -Name 'operatingSystem'
            OperatingSystemVersion        = Get-PropertyValue -InputObject $item -Name 'operatingSystemVersion'
            ApproximateLastSignInDateTime = $signIn
            DaysSinceActivity             = $daysSinceActivity
            RegistrationDateTime          = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'registrationDateTime')
            IsManaged                     = Get-PropertyValue -InputObject $item -Name 'isManaged'
            HasIntuneRecord               = $null -ne $intuneRecord
            IntuneLastSyncDateTime        = Get-PropertyValue -InputObject $intuneRecord -Name 'LastSync'
            AutopilotRegistered           = $autopilot
            Excluded                      = $excluded
            RecoveryKeyCount              = $keys
            Guards                        = $guards.ToArray()
        }
    }
}

function ConvertTo-DeviceRecord {
    <#
        .SYNOPSIS
            Builds the record the script returns for one device: what is known
            about it, what was decided, and why. -Entry is the device's line
            in a disabled-device file, and stands in for a device that no
            longer exists.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter()]
        [AllowNull()]
        $Fact,

        [Parameter()]
        [AllowNull()]
        $Entry,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Status,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Reason = '',

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    $source = $Fact
    if ($null -eq $source) { $source = $Entry }

    $disabled = Get-PropertyValue -InputObject $Entry -Name 'DisabledDateTime'
    $daysDisabled = $null
    if ($disabled) { $daysDisabled = [int][Math]::Floor(($Now - $disabled).TotalDays) }

    [pscustomobject][ordered]@{
        DisplayName                   = Get-PropertyValue -InputObject $source -Name 'DisplayName'
        Status                        = $Status
        Reason                        = $Reason
        ObjectId                      = Get-PropertyValue -InputObject $source -Name 'ObjectId'
        DeviceId                      = Get-PropertyValue -InputObject $Fact -Name 'DeviceId'
        JoinType                      = Get-PropertyValue -InputObject $Fact -Name 'JoinType'
        TrustType                     = Get-PropertyValue -InputObject $Fact -Name 'TrustType'
        AccountEnabled                = Get-PropertyValue -InputObject $Fact -Name 'AccountEnabled'
        OperatingSystem               = Get-PropertyValue -InputObject $Fact -Name 'OperatingSystem'
        OperatingSystemVersion        = Get-PropertyValue -InputObject $Fact -Name 'OperatingSystemVersion'
        ApproximateLastSignInDateTime = Get-PropertyValue -InputObject $Fact -Name 'ApproximateLastSignInDateTime'
        DaysSinceActivity             = Get-PropertyValue -InputObject $Fact -Name 'DaysSinceActivity'
        RegistrationDateTime          = Get-PropertyValue -InputObject $Fact -Name 'RegistrationDateTime'
        IsManaged                     = Get-PropertyValue -InputObject $Fact -Name 'IsManaged'
        HasIntuneRecord               = Get-PropertyValue -InputObject $Fact -Name 'HasIntuneRecord'
        IntuneLastSyncDateTime        = Get-PropertyValue -InputObject $Fact -Name 'IntuneLastSyncDateTime'
        AutopilotRegistered           = Get-PropertyValue -InputObject $Fact -Name 'AutopilotRegistered'
        Excluded                      = Get-PropertyValue -InputObject $Fact -Name 'Excluded'
        RecoveryKeyCount              = Get-PropertyValue -InputObject $Fact -Name 'RecoveryKeyCount'
        DisabledDateTime              = $disabled
        DaysDisabled                  = $daysDisabled
    }
}

function Get-DisableCandidate {
    <#
        .SYNOPSIS
            Decides, for the Report and Disable stages, what happens to each
            device, and returns a record for every one that is stale or has
            no activity timestamp. Devices in use return nothing. Reads no
            state.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Fact,

        [Parameter(Mandatory)]
        [ValidateRange(1, 3650)]
        [int]$StaleAfterDays,

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    $cutoff = $Now.AddDays(-$StaleAfterDays)

    foreach ($item in $Fact) {
        $signIn = $item.ApproximateLastSignInDateTime
        if ($signIn -and $signIn -ge $cutoff) { continue }

        if ($item.Guards.Count -gt 0) {
            $status = 'Skipped'
            $reason = "Left alone: $($item.Guards -join '; ')."
        }
        elseif ($item.AccountEnabled -eq $false) {
            $status = 'AlreadyDisabled'
            $reason = 'Disabled before this run. -Stage Delete removes it only if a disabled-device file lists it.'
        }
        else {
            $status = 'Candidate'
            $reason = ''
        }

        ConvertTo-DeviceRecord -Fact $item -Status $status -Reason $reason -Now $Now
    }
}

function Get-DeleteCandidate {
    <#
        .SYNOPSIS
            Decides, for the Delete stage, what happens to each device in the
            disabled-device files, and returns one record per entry. A device
            is a Candidate only when nothing at all speaks against deleting
            it. Reads no state.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Entry,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Fact,

        [Parameter(Mandatory)]
        [ValidateRange(1, 3650)]
        [int]$StaleAfterDays,

        [Parameter(Mandatory)]
        [ValidateRange(1, 3650)]
        [int]$GraceDays,

        [Parameter()]
        [switch]$IncludeDevicesWithRecoveryKey,

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    $byObjectId = @{}
    foreach ($item in $Fact) { $byObjectId[([string]$item.ObjectId).ToLowerInvariant()] = $item }

    $cutoff = $Now.AddDays(-$StaleAfterDays)

    foreach ($item in $Entry) {
        # Not $fact: variable names ignore case, and that is the parameter.
        $known = $byObjectId[([string]$item.ObjectId).ToLowerInvariant()]
        if ($null -eq $known) {
            ConvertTo-DeviceRecord -Entry $item -Status 'Gone' -Reason 'No device has this object ID any more.' -Now $Now
            continue
        }

        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($known.AccountEnabled -ne $false) { $reasons.Add('enabled again since it was disabled') }
        foreach ($guard in $known.Guards) { $reasons.Add($guard) }

        $signIn = $known.ApproximateLastSignInDateTime
        if ($signIn -and $signIn -gt $item.DisabledDateTime) {
            $reasons.Add('active since it was disabled')
        }
        elseif ($signIn -and $signIn -ge $cutoff) {
            $reasons.Add("active $($known.DaysSinceActivity) day(s) ago, which is within -StaleAfterDays $StaleAfterDays")
        }

        if ($known.RecoveryKeyCount -gt 0 -and -not $IncludeDevicesWithRecoveryKey) {
            $reasons.Add("holds $($known.RecoveryKeyCount) BitLocker recovery key(s), which would be destroyed with it")
        }

        if ($reasons.Count -gt 0) {
            $status = 'Skipped'
            $reason = "Left alone: $($reasons -join '; ')."
        }
        elseif (($Now - $item.DisabledDateTime).TotalDays -lt $GraceDays) {
            $status = 'InGracePeriod'
            $reason = "Disabled $([int][Math]::Floor(($Now - $item.DisabledDateTime).TotalDays)) day(s) ago; the grace period is $GraceDays."
        }
        else {
            $status = 'Candidate'
            $reason = ''
        }

        ConvertTo-DeviceRecord -Fact $known -Entry $item -Status $status -Reason $reason -Now $Now
    }
}

function Get-DeviceChange {
    <#
        .SYNOPSIS
            Says what changed on a device between the read that made it a
            candidate and now, when that change means it must be left alone.
            No output means it is as it was.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Record,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Current,

        [Parameter(Mandatory)]
        [ValidateSet('Disable', 'Delete')]
        [string]$Action
    )

    $enabled = (Get-PropertyValue -InputObject $Current -Name 'accountEnabled') -ne $false
    if ($Action -eq 'Disable' -and -not $enabled) { return 'Left alone: disabled by someone else since the run began.' }
    if ($Action -eq 'Delete' -and $enabled) { return 'Left alone: enabled again since the run began.' }

    $signIn = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $Current -Name 'approximateLastSignInDateTime')
    if ($signIn -and $Record.ApproximateLastSignInDateTime -and $signIn -gt $Record.ApproximateLastSignInDateTime) {
        return 'Left alone: active since the run began.'
    }
}

function Invoke-StaleDeviceAction {
    <#
        .SYNOPSIS
            Disables or deletes every Candidate record's device, one request
            each, after one confirmation for the batch, and records the
            outcome on the record.

        .DESCRIPTION
            Each device is read again just before its request, because the
            confirmation may have waited a long time, and is left alone if it
            changed. A device that is gone counts as Gone, not as a failure.
            The first 403 stops the batch, since every later request would be
            refused for the same reason.

            A disabled device is appended to the disabled-device file at
            once, so a run that is interrupted still leaves a record of what
            it disabled. If the file cannot be written, the batch stops.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([void])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Record,

        [Parameter(Mandatory)]
        [ValidateSet('Disable', 'Delete')]
        [string]$Action,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [AllowEmptyString()]
        [string]$DisabledDeviceFile,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DateTimeFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'",

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Record) { if ($item.Status -eq 'Candidate') { $targets.Add($item) } }
    if ($targets.Count -eq 0) { return }

    if ($Action -eq 'Disable') {
        if (-not $DisabledDeviceFile) { throw 'Disabling devices needs -DisabledDeviceFile, the file that records them.' }
        $done = 'Disabled'
        $would = 'WouldDisable'
        $operation = "Disable $($targets.Count) device(s)"
    }
    else {
        $done = 'Deleted'
        $would = 'WouldDelete'
        $operation = "Permanently delete $($targets.Count) device(s), with any BitLocker recovery keys they hold. This cannot be undone"
    }

    if (-not $PSCmdlet.ShouldProcess('Microsoft Entra ID', $operation)) {
        foreach ($item in $targets) {
            $item.Status = $would
            $item.Reason = 'Not changed: the run was a -WhatIf or the batch was declined.'
        }
        return
    }

    $stopReason = $null
    foreach ($item in $targets) {
        if ($stopReason) {
            $item.Status = 'NotAttempted'
            $item.Reason = $stopReason
            continue
        }

        $uri = "$BaseUri/devices/$($item.ObjectId)"
        try {
            $current = Invoke-GraphRequestWithRetry -Uri "$uri`?`$select=id,accountEnabled,approximateLastSignInDateTime" `
                -MaximumAttempt $MaximumAttempt
            $change = Get-DeviceChange -Record $item -Current $current -Action $Action
            if ($change) {
                $item.Status = 'Skipped'
                $item.Reason = $change
                continue
            }

            Write-Verbose "$Action $($item.DisplayName) ($($item.ObjectId))."
            if ($Action -eq 'Disable') {
                $null = Invoke-GraphRequestWithRetry -Uri $uri -Method PATCH -Body @{ accountEnabled = $false } `
                    -MaximumAttempt $MaximumAttempt
                $item.AccountEnabled = $false
                $item.DisabledDateTime = [datetime]::UtcNow
                $item.DaysDisabled = 0
            }
            else {
                $null = Invoke-GraphRequestWithRetry -Uri $uri -Method DELETE -MaximumAttempt $MaximumAttempt
            }
            $item.Status = $done
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Data.Contains('StatusCode')) { $statusCode = [int]$_.Exception.Data['StatusCode'] }
            $message = $_.Exception.Message

            if ($statusCode -eq 404) {
                $item.Status = 'Gone'
                $item.Reason = 'Deleted by someone else since the run began.'
                continue
            }

            $item.Status = 'Failed'
            $item.Reason = $message

            if ($statusCode -eq 403) {
                $item.Reason = ('Refused (HTTP 403). The signed-in account needs the Intune Administrator or Cloud Device ' +
                    "Administrator role, not scoped to an administrative unit. $message")
                $stopReason = 'Not attempted: an earlier request was refused with HTTP 403.'
            }
            continue
        }

        if ($Action -ne 'Disable') { continue }

        # Written device by device, not at the end: this file is the only
        # record of when a device was disabled.
        try {
            $signIn = ''
            if ($item.ApproximateLastSignInDateTime) {
                $signIn = $item.ApproximateLastSignInDateTime.ToString($DateTimeFormat, [cultureinfo]::InvariantCulture)
            }

            [pscustomobject][ordered]@{
                ObjectId                      = $item.ObjectId
                DeviceId                      = $item.DeviceId
                DisplayName                   = $item.DisplayName
                DisabledDateTime              = $item.DisabledDateTime.ToString($DateTimeFormat, [cultureinfo]::InvariantCulture)
                ApproximateLastSignInDateTime = $signIn
            } | Export-Csv -LiteralPath $DisabledDeviceFile -Append -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
        }
        catch {
            # Failed, although the device is disabled: the run must not end
            # as a success with a device disabled and on no list.
            $item.Status = 'Failed'
            $item.Reason = ("Disabled at $($item.DisabledDateTime.ToString($DateTimeFormat, [cultureinfo]::InvariantCulture)), but not " +
                "written to '$DisabledDeviceFile': $($_.Exception.Message) Add it to the file by hand, or enable the device again.")
            $stopReason = 'Not attempted: the disabled-device file could not be written.'
        }
    }
}

try {
    #region Check the request
    if ($Stage -eq 'Delete' -and -not $DisabledDevicePath) {
        throw ('-Stage Delete needs -DisabledDevicePath: the StaleEntraDevice-Disabled-*.csv file that -Stage Disable wrote. ' +
            'Devices are deleted only from that list.')
    }
    if ($Stage -ne 'Delete' -and $DisabledDevicePath) {
        throw "-DisabledDevicePath is read only by -Stage Delete, and this run is -Stage $Stage."
    }
    if ($Stage -ne 'Delete' -and $IncludeDevicesWithRecoveryKey) {
        throw "-IncludeDevicesWithRecoveryKey applies only to -Stage Delete, and this run is -Stage $Stage."
    }

    $now = [datetime]::UtcNow

    $entries = @()
    if ($Stage -eq 'Delete') {
        $entries = @(Read-DisabledDeviceFile -Path $DisabledDevicePath -Format $DisabledDateTimeFormat -Now $now)
        Write-Verbose "Read $($entries.Count) disabled device(s) from $(@($DisabledDevicePath).Count) file(s)."
    }
    #endregion

    #region Connect to Microsoft Graph
    $ConnectionOpenedHere = Connect-GraphSession -Scope $RequiredScopes -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Read the exclusions before anything else
    $excludedIds = $null
    if ($ExcludeGroupId) {
        $exclusion = Get-ExclusionGroup -GroupId $ExcludeGroupId -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount
        $excludedIds = $exclusion.MemberIds

        Write-Information "Leaving alone the $($excludedIds.Count) member(s) of group '$($exclusion.DisplayName)'."
        if ($excludedIds.Count -eq 0) {
            Write-Warning "Group '$($exclusion.DisplayName)' has no members, so it excludes nothing."
        }
    }
    #endregion

    #region Read the tenant
    $data = Get-StaleDeviceData -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount
    Write-Verbose ("Read $($data.Devices.Count) device(s), $($data.ManagedDevices.Count) Intune managed device(s) and " +
        "$($data.Keys.Count) recovery key(s).")

    $facts = @(Get-DeviceFact -Device @($data.Devices) -ManagedDevice @($data.ManagedDevices) -Key @($data.Keys) `
            -ExcludedId $excludedIds -AutopilotPrefix $AutopilotPhysicalIdPrefix -Now $now)
    if ($facts.Count -eq 0) { Write-Warning 'The tenant returned no devices.' }
    #endregion

    #region Decide
    if ($Stage -eq 'Delete') {
        $records = @(Get-DeleteCandidate -Entry $entries -Fact $facts -StaleAfterDays $StaleAfterDays -GraceDays $GraceDays `
                -IncludeDevicesWithRecoveryKey:$IncludeDevicesWithRecoveryKey -Now $now)
    }
    else {
        $records = @(Get-DisableCandidate -Fact $facts -StaleAfterDays $StaleAfterDays -Now $now)
        Write-Information ("$($facts.Count) device(s) in the tenant, $($facts.Count - $records.Count) of them active within " +
            "$StaleAfterDays days and not reported.")
    }

    $candidates = @($records | Where-Object { $_.Status -eq 'Candidate' })
    #endregion

    #region Refuse a batch over the limit
    $refusal = $null
    if ($candidates.Count -gt $MaximumDeviceCount) {
        if ($Stage -eq 'Report') {
            Write-Warning ("$($candidates.Count) device(s) are candidates, more than -MaximumDeviceCount $MaximumDeviceCount, so " +
                '-Stage Disable would refuse the batch. Take a smaller slice with a higher -StaleAfterDays, or raise ' +
                '-MaximumDeviceCount once this report has been read.')
        }
        else {
            $refusal = ("-Stage $Stage would change $($candidates.Count) device(s), more than -MaximumDeviceCount " +
                "$MaximumDeviceCount, so none was changed. Read the report, then take a smaller slice with a higher " +
                '-StaleAfterDays, or raise -MaximumDeviceCount.')
            foreach ($item in $candidates) {
                $item.Status = 'NotAttempted'
                $item.Reason = "Not attempted: the batch of $($candidates.Count) is over -MaximumDeviceCount $MaximumDeviceCount."
            }
        }
    }
    #endregion

    #region Change
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $disabledFile = Join-Path -Path $OutputPath -ChildPath "StaleEntraDevice-Disabled-$stamp.csv"

    if ($Stage -ne 'Report' -and -not $refusal) {
        Invoke-StaleDeviceAction -Record $records -Action $Stage -BaseUri $GraphBaseUri -DisabledDeviceFile $disabledFile `
            -DateTimeFormat $DisabledDateTimeFormat -MaximumAttempt $MaximumRetryCount
    }

    $counts = foreach ($group in @($records | Group-Object -Property Status | Sort-Object -Property Name)) {
        "$($group.Name) $($group.Count)"
    }
    if ($counts) { Write-Information "Stage $($Stage): $($counts -join ', ')." }
    else { Write-Information "Stage $($Stage): no device to report." }
    #endregion

    #region Write the files
    # Files are reports, not tenant changes: -WhatIf must not stop them.
    if ($records.Count -gt 0) {
        $reportFile = Join-Path -Path $OutputPath -ChildPath "StaleEntraDevice-$Stage-$stamp.csv"
        $records | Export-Csv -LiteralPath $reportFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
        Write-Information "Report: $reportFile"
    }

    if (Test-Path -LiteralPath $disabledFile -PathType Leaf) {
        Write-Information "Disabled devices: $disabledFile"
        Write-Warning ("Keep '$disabledFile' as it is. It is the only record of when these devices were disabled, and " +
            '-Stage Delete deletes nothing that is not in it.')
    }
    #endregion

    $records

    if ($refusal) { throw $refusal }

    $failed = @($records | Where-Object { $_.Status -in @('Failed', 'NotAttempted') }).Count
    if ($failed -gt 0) {
        throw "$failed device(s) were not changed. See Status and Reason on the returned records."
    }
}
catch {
    # -Exception, not -ErrorRecord: Write-Error takes -Message with the first
    # and not with the second, and would fail here instead of reporting.
    # -ErrorAction Continue, or the preference set above would stop the script
    # at this line, before exit sets the code.
    Write-Error -Exception $_.Exception -Message "Script failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
finally {
    if ($ConnectionOpenedHere -and (Get-MgContext)) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            Write-Verbose 'Disconnected from Microsoft Graph.'
        }
        catch {
            Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
        }
    }
}
