# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Registers devices with Windows Autopilot from a hardware hash CSV.

.DESCRIPTION
    Reads a CSV produced by Intune/Windows/Autopilot/Get-AutopilotHardwareHash.ps1
    (or exported from the Intune portal), posts each device to
    /deviceManagement/importedWindowsAutopilotDeviceIdentities on Microsoft
    Graph v1.0, then polls until the service reports a final state for every
    device.

    One object is returned per device carrying the final import status, so the
    result can be sorted, grouped and piped rather than read off the console.
    A device that fails does not stop the ones behind it; the script reports
    every outcome and exits non-zero if any device failed.

    Registration is a tenant write, and the script asks for confirmation once
    before submitting the batch. Use -WhatIf to see exactly what would be sent.
    Registering a device is reversible - delete the Autopilot device identity in
    Intune - but deregistration is not instantaneous, so check the CSV first.

    Duplicate serial numbers within the CSV are collapsed before submission,
    keeping the last occurrence. A device already registered in this tenant
    comes back from the service as ZtdDeviceAlreadyAssigned, which the script
    reports as a skip rather than a failure.

    A registration is resent only after HTTP 429 or 503, the answers that mean
    the service did not act on it. Any other failure is reported as
    submitFailed rather than resent, because a second submission of a request
    that did land would be tracked in place of the first and reported as a
    duplicate. Status checks are reads, and are retried on any transient
    failure.

    Exit codes:
      0  Every device reached the "complete" state, or there was nothing to do.
      1  At least one device failed to import, or the script itself failed.

.PARAMETER CsvPath
    Path to the hardware hash CSV. Must contain the columns
    "Device Serial Number" and "Hardware Hash"; "Group Tag" and "Assigned User"
    are honoured when present.

.PARAMETER TenantId
    Entra ID tenant ID (GUID) or a verified domain name. When omitted, an
    existing Microsoft Graph session is reused if there is one.

.PARAMETER UseDeviceCode
    Sign in with the device code flow, for hosts where a browser prompt cannot
    open.

.PARAMETER GroupTag
    Group tag applied to every device in the batch, overriding whatever the CSV
    carries. Use it when a CSV was collected without a tag, or was collected
    for the wrong one.

.PARAMETER TimeoutMinutes
    How long to wait for the service to reach a final state for every device
    before giving up. Devices still pending at the timeout are reported as
    such; they usually complete on the service side regardless.

.PARAMETER PollIntervalSeconds
    Seconds between status checks while waiting.

.PARAMETER ReportPath
    Existing directory to write a timestamped CSV of the results to. Write it
    outside this repository: it names real devices.

.PARAMETER MaximumRetryCount
    Attempts per Graph request, the first included, before giving up on a
    throttled or transient failure.

.EXAMPLE
    .\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' -WhatIf

    Validates the CSV and reports what would be submitted, without writing to
    the tenant.

.EXAMPLE
    .\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' -Verbose

    Registers every device in the CSV and waits for the outcome.

.EXAMPLE
    .\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' -GroupTag 'Kiosk' -ReportPath 'C:\Reports'

    Applies one group tag to the whole batch and writes the results to a CSV.

.EXAMPLE
    .\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' |
        Where-Object { $_.Status -ne 'complete' }

    Registers the batch and returns only the devices that did not succeed.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-24

    PowerShell    : 5.1 or 7. Keep this line and the #Requires line in step.
    Graph scopes  : DeviceManagementServiceConfig.ReadWrite.All
    Admin consent : Required, once per tenant, for the application signed in
                    with.
    Licensing     : Microsoft Intune Plan 1, with an active Intune licence on
                    the tenant.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later
    Role required : Intune Administrator, or a custom role with the Enrollment
                    programs "Create device" permission.
    Endpoint      : Microsoft Graph v1.0. No beta endpoint is used.

.LINK
    https://learn.microsoft.com/graph/api/intune-enrollment-importedwindowsautopilotdeviceidentity-create
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory, HelpMessage = 'Path to the hardware hash CSV to import.')]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Leaf) { $true }
            else { throw "CsvPath '$_' does not exist or is not a file." }
        })]
    [string]$CsvPath,

    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [ValidateLength(1, 255)]
    [string]$GroupTag,

    [Parameter()]
    [ValidateRange(1, 240)]
    [int]$TimeoutMinutes = 30,

    [Parameter()]
    [ValidateRange(5, 300)]
    [int]$PollIntervalSeconds = 15,

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "ReportPath '$_' does not exist or is not a directory." }
        })]
    [string]$ReportPath,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

# No broader scope covers Autopilot registration, so nothing else is accepted.
$RequiredScopes = [ordered]@{
    'DeviceManagementServiceConfig.ReadWrite.All' = @()
}

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ImportUri = "$GraphBaseUri/deviceManagement/importedWindowsAutopilotDeviceIdentities"
$ConnectionOpenedHere = $false

# Column names as Intune writes them. Matching is case-insensitive.
$SerialColumn = 'Device Serial Number'
$HashColumn = 'Hardware Hash'
$GroupTagColumn = 'Group Tag'
$AssignedUserColumn = 'Assigned User'

# States the service reports. Anything outside PendingState is final.
$PendingState = @('unknown', 'pending')

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

            With -UseDeviceCode, the code and the address to enter it at are
            shown on the information stream while the sign-in waits for them.
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

    # Connect-MgGraph writes what it has to tell the person signing in - the
    # device code and where to enter it, or the welcome where -NoWelcome is
    # missing - to the output stream, as data. Discarded, the code never shows
    # and the sign-in waits until it times out. Passed on as information, each
    # line shows the moment it is written, while the sign-in still waits, and
    # stays out of what this function returns.
    Connect-MgGraph @connectParameters | ForEach-Object {
        Write-Information -MessageData $_ -InformationAction Continue
    }

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

function Get-CsvColumnValue {
    <#
        .SYNOPSIS
            Reads a CSV column case-insensitively. Files exported from the
            portal and files written by hand disagree about capitalisation.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Row,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    foreach ($property in $Row.PSObject.Properties) {
        if ($property.Name.Trim() -eq $Name) { return [string]$property.Value }
    }

    foreach ($property in $Row.PSObject.Properties) {
        if ($property.Name.Trim().ToUpperInvariant() -eq $Name.ToUpperInvariant()) {
            return [string]$property.Value
        }
    }

    return ''
}

function Import-AutopilotCsvRow {
    <#
        .SYNOPSIS
            Turns CSV rows into validated device objects, collapsing duplicate
            serial numbers and reporting which rows were unusable.

        .DESCRIPTION
            The last occurrence of a serial number wins, matching how the
            collector appends: the newest reading is the current one. Rows that
            cannot be imported are counted and described rather than silently
            dropped, because a CSV that quietly loses half its devices is worse
            than one that fails.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]]$Row,

        [Parameter()]
        [AllowNull()]
        [string]$TagOverride
    )

    $devices = New-Object 'System.Collections.Specialized.OrderedDictionary'
    $problems = New-Object System.Collections.Generic.List[string]
    $number = 1

    foreach ($entry in $Row) {
        $number++

        $serial = (Get-CsvColumnValue -Row $entry -Name $SerialColumn).Trim()
        $hash = (Get-CsvColumnValue -Row $entry -Name $HashColumn).Trim()

        if ([string]::IsNullOrWhiteSpace($serial)) {
            $problems.Add("Line ${number}: no '$SerialColumn'.")
            continue
        }

        if ([string]::IsNullOrWhiteSpace($hash)) {
            $problems.Add("Line ${number}: serial '$serial' has no '$HashColumn'.")
            continue
        }

        # The hash is an Edm.Binary property, sent over REST as base64. A value
        # that is not base64 is rejected by the service with an opaque error, so
        # catch it here where the line number is still known.
        try {
            $null = [System.Convert]::FromBase64String($hash)
        }
        catch {
            $problems.Add("Line ${number}: serial '$serial' has a '$HashColumn' that is not valid base64.")
            continue
        }

        $tag = if ($PSBoundParameters.ContainsKey('TagOverride') -and -not [string]::IsNullOrWhiteSpace($TagOverride)) {
            $TagOverride
        }
        else {
            (Get-CsvColumnValue -Row $entry -Name $GroupTagColumn).Trim()
        }

        $key = $serial.ToUpperInvariant()

        $devices[$key] = [pscustomobject][ordered]@{
            SerialNumber = $serial
            HardwareHash = $hash
            GroupTag     = $tag
            AssignedUser = (Get-CsvColumnValue -Row $entry -Name $AssignedUserColumn).Trim()
        }
    }

    $ordered = New-Object System.Collections.Generic.List[psobject]
    foreach ($key in $devices.Keys) { $ordered.Add($devices[$key]) }

    return [pscustomobject]@{
        Device    = $ordered.ToArray()
        Problem   = $problems.ToArray()
        Duplicate = @($Row).Count - $problems.Count - $ordered.Count
    }
}

function ConvertTo-ImportBody {
    <#
        .SYNOPSIS
            Builds the request body for one device. Optional properties are
            omitted rather than sent empty, which the service treats
            differently.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Device
    )

    $body = @{
        '@odata.type'      = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        serialNumber       = $Device.SerialNumber
        hardwareIdentifier = $Device.HardwareHash
    }

    if (-not [string]::IsNullOrWhiteSpace($Device.GroupTag)) {
        $body['groupTag'] = $Device.GroupTag
    }

    if (-not [string]::IsNullOrWhiteSpace($Device.AssignedUser)) {
        $body['assignedUserPrincipalName'] = $Device.AssignedUser
    }

    return $body
}

function Get-ImportAdvice {
    <#
        .SYNOPSIS
            Turns a service error name into something worth acting on.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ErrorName
    )

    switch ($ErrorName) {
        'ZtdDeviceAlreadyAssigned' {
            return 'Already registered to Autopilot, in this tenant or another one. Check the existing registration before deregistering it.'
        }
        'ZtdDeviceNotFound' {
            return 'The service could not match the hardware hash. Re-collect it on the device; a hash goes stale after hardware changes.'
        }
        'ZtdDuplicateDevice' {
            return 'A device with this serial number is already being imported. Wait for the earlier import to finish.'
        }
        default {
            if ([string]::IsNullOrWhiteSpace($ErrorName)) { return '' }
            return "Service reported '$ErrorName'. See the Autopilot registration troubleshooting guidance."
        }
    }
}

try {
    #region Read and validate the CSV
    $csvRows = @(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)
    Write-Verbose "Read $($csvRows.Count) row(s) from '$CsvPath'."

    if ($csvRows.Count -eq 0) {
        throw "'$CsvPath' contains no rows."
    }

    $parseParameters = @{ Row = $csvRows }
    if ($PSBoundParameters.ContainsKey('GroupTag')) { $parseParameters['TagOverride'] = $GroupTag }

    $parsed = Import-AutopilotCsvRow @parseParameters

    foreach ($problem in $parsed.Problem) {
        Write-Warning $problem
    }

    if ($parsed.Duplicate -gt 0) {
        Write-Warning "Collapsed $($parsed.Duplicate) duplicate serial number(s); the last occurrence of each was kept."
    }

    $devices = @($parsed.Device)

    if ($devices.Count -eq 0) {
        throw "No importable device found in '$CsvPath'. $(@($parsed.Problem).Count) row(s) were unusable; see the warnings above."
    }

    Write-Verbose "$($devices.Count) device(s) ready to import."
    #endregion

    $target = "$($devices.Count) device(s) from '$(Split-Path -Path $CsvPath -Leaf)'"

    if (-not $PSCmdlet.ShouldProcess($target, 'Register with Windows Autopilot')) {
        foreach ($device in $devices) {
            [pscustomobject][ordered]@{
                SerialNumber   = $device.SerialNumber
                GroupTag       = $device.GroupTag
                AssignedUser   = $device.AssignedUser
                Status         = 'notSubmitted'
                ErrorCode      = $null
                ErrorName      = $null
                Advice         = 'Reported by -WhatIf. Nothing was sent to the tenant.'
                RegistrationId = $null
            }
        }

        exit 0
    }

    #region Connect to Microsoft Graph
    # Consent can succeed partially; the helper verifies rather than assumes.
    $ConnectionOpenedHere = Connect-GraphSession -Scope $RequiredScopes -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Submit
    $submitted = New-Object System.Collections.Generic.List[psobject]
    $failedToSubmit = New-Object System.Collections.Generic.List[psobject]

    foreach ($device in $devices) {
        Write-Verbose "Submitting $($device.SerialNumber)."

        try {
            $body = ConvertTo-ImportBody -Device $device
            $response = Invoke-GraphRequestWithRetry -Uri $ImportUri -Method POST -Body $body `
                -MaximumAttempt $MaximumRetryCount

            $id = [string](Get-PropertyValue -InputObject $response -Name 'id')

            if ([string]::IsNullOrWhiteSpace($id)) {
                throw 'Graph accepted the request but returned no import id, so the outcome cannot be tracked.'
            }

            $submitted.Add([pscustomobject]@{
                    Device = $device
                    Id     = $id
                })
        }
        catch {
            Write-Warning "Could not submit $($device.SerialNumber): $($_.Exception.Message)"

            $failedToSubmit.Add([pscustomobject][ordered]@{
                    SerialNumber   = $device.SerialNumber
                    GroupTag       = $device.GroupTag
                    AssignedUser   = $device.AssignedUser
                    Status         = 'submitFailed'
                    ErrorCode      = $null
                    ErrorName      = $null
                    Advice         = $_.Exception.Message
                    RegistrationId = $null
                })
        }
    }

    Write-Verbose "$($submitted.Count) device(s) submitted; $($failedToSubmit.Count) could not be submitted."
    #endregion

    #region Wait for a final state
    $results = New-Object System.Collections.Generic.List[psobject]
    $pending = New-Object System.Collections.Generic.List[psobject]
    foreach ($item in $submitted) { $pending.Add($item) }

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $states = @{}

    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollIntervalSeconds

        $stillPending = New-Object System.Collections.Generic.List[psobject]

        foreach ($item in $pending) {
            try {
                $current = Invoke-GraphRequestWithRetry -Uri "$ImportUri/$($item.Id)" `
                    -MaximumAttempt $MaximumRetryCount

                $state = Get-PropertyValue -InputObject $current -Name 'state'
                $status = [string](Get-PropertyValue -InputObject $state -Name 'deviceImportStatus')

                if ([string]::IsNullOrWhiteSpace($status) -or $status.ToLowerInvariant() -in $PendingState) {
                    $stillPending.Add($item)
                    continue
                }

                $states[$item.Id] = $state
            }
            catch {
                Write-Warning "Could not read the import state for $($item.Device.SerialNumber): $($_.Exception.Message)"
                $stillPending.Add($item)
            }
        }

        if ($stillPending.Count -gt 0) {
            Write-Verbose "Waiting for $($stillPending.Count) of $($submitted.Count) device(s)."
        }

        $pending = $stillPending
    }

    foreach ($item in $submitted) {
        $state = if ($states.ContainsKey($item.Id)) { $states[$item.Id] } else { $null }

        $status = [string](Get-PropertyValue -InputObject $state -Name 'deviceImportStatus')
        $errorName = [string](Get-PropertyValue -InputObject $state -Name 'deviceErrorName')

        if ([string]::IsNullOrWhiteSpace($status)) {
            $status = 'timedOut'
            $advice = "Still pending after $TimeoutMinutes minute(s). The service usually finishes regardless; check the Autopilot devices list in Intune."
        }
        else {
            $advice = Get-ImportAdvice -ErrorName $errorName
        }

        $results.Add([pscustomobject][ordered]@{
                SerialNumber   = $item.Device.SerialNumber
                GroupTag       = $item.Device.GroupTag
                AssignedUser   = $item.Device.AssignedUser
                Status         = $status
                ErrorCode      = Get-PropertyValue -InputObject $state -Name 'deviceErrorCode'
                ErrorName      = $errorName
                Advice         = $advice
                RegistrationId = Get-PropertyValue -InputObject $state -Name 'deviceRegistrationId'
            })
    }

    foreach ($failure in $failedToSubmit) { $results.Add($failure) }
    #endregion

    #region Report
    if ($ReportPath) {
        $reportFile = Join-Path -Path $ReportPath -ChildPath "AutopilotImport-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $results | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Report written to '$reportFile'."
    }

    $complete = @($results | Where-Object { $_.Status -eq 'complete' }).Count
    $alreadyAssigned = @($results | Where-Object { $_.ErrorName -eq 'ZtdDeviceAlreadyAssigned' }).Count
    $failed = @($results | Where-Object { $_.Status -notin @('complete', 'timedOut') -and $_.ErrorName -ne 'ZtdDeviceAlreadyAssigned' }).Count
    $timedOut = @($results | Where-Object { $_.Status -eq 'timedOut' }).Count

    Write-Verbose "Complete: $complete; already registered: $alreadyAssigned; failed: $failed; still pending: $timedOut."

    $results
    #endregion

    if ($failed -gt 0) {
        Write-Error -Message "$failed device(s) failed to import. Inspect the Status, ErrorName and Advice of the returned objects." -ErrorAction Continue
        exit 1
    }

    exit 0
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
