# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }

<#
.SYNOPSIS
    Reports every Intune managed device in a tenant, with optional filtering and
    CSV export.

.DESCRIPTION
    Queries /deviceManagement/managedDevices on the Microsoft Graph v1.0
    endpoint, follows @odata.nextLink until every page is read, and emits one
    flat object per device. Nothing is written to the tenant.

    Filtering is done client-side by default. Intune's managedDevices resource
    documents no optional OData query parameters, and $filter support there is
    inconsistent between properties, so pushing a filter to the service is
    opt-in through -Filter rather than the default.

    Throttling is handled by the shared Graph helpers: a 429 or a 5xx is
    retried, waiting the number of seconds in the Retry-After header when the
    service supplies one and falling back to exponential backoff with jitter
    when it does not. The Graph SDK's own retry is switched off during each
    request, so -MaximumRetryCount is the whole story rather than a multiplier
    on the SDK's three hidden attempts.

    Output is objects, so the result can be sorted, grouped and piped. -CsvPath
    additionally writes a CSV.

.PARAMETER TenantId
    Tenant to connect to, as a GUID or a verified domain name. Optional: an
    existing Microsoft Graph session is reused when it matches, and omitting
    this connects to the signed-in user's home tenant.

.PARAMETER UseDeviceCode
    Authenticate with device code flow: the script prints a code and a URL to
    complete sign-in on any device. Use this where an interactive browser
    prompt is unavailable or blocked, such as a remote session or a workstation
    whose broker sign-in fails.

.PARAMETER OperatingSystem
    Keep only devices whose operatingSystem matches one of these values, case
    insensitively. Typical values are Windows, iOS, iPadOS, macOS and Android.

.PARAMETER ComplianceState
    Keep only devices in one of these compliance states.

.PARAMETER Ownership
    Keep only devices with one of these ownership types.

.PARAMETER StaleAfterDays
    Keep only devices that have not checked in for at least this many days.
    Devices that have never synced are always included, because "never" is
    staler than any threshold.

.PARAMETER Filter
    Raw OData $filter expression sent to the service. Verify it against your own
    tenant first: managedDevices accepts $filter on some properties and rejects
    or silently ignores it on others.

.PARAMETER PageSize
    Requested page size ($top). Some Intune endpoints cap or ignore this. Lower
    it if the service rejects the request.

.PARAMETER CsvPath
    Existing directory to write a timestamped CSV into. Objects are returned
    whether or not this is supplied.

.PARAMETER MaximumRetryCount
    Attempts per request, the first included, before giving up on a throttled
    or failing call.

.EXAMPLE
    .\Get-ManagedDeviceInventory.ps1 -UseDeviceCode -Verbose

    Signs in with device code flow and returns every managed device.

.EXAMPLE
    .\Get-ManagedDeviceInventory.ps1 -OperatingSystem Windows -StaleAfterDays 30 |
        Sort-Object DaysSinceLastSync -Descending | Format-Table

    Windows devices that have not checked in for a month, stalest first.

.EXAMPLE
    .\Get-ManagedDeviceInventory.ps1 -ComplianceState noncompliant -CsvPath C:\Reports

    Writes non-compliant devices to a timestamped CSV and returns the objects.

.EXAMPLE
    .\Get-ManagedDeviceInventory.ps1 -Filter "operatingSystem eq 'Windows'"

    Pushes the filter to the service instead of filtering locally. Verify the
    expression against your tenant before relying on it.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-24

    PowerShell    : 5.1 or 7. No PowerShell 7 syntax is used, so the script runs
                    on a stock Windows workstation as well as on 7.
    Graph scopes  : DeviceManagementManagedDevices.Read.All
    Admin consent : Required. An Intune Administrator or Global Administrator
                    consents once per tenant for the application used to sign
                    in.
    Licensing     : Microsoft Intune Plan 1. The tenant needs an active Intune
                    licence for the Graph API for Intune to respond at all.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later, for
                    -StatusCodeVariable and -SkipHttpErrorCheck on
                    Invoke-MgGraphRequest.
    Role required : Any Intune role with read access to devices. Read-only
                    operator roles are enough; this script never writes.

    Endpoint      : v1.0. The beta endpoint exposes further properties, such as
                    join type and Autopilot enrolment, at the cost of a contract
                    that changes without notice.

    Output        : The result describes real devices and real people. Treat the
                    CSV as tenant data: keep it out of this repository and off
                    shared locations.

.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list

.LINK
    https://learn.microsoft.com/graph/throttling
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$OperatingSystem,

    [Parameter()]
    [ValidateSet('compliant', 'noncompliant', 'conflict', 'error', 'inGracePeriod', 'configManager', 'unknown')]
    [string[]]$ComplianceState,

    [Parameter()]
    [ValidateSet('company', 'personal', 'unknown')]
    [string[]]$Ownership,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleAfterDays,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Filter,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$PageSize = 200,

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "CsvPath '$_' does not exist or is not a directory." }
        })]
    [string]$CsvPath,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ReadWrite also grants read; accept it rather than demanding a second consent.
$RequiredScopes = [ordered]@{
    'DeviceManagementManagedDevices.Read.All' = @('DeviceManagementManagedDevices.ReadWrite.All')
}

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ConnectionOpenedHere = $false

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
            arrives at all. POST is retried only on 429 and 503, the answers
            that mean the service did not act on the request: retrying a POST
            after any other failure could create the same object twice.

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
        [ValidateSet('GET', 'POST')]
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

function ConvertTo-UtcDateTime {
    <#
        .SYNOPSIS
            Reads a Graph timestamp as a UTC DateTime. The helpers keep
            timestamps as the text Graph sent where PowerShell allows, and
            PowerShell 7.0 to 7.4 hand back a DateTime instead, so both arrive
            here.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }

    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
            return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
        }
        return $Value.ToUniversalTime()
    }

    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
        [System.Globalization.DateTimeStyles]::AssumeUniversal

    return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, $styles)
}

function ConvertTo-DeviceRecord {
    <#
        .SYNOPSIS
            Flattens one managedDevice into the reporting shape, converting
            bytes to GB and last check-in into an age in days.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Device
    )

    $lastSync = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $Device -Name 'lastSyncDateTime')
    $daysSinceLastSync = $null

    if ($lastSync) {
        $daysSinceLastSync = [int]([datetime]::UtcNow - $lastSync).TotalDays
    }

    $totalBytes = Get-PropertyValue -InputObject $Device -Name 'totalStorageSpaceInBytes'
    $freeBytes = Get-PropertyValue -InputObject $Device -Name 'freeStorageSpaceInBytes'

    # Computed outside the hashtable: Windows PowerShell 5.1 does not accept a
    # statement as a hashtable value.
    $storageTotalGB = $null
    if ($totalBytes) { $storageTotalGB = [Math]::Round($totalBytes / 1GB, 1) }

    $storageFreeGB = $null
    if ($freeBytes) { $storageFreeGB = [Math]::Round($freeBytes / 1GB, 1) }

    [pscustomobject]@{
        DeviceName        = Get-PropertyValue -InputObject $Device -Name 'deviceName'
        UserPrincipalName = Get-PropertyValue -InputObject $Device -Name 'userPrincipalName'
        UserDisplayName   = Get-PropertyValue -InputObject $Device -Name 'userDisplayName'
        OperatingSystem   = Get-PropertyValue -InputObject $Device -Name 'operatingSystem'
        OsVersion         = Get-PropertyValue -InputObject $Device -Name 'osVersion'
        ComplianceState   = Get-PropertyValue -InputObject $Device -Name 'complianceState'
        Ownership         = Get-PropertyValue -InputObject $Device -Name 'managedDeviceOwnerType'
        ManagementAgent   = Get-PropertyValue -InputObject $Device -Name 'managementAgent'
        EnrollmentType    = Get-PropertyValue -InputObject $Device -Name 'deviceEnrollmentType'
        RegistrationState = Get-PropertyValue -InputObject $Device -Name 'deviceRegistrationState'
        EnrolledDateTime  = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $Device -Name 'enrolledDateTime')
        LastSyncDateTime  = $lastSync
        DaysSinceLastSync = $daysSinceLastSync
        Manufacturer      = Get-PropertyValue -InputObject $Device -Name 'manufacturer'
        Model             = Get-PropertyValue -InputObject $Device -Name 'model'
        SerialNumber      = Get-PropertyValue -InputObject $Device -Name 'serialNumber'
        IsEncrypted       = Get-PropertyValue -InputObject $Device -Name 'isEncrypted'
        IsSupervised      = Get-PropertyValue -InputObject $Device -Name 'isSupervised'
        StorageTotalGB    = $storageTotalGB
        StorageFreeGB     = $storageFreeGB
        Category          = Get-PropertyValue -InputObject $Device -Name 'deviceCategoryDisplayName'
        EntraDeviceId     = Get-PropertyValue -InputObject $Device -Name 'azureADDeviceId'
        IntuneDeviceId    = Get-PropertyValue -InputObject $Device -Name 'id'
    }
}

try {
    #region Connect to Microsoft Graph
    # Reuses a session that already holds the scope, signs in otherwise, and
    # verifies consent either way rather than discovering a gap mid-run.
    $ConnectionOpenedHere = Connect-GraphSession -Scope $RequiredScopes -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Read every page
    $query = @("`$top=$PageSize")
    if ($Filter) { $query += "`$filter=$([uri]::EscapeDataString($Filter))" }

    $uri = '{0}/deviceManagement/managedDevices?{1}' -f $GraphBaseUri, ($query -join '&')

    $devices = New-Object System.Collections.Generic.List[psobject]

    foreach ($device in (Get-GraphCollection -Uri $uri -MaximumAttempt $MaximumRetryCount)) {
        $devices.Add((ConvertTo-DeviceRecord -Device $device))
    }

    Write-Verbose "Retrieved $($devices.Count) device(s)."
    #endregion

    #region Filter
    $results = $devices

    if ($OperatingSystem) {
        $results = @($results | Where-Object { $_.OperatingSystem -and $OperatingSystem -contains $_.OperatingSystem })
    }

    if ($ComplianceState) {
        $results = @($results | Where-Object { $ComplianceState -contains $_.ComplianceState })
    }

    if ($Ownership) {
        $results = @($results | Where-Object { $Ownership -contains $_.Ownership })
    }

    if ($PSBoundParameters.ContainsKey('StaleAfterDays')) {
        # A device that has never synced is staler than any threshold.
        $results = @($results | Where-Object {
                $null -eq $_.DaysSinceLastSync -or $_.DaysSinceLastSync -ge $StaleAfterDays
            })
    }

    $results = @($results)
    Write-Verbose "$($results.Count) device(s) remain after filtering."

    if ($results.Count -eq 0) {
        Write-Warning 'No devices matched. Check the filters, or whether the tenant has enrolled devices.'
    }
    #endregion

    #region Export
    if ($CsvPath) {
        $file = Join-Path -Path $CsvPath -ChildPath ('ManagedDeviceInventory-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $results | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Wrote $($results.Count) row(s) to '$file'."
    }
    #endregion

    $results
}
catch {
    Write-Error -Message "Inventory failed: $($_.Exception.Message)" -ErrorRecord $_
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
