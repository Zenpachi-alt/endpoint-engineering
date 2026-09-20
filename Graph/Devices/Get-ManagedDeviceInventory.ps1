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

    Throttling is handled by reading the status code rather than by catching
    exceptions: a 429 or a 5xx is retried, waiting the number of seconds in the
    Retry-After header when the service supplies one and falling back to
    exponential backoff with jitter when it does not.

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
    Attempts per request before giving up on a throttled or failing call.

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
    Version       : 1.0.0
    Last updated  : 2026-09-20

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

$RequiredScopes = @(
    'DeviceManagementManagedDevices.Read.All'
)

# ReadWrite also grants read; accept it rather than demanding a second consent.
$AcceptedScopes = @(
    'DeviceManagementManagedDevices.Read.All'
    'DeviceManagementManagedDevices.ReadWrite.All'
)

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ConnectionOpenedHere = $false

function Get-PropertyValue {
    <#
        .SYNOPSIS
            Reads a property that may not exist on the response object, without
            tripping Set-StrictMode. Graph omits properties that are null, and
            they differ between v1.0 and beta.
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

function Get-RetryDelaySecond {
    <#
        .SYNOPSIS
            Returns how long to wait before retrying: the Retry-After header
            when the service sent one, otherwise exponential backoff with
            jitter so that parallel runs do not retry in lockstep.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter()]
        [AllowNull()]
        $ResponseHeaders,

        [Parameter(Mandatory)]
        [ValidateRange(1, 100)]
        [int]$Attempt,

        [Parameter()]
        [ValidateRange(1, 600)]
        [int]$MaximumDelaySeconds = 120
    )

    if ($null -ne $ResponseHeaders) {
        foreach ($key in $ResponseHeaders.Keys) {
            if ($key -ne 'Retry-After') { continue }

            # The value arrives as a string or as a single-element collection.
            $raw = @($ResponseHeaders[$key])[0]
            $parsed = 0
            if ([int]::TryParse([string]$raw, [ref]$parsed) -and $parsed -gt 0) {
                return [Math]::Min($parsed, $MaximumDelaySeconds)
            }
        }
    }

    $backoff = [Math]::Pow(2, $Attempt)
    $jitter = Get-Random -Minimum 0 -Maximum 2

    return [int][Math]::Min($backoff + $jitter, $MaximumDelaySeconds)
}

function Invoke-GraphRequestWithRetry {
    <#
        .SYNOPSIS
            GETs a Graph URI, retrying throttled and transient failures.

        .DESCRIPTION
            -SkipHttpErrorCheck turns an HTTP error into a status code and a
            response body rather than an exception, so the retry decision can
            be made on the status code itself. That behaviour is the same on
            Windows PowerShell 5.1 and PowerShell 7, which exception types are
            not.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumRetry = 5
    )

    $attempt = 0

    while ($true) {
        $attempt++

        $statusCode = 0
        $responseHeaders = $null

        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject `
            -StatusCodeVariable statusCode -ResponseHeadersVariable responseHeaders `
            -SkipHttpErrorCheck -ErrorAction Stop

        if ($statusCode -ge 200 -and $statusCode -lt 300) {
            return $response
        }

        $isRetryable = $statusCode -in @(429, 500, 502, 503, 504)

        if (-not $isRetryable -or $attempt -gt $MaximumRetry) {
            $detail = Get-PropertyValue -InputObject (Get-PropertyValue -InputObject $response -Name 'error') -Name 'message'
            if (-not $detail) { $detail = 'no error message returned' }

            throw "Graph returned HTTP $statusCode after $attempt attempt(s) for '$Uri': $detail"
        }

        $delay = Get-RetryDelaySecond -ResponseHeaders $responseHeaders -Attempt $attempt

        if ($statusCode -eq 429) {
            Write-Warning "Throttled by Graph (HTTP 429). Waiting $delay second(s) before attempt $($attempt + 1) of $($MaximumRetry + 1)."
        }
        else {
            Write-Warning "Graph returned HTTP $statusCode. Waiting $delay second(s) before attempt $($attempt + 1) of $($MaximumRetry + 1)."
        }

        Start-Sleep -Seconds $delay
    }
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

    $lastSync = Get-PropertyValue -InputObject $Device -Name 'lastSyncDateTime'
    $daysSinceLastSync = $null

    if ($lastSync) {
        $lastSync = [datetime]$lastSync
        $daysSinceLastSync = [int](New-TimeSpan -Start $lastSync -End (Get-Date)).TotalDays
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
        EnrolledDateTime  = Get-PropertyValue -InputObject $Device -Name 'enrolledDateTime'
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
    $context = Get-MgContext

    $needsConnection = $true
    if ($context) {
        if ($TenantId -and $context.TenantId -ne $TenantId -and $context.Account -notlike "*@$TenantId") {
            Write-Verbose "Existing session is for tenant '$($context.TenantId)'; connecting to '$TenantId' instead."
        }
        else {
            Write-Verbose "Reusing the existing Microsoft Graph session for tenant '$($context.TenantId)'."
            $needsConnection = $false
        }
    }

    if ($needsConnection) {
        $connectParameters = @{
            Scopes      = $RequiredScopes
            NoWelcome   = $true
            ErrorAction = 'Stop'
        }

        if ($TenantId) { $connectParameters['TenantId'] = $TenantId }

        if ($UseDeviceCode) {
            $connectParameters['UseDeviceCode'] = $true
            Write-Verbose 'Starting device code sign-in. A code and URL follow.'
        }

        Connect-MgGraph @connectParameters
        $ConnectionOpenedHere = $true
        $context = Get-MgContext -ErrorAction Stop
    }

    if (-not $context) {
        throw 'No Microsoft Graph session is available after connecting.'
    }
    #endregion

    #region Verify granted scopes
    # Consent can be partial, and a reused session may hold narrower scopes
    # than this script asks for. Check rather than discover it mid-run.
    $grantedScopes = @(Get-PropertyValue -InputObject $context -Name 'Scopes')
    $hasScope = $false

    foreach ($scope in $AcceptedScopes) {
        if ($grantedScopes -contains $scope) { $hasScope = $true; break }
    }

    if (-not $hasScope) {
        throw "The session is missing '$($RequiredScopes -join ', ')'. Reconnect and make sure an administrator has consented. Granted: $($grantedScopes -join ', ')."
    }

    Write-Verbose "Connected as '$($context.Account)' in tenant '$($context.TenantId)'."
    #endregion

    #region Read every page
    $query = @("`$top=$PageSize")
    if ($Filter) { $query += "`$filter=$([uri]::EscapeDataString($Filter))" }

    $uri = '{0}/deviceManagement/managedDevices?{1}' -f $GraphBaseUri, ($query -join '&')

    $devices = New-Object System.Collections.Generic.List[psobject]
    $page = 0

    while ($uri) {
        $page++
        Write-Verbose "Requesting page $page."

        $response = Invoke-GraphRequestWithRetry -Uri $uri -MaximumRetry $MaximumRetryCount

        foreach ($device in @(Get-PropertyValue -InputObject $response -Name 'value')) {
            $devices.Add((ConvertTo-DeviceRecord -Device $device))
        }

        $uri = Get-PropertyValue -InputObject $response -Name '@odata.nextLink'
    }

    Write-Verbose "Retrieved $($devices.Count) device(s) across $page page(s)."
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
