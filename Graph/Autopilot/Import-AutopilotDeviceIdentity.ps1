# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }

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
    Attempts per Graph request before giving up on a throttled or transient
    failure.

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
    Version       : 1.0.0
    Last updated  : 2026-09-20

    PowerShell    : 5.1 or 7. Keep this line and the #Requires line in step.
    Graph scopes  : DeviceManagementServiceConfig.ReadWrite.All
    Admin consent : Required, once per tenant, for the application signed in
                    with.
    Licensing     : Microsoft Intune Plan 1, with an active Intune licence on
                    the tenant.
    Modules       : Microsoft.Graph.Authentication
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

$RequiredScopes = @(
    'DeviceManagementServiceConfig.ReadWrite.All'
)

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

function Get-PropertyValue {
    <#
        .SYNOPSIS
            Reads a property that may not exist on the response object, without
            tripping Set-StrictMode. Graph omits properties that are null.
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
            Calls a Graph URI, retrying throttled and transient failures.

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
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        [Parameter()]
        [AllowNull()]
        [hashtable]$Body,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumRetry = 5
    )

    $attempt = 0

    while ($true) {
        $attempt++

        $statusCode = 0
        $responseHeaders = $null

        $requestParameters = @{
            Method                  = $Method
            Uri                     = $Uri
            OutputType              = 'PSObject'
            StatusCodeVariable      = 'statusCode'
            ResponseHeadersVariable = 'responseHeaders'
            SkipHttpErrorCheck      = $true
            ErrorAction             = 'Stop'
        }

        if ($Body) { $requestParameters['Body'] = $Body }

        $response = Invoke-MgGraphRequest @requestParameters

        if ($statusCode -ge 200 -and $statusCode -lt 300) {
            return $response
        }

        $isRetryable = $statusCode -in @(429, 500, 502, 503, 504)

        if (-not $isRetryable -or $attempt -gt $MaximumRetry) {
            $detail = Get-PropertyValue -InputObject (Get-PropertyValue -InputObject $response -Name 'error') -Name 'message'
            if (-not $detail) { $detail = 'no error message returned' }

            throw "Graph returned HTTP $statusCode after $attempt attempt(s) for '$Method $Uri': $detail"
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

    # Consent can succeed partially - verify rather than assume.
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missingScopes) {
        throw "The Graph session is missing required scope(s): $($missingScopes -join ', '). Reconnect and grant admin consent."
    }
    #endregion

    #region Submit
    $submitted = New-Object System.Collections.Generic.List[psobject]
    $failedToSubmit = New-Object System.Collections.Generic.List[psobject]

    foreach ($device in $devices) {
        Write-Verbose "Submitting $($device.SerialNumber)."

        try {
            $body = ConvertTo-ImportBody -Device $device
            $response = Invoke-GraphRequestWithRetry -Uri $ImportUri -Method POST -Body $body `
                -MaximumRetry $MaximumRetryCount

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
                    -MaximumRetry $MaximumRetryCount

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
    Write-Error -Message "Script failed: $($_.Exception.Message)" -ErrorRecord $_ -ErrorAction Continue
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
