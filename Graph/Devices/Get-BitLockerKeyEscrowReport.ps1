# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Reports, for every Windows device Intune manages, whether Microsoft Entra
    ID holds a BitLocker recovery key for it.

.DESCRIPTION
    Reads every Intune managed device and every BitLocker recovery key in the
    tenant, joins them on the Entra device ID, and returns one object per
    Windows device with a status:

      Escrowed       Entra ID holds a key for the device's OS volume.
      MissingKey     Intune reports the device encrypted, and Entra ID holds
                     no OS volume key for it. These devices cannot be
                     recovered by the helpdesk.
      NotEncrypted   Intune reports the device not encrypted, and Entra ID
                     holds no OS volume key for it.
      NoEntraDevice  The device has no Entra device ID, so its keys cannot be
                     looked up.

    This is the authoritative side of the BitLockerKeyEscrow remediation
    package: the device reports what it sent, Entra ID says what it holds. The
    key IDs listed for each device are the protector IDs the device reports,
    in lower case.

    The recovery keys themselves are never read. The script requests
    BitlockerKey.ReadBasic.All, which cannot return them, and never asks for
    the key property, which would also write an audit record for each key.
    Nothing is written to the tenant.

    Keys for fixed data volumes are counted, but they do not change the
    status: Graph does not say which devices have fixed data volumes. The
    remediation package checks those on the device.

    Devices with 150 or more keys are named in a warning. Entra ID keeps at
    most 200 recovery keys per device, and silent encryption fails past that.

.PARAMETER TenantId
    Tenant to connect to, as a GUID or a verified domain name. Optional: an
    existing Microsoft Graph session is reused when it matches, and omitting
    this connects to the signed-in user's home tenant.

.PARAMETER UseDeviceCode
    Authenticate with device code flow: the script prints a code and a URL to
    complete sign-in on any device.

.PARAMETER Status
    Keep only devices with one of these statuses.

.PARAMETER CsvPath
    Existing directory to write a timestamped CSV into. Objects are returned
    whether or not this is supplied.

.PARAMETER MaximumRetryCount
    Attempts per request, the first included, before giving up on a throttled
    or failing call.

.EXAMPLE
    .\Get-BitLockerKeyEscrowReport.ps1 -Status MissingKey | Format-Table DeviceName, UserPrincipalName, LastSyncDateTime

    The encrypted devices whose key Entra ID does not hold.

.EXAMPLE
    .\Get-BitLockerKeyEscrowReport.ps1 -CsvPath C:\Reports -Verbose

    Every Windows device, written to a timestamped CSV, with a count of each
    status in the verbose stream.

.EXAMPLE
    .\Get-BitLockerKeyEscrowReport.ps1 | Group-Object Status -NoElement

    How many devices are in each status.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-27

    PowerShell    : 5.1 or 7. No PowerShell 7 syntax is used.
    Graph scopes  : DeviceManagementManagedDevices.Read.All
                    (DeviceManagementManagedDevices.ReadWrite.All accepted)
                    BitlockerKey.ReadBasic.All
                    (BitlockerKey.Read.All accepted when already granted)
    Admin consent : Required, for both scopes.
    Licensing     : Microsoft Intune Plan 1.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later.
    Role required : Read access to Intune devices, and an Entra role that may
                    list BitLocker keys: Global Reader, Security Reader,
                    Security Administrator, Helpdesk Administrator, Cloud
                    Device Administrator or Intune Administrator.

    Scoped roles  : An administrator whose role is scoped to administrative
                    units sees only the keys inside that scope. Devices
                    outside it would show MissingKey. Run the report with a
                    tenant-wide role.

    Endpoint      : v1.0.

    Output        : The result names real devices and real people. Treat the
                    CSV as tenant data: keep it out of this repository and off
                    shared locations.

.LINK
    https://learn.microsoft.com/graph/api/bitlocker-list-recoverykeys

.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [ValidateSet('Escrowed', 'MissingKey', 'NotEncrypted', 'NoEntraDevice')]
    [string[]]$Status,

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

# ReadBasic cannot return a key; Read.All can, and is accepted only because an
# administrator who already consented to it should not be asked again.
$RequiredScopes = [ordered]@{
    'DeviceManagementManagedDevices.Read.All' = @('DeviceManagementManagedDevices.ReadWrite.All')
    'BitlockerKey.ReadBasic.All'              = @('BitlockerKey.Read.All')
}

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ConnectionOpenedHere = $false

# Entra ID keeps at most 200 recovery keys per device.
$KeyCountWarningThreshold = 150

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

function ConvertTo-VolumeKind {
    <#
        .SYNOPSIS
            Names the volume a key belongs to. Graph documents volumeType as
            numbers and returns the enum names, so both are read.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $VolumeType
    )

    switch ([string]$VolumeType) {
        { $_ -in @('1', 'operatingSystemVolume') } { return 'OperatingSystem' }
        { $_ -in @('2', 'fixedDataVolume') } { return 'FixedData' }
        { $_ -in @('3', 'removableDataVolume') } { return 'Removable' }
        default { return 'Unknown' }
    }
}

function Get-EscrowReportData {
    <#
        .SYNOPSIS
            Reads every managed device and every BitLocker recovery key,
            without the key itself, and returns both lists.
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

    # No query options: managedDevices documents none, and support for $filter
    # differs between properties. Windows devices are picked out locally.
    $devices = Get-GraphCollection -Uri "$BaseUri/deviceManagement/managedDevices" -MaximumAttempt $MaximumAttempt

    # Never $select=key: the scope cannot return it, and asking would write an
    # audit record per key. The list returns id, createdDateTime, deviceId and
    # volumeType.
    try {
        $keys = Get-GraphCollection -Uri "$BaseUri/informationProtection/bitlocker/recoveryKeys" -MaximumAttempt $MaximumAttempt
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Data.Contains('StatusCode')) { $statusCode = [int]$_.Exception.Data['StatusCode'] }

        if ($statusCode -eq 403) {
            throw ("Listing BitLocker recovery keys was refused (HTTP 403). BitlockerKey.ReadBasic.All is granted, so the " +
                'signed-in account also needs an Entra role that may list keys: Global Reader, Security Reader, Security ' +
                "Administrator, Helpdesk Administrator, Cloud Device Administrator or Intune Administrator. $($_.Exception.Message)")
        }
        throw
    }

    return [pscustomobject]@{
        Devices = $devices
        Keys    = $keys
    }
}

function ConvertTo-EscrowReport {
    <#
        .SYNOPSIS
            Joins Windows managed devices to recovery keys on the Entra device
            ID and returns one record per device. Reads no state, so every
            combination can be tested without a tenant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Device,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Key
    )

    # Keys by Entra device ID, compared without regard to case.
    $keysByDevice = @{}
    foreach ($item in $Key) {
        $deviceId = [string](Get-PropertyValue -InputObject $item -Name 'deviceId')
        if (-not $deviceId) { continue }

        $lookup = $deviceId.ToLowerInvariant()
        if (-not $keysByDevice.ContainsKey($lookup)) {
            # ::new(), not New-Object: a List from New-Object stored in a
            # hashtable makes @() over it throw "Argument types do not match".
            $keysByDevice[$lookup] = [System.Collections.Generic.List[object]]::new()
        }
        $keysByDevice[$lookup].Add($item)
    }

    foreach ($item in $Device) {
        if ([string](Get-PropertyValue -InputObject $item -Name 'operatingSystem') -ne 'Windows') { continue }

        $entraId = [string](Get-PropertyValue -InputObject $item -Name 'azureADDeviceId')
        $parsed = [guid]::Empty
        $hasEntraId = [guid]::TryParse($entraId, [ref]$parsed) -and $parsed -ne [guid]::Empty

        $deviceKeys = @()
        if ($hasEntraId -and $keysByDevice.ContainsKey($entraId.ToLowerInvariant())) {
            $deviceKeys = @($keysByDevice[$entraId.ToLowerInvariant()])
        }

        $osKeyCount = @($deviceKeys | Where-Object { (ConvertTo-VolumeKind -VolumeType (Get-PropertyValue -InputObject $_ -Name 'volumeType')) -eq 'OperatingSystem' }).Count
        $fixedKeyCount = @($deviceKeys | Where-Object { (ConvertTo-VolumeKind -VolumeType (Get-PropertyValue -InputObject $_ -Name 'volumeType')) -eq 'FixedData' }).Count

        $latestKey = $null
        foreach ($entry in $deviceKeys) {
            $created = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $entry -Name 'createdDateTime')
            if ($created -and ($null -eq $latestKey -or $created -gt $latestKey)) { $latestKey = $created }
        }

        $isEncrypted = Get-PropertyValue -InputObject $item -Name 'isEncrypted'

        $status = if (-not $hasEntraId) { 'NoEntraDevice' }
        elseif ($osKeyCount -gt 0) { 'Escrowed' }
        elseif ($isEncrypted -eq $true) { 'MissingKey' }
        else { 'NotEncrypted' }

        $lastSync = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'lastSyncDateTime')
        $daysSinceLastSync = $null
        if ($lastSync) { $daysSinceLastSync = [int]([datetime]::UtcNow - $lastSync).TotalDays }

        $keyIds = @($deviceKeys | ForEach-Object { ([string](Get-PropertyValue -InputObject $_ -Name 'id')).ToLowerInvariant() } | Sort-Object)

        [pscustomobject]@{
            DeviceName        = Get-PropertyValue -InputObject $item -Name 'deviceName'
            UserPrincipalName = Get-PropertyValue -InputObject $item -Name 'userPrincipalName'
            Status            = $status
            IsEncrypted       = $isEncrypted
            OsVolumeKeyCount  = $osKeyCount
            FixedDataKeyCount = $fixedKeyCount
            KeyCount          = $deviceKeys.Count
            LatestKeyDateTime = $latestKey
            KeyIds            = $keyIds -join '; '
            LastSyncDateTime  = $lastSync
            DaysSinceLastSync = $daysSinceLastSync
            EntraDeviceId     = $entraId
            IntuneDeviceId    = Get-PropertyValue -InputObject $item -Name 'id'
        }
    }
}

try {
    #region Connect to Microsoft Graph
    $ConnectionOpenedHere = Connect-GraphSession -Scope $RequiredScopes -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Read and join
    $data = Get-EscrowReportData -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount
    Write-Verbose "Read $($data.Devices.Count) managed device(s) and $($data.Keys.Count) recovery key(s)."

    $records = @(ConvertTo-EscrowReport -Device @($data.Devices) -Key @($data.Keys))
    Write-Verbose "$($records.Count) Windows device(s)."

    $reported = @{}
    foreach ($record in $records) { if ($record.EntraDeviceId) { $reported[$record.EntraDeviceId.ToLowerInvariant()] = $true } }
    $unmatched = @($data.Keys | Where-Object {
            $keyDevice = [string](Get-PropertyValue -InputObject $_ -Name 'deviceId')
            -not $keyDevice -or -not $reported.ContainsKey($keyDevice.ToLowerInvariant())
        })
    if ($unmatched.Count -gt 0) {
        Write-Verbose "$($unmatched.Count) key(s) belong to devices Intune does not manage as Windows devices, and are not reported."
    }

    foreach ($group in @($records | Group-Object -Property Status | Sort-Object -Property Name)) {
        Write-Verbose "$($group.Name): $($group.Count)"
    }

    $crowded = @($records | Where-Object { $_.KeyCount -ge $KeyCountWarningThreshold })
    if ($crowded.Count -gt 0) {
        Write-Warning ("$($crowded.Count) device(s) hold $KeyCountWarningThreshold or more recovery keys, and Entra ID keeps at most 200 per device: " +
            (@($crowded | ForEach-Object { "$($_.DeviceName) ($($_.KeyCount))" }) -join ', ') + '.')
    }
    #endregion

    #region Filter
    $results = $records
    if ($Status) {
        $results = @($results | Where-Object { $Status -contains $_.Status })
    }

    if ($results.Count -eq 0) {
        Write-Warning 'No devices matched. Check -Status, or whether the tenant has Windows devices enrolled.'
    }
    #endregion

    #region Export
    if ($CsvPath) {
        $file = Join-Path -Path $CsvPath -ChildPath ('BitLockerKeyEscrowReport-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $results | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Wrote $($results.Count) row(s) to '$file'."
    }
    #endregion

    $results
}
catch {
    # -Exception, not -ErrorRecord: Write-Error takes -Message with the first
    # and not with the second, and would fail here instead of reporting.
    # -ErrorAction Continue, or the preference set above would stop the script
    # at this line, before exit sets the code.
    Write-Error -Exception $_.Exception -Message "Report failed: $($_.Exception.Message)" -ErrorAction Continue
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
