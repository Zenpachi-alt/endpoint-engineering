# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Resolves a list of device names to Microsoft Entra device object IDs,
    keeps only the devices that pass the filters, and adds them to a group or
    writes them to a CSV for the portal's bulk import.

.DESCRIPTION
    Reads device names from a text file, a CSV column or -DeviceName, looks
    each one up among the Microsoft Entra ID device objects, and returns one
    record per name with a status:

      Matched    Exactly one device record by that name passed the filters.
      NotFound   No device record has that name.
      Excluded   Device records have that name, and none passed the filters.
                 Reason says what each one failed.
      Ambiguous  More than one record by that name passed the filters. None
                 is chosen: narrow the filters or clean up the duplicates.

    Names are trimmed, compared without regard to case, and read up to the
    first dot, so a fully qualified name such as pc01.contoso.com is looked
    up as pc01. Duplicate names in the input are collapsed.

    The filters:

      -TrustType         ServerAd (Microsoft Entra hybrid joined), AzureAd
                         (Microsoft Entra joined), Workplace (Microsoft Entra
                         registered).
      -ActiveWithinDays  The device's activity timestamp,
                         approximateLastSignInDateTime, is no older than this.
                         Entra ID refreshes the timestamp only when it is
                         14 days old, give or take 5, so a window under 21
                         days excludes active devices.
      Disabled devices   Excluded unless -IncludeDisabled is set.

    Without -GroupId, nothing is written to the tenant. The Matched devices'
    object IDs are written to a CSV in the format the Microsoft Entra admin
    center's bulk import of group members expects (Groups > the group >
    Members > Bulk operations > Import members).

    With -GroupId, the script first checks that the group can hold devices
    added by hand: an assigned security group, not dynamic, not synced from
    on-premises, not mail-enabled, not a Microsoft 365 group. It then adds
    every Matched device that is not already a member, after one
    confirmation for the batch. -WhatIf reads everything and adds nothing.
    Adding a device to a group can start deployments to it immediately:
    whatever the group is assigned, the device receives.

    Records are returned whether or not a file is written, and a resolution
    report of every record is written to -OutputPath.

    Exit codes:
      0  The run finished. Names that did not resolve are reported, not
         treated as failures.
      1  A device could not be added, or the script itself failed.

.PARAMETER Path
    A text file with one device name per line, or a CSV file. For a CSV, the
    names are read from -ColumnName, or from its only column.

.PARAMETER ColumnName
    The CSV column that holds the device names. Matched without regard to
    case. Needed only when the CSV has more than one column.

.PARAMETER DeviceName
    Device names given directly instead of through -Path.

.PARAMETER TrustType
    Keep only devices with one of these trust types: ServerAd (hybrid
    joined), AzureAd (Entra joined), Workplace (Entra registered).

.PARAMETER ActiveWithinDays
    Keep only devices whose activity timestamp is no older than this many
    days. A device with no activity timestamp is excluded.

.PARAMETER IncludeDisabled
    Keep disabled devices. By default they are excluded, since a disabled
    device cannot authenticate to Entra ID.

.PARAMETER GroupId
    Object ID of the security group to add the Matched devices to. Without
    it, the script only reads and writes files.

.PARAMETER OutputPath
    Existing directory for the resolution report and the import CSV.
    Defaults to the user's temp directory. Keep it outside this repository:
    the files name real devices.

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
    .\Add-GroupDeviceMember.ps1 -Path .\servers.txt -TrustType ServerAd -ActiveWithinDays 30

    Resolves the names to hybrid joined devices active in the last 30 days,
    and writes the resolution report and the portal import CSV to the temp
    directory. Nothing is written to the tenant.

.EXAMPLE
    .\Add-GroupDeviceMember.ps1 -Path .\devices.csv -ColumnName Hostname -GroupId '<GroupId>' -TrustType ServerAd -WhatIf

    Checks the group, resolves the names, and reports which devices would be
    added and which are already members, without adding any.

.EXAMPLE
    .\Add-GroupDeviceMember.ps1 -Path .\servers.txt -GroupId '<GroupId>' -TrustType ServerAd -ActiveWithinDays 30 -OutputPath C:\Reports

    Adds the resolved devices to the group after one confirmation.

.EXAMPLE
    .\Add-GroupDeviceMember.ps1 -DeviceName 'PC01', 'PC02' | Where-Object Status -ne 'Matched' | Format-Table InputName, Status, Reason

    The names that did not resolve to exactly one device, and why.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-28

    PowerShell    : 5.1 or 7. No PowerShell 7 syntax is used.
    Graph scopes  : Device.Read.All (Device.ReadWrite.All, Directory.Read.All
                    or Directory.ReadWrite.All accepted when already granted)
                    With -GroupId: GroupMember.ReadWrite.All (Group.ReadWrite.All
                    or Directory.ReadWrite.All accepted). With -GroupId and
                    -WhatIf, GroupMember.Read.All is enough (any of the above,
                    Group.Read.All or Directory.Read.All accepted).
    Admin consent : Required, for every scope above.
    Licensing     : Microsoft Entra ID Free. No Intune licence is needed.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later.
    Role required : Reading devices: any member user, unless the tenant
                    restricts default user permissions; Directory Readers
                    otherwise. Adding: Groups Administrator, Intune
                    Administrator (security groups only), User Administrator,
                    Directory Writers, or an owner of the group. A
                    role-assignable group needs Privileged Role Administrator
                    as well.

    Endpoint      : v1.0.

    Output        : The report and the import CSV name real devices. Treat
                    them as tenant data: keep them out of this repository.

.LINK
    https://learn.microsoft.com/graph/api/group-post-members

.LINK
    https://learn.microsoft.com/graph/api/resources/device

.LINK
    https://learn.microsoft.com/entra/identity/users/groups-bulk-import-members

.LINK
    https://learn.microsoft.com/entra/identity/devices/manage-stale-devices
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Path')]
param (
    [Parameter(Mandatory, ParameterSetName = 'Path', HelpMessage = 'Text file with one device name per line, or a CSV.')]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Leaf) { $true }
            else { throw "Path '$_' does not exist or is not a file." }
        })]
    [string]$Path,

    [Parameter(ParameterSetName = 'Path')]
    [ValidateNotNullOrEmpty()]
    [string]$ColumnName,

    [Parameter(Mandatory, ParameterSetName = 'Name')]
    [ValidateNotNullOrEmpty()]
    [string[]]$DeviceName,

    [Parameter()]
    [ValidateSet('ServerAd', 'AzureAd', 'Workplace')]
    [string[]]$TrustType,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$ActiveWithinDays,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$GroupId,

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

# Reading devices always; reading the group with -WhatIf; changing it without.
$RequiredScopes = [ordered]@{
    'Device.Read.All' = @('Device.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
}
if ($GroupId -and $WhatIfPreference) {
    $RequiredScopes['GroupMember.Read.All'] = @('GroupMember.ReadWrite.All', 'Group.Read.All', 'Group.ReadWrite.All',
        'Directory.Read.All', 'Directory.ReadWrite.All')
}
elseif ($GroupId) {
    $RequiredScopes['GroupMember.ReadWrite.All'] = @('Group.ReadWrite.All', 'Directory.ReadWrite.All')
}

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ConnectionOpenedHere = $false

# The header of the admin center's template for importing group members,
# exactly as downloaded. The template has no version row.
$ImportCsvHeader = 'Member object ID or user principal name [memberObjectIdOrUpn] Required'

# Entra ID refreshes the activity timestamp only once it is 14 days old, give
# or take 5, so a shorter window excludes devices that are in use.
$ActivityTimestampResolutionDays = 21

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

            A URI on https://graph.microsoft.com reaches the SDK as a path
            relative to it, which the SDK sends to the same address. Given an
            absolute URI, Invoke-MgGraphRequest swaps the session's cloud
            environment for one with no sign-in endpoint, and keeps the swap.
            The SDK then rebuilds its HTTP client after the next
            Set-MgRequestContext, and a session signed in as a user, or with a
            certificate or secret, fails that request and every one after it
            with "Invalid URI: The format of the URI could not be determined."
            Seen in Microsoft.Graph.Authentication 2.41.0.
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

    # Relative, so that the SDK leaves the session's environment alone; the
    # description says why. Messages keep the URI as the caller gave it.
    $graphHost = 'https://graph.microsoft.com/'
    $requestUri = $Uri
    if ($Uri.StartsWith($graphHost, [System.StringComparison]::OrdinalIgnoreCase)) {
        $requestUri = $Uri.Substring($graphHost.Length)
    }

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
                Uri                     = $requestUri
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

function Read-DeviceNameFile {
    <#
        .SYNOPSIS
            Reads the raw device names from a text file, one per line, or from
            one column of a CSV file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [AllowEmptyString()]
        [string]$ColumnName
    )

    if ([System.IO.Path]::GetExtension($Path) -ne '.csv') {
        return @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    }

    $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    if ($rows.Count -eq 0) { return @() }

    $columns = @($rows[0].PSObject.Properties.Name)

    if ($ColumnName) {
        $column = @($columns | Where-Object { $_.Trim() -eq $ColumnName.Trim() })
        if ($column.Count -eq 0) {
            throw "'$Path' has no column '$ColumnName'. Its columns are: $($columns -join ', ')."
        }
    }
    elseif ($columns.Count -eq 1) {
        $column = $columns
    }
    else {
        throw "'$Path' has $($columns.Count) columns: $($columns -join ', '). Name the one that holds the device names with -ColumnName."
    }

    foreach ($row in $rows) { [string]$row.($column[0]) }
}

function ConvertTo-DeviceNameList {
    <#
        .SYNOPSIS
            Trims the raw names, reads each up to its first dot, drops blanks,
            and collapses duplicates without regard to case, keeping the
            first spelling.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$Name
    )

    $names = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $duplicates = 0

    foreach ($entry in $Name) {
        if ($null -eq $entry) { continue }

        $inputName = $entry.Trim().Trim('"', "'").Trim()
        if (-not $inputName) { continue }

        # A host name has no dots; a fully qualified name starts with one.
        # A name with a space is a display name, and is kept whole.
        $lookupName = $inputName
        if ($inputName -notmatch '\s' -and $inputName.Contains('.')) {
            $lookupName = $inputName.Split('.')[0]
        }
        if (-not $lookupName) { continue }

        if (-not $seen.Add($lookupName)) {
            $duplicates++
            continue
        }

        $names.Add([pscustomobject]@{
                InputName  = $inputName
                LookupName = $lookupName
            })
    }

    return [pscustomobject]@{
        Names          = $names
        DuplicateCount = $duplicates
    }
}

function Get-DeviceByDisplayName {
    <#
        .SYNOPSIS
            Reads every Entra device object whose display name is one of the
            names given, 15 names to a request.

        .DESCRIPTION
            displayName supports 'in' without advanced query parameters, so no
            ConsistencyLevel header is needed. Graph compares display names
            without regard to case. Filtering by trust type and activity is
            left to Get-DeviceFilterMiss, so that a device it excludes can be
            reported with the reason.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]], [object[]])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5,

        [Parameter()]
        [ValidateRange(1, 15)]
        [int]$BatchSize = 15
    )

    $select = 'id,deviceId,displayName,trustType,accountEnabled,approximateLastSignInDateTime,operatingSystem,operatingSystemVersion'
    $devices = [System.Collections.Generic.List[object]]::new()

    for ($start = 0; $start -lt $Name.Count; $start += $BatchSize) {
        $end = [Math]::Min($start + $BatchSize, $Name.Count) - 1
        $quoted = @($Name[$start..$end] | ForEach-Object { "'" + $_.Replace("'", "''") + "'" })
        $filter = [uri]::EscapeDataString("displayName in ($($quoted -join ','))")

        $page = Get-GraphCollection -Uri "$BaseUri/devices?`$filter=$filter&`$select=$select&`$top=999" `
            -MaximumAttempt $MaximumAttempt
        foreach ($device in $page) { $devices.Add($device) }
    }

    return , $devices
}

function Get-DeviceFilterMiss {
    <#
        .SYNOPSIS
            Returns each filter a device fails, as text for the report. No
            output means the device passes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Device,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$TrustType,

        [Parameter()]
        [int]$ActiveWithinDays = 0,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    if ($TrustType) {
        $trust = [string](Get-PropertyValue -InputObject $Device -Name 'trustType')
        if ($TrustType -notcontains $trust) {
            if ($trust) { "trust type $trust" } else { 'no trust type' }
        }
    }

    if (-not $IncludeDisabled -and (Get-PropertyValue -InputObject $Device -Name 'accountEnabled') -eq $false) {
        'disabled'
    }

    if ($ActiveWithinDays -gt 0) {
        $signIn = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $Device -Name 'approximateLastSignInDateTime')
        if (-not $signIn) {
            'no activity recorded'
        }
        elseif ($signIn -lt $Now.AddDays(-$ActiveWithinDays)) {
            "last active $([int][Math]::Floor(($Now - $signIn).TotalDays)) days ago"
        }
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

function Resolve-DeviceName {
    <#
        .SYNOPSIS
            Decides, for every name, which device record it means, if any, and
            returns one record per name in input order. Reads no state, so
            every case can be tested without a tenant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Name,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Device,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$TrustType,

        [Parameter()]
        [int]$ActiveWithinDays = 0,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [datetime]$Now = [datetime]::UtcNow
    )

    $byName = @{}
    foreach ($item in $Device) {
        $displayName = [string](Get-PropertyValue -InputObject $item -Name 'displayName')
        if (-not $displayName) { continue }

        $key = $displayName.ToUpperInvariant()
        if (-not $byName.ContainsKey($key)) {
            # ::new(), not New-Object: a List from New-Object stored in a
            # hashtable makes @() over it throw "Argument types do not match".
            $byName[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $byName[$key].Add($item)
    }

    foreach ($entry in $Name) {
        $key = ([string]$entry.LookupName).ToUpperInvariant()
        $candidates = @()
        if ($byName.ContainsKey($key)) { $candidates = @($byName[$key]) }

        $passing = [System.Collections.Generic.List[object]]::new()
        $misses = [System.Collections.Generic.List[string]]::new()
        foreach ($candidate in $candidates) {
            $miss = @(Get-DeviceFilterMiss -Device $candidate -TrustType $TrustType -ActiveWithinDays $ActiveWithinDays `
                    -IncludeDisabled:$IncludeDisabled -Now $Now)
            if ($miss.Count -eq 0) { $passing.Add($candidate) } else { $misses.Add($miss -join ', ') }
        }

        if ($candidates.Count -eq 0) {
            $status = 'NotFound'
            $reason = 'No Microsoft Entra device has this name.'
        }
        elseif ($passing.Count -eq 1) {
            $status = 'Matched'
            $reason = ''
            if ($candidates.Count -gt 1) {
                $reason = "$($candidates.Count - 1) other record(s) by this name failed the filters: $($misses -join ' | ')."
            }
        }
        elseif ($passing.Count -eq 0) {
            $status = 'Excluded'
            $reason = "Failed the filters: $($misses -join ' | ')."
        }
        else {
            $status = 'Ambiguous'
            $reason = "$($passing.Count) records by this name passed the filters. Narrow them with -TrustType or -ActiveWithinDays, or remove the stale duplicates."
        }

        # The details of the one device the name means, when there is one.
        $shown = $null
        if ($passing.Count -eq 1) { $shown = $passing[0] }
        elseif ($candidates.Count -eq 1) { $shown = $candidates[0] }

        $signIn = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $shown -Name 'approximateLastSignInDateTime')
        $daysSinceActivity = $null
        if ($signIn) { $daysSinceActivity = [int][Math]::Floor(($Now - $signIn).TotalDays) }

        $trust = [string](Get-PropertyValue -InputObject $shown -Name 'trustType')
        $candidateIds = @($candidates | ForEach-Object { [string](Get-PropertyValue -InputObject $_ -Name 'id') })

        [pscustomobject][ordered]@{
            InputName                     = $entry.InputName
            Status                        = $status
            Reason                        = $reason
            DisplayName                   = Get-PropertyValue -InputObject $shown -Name 'displayName'
            ObjectId                      = if ($status -eq 'Matched') { [string](Get-PropertyValue -InputObject $shown -Name 'id') } else { $null }
            DeviceId                      = Get-PropertyValue -InputObject $shown -Name 'deviceId'
            TrustType                     = $trust
            JoinType                      = ConvertTo-JoinType -TrustType $trust
            AccountEnabled                = Get-PropertyValue -InputObject $shown -Name 'accountEnabled'
            OperatingSystem               = Get-PropertyValue -InputObject $shown -Name 'operatingSystem'
            OperatingSystemVersion        = Get-PropertyValue -InputObject $shown -Name 'operatingSystemVersion'
            ApproximateLastSignInDateTime = $signIn
            DaysSinceActivity             = $daysSinceActivity
            CandidateCount                = $candidates.Count
            CandidateObjectIds            = $candidateIds -join '; '
            Membership                    = $null
            MembershipDetail              = $null
        }
    }
}

function Get-GroupRefusal {
    <#
        .SYNOPSIS
            Says why devices cannot be added to this group by hand, or returns
            nothing when they can.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Group
    )

    $groupTypes = @(Get-PropertyValue -InputObject $Group -Name 'groupTypes')

    if ($groupTypes -contains 'DynamicMembership') {
        return 'has dynamic membership: its rule decides the members, and none can be added by hand.'
    }
    if ($groupTypes -contains 'Unified') {
        return 'is a Microsoft 365 group, and only security groups can hold devices.'
    }
    if ((Get-PropertyValue -InputObject $Group -Name 'securityEnabled') -ne $true) {
        return 'is not a security group, and only security groups can hold devices.'
    }
    if ((Get-PropertyValue -InputObject $Group -Name 'mailEnabled') -eq $true) {
        return 'is a mail-enabled security group, which Microsoft Graph cannot change. Manage it in Exchange.'
    }
    if ((Get-PropertyValue -InputObject $Group -Name 'onPremisesSyncEnabled') -eq $true) {
        return 'is synced from on-premises Active Directory. Change its members there.'
    }
}

function Get-TargetGroup {
    <#
        .SYNOPSIS
            Reads the group, refuses one that cannot take devices added by
            hand, and returns it with the object IDs of its direct members.
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

    $select = 'id,displayName,groupTypes,securityEnabled,mailEnabled,onPremisesSyncEnabled'
    try {
        $group = Invoke-GraphRequestWithRetry -Uri "$BaseUri/groups/$GroupId`?`$select=$select" -MaximumAttempt $MaximumAttempt
    }
    catch {
        if ($_.Exception.Data.Contains('StatusCode') -and [int]$_.Exception.Data['StatusCode'] -eq 404) {
            throw "No group has the object ID '$GroupId'. Check that it is the group's object ID, in this tenant."
        }
        throw
    }

    $name = [string](Get-PropertyValue -InputObject $group -Name 'displayName')
    $refusal = Get-GroupRefusal -Group $group
    if ($refusal) { throw "Group '$name' $refusal" }

    $memberIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $members = Get-GraphCollection -Uri "$BaseUri/groups/$GroupId/members?`$select=id&`$top=999" -MaximumAttempt $MaximumAttempt
    foreach ($member in $members) { $null = $memberIds.Add([string](Get-PropertyValue -InputObject $member -Name 'id')) }

    return [pscustomobject]@{
        Id          = $GroupId
        DisplayName = $name
        MemberIds   = $memberIds
    }
}

function Add-DeviceToGroup {
    <#
        .SYNOPSIS
            Adds each Matched record's device to the group, one request each,
            after one confirmation for the batch, and records the outcome on
            the record.

        .DESCRIPTION
            One request per device, because a request that adds several fails
            as a whole when any one of them is refused. Devices already in the
            group are skipped. A 400 that says the device is already a member
            counts as AlreadyMember: that is what a retried request that had
            landed returns. The first 403 stops the batch, since every other
            request would be refused for the same reason.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([void])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Record,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Group,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $toAdd = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Record) {
        if ($item.Status -ne 'Matched') { continue }

        if ($Group.MemberIds.Contains($item.ObjectId)) {
            $item.Membership = 'AlreadyMember'
            continue
        }
        $toAdd.Add($item)
    }

    if ($toAdd.Count -eq 0) { return }

    if (-not $PSCmdlet.ShouldProcess("group '$($Group.DisplayName)' ($($Group.Id))", "Add $($toAdd.Count) device(s)")) {
        foreach ($item in $toAdd) {
            $item.Membership = 'WouldAdd'
            $item.MembershipDetail = 'Not added: the run was a -WhatIf or the batch was declined.'
        }
        return
    }

    $stopReason = $null
    foreach ($item in $toAdd) {
        if ($stopReason) {
            $item.Membership = 'NotAttempted'
            $item.MembershipDetail = $stopReason
            continue
        }

        Write-Verbose "Adding $($item.DisplayName) ($($item.ObjectId))."
        try {
            $body = @{ '@odata.id' = "$BaseUri/directoryObjects/$($item.ObjectId)" }
            $null = Invoke-GraphRequestWithRetry -Uri "$BaseUri/groups/$($Group.Id)/members/`$ref" -Method POST -Body $body `
                -MaximumAttempt $MaximumAttempt
            $item.Membership = 'Added'
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Data.Contains('StatusCode')) { $statusCode = [int]$_.Exception.Data['StatusCode'] }
            $message = $_.Exception.Message

            if ($statusCode -eq 400 -and $message -match 'already exist') {
                $item.Membership = 'AlreadyMember'
                continue
            }

            $item.Membership = 'Failed'
            $item.MembershipDetail = $message

            if ($statusCode -eq 403) {
                $item.MembershipDetail = ('Refused (HTTP 403). The signed-in account needs a role that may change this ' +
                    'group: Groups Administrator, Intune Administrator, User Administrator, Directory Writers or group ' +
                    "owner; a role-assignable group also needs Privileged Role Administrator. $message")
                $stopReason = 'Not attempted: an earlier request was refused with HTTP 403.'
            }
        }
    }
}

try {
    #region Read the names
    if ($Path) {
        $rawNames = @(Read-DeviceNameFile -Path $Path -ColumnName $ColumnName)
        $source = "'$Path'"
    }
    else {
        $rawNames = @($DeviceName)
        $source = '-DeviceName'
    }

    $list = ConvertTo-DeviceNameList -Name $rawNames
    $names = @($list.Names)
    if ($names.Count -eq 0) { throw "$source holds no device names." }

    Write-Verbose "Read $($names.Count) device name(s) from $source."
    if ($list.DuplicateCount -gt 0) {
        Write-Warning "Collapsed $($list.DuplicateCount) duplicate name(s); names are compared without regard to case or domain."
    }

    if ($ActiveWithinDays -gt 0 -and $ActiveWithinDays -lt $ActivityTimestampResolutionDays) {
        Write-Warning ("-ActiveWithinDays $ActiveWithinDays is shorter than the activity timestamp can show: Entra ID refreshes " +
            "it only when it is 14 days old, give or take 5. Devices in use can be excluded; $ActivityTimestampResolutionDays days or more is reliable.")
    }
    #endregion

    #region Connect to Microsoft Graph
    $ConnectionOpenedHere = Connect-GraphSession -Scope $RequiredScopes -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Check the group before anything else is read
    $group = $null
    if ($GroupId) {
        $group = Get-TargetGroup -GroupId $GroupId -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount
        Write-Verbose "Group '$($group.DisplayName)' has $($group.MemberIds.Count) direct member(s)."
    }
    #endregion

    #region Resolve
    # ForEach-Object { $_.Name }, never ForEach-Object Name: the second form
    # honours -WhatIf, and returns nothing under it.
    $devices =Get-DeviceByDisplayName -Name @($names | ForEach-Object { $_.LookupName }) -BaseUri $GraphBaseUri `
        -MaximumAttempt $MaximumRetryCount
    Write-Verbose "Found $($devices.Count) device record(s) with those names."

    $records = @(Resolve-DeviceName -Name $names -Device @($devices) -TrustType $TrustType `
            -ActiveWithinDays $ActiveWithinDays -IncludeDisabled:$IncludeDisabled)

    $counts = foreach ($status in 'Matched', 'NotFound', 'Excluded', 'Ambiguous') {
        "$status $(@($records | Where-Object Status -EQ $status).Count)"
    }
    Write-Information "Resolved $($records.Count) name(s): $($counts -join ', ')."

    if (@($records | Where-Object Status -EQ 'Matched').Count -eq 0) {
        Write-Warning 'No name resolved to a device that passed the filters. See Status and Reason on each record.'
    }
    #endregion

    #region Add to the group
    if ($group) {
        Add-DeviceToGroup -Record $records -Group $group -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount

        $membership = foreach ($outcome in 'Added', 'AlreadyMember', 'WouldAdd', 'Failed', 'NotAttempted') {
            $count = @($records | Where-Object Membership -EQ $outcome).Count
            if ($count -gt 0) { "$outcome $count" }
        }
        if ($membership) { Write-Information "Group '$($group.DisplayName)': $($membership -join ', ')." }
    }
    #endregion

    #region Write the files
    # Files are reports, not tenant changes: -WhatIf must not stop them.
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportFile = Join-Path -Path $OutputPath -ChildPath "GroupDeviceMember-$stamp.csv"
    $records | Export-Csv -LiteralPath $reportFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
    Write-Information "Report: $reportFile"

    # The portal import is the alternative to -GroupId, so it is written
    # unless the devices were added here. Current members are left out: the
    # import would fail on them.
    $added = @($records | Where-Object { $_.Membership -in @('Added', 'Failed', 'NotAttempted') }).Count -gt 0
    $importIds = @($records | Where-Object { $_.Status -eq 'Matched' -and $_.Membership -ne 'AlreadyMember' } |
            ForEach-Object { $_.ObjectId })

    if (-not $added -and $importIds.Count -gt 0) {
        $importFile = Join-Path -Path $OutputPath -ChildPath "GroupDeviceMember-$stamp-Import.csv"
        @($ImportCsvHeader) + $importIds |
            Set-Content -LiteralPath $importFile -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
        Write-Information "Import CSV: $importFile ($($importIds.Count) object ID(s))"

        if ($importIds.Count -eq 1) {
            Write-Warning 'The admin center asks for at least two members in an import file. Add a single device in the portal directly, or with -GroupId.'
        }
    }
    #endregion

    $records

    $failed = @($records | Where-Object { $_.Membership -in @('Failed', 'NotAttempted') }).Count
    if ($failed -gt 0) {
        throw "$failed device(s) were not added to the group. See Membership and MembershipDetail on the returned records."
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
