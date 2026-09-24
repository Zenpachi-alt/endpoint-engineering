# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }

<#
.SYNOPSIS
    Read-only backup of Intune remediations, platform scripts, configuration
    profiles and compliance policies through Microsoft Graph.

.DESCRIPTION
    For each object the script saves the full definition as JSON, its
    assignments, and any embedded script content as a separate .ps1 or .sh file.
    It also writes:

      BackupIndex.csv     one row per object: category, sub-type, name, ID, last
                          modified, resolved assignment summary (group and
                          filter names), status and notes
      BackupManifest.json run metadata (tenant, account, parameters, counts)
      Backup.log          timestamped log

    Nothing is changed in the tenant. Every call is an HTTP GET.

    Graph endpoints, all called on beta:

      Remediations          deviceManagement/deviceHealthScripts
                            beta only
      PlatformScripts       deviceManagement/deviceManagementScripts (Windows)
                            deviceManagement/deviceShellScripts (macOS)
                            beta only
      ConfigurationProfiles deviceManagement/configurationPolicies
                            beta only; settings catalog, endpoint security,
                            security baselines
                            deviceManagement/deviceConfigurations
                            v1.0 exists; beta used because it returns the full
                            profile type set
                            deviceManagement/groupPolicyConfigurations
                            beta only; administrative templates
      CompliancePolicies    deviceManagement/deviceCompliancePolicies
                            v1.0 exists; beta used for parity
                            deviceManagement/deviceComplianceScripts
                            beta only; custom compliance
      Name resolution       v1.0 groups/{id}
                            beta deviceManagement/assignmentFilters/{id}

.PARAMETER OutputPath
    Folder where a timestamped IntuneBackup_yyyyMMdd-HHmmss subfolder is
    created. Point this outside the repository: the backup contains tenant data.

.PARAMETER Category
    One or more of Remediations, PlatformScripts, ConfigurationProfiles,
    CompliancePolicies. Defaults to all four.

.PARAMETER Name
    Limit the backup to objects with these display names. Case-insensitive, and
    compared after normalising whitespace (including non-breaking and trailing
    spaces), dash and quote variants, and zero-width characters; a match that
    needed normalising is logged. Values containing * or ? are wildcards
    (brackets stay literal). Names that match nothing are reported at the end
    with the closest names found.

.PARAMETER Id
    Limit the backup to objects with these IDs. Can be combined with -Name: an
    object matching either is included.

.PARAMETER IncludeDeviceRunStates
    Also export per-device run state CSVs for remediations and platform scripts,
    the device status report. Recommended before deleting a remediation, because
    its report history is deleted with it. Adds
    DeviceManagementManagedDevices.Read.All to the requested scopes. Slow on
    large estates.

.PARAMETER IncludeOmaSecretValues
    For custom (OMA-URI) profiles with encrypted values, retrieve and save the
    plain-text values. This writes secrets to disk in clear text - store the
    backup accordingly. Off by default.

.PARAMETER SkipGroupNameResolution
    Record assignment group IDs only. Use when GroupMember.Read.All is not
    available.

.PARAMETER TenantId
    Tenant to connect to when a new connection is needed, as a GUID or a
    verified domain name. Omitting this uses the signed-in user's home tenant.

.PARAMETER CsvDelimiter
    Delimiter for BackupIndex.csv and the run state CSVs. Defaults to ','. Use
    ';' where Excel on the device uses a semicolon list separator.

.PARAMETER MaxRetries
    Attempts per request, the first included, for throttled (429), transient
    (5xx) and unanswered requests. Each retry is logged to Backup.log.

.EXAMPLE
    .\Backup-IntuneConfiguration.ps1 -OutputPath 'C:\IntuneBackups'

    Full backup of all four categories.

.EXAMPLE
    $items = Get-Content .\cmr-items.txt
    .\Backup-IntuneConfiguration.ps1 -OutputPath 'C:\IntuneBackups' -Category Remediations -Name $items -IncludeDeviceRunStates

    Backs up only the remediations listed for a cleanup change request, one
    display name per line, including their device status reports.

.EXAMPLE
    .\Backup-IntuneConfiguration.ps1 -OutputPath 'C:\IntuneBackups' -SkipGroupNameResolution -Verbose

    Records assignment group IDs rather than names, for an account that has no
    directory read permission.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.2.0
    Last updated  : 2026-09-24

    PowerShell    : 7.2 or later. The script uses Path.GetRelativePath and
                    -Encoding utf8BOM, which Windows PowerShell 5.1 lacks, and
                    keeps Graph timestamps as strings on 7.5 and later, where
                    ConvertFrom-Json -DateKind exists.
    Graph scopes  : DeviceManagementConfiguration.Read.All, always.
                    DeviceManagementScripts.Read.All, for Remediations,
                    PlatformScripts and CompliancePolicies.
                    DeviceManagementManagedDevices.Read.All, only with
                    -IncludeDeviceRunStates.
                    GroupMember.Read.All, unless -SkipGroupNameResolution.
                    The ReadWrite equivalents are accepted where already
                    granted, as are Group.Read.All and Directory.Read.All for
                    the group read.
    Admin consent : Required, once per tenant, for every scope above.
    Licensing     : Microsoft Intune Plan 1. The tenant needs an active Intune
                    licence for the Graph API for Intune to respond at all.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later, for
                    -StatusCodeVariable and -SkipHttpErrorCheck on
                    Invoke-MgGraphRequest.
    Role required : Any Intune role that can read these objects. Read-only
                    operator roles are enough; this script never writes.

    Endpoint      : beta, by necessity. Most of these resources exist nowhere
                    else, and the two that also exist on v1.0 are read on beta
                    for parity. The beta contract changes without notice; the
                    description above lists which endpoint serves what.

    Scope tags    : Intune scope tags apply. Objects outside the signed-in
                    account's scope are not returned, and will be missing from
                    the backup without an error.

    App-only      : For unattended use, connect with Connect-MgGraph and a
                    certificate before running. The equivalent application
                    permissions must be granted. The script verifies them
                    against the session and stops, naming the missing one,
                    rather than failing object by object; an app-only session
                    is never replaced by an interactive sign-in.

    Session       : An existing session that already holds the scopes is
                    reused and left open. Otherwise the script signs in, and
                    disconnects that session when the run ends.

    Not included  : Apps, legacy endpoint security intents
                    (deviceManagement/intents), notification message templates
                    referenced by compliance actions (their IDs are recorded in
                    Notes), and secret values that Graph does not return, such
                    as some Wi-Fi and VPN keys. Those must be re-entered on
                    restore.

    Output        : The backup contains policy names, assignment group names and
                    the tenant ID, and with -IncludeDeviceRunStates it names
                    real devices. Treat the output folder as tenant data and
                    keep it out of this repository.

    Exit codes    : 0 all selected objects backed up; warnings may still be
                      listed in BackupIndex.csv.
                    1 fatal error: the output folder or the Graph connection
                      failed.
                    2 finished, but one or more objects or category listings
                      failed.

.LINK
    https://learn.microsoft.com/graph/api/resources/intune-graph-overview

.LINK
    https://learn.microsoft.com/graph/throttling
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('Remediations', 'PlatformScripts', 'ConfigurationProfiles', 'CompliancePolicies')]
    [string[]]$Category = @('Remediations', 'PlatformScripts', 'ConfigurationProfiles', 'CompliancePolicies'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Name,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$Id,

    [Parameter()]
    [switch]$IncludeDeviceRunStates,

    [Parameter()]
    [switch]$IncludeOmaSecretValues,

    [Parameter()]
    [switch]$SkipGroupNameResolution,

    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [char]$CsvDelimiter = ',',

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 6
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$script:GraphBeta      = 'https://graph.microsoft.com/beta'
$script:GraphV1        = 'https://graph.microsoft.com/v1.0'
$script:ScriptVersion  = '1.2.0'
$script:LogFile        = $null
$script:BackupRoot     = $null
$script:Index          = [System.Collections.Generic.List[object]]::new()
$script:FailedCount    = 0
$script:CategoryErrors = 0
$script:GroupCache     = @{}
$script:FilterCache    = @{}
$script:ResolveGroups  = -not $SkipGroupNameResolution
$script:MatchedNames   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:MatchedIds     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:SeenObjects    = [System.Collections.Generic.List[object]]::new()

# Passed to every Graph call: the attempt limit from -MaxRetries, and retry
# notices written to Backup.log as well as to the console.
$script:GraphRequestOptions = @{
    MaximumAttempt = $MaxRetries
    OnRetry        = { param($Message) Write-BackupLog -Level WARN -Message $Message }
}

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

#region Helpers ---------------------------------------------------------------------------------------

function Write-BackupLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'), $Level, $Message
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding utf8
    }
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error -Message $Message -ErrorAction Continue }
        default { Write-Verbose $Message }
    }
}

function Get-GraphObject {
    # One GET through the shared helpers, with this run's retry settings. A
    # failure carries the HTTP status in $_.Exception.Data['StatusCode'].
    [CmdletBinding()]
    [OutputType([psobject])]
    param([Parameter(Mandatory)][string]$Uri)
    Invoke-GraphRequestWithRetry -Uri $Uri @GraphRequestOptions
}

function Save-JsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Path)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 100
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Save-Base64File {
    # Writes decoded script content byte-for-byte (keeps the original encoding). Returns $true if written.
    [CmdletBinding()]
    param([AllowNull()][string]$Base64, [Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Base64)) { return $false }
    [System.IO.File]::WriteAllBytes($Path, [Convert]::FromBase64String($Base64))
    return $true
}

function Get-SafeName {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][string]$Value, [int]$MaxLength = 60)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Unnamed' }
    $safe = ($Value -replace '[<>:"/\\|?*\x00-\x1F]', '_') -replace '\s+', ' '
    $safe = $safe.Trim().TrimEnd('.', ' ')
    if ($safe.Length -gt $MaxLength) { $safe = $safe.Substring(0, $MaxLength).TrimEnd('.', ' ') }
    if ($safe -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { $safe = "${safe}_" }
    if (-not $safe) { $safe = 'Unnamed' }
    return $safe
}

function Initialize-BackupFolder {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    return $Path
}

function Format-UtcDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    try {
        $utc = if ($Value -is [datetime]) {
            if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value } else { $Value.ToUniversalTime() }
        }
        else {
            [datetimeoffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture).UtcDateTime
        }
        return $utc.ToString('dd.MM.yyyy HH:mm') + ' UTC'
    }
    catch { return [string]$Value }
}

function Resolve-GroupName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$GroupId)
    if (-not $script:ResolveGroups) { return $GroupId }
    if ($script:GroupCache.ContainsKey($GroupId)) { return $script:GroupCache[$GroupId] }
    $name = $GroupId
    try {
        $group = Get-GraphObject -Uri ('{0}/groups/{1}?$select=id,displayName' -f $script:GraphV1, $GroupId)
        $name = $group.displayName
    }
    catch {
        $code = $_.Exception.Data['StatusCode']
        if ($code -eq 404) {
            $name = "[deleted group $GroupId]"
        }
        elseif ($code -in 401, 403) {
            Write-BackupLog -Level WARN -Message 'No permission to read groups (GroupMember.Read.All). Recording group IDs only for the rest of the run.'
            $script:ResolveGroups = $false
            return $GroupId
        }
        else {
            Write-BackupLog -Level WARN -Message "Could not resolve group ${GroupId}: $($_.Exception.Message)"
        }
    }
    $script:GroupCache[$GroupId] = $name
    return $name
}

function Resolve-FilterName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilterId)
    if ($script:FilterCache.ContainsKey($FilterId)) { return $script:FilterCache[$FilterId] }
    $name = $FilterId
    try {
        $filter = Get-GraphObject -Uri ('{0}/deviceManagement/assignmentFilters/{1}?$select=id,displayName' -f $script:GraphBeta, $FilterId)
        $name = $filter.displayName
    }
    catch {
        if ($_.Exception.Data['StatusCode'] -eq 404) { $name = "[deleted filter $FilterId]" }
        else { Write-BackupLog -Level WARN -Message "Could not resolve filter ${FilterId}: $($_.Exception.Message)" }
    }
    $script:FilterCache[$FilterId] = $name
    return $name
}

function Format-RunSchedule {
    [CmdletBinding()]
    param([AllowNull()]$Schedule)
    if (-not $Schedule) { return $null }
    $type = [string]$Schedule.'@odata.type'
    $time = if ($Schedule.time) { ([string]$Schedule.time).Substring(0, [math]::Min(5, ([string]$Schedule.time).Length)) } else { $null }
    $zone = if ($Schedule.useUtc) { ' UTC' } else { ' device time' }
    switch -Wildcard ($type) {
        '*HourlySchedule' { return 'every {0} hour(s)' -f $Schedule.interval }
        '*DailySchedule'  { return 'every {0} day(s) at {1}{2}' -f $Schedule.interval, $time, $zone }
        '*RunOnceSchedule' { return 'once on {0} at {1}{2}' -f $Schedule.date, $time, $zone }
        default { return $type }
    }
}

function Format-AssignmentSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Assignments)
    $parts = foreach ($assignment in $Assignments) {
        $target = $assignment.target
        $type = [string]$target.'@odata.type'
        $text = switch -Wildcard ($type) {
            '*exclusionGroupAssignmentTarget'   { 'Exclude: ' + (Resolve-GroupName -GroupId $target.groupId); break }
            '*groupAssignmentTarget'            { 'Include: ' + (Resolve-GroupName -GroupId $target.groupId); break }
            '*allDevicesAssignmentTarget'       { 'Include: All Devices'; break }
            '*allLicensedUsersAssignmentTarget' { 'Include: All Users'; break }
            default                             { "Target: $type" }
        }
        $filterId = [string]$target.deviceAndAppManagementAssignmentFilterId
        $filterType = [string]$target.deviceAndAppManagementAssignmentFilterType
        if ($filterId -and $filterType -and $filterType -ne 'none') {
            $text += ' [filter {0}: {1}]' -f $filterType, (Resolve-FilterName -FilterId $filterId)
        }
        if ($assignment.PSObject.Properties['runSchedule'] -and $assignment.runSchedule) {
            $text += ' [' + (Format-RunSchedule -Schedule $assignment.runSchedule) + ']'
        }
        if ($assignment.PSObject.Properties['runRemediationScript'] -and $assignment.runRemediationScript -eq $false) {
            $text += ' [detection only]'
        }
        $text
    }
    if (-not $parts) { return 'Not assigned' }
    return ($parts -join '; ')
}

function ConvertTo-MatchKey {
    # Normalises a display name for comparison: Unicode compatibility form, dash/quote variants,
    # zero-width characters and BOM removed, all whitespace runs collapsed to one space, trimmed.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    try { $Value = $Value.Normalize([System.Text.NormalizationForm]::FormKC) }
    catch { Write-Debug 'Could not normalise a display name; comparing it as supplied.' }
    $Value = $Value -replace '[\u2010-\u2015\u2212]', '-'
    $Value = $Value -replace '[\u2018\u2019\u201A\u201B]', "'"
    $Value = $Value -replace '[\u201C\u201D\u201E\u201F]', '"'
    $Value = $Value -replace '[\u200B-\u200D\u2060\uFEFF]', ''
    $Value = $Value -replace '\s+', ' '
    return $Value.Trim()
}

function Get-EditDistance {
    # Case-insensitive Levenshtein distance, used only to suggest close names for unmatched -Name values.
    [CmdletBinding()]
    param([AllowEmptyString()][string]$First, [AllowEmptyString()][string]$Second)
    $a = $First.ToLowerInvariant()
    $b = $Second.ToLowerInvariant()
    $previous = [int[]](0..$b.Length)
    for ($i = 1; $i -le $a.Length; $i++) {
        $current = [int[]]::new($b.Length + 1)
        $current[0] = $i
        for ($j = 1; $j -le $b.Length; $j++) {
            $cost = if ($a[$i - 1] -ceq $b[$j - 1]) { 0 } else { 1 }
            $current[$j] = [math]::Min([math]::Min($current[$j - 1] + 1, $previous[$j] + 1), $previous[$j - 1] + $cost)
        }
        $previous = $current
    }
    return $previous[$b.Length]
}

function Test-Selected {
    # True when no -Name/-Id filter is set, or the object matches one. Records which filters matched.
    [CmdletBinding()]
    param([AllowNull()][string]$DisplayName, [AllowNull()][string]$ObjectId)
    if (-not $Name -and -not $Id) { return $true }

    $key = ConvertTo-MatchKey -Value $DisplayName
    $script:SeenObjects.Add([pscustomobject]@{ Name = $DisplayName; Key = $key; Id = $ObjectId })
    $selected = $false

    foreach ($pattern in $Name) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        $patternKey = ConvertTo-MatchKey -Value $pattern
        if ($pattern.Contains('*') -or $pattern.Contains('?')) {
            $isMatch = $key -like ($patternKey -replace '(\[|\])', '`$1')
            $isExact = $isMatch
        }
        else {
            $isMatch = $key -eq $patternKey
            $isExact = $DisplayName -eq $pattern
        }
        if ($isMatch) {
            [void]$script:MatchedNames.Add($pattern)
            $selected = $true
            if (-not $isExact) {
                Write-BackupLog -Level WARN -Message ("-Name '{0}' matched '{1}' ({2}) only after normalising spaces, dashes or quotes. Correct the name in the source list." -f $pattern, $DisplayName, $ObjectId)
            }
        }
    }

    $idKey = ([string]$ObjectId).Trim()
    foreach ($entry in $Id) {
        if (-not [string]::IsNullOrWhiteSpace($entry) -and $entry.Trim() -eq $idKey) {
            [void]$script:MatchedIds.Add($entry)
            $selected = $true
        }
    }
    return $selected
}

function Get-CategoryList {
    # Lists a collection; on failure logs and returns $null so other categories continue.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]], [object[]])]
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Uri, [switch]$Optional)
    try {
        $list = Get-GraphCollection -Uri $Uri @GraphRequestOptions
        Write-BackupLog -Message ('{0}: {1} object(s) in tenant' -f $Label, $list.Count)
        return , $list
    }
    catch {
        if ($Optional) {
            Write-BackupLog -Level WARN -Message "${Label}: listing skipped - $($_.Exception.Message)"
        }
        else {
            Write-BackupLog -Level ERROR -Message "${Label}: listing failed - $($_.Exception.Message)"
            $script:CategoryErrors++
        }
        return $null
    }
}

function Invoke-ItemBackup {
    <#
        Runs one object's backup body, catches failures, and adds the index row.
        The body receives ($Item, $Folder, $Context); it sets $Context.SubType, .GraphType, .Assignments
        and calls Add-ItemNote for warnings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)]$Item,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$CategoryRoot,
        [Parameter(Mandatory)][scriptblock]$Body
    )
    $objectId = [string]$Item.id
    $shortId = if ($objectId.Length -ge 8) { $objectId.Substring(0, 8) } else { $objectId }
    $context = [pscustomobject]@{
        SubType      = ''
        GraphType    = ([string]$Item.'@odata.type') -replace '^#microsoft\.graph\.', ''
        Assignments  = $null
        LastModified = $Item.lastModifiedDateTime
        Status       = 'OK'
        Notes        = [System.Collections.Generic.List[string]]::new()
        Folder       = $null
    }
    try {
        $context.Folder = Initialize-BackupFolder -Path (Join-Path $CategoryRoot ('{0}_{1}' -f (Get-SafeName -Value $DisplayName), $shortId))
        & $Body $Item $context.Folder $context
        Write-BackupLog -Message ('{0}: backed up "{1}" ({2})' -f $Category, $DisplayName, $objectId)
    }
    catch {
        $context.Status = 'Failed'
        $context.Notes.Add($_.Exception.Message)
        $script:FailedCount++
        if ($context.Folder -and (Test-Path -LiteralPath $context.Folder) -and -not (Get-ChildItem -LiteralPath $context.Folder -Force)) {
            Remove-Item -LiteralPath $context.Folder -Force
            $context.Folder = $null
        }
        Write-BackupLog -Level ERROR -Message ('{0}: "{1}" ({2}) failed - {3}' -f $Category, $DisplayName, $objectId, $_.Exception.Message)
    }

    $assignmentCount = if ($null -ne $context.Assignments) { @($context.Assignments).Count } else { '' }
    $assignmentText = ''
    if ($null -ne $context.Assignments) {
        try { $assignmentText = Format-AssignmentSummary -Assignments $context.Assignments }
        catch { $assignmentText = "Could not format assignments: $($_.Exception.Message)" }
    }
    $relativeFolder = if ($context.Folder) { [System.IO.Path]::GetRelativePath($script:BackupRoot, $context.Folder) } else { '' }

    $script:Index.Add([pscustomobject][ordered]@{
            Category        = $Category
            SubType         = $context.SubType
            DisplayName     = $DisplayName
            Id              = $objectId
            GraphType       = $context.GraphType
            LastModified    = Format-UtcDate -Value $context.LastModified
            AssignmentCount = $assignmentCount
            Assignments     = $assignmentText
            Status          = $context.Status
            Notes           = ($context.Notes -join ' | ')
            Folder          = $relativeFolder
        })
}

function Add-ItemNote {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Message, [switch]$Warning)
    $Context.Notes.Add($Message)
    if ($Warning -and $Context.Status -eq 'OK') { $Context.Status = 'Warning' }
}

function Export-DeviceRunState {
    # Exports deviceRunStates for a remediation or platform script. Returns the number of rows.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$ObjectUri,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Fields
    )
    $states = $null
    $expandOptions = @('?$expand=managedDevice($select=id,deviceName)', '?$expand=managedDevice', '')
    foreach ($expand in $expandOptions) {
        try {
            $states = Get-GraphCollection -Uri ($ObjectUri + '/deviceRunStates' + $expand) @GraphRequestOptions
            break
        }
        catch {
            if ($_.Exception.Data['StatusCode'] -ne 400 -or $expand -eq '') { throw }
        }
    }
    if (-not $states -or $states.Count -eq 0) { return 0 }

    $rows = foreach ($state in $states) {
        $row = [ordered]@{
            DeviceName      = $state.managedDevice.deviceName
            ManagedDeviceId = $state.managedDevice.id
        }
        foreach ($field in $Fields) { $row[$field] = $state.$field }
        [pscustomobject]$row
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8BOM -Delimiter $CsvDelimiter
    return $states.Count
}

#endregion

#region Category backups -------------------------------------------------------------------------------

function Backup-Remediation {
    [CmdletBinding()]
    param()
    $label = 'Remediations'
    $root = Initialize-BackupFolder -Path (Join-Path $script:BackupRoot $label)
    $list = Get-CategoryList -Label $label -Uri "$script:GraphBeta/deviceManagement/deviceHealthScripts"
    if ($null -eq $list) { return }

    foreach ($item in $list) {
        if (-not (Test-Selected -DisplayName $item.displayName -ObjectId $item.id)) { continue }
        Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.displayName) -CategoryRoot $root -Body {
            param($Item, $Folder, $Context)
            $objectUri = '{0}/deviceManagement/deviceHealthScripts/{1}' -f $script:GraphBeta, $Item.id
            $object = Get-GraphObject -Uri $objectUri
            Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'remediation.json')

            $Context.LastModified = $object.lastModifiedDateTime
            $hasDetection = Save-Base64File -Base64 $object.detectionScriptContent -Path (Join-Path $Folder 'detection.ps1')
            $hasRemediation = Save-Base64File -Base64 $object.remediationScriptContent -Path (Join-Path $Folder 'remediation.ps1')
            $Context.SubType = if ($hasRemediation) { 'Detection and remediation' } else { 'Detection only' }

            if ($object.isGlobalScript) {
                $Context.SubType = 'Microsoft-published'
                Add-ItemNote -Context $Context -Message 'Microsoft-published script (read-only in Intune)'
            }
            elseif (-not $hasDetection) {
                Add-ItemNote -Context $Context -Warning -Message 'No detection script content returned'
            }
            $Context.GraphType = 'deviceHealthScript ({0}, 32-bit: {1}, signature check: {2})' -f $object.runAsAccount, $object.runAs32Bit, $object.enforceSignatureCheck

            $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments" @GraphRequestOptions
            Save-JsonFile -InputObject $Context.Assignments -Path (Join-Path $Folder 'assignments.json')

            if ($IncludeDeviceRunStates) {
                $count = Export-DeviceRunState -ObjectUri $objectUri -Path (Join-Path $Folder 'deviceRunStates.csv') -Fields @(
                    'detectionState', 'remediationState', 'lastStateUpdateDateTime', 'lastSyncDateTime',
                    'preRemediationDetectionScriptOutput', 'preRemediationDetectionScriptError',
                    'remediationScriptError', 'postRemediationDetectionScriptOutput', 'postRemediationDetectionScriptError')
                Add-ItemNote -Context $Context -Message "$count device run state(s) exported"
            }
        }
    }
}

function Backup-PlatformScript {
    [CmdletBinding()]
    param()
    $label = 'PlatformScripts'
    $root = Initialize-BackupFolder -Path (Join-Path $script:BackupRoot $label)

    $sources = @(
        @{ Segment = 'deviceManagementScripts'; Folder = 'Windows'; Extension = '.ps1'; Optional = $false }
        @{ Segment = 'deviceShellScripts'; Folder = 'macOS'; Extension = '.sh'; Optional = $true }
    )

    foreach ($source in $sources) {
        $list = Get-CategoryList -Label "$label ($($source.Folder))" -Uri "$script:GraphBeta/deviceManagement/$($source.Segment)" -Optional:$source.Optional
        if ($null -eq $list) { continue }
        $subRoot = Join-Path $root $source.Folder
        $selected = @($list | Where-Object { Test-Selected -DisplayName $_.displayName -ObjectId $_.id })
        if ($selected.Count -gt 0) { [void](Initialize-BackupFolder -Path $subRoot) }

        foreach ($item in $selected) {
            Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.displayName) -CategoryRoot $subRoot -Body {
                param($Item, $Folder, $Context)
                $objectUri = '{0}/deviceManagement/{1}/{2}' -f $script:GraphBeta, $source.Segment, $Item.id
                $object = Get-GraphObject -Uri $objectUri
                Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'script.json')
                $Context.LastModified = $object.lastModifiedDateTime

                $fileName = Get-SafeName -Value ([string]$object.fileName) -MaxLength 80
                if ($fileName -eq 'Unnamed') { $fileName = 'script' + $source.Extension }
                elseif (-not $fileName.EndsWith($source.Extension, [System.StringComparison]::OrdinalIgnoreCase)) { $fileName += $source.Extension }
                if (-not (Save-Base64File -Base64 $object.scriptContent -Path (Join-Path $Folder $fileName))) {
                    Add-ItemNote -Context $Context -Warning -Message 'No script content returned'
                }

                if ($source.Folder -eq 'Windows') {
                    $Context.SubType = if ($object.runAsAccount -eq 'user') { 'Windows - run as signed-in user' } else { 'Windows - run as System' }
                    $Context.GraphType = 'deviceManagementScript (32-bit: {0}, signature check: {1})' -f $object.runAs32Bit, $object.enforceSignatureCheck
                }
                else {
                    $Context.SubType = 'macOS - shell script'
                    $Context.GraphType = 'deviceShellScript (run as: {0}, frequency: {1}, retries: {2})' -f $object.runAsAccount, $object.executionFrequency, $object.retryCount
                }

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments" @GraphRequestOptions
                Save-JsonFile -InputObject $Context.Assignments -Path (Join-Path $Folder 'assignments.json')

                if ($IncludeDeviceRunStates) {
                    $count = Export-DeviceRunState -ObjectUri $objectUri -Path (Join-Path $Folder 'deviceRunStates.csv') -Fields @(
                        'runState', 'resultMessage', 'lastStateUpdateDateTime', 'errorCode', 'errorDescription')
                    Add-ItemNote -Context $Context -Message "$count device run state(s) exported"
                }
            }
        }
    }
}

function Get-DeviceConfigurationSubType {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$GraphType)
    switch -Regex ($GraphType) {
        'CustomConfiguration$'                  { return 'Template - Custom (OMA-URI)' }
        'EndpointProtectionConfiguration$'      { return 'Template - Endpoint protection' }
        'GeneralConfiguration$|DeviceOwner.*Configuration$|WorkProfileGeneral' { return 'Template - Device restrictions' }
        'Wi-?Fi|Wifi'                           { return 'Template - Wi-Fi' }
        'Vpn'                                   { return 'Template - VPN' }
        'Certificate|Pkcs|Scep|TrustedRoot'     { return 'Template - Certificate' }
        'Email|EasEmail'                        { return 'Template - Email' }
        'DeviceFeaturesConfiguration$'          { return 'Template - Device features' }
        'UpdateForBusinessConfiguration$'       { return 'Template - Update ring' }
        default                                 { return 'Template - Other' }
    }
}

function Backup-ConfigurationProfile {
    [CmdletBinding()]
    param()
    $label = 'ConfigurationProfiles'
    $root = Initialize-BackupFolder -Path (Join-Path $script:BackupRoot $label)

    # Settings catalog, endpoint security and security baselines (configurationPolicies)
    $list = Get-CategoryList -Label "$label (configurationPolicies)" -Uri "$script:GraphBeta/deviceManagement/configurationPolicies"
    if ($null -ne $list) {
        foreach ($item in $list) {
            if (-not (Test-Selected -DisplayName $item.name -ObjectId $item.id)) { continue }
            $family = [string]$item.templateReference.templateFamily
            $templateName = [string]$item.templateReference.templateDisplayName
            $subFolder, $subType = switch -Wildcard ($family) {
                ''                  { 'SettingsCatalog', 'Settings catalog'; break }
                'none'              { 'SettingsCatalog', 'Settings catalog'; break }
                'endpointSecurity*' { 'EndpointSecurity', "Endpoint security - $templateName"; break }
                'baseline'          { 'SecurityBaselines', "Security baseline - $templateName"; break }
                default             { 'OtherTemplates', "$family - $templateName" }
            }
            $subRoot = Initialize-BackupFolder -Path (Join-Path $root $subFolder)
            Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.name) -CategoryRoot $subRoot -Body {
                param($Item, $Folder, $Context)
                $objectUri = '{0}/deviceManagement/configurationPolicies/{1}' -f $script:GraphBeta, $Item.id
                $object = Get-GraphObject -Uri $objectUri
                Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'policy.json')
                $Context.LastModified = $object.lastModifiedDateTime
                $Context.SubType = $subType
                $Context.GraphType = 'configurationPolicy ({0}; {1})' -f $object.platforms, $object.technologies

                $settings = Get-GraphCollection -Uri "$objectUri/settings" @GraphRequestOptions
                Save-JsonFile -InputObject $settings -Path (Join-Path $Folder 'settings.json')
                Add-ItemNote -Context $Context -Message "$($settings.Count) setting(s)"

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments" @GraphRequestOptions
                Save-JsonFile -InputObject $Context.Assignments -Path (Join-Path $Folder 'assignments.json')
            }
        }
    }

    # Template profiles (deviceConfigurations)
    $list = Get-CategoryList -Label "$label (deviceConfigurations)" -Uri "$script:GraphBeta/deviceManagement/deviceConfigurations"
    if ($null -ne $list) {
        $subRoot = Join-Path $root 'Templates'
        foreach ($item in $list) {
            if (-not (Test-Selected -DisplayName $item.displayName -ObjectId $item.id)) { continue }
            [void](Initialize-BackupFolder -Path $subRoot)
            Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.displayName) -CategoryRoot $subRoot -Body {
                param($Item, $Folder, $Context)
                $objectUri = '{0}/deviceManagement/deviceConfigurations/{1}' -f $script:GraphBeta, $Item.id
                $object = Get-GraphObject -Uri $objectUri
                Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'profile.json')
                $Context.LastModified = $object.lastModifiedDateTime
                $Context.GraphType = ([string]$object.'@odata.type') -replace '^#microsoft\.graph\.', ''
                $Context.SubType = Get-DeviceConfigurationSubType -GraphType $Context.GraphType

                $encrypted = @($object.omaSettings | Where-Object { $_.isEncrypted -eq $true })
                if ($encrypted.Count -gt 0) {
                    if ($IncludeOmaSecretValues) {
                        $plain = foreach ($setting in $encrypted) {
                            $valueUri = "{0}/getOmaSettingPlainTextValue(secretReferenceValueId='{1}')" -f $objectUri, $setting.secretReferenceValueId
                            [pscustomobject][ordered]@{
                                displayName            = $setting.displayName
                                omaUri                 = $setting.omaUri
                                secretReferenceValueId = $setting.secretReferenceValueId
                                value                  = (Get-GraphObject -Uri $valueUri).value
                            }
                        }
                        Save-JsonFile -InputObject @($plain) -Path (Join-Path $Folder 'omaSettings-plaintext.json')
                        Add-ItemNote -Context $Context -Warning -Message "$($encrypted.Count) encrypted OMA-URI value(s) saved in PLAIN TEXT to omaSettings-plaintext.json"
                    }
                    else {
                        Add-ItemNote -Context $Context -Warning -Message "$($encrypted.Count) OMA-URI value(s) are encrypted in the export; restore needs the values re-entered or a rerun with -IncludeOmaSecretValues"
                    }
                }

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments" @GraphRequestOptions
                Save-JsonFile -InputObject $Context.Assignments -Path (Join-Path $Folder 'assignments.json')
            }
        }
    }

    # Administrative templates (groupPolicyConfigurations)
    $list = Get-CategoryList -Label "$label (groupPolicyConfigurations)" -Uri "$script:GraphBeta/deviceManagement/groupPolicyConfigurations"
    if ($null -ne $list) {
        $subRoot = Join-Path $root 'AdministrativeTemplates'
        foreach ($item in $list) {
            if (-not (Test-Selected -DisplayName $item.displayName -ObjectId $item.id)) { continue }
            [void](Initialize-BackupFolder -Path $subRoot)
            Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.displayName) -CategoryRoot $subRoot -Body {
                param($Item, $Folder, $Context)
                $objectUri = '{0}/deviceManagement/groupPolicyConfigurations/{1}' -f $script:GraphBeta, $Item.id
                $object = Get-GraphObject -Uri $objectUri
                Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'profile.json')
                $Context.LastModified = $object.lastModifiedDateTime
                $Context.SubType = 'Template - Administrative templates'
                $Context.GraphType = 'groupPolicyConfiguration'

                $definitionValues = Get-GraphCollection -Uri ('{0}/definitionValues?$expand=definition' -f $objectUri) @GraphRequestOptions
                foreach ($definitionValue in $definitionValues) {
                    $presentationValues = Get-GraphCollection -Uri ('{0}/definitionValues/{1}/presentationValues?$expand=presentation' -f $objectUri, $definitionValue.id) @GraphRequestOptions
                    $definitionValue | Add-Member -NotePropertyName 'presentationValues' -NotePropertyValue $presentationValues -Force
                }
                Save-JsonFile -InputObject $definitionValues -Path (Join-Path $Folder 'definitionValues.json')
                Add-ItemNote -Context $Context -Message "$($definitionValues.Count) setting(s)"

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments" @GraphRequestOptions
                Save-JsonFile -InputObject $Context.Assignments -Path (Join-Path $Folder 'assignments.json')
            }
        }
    }
}

function Backup-CompliancePolicy {
    [CmdletBinding()]
    param()
    $label = 'CompliancePolicies'
    $root = Initialize-BackupFolder -Path (Join-Path $script:BackupRoot $label)
    $referencedScriptIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $list = Get-CategoryList -Label "$label (deviceCompliancePolicies)" -Uri "$script:GraphBeta/deviceManagement/deviceCompliancePolicies"
    if ($null -ne $list) {
        $subRoot = Join-Path $root 'Policies'
        foreach ($item in $list) {
            if (-not (Test-Selected -DisplayName $item.displayName -ObjectId $item.id)) { continue }
            [void](Initialize-BackupFolder -Path $subRoot)
            Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.displayName) -CategoryRoot $subRoot -Body {
                param($Item, $Folder, $Context)
                $objectUri = '{0}/deviceManagement/deviceCompliancePolicies/{1}' -f $script:GraphBeta, $Item.id
                $object = Get-GraphObject -Uri ('{0}?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)' -f $objectUri)
                Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'policy.json')
                $Context.LastModified = $object.lastModifiedDateTime
                $Context.GraphType = ([string]$object.'@odata.type') -replace '^#microsoft\.graph\.', ''
                $Context.SubType = switch -Wildcard ($Context.GraphType) {
                    'windows*' { 'Windows'; break }
                    'ios*'     { 'iOS/iPadOS'; break }
                    'android*' { 'Android'; break }
                    'macOS*'   { 'macOS'; break }
                    default    { 'Other' }
                }

                $templateIds = @(
                    foreach ($rule in $object.scheduledActionsForRule) {
                        foreach ($action in $rule.scheduledActionConfigurations) {
                            $templateId = [string]$action.notificationTemplateId
                            if ($templateId -and $templateId -ne '00000000-0000-0000-0000-000000000000') { $templateId }
                        }
                    }
                ) | Select-Object -Unique
                if ($templateIds) {
                    Add-ItemNote -Context $Context -Message ('Notification template(s) referenced, not backed up: {0}' -f ($templateIds -join ', '))
                }

                $scriptId = [string]$object.deviceCompliancePolicyScript.deviceComplianceScriptId
                if ($scriptId) {
                    [void]$referencedScriptIds.Add($scriptId)
                    Add-ItemNote -Context $Context -Message "Uses custom compliance script $scriptId (backed up under CustomComplianceScripts)"
                }

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments" @GraphRequestOptions
                Save-JsonFile -InputObject $Context.Assignments -Path (Join-Path $Folder 'assignments.json')
            }
        }
    }

    # Custom compliance discovery scripts. With -Name/-Id, scripts referenced by selected policies are included.
    $list = Get-CategoryList -Label "$label (deviceComplianceScripts)" -Uri "$script:GraphBeta/deviceManagement/deviceComplianceScripts" -Optional
    if ($null -ne $list) {
        $subRoot = Join-Path $root 'CustomComplianceScripts'
        foreach ($item in $list) {
            $selected = (Test-Selected -DisplayName $item.displayName -ObjectId $item.id) -or $referencedScriptIds.Contains([string]$item.id)
            if (-not $selected) { continue }
            [void](Initialize-BackupFolder -Path $subRoot)
            Invoke-ItemBackup -Category $label -Item $item -DisplayName ([string]$item.displayName) -CategoryRoot $subRoot -Body {
                param($Item, $Folder, $Context)
                $objectUri = '{0}/deviceManagement/deviceComplianceScripts/{1}' -f $script:GraphBeta, $Item.id
                $object = Get-GraphObject -Uri $objectUri
                Save-JsonFile -InputObject $object -Path (Join-Path $Folder 'script.json')
                $Context.LastModified = $object.lastModifiedDateTime
                $Context.SubType = 'Custom compliance discovery script'
                $Context.GraphType = 'deviceComplianceScript ({0}, 32-bit: {1})' -f $object.runAsAccount, $object.runAs32Bit
                if (-not (Save-Base64File -Base64 $object.detectionScriptContent -Path (Join-Path $Folder 'discovery.ps1'))) {
                    Add-ItemNote -Context $Context -Warning -Message 'No script content returned'
                }
                if ($referencedScriptIds.Contains([string]$Item.id)) {
                    Add-ItemNote -Context $Context -Message 'Referenced by a compliance policy in this backup'
                }
                else {
                    Add-ItemNote -Context $Context -Message 'Not referenced by any compliance policy in this backup'
                }
            }
        }
    }
}

#endregion

#region Connection -------------------------------------------------------------------------------------

function Connect-GraphForBackup {
    # Connects through the shared helper with the scopes this run needs, and logs
    # which session the backup runs under. Returns $true when it signed in.
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Each scope this run needs, with the broader scopes that also satisfy it.
    $scopes = [ordered]@{
        'DeviceManagementConfiguration.Read.All' = @('DeviceManagementConfiguration.ReadWrite.All')
    }
    if ($Category | Where-Object { $_ -in 'Remediations', 'PlatformScripts', 'CompliancePolicies' }) {
        $scopes['DeviceManagementScripts.Read.All'] = @('DeviceManagementScripts.ReadWrite.All')
    }
    if ($IncludeDeviceRunStates) {
        $scopes['DeviceManagementManagedDevices.Read.All'] = @('DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
    }
    if (-not $SkipGroupNameResolution) {
        $scopes['GroupMember.Read.All'] = @('Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
    }

    $openedHere = Connect-GraphSession -Scope $scopes -TenantId $TenantId

    $context = Get-MgContext
    $identity = if ($context.AuthType -eq 'AppOnly') { "app $($context.AppName)" } else { $context.Account }
    if ($openedHere) {
        Write-BackupLog -Message "Connected as $identity to tenant $($context.TenantId)"
    }
    else {
        Write-BackupLog -Message "Using the existing $($context.AuthType) connection ($identity) to tenant $($context.TenantId)"
    }

    return $openedHere
}

#endregion

#region Main -------------------------------------------------------------------------------------------

$startedUtc = [datetime]::UtcNow
$ConnectionOpenedHere = $false

try {
    try {
        if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        $script:BackupRoot = Initialize-BackupFolder -Path (Join-Path (Resolve-Path -LiteralPath $OutputPath).ProviderPath ('IntuneBackup_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
        $script:LogFile = Join-Path $script:BackupRoot 'Backup.log'
        Write-BackupLog -Message "Backup-IntuneConfiguration $script:ScriptVersion started. Output: $script:BackupRoot"
        Write-BackupLog -Message ('Categories: {0}; Name filter: {1}; Id filter: {2}; Run states: {3}; OMA secrets: {4}' -f
            ($Category -join ', '), ($(if ($Name) { $Name.Count } else { 'none' })), ($(if ($Id) { $Id.Count } else { 'none' })),
            $IncludeDeviceRunStates.IsPresent, $IncludeOmaSecretValues.IsPresent)
        Write-BackupLog -Message ('Requested tenant: {0}; attempts per request: {1}' -f
            ($(if ($TenantId) { $TenantId } else { 'signed-in user home tenant' })), $MaxRetries)
        if ($IncludeOmaSecretValues) {
            Write-BackupLog -Level WARN -Message 'Encrypted OMA-URI values will be written to disk in plain text.'
        }

        $ConnectionOpenedHere = Connect-GraphForBackup
        $graphContext = Get-MgContext
    }
    catch {
        $message = "FATAL: $($_.Exception.Message)"
        if ($script:LogFile) { Write-BackupLog -Level ERROR -Message $message }
        else { Write-Error -Message $message -ErrorAction Continue }
        exit 1
    }

    $categoryActions = [ordered]@{
        Remediations          = { Backup-Remediation }
        PlatformScripts       = { Backup-PlatformScript }
        ConfigurationProfiles = { Backup-ConfigurationProfile }
        CompliancePolicies    = { Backup-CompliancePolicy }
    }

    foreach ($categoryName in $categoryActions.Keys) {
        if ($Category -notcontains $categoryName) { continue }
        Write-Information "Backing up $categoryName..."
        try {
            & $categoryActions[$categoryName]
        }
        catch {
            $script:CategoryErrors++
            Write-BackupLog -Level ERROR -Message "${categoryName}: unexpected error - $($_.Exception.Message)"
        }
    }

    # Filters that matched nothing, with the closest names seen in the selected categories
    $unmatchedNames = @($Name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $script:MatchedNames.Contains($_) })
    $unmatchedIds = @($Id | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $script:MatchedIds.Contains($_) })
    foreach ($entry in $unmatchedNames) {
        $message = "No object found for -Name '$entry' in the selected categories"
        if (-not ($entry.Contains('*') -or $entry.Contains('?'))) {
            $entryKey = ConvertTo-MatchKey -Value $entry
            $limit = [math]::Max(3, [int][math]::Floor($entryKey.Length * 0.2))
            $suggestions = @(
                foreach ($seen in $script:SeenObjects) {
                    if (-not $seen.Key) { continue }
                    if ($seen.Key.IndexOf($entryKey, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                        $entryKey.IndexOf($seen.Key, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        [pscustomobject]@{ Seen = $seen; Distance = [math]::Abs($seen.Key.Length - $entryKey.Length) }
                    }
                    elseif ([math]::Abs($seen.Key.Length - $entryKey.Length) -le $limit) {
                        $distance = Get-EditDistance -First $entryKey -Second $seen.Key
                        if ($distance -le $limit) { [pscustomobject]@{ Seen = $seen; Distance = $distance } }
                    }
                }
            ) | Sort-Object Distance | Select-Object -First 3
            if ($suggestions) {
                $message += '. Closest: ' + (($suggestions | ForEach-Object { "'{0}' ({1})" -f $_.Seen.Name, $_.Seen.Id }) -join ', ')
            }
        }
        Write-BackupLog -Level WARN -Message $message
    }
    foreach ($entry in $unmatchedIds) { Write-BackupLog -Level WARN -Message "No object found for -Id '$entry' in the selected categories" }

    # Index and manifest
    $indexPath = Join-Path $script:BackupRoot 'BackupIndex.csv'
    if ($script:Index.Count -gt 0) {
        $script:Index | Export-Csv -LiteralPath $indexPath -NoTypeInformation -Encoding utf8BOM -Delimiter $CsvDelimiter
    }

    $statusCounts = [ordered]@{}
    foreach ($group in ($script:Index | Group-Object -Property Status -NoElement | Sort-Object Name)) { $statusCounts[$group.Name] = $group.Count }
    $manifest = [ordered]@{
        ScriptVersion          = $script:ScriptVersion
        StartedUtc             = $startedUtc.ToString('o')
        CompletedUtc           = [datetime]::UtcNow.ToString('o')
        TenantId               = $graphContext.TenantId
        Account                = if ($graphContext.AuthType -eq 'AppOnly') { "app:$($graphContext.AppName)" } else { $graphContext.Account }
        Categories             = $Category
        NameFilter             = $Name
        IdFilter               = $Id
        UnmatchedNames         = $unmatchedNames
        UnmatchedIds           = $unmatchedIds
        IncludeDeviceRunStates = $IncludeDeviceRunStates.IsPresent
        IncludeOmaSecretValues = $IncludeOmaSecretValues.IsPresent
        ObjectCount            = $script:Index.Count
        StatusCounts           = $statusCounts
        CategoryErrors         = $script:CategoryErrors
        MaxRetries             = $MaxRetries
    }
    Save-JsonFile -InputObject $manifest -Path (Join-Path $script:BackupRoot 'BackupManifest.json')

    # Console summary
    Write-Information ''
    Write-Information "Backup folder: $script:BackupRoot"
    if ($script:Index.Count -gt 0) {
        Write-Information ('{0,-24} {1,-8} {2,6}' -f 'Category', 'Status', 'Count')
        foreach ($group in ($script:Index | Group-Object -Property Category, Status | Sort-Object Name)) {
            $first = $group.Group[0]
            Write-Information ('{0,-24} {1,-8} {2,6}' -f $first.Category, $first.Status, $group.Count)
        }
    }
    else {
        Write-Information 'No objects were backed up.'
    }
    if ($unmatchedNames.Count -or $unmatchedIds.Count) {
        Write-Warning ('Filters with no match: {0}' -f (($unmatchedNames + $unmatchedIds) -join '; '))
    }

    $exitCode = if ($script:FailedCount -gt 0 -or $script:CategoryErrors -gt 0) { 2 } else { 0 }
    Write-BackupLog -Message ('Finished. Objects: {0}; failed: {1}; category errors: {2}; exit code {3}' -f $script:Index.Count, $script:FailedCount, $script:CategoryErrors, $exitCode)
    exit $exitCode
}
finally {
    # Close only a session this run opened; leave one the caller brought intact.
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

#endregion
