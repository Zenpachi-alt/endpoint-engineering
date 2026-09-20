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
    Attempts per request for throttled (429) and transient (5xx) responses.

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
    Version       : 1.1.0
    Last updated  : 2026-09-20

    PowerShell    : 7.2 or later. The script uses -SkipHttpErrorCheck and
                    ternary syntax, and reads Graph timestamps as strings on
                    7.5 and later, where ConvertFrom-Json -DateKind exists.
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
                    permissions must be granted; the script does not verify
                    them.

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
$script:ScriptVersion  = '1.1.0'
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

# Keep Graph timestamps as strings where the PowerShell version supports it (7.5+).
$script:JsonReadParams = @{}
if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
    $script:JsonReadParams['DateKind'] = 'String'
}

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

function ConvertFrom-GraphJson {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Json)
    process {
        if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
        ConvertFrom-Json -InputObject $Json @script:JsonReadParams
    }
}

function Get-RetryAfterDelay {
    [CmdletBinding()]
    param($Headers)
    if (-not $Headers) { return $null }
    $value = $null
    foreach ($key in 'Retry-After', 'retry-after') {
        try { $value = $Headers[$key] } catch { $value = $null }
        if ($value) { break }
    }
    if (-not $value) { return $null }
    $seconds = 0
    if ([int]::TryParse([string](@($value)[0]), [ref]$seconds)) {
        return [math]::Min([math]::Max($seconds, 1), 300)
    }
    return $null
}

function Get-GraphErrorText {
    [CmdletBinding()]
    param([string]$Body)
    if ([string]::IsNullOrWhiteSpace($Body)) { return 'No response body' }
    try {
        $parsed = ConvertFrom-Json -InputObject $Body
        if ($parsed.error) { return ('{0}: {1}' -f $parsed.error.code, $parsed.error.message) }
    }
    catch {
        Write-Debug "Response body is not a Graph error object; returning it as text. $($_.Exception.Message)"
    }
    if ($Body.Length -gt 300) { return $Body.Substring(0, 300) }
    return $Body
}

function Invoke-GraphGet {
    <#
        GET with retry on 429/5xx (honours Retry-After). Returns the response body as a JSON string.
        Throws on other failures; the HTTP status is in $_.Exception.Data['StatusCode'].
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    $attempt = 0
    while ($true) {
        $attempt++
        $gStatus = $null
        $gHeaders = $null
        $body = $null
        $retryAfter = $null
        $transportError = $null

        try {
            $body = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Json -SkipHttpErrorCheck `
                -StatusCodeVariable 'gStatus' -ResponseHeadersVariable 'gHeaders' -ErrorAction Stop
        }
        catch {
            $transportError = $_.Exception
            $response = $null
            if ($transportError.PSObject.Properties['Response']) { $response = $transportError.Response }
            if ($response -and $response.PSObject.Properties['StatusCode']) {
                $gStatus = [int]$response.StatusCode
                try { $retryAfter = [int]$response.Headers.RetryAfter.Delta.TotalSeconds }
                catch { $retryAfter = $null }
            }
            elseif ($transportError.Message -match '\b(429|5\d\d)\b') {
                $gStatus = [int]$Matches[1]
            }
            else {
                $gStatus = 0
            }
        }

        if ($null -eq $gStatus) {
            # Status variable not populated: infer from the body.
            if ($body -match '^\s*\{\s*"error"\s*:') {
                $gStatus = if ($body -match 'TooManyRequests') { 429 } else { 520 }
            }
            else {
                $gStatus = 200
            }
        }

        if ($gStatus -ge 200 -and $gStatus -lt 300) { return $body }

        $transient = $gStatus -in 0, 429, 500, 502, 503, 504
        if ($transient -and $attempt -lt $MaxRetries) {
            if (-not $retryAfter) { $retryAfter = Get-RetryAfterDelay -Headers $gHeaders }
            $delay = if ($retryAfter) { $retryAfter } else { [int][math]::Min([math]::Pow(2, $attempt), 60) + (Get-Random -Maximum 3) }
            Write-BackupLog -Level WARN -Message ('HTTP {0} on GET {1} - retry {2}/{3} in {4}s' -f $gStatus, $Uri, $attempt, ($MaxRetries - 1), $delay)
            Start-Sleep -Seconds $delay
            continue
        }

        $detail = if ($transportError -and -not $body) { $transportError.Message } else { Get-GraphErrorText -Body $body }
        $exception = [System.Exception]::new(('GET {0} failed (HTTP {1}): {2}' -f $Uri, $gStatus, $detail))
        $exception.Data['StatusCode'] = $gStatus
        throw $exception
    }
}

function Get-GraphObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)
    Invoke-GraphGet -Uri $Uri | ConvertFrom-GraphJson
}

function Get-GraphCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-GraphGet -Uri $next | ConvertFrom-GraphJson
        foreach ($item in $page.value) { $items.Add($item) }
        $next = $page.'@odata.nextLink'
    }
    return , $items
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
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Uri, [switch]$Optional)
    try {
        $list = Get-GraphCollection -Uri $Uri
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
    param(
        [Parameter(Mandatory)][string]$ObjectUri,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Fields
    )
    $states = $null
    $expandOptions = @('?$expand=managedDevice($select=id,deviceName)', '?$expand=managedDevice', '')
    foreach ($expand in $expandOptions) {
        try {
            $states = Get-GraphCollection -Uri ($ObjectUri + '/deviceRunStates' + $expand)
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

            $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments"
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

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments"
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

                $settings = Get-GraphCollection -Uri "$objectUri/settings"
                Save-JsonFile -InputObject $settings -Path (Join-Path $Folder 'settings.json')
                Add-ItemNote -Context $Context -Message "$($settings.Count) setting(s)"

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments"
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

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments"
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

                $definitionValues = Get-GraphCollection -Uri ('{0}/definitionValues?$expand=definition' -f $objectUri)
                foreach ($definitionValue in $definitionValues) {
                    $presentationValues = Get-GraphCollection -Uri ('{0}/definitionValues/{1}/presentationValues?$expand=presentation' -f $objectUri, $definitionValue.id)
                    $definitionValue | Add-Member -NotePropertyName 'presentationValues' -NotePropertyValue $presentationValues -Force
                }
                Save-JsonFile -InputObject $definitionValues -Path (Join-Path $Folder 'definitionValues.json')
                Add-ItemNote -Context $Context -Message "$($definitionValues.Count) setting(s)"

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments"
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

                $Context.Assignments = Get-GraphCollection -Uri "$objectUri/assignments"
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
    [CmdletBinding()]
    param()

    $required = [System.Collections.Generic.List[string]]::new()
    $required.Add('DeviceManagementConfiguration.Read.All')
    if ($Category | Where-Object { $_ -in 'Remediations', 'PlatformScripts', 'CompliancePolicies' }) {
        $required.Add('DeviceManagementScripts.Read.All')
    }
    if ($IncludeDeviceRunStates) { $required.Add('DeviceManagementManagedDevices.Read.All') }
    if (-not $SkipGroupNameResolution) { $required.Add('GroupMember.Read.All') }

    # Broader scopes that also satisfy each requirement
    $satisfiedBy = @{
        'DeviceManagementConfiguration.Read.All'  = @('DeviceManagementConfiguration.ReadWrite.All')
        'DeviceManagementScripts.Read.All'        = @('DeviceManagementScripts.ReadWrite.All')
        'DeviceManagementManagedDevices.Read.All' = @('DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
        'GroupMember.Read.All'                    = @('Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
    }

    $context = Get-MgContext
    if ($context -and $TenantId -and $context.TenantId -ne $TenantId) {
        Write-BackupLog -Message "Existing Graph connection is for tenant $($context.TenantId); reconnecting to $TenantId"
        $context = $null
    }

    if ($context -and $context.AuthType -eq 'AppOnly') {
        Write-BackupLog -Message "Using existing app-only connection (app: $($context.AppName)). Application permissions are not checked here."
        return $context
    }

    if ($context) {
        $missing = @($required | Where-Object {
                $scope = $_
                -not (($context.Scopes -contains $scope) -or ($satisfiedBy[$scope] | Where-Object { $context.Scopes -contains $_ }))
            })
        if ($missing.Count -eq 0) {
            Write-BackupLog -Message "Using existing delegated connection ($($context.Account))"
            return $context
        }
        Write-BackupLog -Message ('Existing connection is missing scope(s): {0}. Reconnecting.' -f ($missing -join ', '))
    }

    $connectParams = @{ Scopes = $required.ToArray(); ErrorAction = 'Stop' }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    if ((Get-Command Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) { $connectParams['NoWelcome'] = $true }
    Connect-MgGraph @connectParams | Out-Null

    $context = Get-MgContext
    if (-not $context) { throw 'Connect-MgGraph completed but no Graph context is available.' }
    Write-BackupLog -Message "Connected as $($context.Account) to tenant $($context.TenantId)"
    return $context
}

#endregion

#region Main -------------------------------------------------------------------------------------------

$startedUtc = [datetime]::UtcNow

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

    $graphContext = Connect-GraphForBackup
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

#endregion
