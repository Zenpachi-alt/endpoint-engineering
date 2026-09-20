#Requires -Version 5.1

<#
.SYNOPSIS
    Scans repository content for identifiers and secrets that must never be
    committed to a public repository.

.DESCRIPTION
    Looks for tenant and environment identifiers (GUIDs, UPNs, tenant domains,
    internal hostnames, IP addresses) and for credential material (JWTs, private
    keys, provider tokens, hard-coded secret assignments), and reports where
    they appear.

    Known-fictitious values are ignored: all-zero or single-character GUIDs,
    well-known Microsoft application IDs, contoso/fabrikam/adatum/example
    domains, loopback and RFC 5737 documentation IP addresses. Extend the
    allowed set with -AllowPattern, or silence one line by ending it with the
    marker:

        # sensitive-content:allow

    Matched values are masked by default so that findings can be pasted into a
    build log or an issue without leaking the very thing they flag. Use
    -ShowMatch locally when you need to see what was found.

    Findings are written to the pipeline as objects. The script exits 1 when
    anything is found, so it can gate a commit or a CI job.

.PARAMETER Path
    Files or directories to scan. Defaults to the repository root.

.PARAMETER Staged
    Scan the staged content of the current git index instead of the working
    tree. This is what the pre-commit hook uses: it checks what is about to be
    committed, not what happens to be on disk.

.PARAMETER AllowPattern
    Additional regular expressions. A match that satisfies any of these is not
    reported.

.PARAMETER ExcludePath
    Wildcard patterns matched against the relative path of each file. Files that
    match are skipped.

.PARAMETER ShowMatch
    Print matched values in full instead of masking them. Never use this in CI.

.PARAMETER MaximumFileSizeBytes
    Files larger than this are skipped as presumed data or binaries.

.EXAMPLE
    .\Tools\Test-SensitiveContent.ps1

    Scans the whole repository and lists anything suspicious.

.EXAMPLE
    .\Tools\Test-SensitiveContent.ps1 -Staged

    Scans only what is staged for the next commit.

.EXAMPLE
    .\Tools\Test-SensitiveContent.ps1 -Path .\Intune -ShowMatch -Verbose

    Scans one folder and shows the matched values.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-20

    PowerShell    : 5.1 or 7. Declared as 5.1 so the pre-commit hook works on a
                    machine without PowerShell 7 installed.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : None. Requires git on PATH only when -Staged is used.
    Role required : None.

    Exit codes    : 0 clean, 1 findings, 2 the scan itself failed.

    This is a safety net, not a guarantee. It cannot recognise an identifier
    that looks like ordinary text - a policy name, a naming convention, a custom
    OMA-URI. Those still need a human read before publishing.
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter()]
    [switch]$Staged,

    [Parameter()]
    [string[]]$AllowPattern = @(),

    [Parameter()]
    [string[]]$ExcludePath = @(),

    [Parameter()]
    [switch]$ShowMatch,

    [Parameter()]
    [ValidateRange(1024, 104857600)]
    [int]$MaximumFileSizeBytes = 2097152
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitClean = 0
$ExitFindings = 1
$ExitError = 2

$AllowMarker = 'sensitive-content:allow'

# Extensions that never contain reviewable text.
$BinaryExtension = @(
    '.intunewin', '.msi', '.msix', '.appx', '.exe', '.dll', '.cab', '.zip',
    '.7z', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.pfx', '.p12',
    '.cer', '.der', '.mui', '.bin', '.dat'
)

$DefaultExcludePath = @(
    '.git/*'
    '.git\*'
)

# Application IDs that are the same in every tenant on earth.
$WellKnownGuid = @(
    '00000002-0000-0000-c000-000000000000'  # Azure AD Graph
    '00000003-0000-0000-c000-000000000000'  # Microsoft Graph
    '00000002-0000-0ff1-ce00-000000000000'  # Exchange Online
    '00000003-0000-0ff1-ce00-000000000000'  # SharePoint Online
    '1950a258-227b-4e31-a9cf-717495945fc2'  # Microsoft Azure PowerShell
    '14d82eec-204b-4c2f-b7e8-296a70dab67e'  # Microsoft Graph Command Line Tools
    'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'  # Microsoft Intune PowerShell
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46'  # Azure CLI
    '0000000a-0000-0000-c000-000000000000'  # Microsoft Intune service
)

# Domains that are fictitious by convention, plus the public services this
# repository legitimately links to.
$AllowedDomain = @(
    'contoso.com', 'contoso.local', 'contoso.onmicrosoft.com'
    'fabrikam.com', 'adatum.com', 'tailspintoys.com', 'woodgrovebank.com'
    'example.com', 'example.net', 'example.org', 'localhost'
    'microsoft.com', 'windows.com', 'office.com', 'azure.com'
    'github.com', 'githubusercontent.com', 'powershellgallery.com', 'nuget.org'
    'ietf.org', 'opensource.org'
)

$AllowedIPAddress = @(
    '0.0.0.0', '127.0.0.1', '255.255.255.255', '255.255.255.0', '::1'
)

function Test-AllowedDomain {
    <#
        .SYNOPSIS
            True when the host name is, or sits under, an allowed domain, or
            uses the reserved .example / .invalid / .test TLDs.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$HostName
    )

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $true }

    $candidate = $HostName.TrimEnd('.').ToLowerInvariant()

    if ($candidate -match '\.(example|invalid|test|localhost)$') { return $true }

    foreach ($domain in $AllowedDomain) {
        if ($candidate -eq $domain -or $candidate.EndsWith(".$domain")) { return $true }
    }

    return $false
}

function Test-AllowedGuid {
    <#
        .SYNOPSIS
            True for placeholder GUIDs (all zeros with an optional counter, or a
            single repeated character) and for well-known Microsoft app IDs.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Guid
    )

    $value = $Guid.ToLowerInvariant()

    if ($WellKnownGuid -contains $value) { return $true }

    $hex = $value -replace '-', ''

    # 00000000-0000-0000-0000-000000000000 and the counter variants of it.
    if ($hex -match '^0+[0-9]{0,8}$') { return $true }

    # 11111111-1111-..., aaaaaaaa-aaaa-..., and similar obvious placeholders.
    if ($hex -match "^(.)\1{31}$") { return $true }

    return $false
}

function Test-AllowedIPAddress {
    <#
        .SYNOPSIS
            True for invalid dotted quads (version numbers), loopback, and the
            RFC 5737 documentation ranges.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Address
    )

    if ($AllowedIPAddress -contains $Address) { return $true }

    $octets = $Address.Split('.')
    foreach ($octet in $octets) {
        # 10.0.19041.1 is a Windows build, not an address.
        if ([int]$octet -gt 255) { return $true }
    }

    # RFC 5737 documentation ranges, and RFC 3927 link-local.
    if ($Address -match '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|169\.254\.)') { return $true }

    return $false
}

function Get-ScanRule {
    <#
        .SYNOPSIS
            Returns the rule set. Each rule carries a pattern, a severity, and
            an optional filter that decides whether a match is benign.
    #>
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param ()

    @(
        [pscustomobject]@{
            Name     = 'PrivateKey'
            Severity = 'Error'
            Pattern  = '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
            Filter   = { $false }   # never benign
            Advice   = 'Private key material. Remove it and rotate the key.'
        }
        [pscustomobject]@{
            Name     = 'BearerToken'
            Severity = 'Error'
            Pattern  = 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            Filter   = { $false }   # never benign
            Advice   = 'Looks like a JWT. Remove it and treat the token as compromised.'
        }
        [pscustomobject]@{
            Name     = 'ProviderToken'
            Severity = 'Error'
            Pattern  = '(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})'
            Filter   = { $false }   # never benign
            Advice   = 'Service access token. Remove it and revoke the token.'
        }
        [pscustomobject]@{
            Name     = 'HardCodedSecret'
            Severity = 'Error'
            Pattern  = '(?i)\b(?:client_?secret|password|passwd|pwd|api_?key|access_?token|refresh_?token|connection_?string|sas_?token)\b\s*[:=]\s*[''"][^''"]{8,}[''"]'
            Advice   = 'Secret assigned as a literal. Take it as a parameter or read it at run time.'
            Filter   = {
                param($m)
                # Placeholders and obvious examples are fine.
                $m.Value -match '(?i)(<[^>]+>|\$\(|\$\w|\{\{|placeholder|example|changeme|redacted|\*{4,})'
            }
        }
        [pscustomobject]@{
            Name     = 'Guid'
            Severity = 'Warning'
            Pattern  = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
            Advice   = 'Tenant, object, policy or app ID. Replace with a zeroed placeholder.'
            Filter   = { param($m) Test-AllowedGuid -Guid $m.Value }
        }
        [pscustomobject]@{
            Name     = 'EmailOrUpn'
            Severity = 'Warning'
            Pattern  = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
            Advice   = 'Address or UPN. Use user@contoso.com.'
            Filter   = {
                param($m)
                $domain = $m.Value.Substring($m.Value.IndexOf('@') + 1)
                Test-AllowedDomain -HostName $domain
            }
        }
        [pscustomobject]@{
            Name     = 'TenantDomain'
            Severity = 'Warning'
            Pattern  = '\b[A-Za-z0-9][A-Za-z0-9-]{1,62}\.(?:onmicrosoft\.com|mail\.onmicrosoft\.com)\b'
            Advice   = 'Tenant domain. Use contoso.onmicrosoft.com.'
            Filter   = { param($m) Test-AllowedDomain -HostName $m.Value }
        }
        [pscustomobject]@{
            Name     = 'Url'
            Severity = 'Warning'
            Pattern  = '\bhttps?://([A-Za-z0-9._-]+)(?::\d+)?(?:/[^\s''"<>)]*)?'
            Advice   = 'Non-public URL. Check whether it names an internal system.'
            Filter   = { param($m) Test-AllowedDomain -HostName $m.Groups[1].Value }
        }
        [pscustomobject]@{
            Name     = 'UncPath'
            Severity = 'Warning'
            Pattern  = '\\\\[A-Za-z0-9][A-Za-z0-9._-]{2,}\\[A-Za-z0-9$._-]+'
            Advice   = 'UNC path naming a file server. Replace the host with SERVER-001.'
            Filter   = {
                param($m)
                $m.Value -match '(?i)\\\\(SERVER-001|HOST-\d+|localhost|\.|\?|<)'
            }
        }
        [pscustomobject]@{
            Name     = 'IPAddress'
            Severity = 'Warning'
            Pattern  = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
            Advice   = 'IP address. Use the 192.0.2.0/24 documentation range.'
            Filter   = { param($m) Test-AllowedIPAddress -Address $m.Value }
        }
    )
}

function Get-TargetFile {
    <#
        .SYNOPSIS
            Returns the relative paths to scan, from the git index when -Staged
            is used and from disk otherwise.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RepositoryRoot,

        [Parameter()]
        [string[]]$SearchPath,

        [Parameter()]
        [switch]$FromIndex
    )

    if ($FromIndex) {
        $staged = & git -C $RepositoryRoot diff --cached --name-only --diff-filter=ACM
        if ($LASTEXITCODE -ne 0) {
            throw "git could not list staged files (exit code $LASTEXITCODE). Is this a git repository?"
        }

        return @($staged | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $roots = if ($SearchPath) { $SearchPath } else { @($RepositoryRoot) }
    $files = New-Object System.Collections.Generic.List[string]

    foreach ($root in $roots) {
        $resolved = Resolve-Path -LiteralPath $root -ErrorAction Stop

        foreach ($item in @(Get-Item -LiteralPath $resolved.Path -Force -ErrorAction Stop)) {
            if ($item.PSIsContainer) {
                Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction Stop |
                    ForEach-Object { $files.Add($_.FullName) }
            }
            else {
                $files.Add($item.FullName)
            }
        }
    }

    $prefix = (Resolve-Path -LiteralPath $RepositoryRoot).Path.TrimEnd('\', '/')

    return @($files | ForEach-Object {
            if ($_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                $_.Substring($prefix.Length).TrimStart('\', '/')
            }
            else {
                $_
            }
        })
}

function Get-FileLine {
    <#
        .SYNOPSIS
            Returns the lines of a file, read from the git index when scanning
            staged content so that the scan matches the commit.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RepositoryRoot,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,

        [Parameter()]
        [switch]$FromIndex
    )

    if ($FromIndex) {
        $content = & git -C $RepositoryRoot show ":$RelativePath" 2>$null
        if ($LASTEXITCODE -ne 0) { return @() }
        return @($content)
    }

    # -Force throughout: on Linux and macOS, PowerShell treats a leading dot as
    # hidden, so .gitattributes and .editorconfig are unreadable without it.

    $full = if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        $RelativePath
    }
    else {
        Join-Path -Path $RepositoryRoot -ChildPath $RelativePath
    }

    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return @() }

    return @(Get-Content -LiteralPath $full -Force -ErrorAction Stop)
}

function Format-MaskedValue {
    <#
        .SYNOPSIS
            Masks a matched value so a finding can be shown without repeating
            the identifier it reports.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -le 8) { return ('*' * $Value.Length) }

    return '{0}...{1} ({2} chars)' -f $Value.Substring(0, 4), $Value.Substring($Value.Length - 2), $Value.Length
}

try {
    $repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
    Write-Verbose "Repository root: $repositoryRoot"

    $rules = Get-ScanRule
    $excludes = $DefaultExcludePath + $ExcludePath
    $targets = Get-TargetFile -RepositoryRoot $repositoryRoot -SearchPath $Path -FromIndex:$Staged

    Write-Verbose "Files to consider: $($targets.Count)"

    $findings = New-Object System.Collections.Generic.List[psobject]
    $scanned = 0

    foreach ($relativePath in $targets) {
        $normalised = $relativePath -replace '\\', '/'

        $skip = $false
        foreach ($pattern in $excludes) {
            if ($normalised -like ($pattern -replace '\\', '/')) { $skip = $true; break }
        }
        if ($skip) { continue }

        if ($BinaryExtension -contains [System.IO.Path]::GetExtension($normalised).ToLowerInvariant()) { continue }

        $fullPath = if ([System.IO.Path]::IsPathRooted($relativePath)) {
            $relativePath
        }
        else {
            Join-Path -Path $repositoryRoot -ChildPath $relativePath
        }

        if ((-not $Staged) -and (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $size = (Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop).Length
            if ($size -gt $MaximumFileSizeBytes) {
                Write-Warning "Skipped '$normalised': $size bytes exceeds the $MaximumFileSizeBytes byte limit."
                continue
            }
        }

        $lines = Get-FileLine -RepositoryRoot $repositoryRoot -RelativePath $relativePath -FromIndex:$Staged
        if ($lines.Count -eq 0) { continue }

        $scanned++
        $lineNumber = 0

        foreach ($line in $lines) {
            $lineNumber++

            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -like "*$AllowMarker*") { continue }

            foreach ($rule in $rules) {
                foreach ($match in [regex]::Matches($line, $rule.Pattern)) {

                    if (& $rule.Filter $match) { continue }

                    $allowed = $false
                    foreach ($pattern in $AllowPattern) {
                        if ($match.Value -match $pattern) { $allowed = $true; break }
                    }
                    if ($allowed) { continue }

                    $findings.Add([pscustomobject]@{
                            File     = $normalised
                            Line     = $lineNumber
                            Rule     = $rule.Name
                            Severity = $rule.Severity
                            Match    = if ($ShowMatch) { $match.Value } else { Format-MaskedValue -Value $match.Value }
                            Advice   = $rule.Advice
                        })
                }
            }
        }
    }

    Write-Verbose "Scanned $scanned file(s)."

    if ($findings.Count -eq 0) {
        Write-Verbose 'No sensitive content found.'
        exit $ExitClean
    }

    $findings | Sort-Object -Property Severity, File, Line

    $errorCount = @($findings | Where-Object { $_.Severity -eq 'Error' }).Count
    Write-Warning "$($findings.Count) finding(s) in $scanned scanned file(s); $errorCount at Error severity. Values are masked - rerun with -ShowMatch locally to see them."

    exit $ExitFindings
}
catch {
    Write-Error -Message "Scan failed: $($_.Exception.Message)" -ErrorAction Continue
    exit $ExitError
}
