# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 7.0

<#
.SYNOPSIS
    Replaces identifying values in text with consistent placeholders, so that
    only what the reader needs is shared, and puts the real values back.

.DESCRIPTION
    Scrubs a file, the clipboard, or pipeline text. Each distinct value gets a
    stable placeholder, so the result still reads coherently: the same device
    ID is the same placeholder on every line, and on every later run.

    Useful wherever data is shared, inside the organisation or out: tickets,
    vendor support cases, approved AI tools, documentation. Being allowed to
    share something is not the same as needing to share all of it.

    Replaced, in this order:
        private keys, JWTs, bearer tokens, password=... style values (one way)
        e-mail addresses and UPNs, GUIDs, SIDs, MAC addresses, SHA-1 thumbprints
        tenant names in *.onmicrosoft.com and *.sharepoint.com
        configured domains and every host name under them
        UNC server names and user profile folder names
        host names matching configured patterns, configured literal terms
        configured extra patterns, ServiceNow-style record numbers, IPv4

    Secrets are redacted one way. They are never stored and cannot be restored.

    Placeholders come from values reserved for documentation - RFC 2606
    domains, RFC 5737 addresses, the RFC 7042 MAC block - so they can never be
    mistaken for, or collide with, something real.

    Two files hold real values and must stay on the device that made them:
        config.json  your domains, host name patterns and literal terms
        map.json     real value <-> placeholder pairs, read by -Restore
    Both live in -DataDirectory, outside any repository. The script warns when
    that directory sits inside a git working tree. The script itself holds
    nothing environment-specific.

    Regular expressions cannot recognise a person's name in free text, a
    street address, or anything the config does not describe. Read the output
    before it leaves the device.

.PARAMETER Path
    One or more files to convert. Wildcards are accepted. Each file is written
    next to its source as <name>.scrubbed<ext> or <name>.restored<ext>, or into
    -OutputDirectory. Output is UTF-8 without a BOM.

.PARAMETER OutputDirectory
    Directory to write converted files into instead of beside their sources.
    Created if it does not exist.

.PARAMETER Clipboard
    Convert the clipboard text and put the result back on the clipboard.

.PARAMETER InputObject
    Text to convert, usually piped in. The result goes to the pipeline.

.PARAMETER NewConfig
    Write a template config.json to -ConfigPath and stop. Refuses to overwrite
    an existing config.

.PARAMETER Restore
    Swap placeholders back to the real values recorded in map.json, for text
    coming back to the device. Warns when the text holds no known placeholder.

.PARAMETER ReportOnly
    List what a scrub would replace, as objects, and write nothing: no output
    file, no clipboard change, no map update. The objects contain real values;
    they are for reading on this device. Cannot be combined with -Restore.

.PARAMETER Domain
    Scrub only. Additional domains to replace, on top of config.json. Every
    host name under a domain is replaced as well.

.PARAMETER HostnamePattern
    Scrub only. Additional regular expressions for device names, on top of
    config.json.

.PARAMETER LiteralTerm
    Scrub only. Additional literal strings to replace, on top of config.json,
    such as a company or project name.

.PARAMETER SkipIPv4
    Scrub only. Leave IPv4 addresses alone. Useful for text full of four-part
    version numbers, which the IPv4 pattern cannot tell apart from addresses.

.PARAMETER SkipLocalIdentity
    Scrub only. Do not add this machine's name, the signed-in user name and the
    logon domain to the literal terms. Values shorter than four characters are
    never added, because they match inside ordinary words.

.PARAMETER DataDirectory
    Where config.json, map.json and scrub.log live. Defaults to TextScrub under
    the local application data folder (%LOCALAPPDATA% on Windows).

.PARAMETER ConfigPath
    Config file to use instead of <DataDirectory>\config.json.

.PARAMETER MapPath
    Map file to use instead of <DataDirectory>\map.json.

.EXAMPLE
    .\Invoke-TextScrub.ps1 -NewConfig

    Writes a template config.json. Edit it on the device; once it holds real
    values it must not leave the device.

.EXAMPLE
    .\Invoke-TextScrub.ps1 -Path .\IntuneManagementExtension.log -ReportOnly |
        Format-Table Category, Original, Placeholder, Occurrences

    Shows every value a scrub would replace, and with what, writing nothing.

.EXAMPLE
    .\Invoke-TextScrub.ps1 -Path .\export.csv, .\error.txt -OutputDirectory C:\Temp\Out

    Writes export.scrubbed.csv and error.scrubbed.txt into C:\Temp\Out.

.EXAMPLE
    .\Invoke-TextScrub.ps1 -Clipboard

    Scrubs the clipboard in place, ready to paste.

.EXAMPLE
    Get-Content .\Detect.ps1 | .\Invoke-TextScrub.ps1 | Set-Content .\Detect.scrubbed.ps1

    Scrubs pipeline text.

.EXAMPLE
    .\Invoke-TextScrub.ps1 -Path .\Answer.ps1 -Restore

    Writes Answer.restored.ps1 with the real values put back.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.1
    Last updated  : 2026-09-23

    PowerShell    : 7.0 or later. A workstation utility that is never deployed
                    through Intune, so it is not held to Windows PowerShell 5.1.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : None.
    Role required : None. Runs as the signed-in user and reads only what that
                    user can read.

    Platform      : Written for Windows. Runs on Linux and macOS, where
                    -Clipboard needs the platform clipboard tool (xclip on
                    Linux).

    Exit codes    : 0 success.
                    1 the run failed; nothing was written after the failure.
                    2 output was written, but a value already in the map is
                      still in it, usually inside a longer token. The warning
                      gives the line and the placeholder, never the value.

    Limits        : IPv6 addresses are not recognised. Four-part version numbers
                    match the IPv4 pattern; use -SkipIPv4 where that matters.
                    MAC and IPv4 placeholders come from documentation ranges
                    that hold 256 and 762 values; a map that needs more stops
                    with an error rather than reusing a placeholder.
#>

[CmdletBinding(DefaultParameterSetName = 'Text', SupportsShouldProcess, ConfirmImpact = 'Low')]
param (
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'File')]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) { $true }
            else { throw "No file matches '$_'." }
        })]
    [string[]]$Path,

    [Parameter(ParameterSetName = 'File')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter(Mandatory, ParameterSetName = 'Clipboard')]
    [switch]$Clipboard,

    [Parameter(ParameterSetName = 'Text', ValueFromPipeline)]
    [AllowEmptyString()]
    [AllowNull()]
    [string[]]$InputObject,

    [Parameter(Mandatory, ParameterSetName = 'NewConfig')]
    [switch]$NewConfig,

    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Clipboard')]
    [Parameter(ParameterSetName = 'Text')]
    [switch]$Restore,

    [Parameter(ParameterSetName = 'File')]
    [Parameter(ParameterSetName = 'Clipboard')]
    [Parameter(ParameterSetName = 'Text')]
    [switch]$ReportOnly,

    [Parameter()]
    [ValidatePattern('^\.?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')]
    [string[]]$Domain,

    [Parameter()]
    [ValidateScript({
            $pattern = $_
            try { [void][regex]::new($pattern); $true }
            catch { throw "Not a valid regular expression: '$pattern'. $($_.Exception.Message)" }
        })]
    [string[]]$HostnamePattern,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$LiteralTerm,

    [Parameter()]
    [switch]$SkipIPv4,

    [Parameter()]
    [switch]$SkipLocalIdentity,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DataDirectory = (Join-Path -Path ([Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'TextScrub'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MapPath
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $ExitSuccess = 0
    $ExitFailure = 1
    $ExitResidual = 2

    $Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $RxOptions = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'

    # Public, well-known GUIDs that are more useful readable than replaced.
    $PreserveGuid = @(
        '00000000-0000-0000-0000-000000000000'
        '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
        '0000000a-0000-0000-c000-000000000000'   # Microsoft Intune
        '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
    )
    $PreserveProfile = @('Public', 'Default', 'Default User', 'All Users', 'defaultuser0', 'Administrator')

    # Categories whose placeholders come from a finite documentation range.
    $Capacity = @{ MAC = 256; IPV4 = 762 }

    $Octet = '(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    $Rx = @{
        PrivateKey  = '-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'
        Jwt         = 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*'
        Bearer      = '(bearer\s+)[A-Za-z0-9._~+/=-]{20,}'
        SecretValue = '(\b(?:password|passwd|pwd|secret|client_secret|clientsecret|apikey|api_key|' +
                      'access_token|refresh_token|sas_token|sig)\b["'']?\s*[=:]\s*["'']?)' +
                      '(?![\$\(\[\{@<\s])[^\s"'';&,]{6,}'
        Email       = '\b[A-Z0-9][A-Z0-9._%+''-]*@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+\b'
        Guid        = '(?<![0-9A-F])[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}(?![0-9A-F])'
        Sid         = '\bS-1-(?:5-21|12-1)(?:-\d+){3,5}\b'
        Mac         = '(?<![0-9A-F:-])(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}(?![0-9A-F:-])'
        Thumbprint  = '(?<![0-9A-F])[0-9A-F]{40}(?![0-9A-F])'
        Tenant      = '\b([A-Z0-9][A-Z0-9-]*?)(-my|-admin)?\.((?:mail\.)?onmicrosoft\.com|sharepoint\.com)\b'
        Unc         = '(?<![\\\w])(\\\\)([A-Z0-9][A-Z0-9._-]*)(?=\\)'
        Profile     = '([A-Z]:\\Users\\)([^\\/\s"''<>|:*?]+)'
        Ticket      = '\b(INC|RITM|REQ|CHG|CTASK|SCTASK|PRB|PTASK|TASK|KB)(\d{5,})\b'
        # Four-part version numbers match too; -SkipIPv4 exists for that.
        IPv4        = "(?<![\d.])(?:$Octet\.){3}$Octet(?![\d.])"
    }

    $Map = @{
        Entries  = [System.Collections.Generic.List[object]]::new()   # Category, Original, Placeholder
        Lookup   = @{}      # 'CATEGORY|original' (lower case) -> placeholder
        Issued   = @{}      # placeholder (lower case) -> original
        Counters = @{}      # category -> last number issued
        Dirty    = $false
    }
    $Guard = @{ Count = -1; Regex = $null; MaxLength = 0 }   # see Get-PlaceholderGuard
    $Run = @{
        Counts   = @{}                  # category -> replacements in the current text
        Totals   = @{}                  # category -> replacements across the run
        Found    = [ordered]@{}         # report rows for -ReportOnly
        Label    = ''
        ExitCode = $ExitSuccess
    }
    $Config = @{
        Domains      = [System.Collections.Generic.List[string]]::new()
        HostPatterns = [System.Collections.Generic.List[string]]::new()
        Terms        = @{}              # literal term -> explicit placeholder, or '' for a numbered one
        Extra        = [ordered]@{}     # category -> pattern
        SkipIPv4     = $SkipIPv4.IsPresent
    }
    $Buffer = [System.Collections.Generic.List[string]]::new()

    function Write-ScrubLog {
        # Counts and file names only. Never a real value, never a placeholder.
        param ([string]$Message)
        try {
            $line = '{0} {1}{2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message, [Environment]::NewLine
            [IO.File]::AppendAllText((Join-Path -Path $DataDirectory -ChildPath 'scrub.log'), $line, $Utf8NoBom)
        }
        catch {
            Write-Warning "Could not write to scrub.log in '$DataDirectory': $($_.Exception.Message)"
        }
    }

    function Test-InGitWorkTree {
        param ([string]$Directory)
        $current = [IO.DirectoryInfo]::new($Directory)
        while ($null -ne $current) {
            if (Test-Path -LiteralPath (Join-Path -Path $current.FullName -ChildPath '.git')) { return $true }
            $current = $current.Parent
        }
        return $false
    }

    function Test-RegexPattern {
        param ([string]$Pattern, [string]$Source)
        try { [void][regex]::new($Pattern) }
        catch { throw "$Source is not a valid regular expression: '$Pattern'. $($_.Exception.Message)" }
    }

    function Invoke-Replace {
        param ([string]$Text, [string]$Pattern, [scriptblock]$Evaluator)
        [regex]::Replace($Text, $Pattern, [System.Text.RegularExpressions.MatchEvaluator]$Evaluator, $RxOptions)
    }

    function Format-Placeholder {
        param ([string]$Category, [int]$Number)
        switch ($Category) {
            # Decimal, not hex: the repository scanner accepts zeroed GUIDs with a decimal counter.
            'GUID'   { '00000000-0000-0000-0000-{0:d12}' -f $Number }
            'EMAIL'  { 'user{0:d3}@example.com' -f $Number }
            'SID'    { 'S-1-5-21-0-0-0-{0}' -f (1000 + $Number) }
            'MAC'    { '00-00-5E-00-53-{0:X2}' -f ($Number % 256) }
            'TENANT' { 'tenant{0:d3}' -f $Number }
            'DOMAIN' { 'corp{0:d3}.example' -f $Number }
            'FQDN'   { 'host{0:d3}' -f $Number }        # the caller appends the domain placeholder
            'IPV4'   {
                $networks = @('192.0.2', '198.51.100', '203.0.113')
                '{0}.{1}' -f $networks[[math]::Floor(($Number - 1) / 254)], ((($Number - 1) % 254) + 1)
            }
            'TICKET' { '{0:d7}' -f $Number }             # the caller prepends the record prefix
            default  { '{0}-{1:d3}' -f $Category, $Number }
        }
    }

    function Add-Finding {
        param ([string]$Category, [string]$Original, [string]$Placeholder)
        $Run.Counts[$Category] = [int]$Run.Counts[$Category] + 1
        $key = '{0}|{1}|{2}|{3}' -f $Run.Label, $Category, $Original.ToLowerInvariant(), $Placeholder
        if ($Run.Found.Contains($key)) {
            $Run.Found[$key].Occurrences++
        }
        else {
            $Run.Found[$key] = [pscustomobject]@{
                Source      = $Run.Label
                Category    = $Category
                Original    = $Original
                Placeholder = $Placeholder
                Occurrences = 1
            }
        }
    }

    function Get-Redaction {
        param ([string]$Marker)
        Add-Finding -Category 'SECRET' -Original '(not shown)' -Placeholder $Marker
        $Marker
    }

    function Get-Placeholder {
        param (
            [string]$Category,
            [string]$Value,
            [string]$Explicit,
            [string]$Prefix,
            [string]$Suffix,
            [switch]$NoCount
        )
        $lower = $Value.ToLowerInvariant()

        # A value that is already a placeholder stays put, so scrubbing twice changes nothing.
        if ($Map.Issued.ContainsKey($lower)) { return $Value }

        $key = '{0}|{1}' -f $Category, $lower
        $placeholder = $Map.Lookup[$key]
        if (-not $placeholder) {
            if ($Explicit) {
                $placeholder = $Explicit
            }
            else {
                do {
                    $number = [int]$Map.Counters[$Category] + 1
                    $Map.Counters[$Category] = $number
                    if ($Capacity.ContainsKey($Category) -and $number -gt $Capacity[$Category]) {
                        throw (("More than {0} distinct {1} values: the documentation range is used up. " +
                            'Split the input, or use a separate -DataDirectory.') -f $Capacity[$Category], $Category)
                    }
                    $placeholder = $Prefix + (Format-Placeholder -Category $Category -Number $number) + $Suffix
                } while ($Map.Issued.ContainsKey($placeholder.ToLowerInvariant()))
            }

            $Map.Lookup[$key] = $placeholder
            if (-not $Map.Issued.ContainsKey($placeholder.ToLowerInvariant())) {
                $Map.Issued[$placeholder.ToLowerInvariant()] = $Value
            }
            $Map.Entries.Add([pscustomobject]@{ Category = $Category; Original = $Value; Placeholder = $placeholder })
            $Map.Dirty = $true
        }

        if (-not $NoCount) { Add-Finding -Category $Category -Original $Value -Placeholder $placeholder }
        return $placeholder
    }

    function Invoke-ScrubStep {
        # Runs one scrub pattern, leaving alone every match that overlaps a placeholder
        # or redaction marker already in the text. Without this, a later step rewrites
        # an earlier one's output: a literal term 'user' turns USER-001 into TERM-001-001,
        # and the result can no longer be restored.
        param ([string]$Text, [string]$Pattern, [scriptblock]$Evaluator)

        # Most steps match nothing in most text; skip them before paying for the guard.
        if (-not [regex]::IsMatch($Text, $Pattern, $RxOptions)) { return $Text }

        $guard = Get-PlaceholderGuard
        $source = $Text
        # Scriptblocks resolve variables through the call stack, and Invoke-Replace has
        # its own $Evaluator: inside the wrapper that name would mean the wrapper itself.
        $stepEvaluator = $Evaluator
        Invoke-Replace -Text $Text -Pattern $Pattern -Evaluator {
            param($m)
            if (Test-InPlaceholder -Text $source -Index $m.Index -Length $m.Length -Guard $guard) { return $m.Value }
            & $stepEvaluator $m
        }
    }

    function Get-PlaceholderGuard {
        # The regex that recognises placeholders and redaction markers. Rebuilt only
        # when the map has grown, so each step pays for it at most once.
        if ($Guard.Count -ne $Map.Issued.Count) {
            $pattern = '\[REDACTED[A-Z-]*\]'
            $longest = 24
            if ($Map.Issued.Count -gt 0) {
                $pattern += '|' + (Get-PlaceholderPattern)
                $longest = [Math]::Max($longest, ($Map.Issued.Keys | Measure-Object -Property Length -Maximum).Maximum)
            }
            $Guard.Regex = [regex]::new($pattern, $RxOptions)
            $Guard.MaxLength = [int]$longest
            $Guard.Count = $Map.Issued.Count
        }
        return $Guard
    }

    function Test-InPlaceholder {
        # True when the range overlaps a placeholder or redaction marker. Only a window
        # around the range is searched, cut out with Substring: Regex.Match(text, start,
        # length) costs time in proportion to the whole text, thousands of times slower
        # on a large file. Word boundaries are checked here against the full text,
        # because a lookbehind cannot see past the start of the window.
        param ([string]$Text, [int]$Index, [int]$Length, [hashtable]$Guard)
        $from = [Math]::Max(0, $Index - $Guard.MaxLength)
        $to = [Math]::Min($Text.Length, $Index + $Length + $Guard.MaxLength)
        $probe = $Guard.Regex.Match($Text.Substring($from, $to - $from))
        while ($probe.Success) {
            $start = $from + $probe.Index
            $end = $start + $probe.Length
            if ($start -lt $Index + $Length -and $end -gt $Index -and
                ($start -eq 0 -or $Text[$start - 1] -notmatch '[A-Za-z0-9]') -and
                ($end -eq $Text.Length -or $Text[$end] -notmatch '[A-Za-z0-9]')) {
                return $true
            }
            $probe = $probe.NextMatch()
        }
        return $false
    }

    function Invoke-Scrub {
        param ([string]$Text)
        $t = $Text

        # Secrets first, one way, never stored in the map.
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.PrivateKey -Evaluator { Get-Redaction '[REDACTED-PRIVATE-KEY]' }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Jwt -Evaluator { Get-Redaction '[REDACTED-JWT]' }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Bearer -Evaluator { param($m) $m.Groups[1].Value + (Get-Redaction '[REDACTED-TOKEN]') }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.SecretValue -Evaluator { param($m) $m.Groups[1].Value + (Get-Redaction '[REDACTED]') }

        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Email -Evaluator { param($m) Get-Placeholder -Category 'EMAIL' -Value $m.Value }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Guid -Evaluator {
            param($m)
            if ($PreserveGuid -contains $m.Value.ToLowerInvariant()) { $m.Value }
            else { Get-Placeholder -Category 'GUID' -Value $m.Value }
        }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Sid -Evaluator { param($m) Get-Placeholder -Category 'SID' -Value $m.Value }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Mac -Evaluator { param($m) Get-Placeholder -Category 'MAC' -Value $m.Value }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Thumbprint -Evaluator { param($m) Get-Placeholder -Category 'THUMBPRINT' -Value $m.Value }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Tenant -Evaluator {
            param($m)
            (Get-Placeholder -Category 'TENANT' -Value $m.Groups[1].Value) + $m.Groups[2].Value + '.' + $m.Groups[3].Value
        }

        # Configured domains, including any host or subdomain in front of them. Longest first,
        # so a subdomain that is itself configured wins over its parent.
        foreach ($domainName in ($Config.Domains | Sort-Object -Property Length -Descending)) {
            $pattern = '(?<![A-Z0-9.-])((?:[A-Z0-9_-]+\.)*)' + [regex]::Escape($domainName) + '(?![A-Z0-9-]|\.[A-Z0-9])'
            if (-not [regex]::IsMatch($t, $pattern, $RxOptions)) { continue }
            $base = Get-Placeholder -Category 'DOMAIN' -Value $domainName -NoCount
            $t = Invoke-ScrubStep -Text $t -Pattern $pattern -Evaluator {
                param($m)
                if ($m.Groups[1].Value) { Get-Placeholder -Category 'FQDN' -Value $m.Value -Suffix ".$base" }
                else { Get-Placeholder -Category 'DOMAIN' -Value $domainName }
            }
        }

        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Unc -Evaluator {
            param($m)
            $m.Groups[1].Value + (Get-Placeholder -Category 'SERVER' -Value $m.Groups[2].Value)
        }
        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Profile -Evaluator {
            param($m)
            if ($PreserveProfile -contains $m.Groups[2].Value) { $m.Value }
            else { $m.Groups[1].Value + (Get-Placeholder -Category 'USER' -Value $m.Groups[2].Value) }
        }

        foreach ($pattern in $Config.HostPatterns) {
            $t = Invoke-ScrubStep -Text $t -Pattern $pattern -Evaluator { param($m) Get-Placeholder -Category 'DEVICE' -Value $m.Value }
        }

        # Literal terms: company and project names, and this machine's own identity.
        foreach ($term in ($Config.Terms.Keys | Sort-Object -Property Length -Descending)) {
            $explicit = $Config.Terms[$term]
            $pattern = '(?<![A-Z0-9])' + [regex]::Escape($term) + '(?![A-Z0-9])'
            $t = Invoke-ScrubStep -Text $t -Pattern $pattern -Evaluator { Get-Placeholder -Category 'TERM' -Value $term -Explicit $explicit }
        }

        # Extra patterns from config: { "SERIAL": "regex" } gives SERIAL-001.
        foreach ($category in $Config.Extra.Keys) {
            $t = Invoke-ScrubStep -Text $t -Pattern $Config.Extra[$category] -Evaluator {
                param($m)
                Get-Placeholder -Category $category.ToUpperInvariant() -Value $m.Value
            }
        }

        $t = Invoke-ScrubStep -Text $t -Pattern $Rx.Ticket -Evaluator {
            param($m)
            Get-Placeholder -Category 'TICKET' -Value $m.Value -Prefix $m.Groups[1].Value.ToUpperInvariant()
        }

        if (-not $Config.SkipIPv4) {
            $t = Invoke-ScrubStep -Text $t -Pattern $Rx.IPv4 -Evaluator {
                param($m)
                if ($m.Value -match '^(127\.|255\.|0\.0\.0\.0$)') { $m.Value }
                else { Get-Placeholder -Category 'IPV4' -Value $m.Value }
            }
        }

        return $t
    }

    function Get-PlaceholderPattern {
        # Every issued placeholder as one alternation, longest first so that
        # host001.corp001.example is matched whole rather than as corp001.example.
        $escaped = $Map.Issued.Keys | Sort-Object -Property Length -Descending | ForEach-Object { [regex]::Escape($_) }
        '(?:' + ($escaped -join '|') + ')'
    }

    function Invoke-Restore {
        param ([string]$Text)
        if ($Map.Issued.Count -eq 0) { return $Text }
        $pattern = '(?<![A-Z0-9])' + (Get-PlaceholderPattern) + '(?![A-Z0-9])'
        Invoke-Replace -Text $Text -Pattern $pattern -Evaluator {
            param($m)
            $Run.Counts['RESTORED'] = [int]$Run.Counts['RESTORED'] + 1
            $Map.Issued[$m.Value.ToLowerInvariant()]
        }
    }

    function Find-Residual {
        # Known real values still present in scrubbed text. Deliberately a substring
        # search, so ACME inside ACMEcorp is caught. A hit inside a placeholder is not a
        # leak: the term 'user' inside user001@example.com.
        # One IndexOf per value, not one regex of all values: random GUIDs share no
        # prefix, and such an alternation is a hundred times slower on a large file.
        param ([string]$Text)
        $guard = Get-PlaceholderGuard
        $checked = @{}
        foreach ($entry in $Map.Entries) {
            if ($entry.Original.Length -lt 4 -or $checked.ContainsKey($entry.Original)) { continue }
            $checked[$entry.Original] = $true

            $index = $Text.IndexOf($entry.Original, [StringComparison]::OrdinalIgnoreCase)
            while ($index -ge 0 -and
                (Test-InPlaceholder -Text $Text -Index $index -Length $entry.Original.Length -Guard $guard)) {
                $index = $Text.IndexOf($entry.Original, $index + 1, [StringComparison]::OrdinalIgnoreCase)
            }
            if ($index -lt 0) { continue }

            [pscustomobject]@{
                Category    = $entry.Category
                Placeholder = $entry.Placeholder
                Line        = $Text.Substring(0, $index).Split("`n").Count
            }
        }
    }

    function Convert-Text {
        param ([string]$Text, [string]$Label)
        $Run.Label = $Label
        $Run.Counts = @{}

        if ($Restore) {
            $result = Invoke-Restore -Text $Text
            if (-not $Run.Counts['RESTORED'] -and -not [string]::IsNullOrWhiteSpace($Text)) {
                Write-Warning (("{0}: no placeholder from '{1}' was found, so nothing was restored. " +
                    'Was the text scrubbed on another device, or with a different -DataDirectory?') -f $Label, $MapPath)
            }
        }
        else {
            $result = Invoke-Scrub -Text $Text
            $residual = @(Find-Residual -Text $result)
            if ($residual.Count -gt 0) {
                $Run.ExitCode = $ExitResidual
                Write-Warning (("{0}: {1} known real value(s) are still in the output, usually inside a longer " +
                    'token the word boundaries skipped. Values are not shown. Fix the source text or add a ' +
                    'pattern, then scrub again.') -f $Label, $residual.Count)
                foreach ($hit in $residual) {
                    Write-Warning ('  line {0}: the value mapped to {1} [{2}]' -f $hit.Line, $hit.Placeholder, $hit.Category)
                }
            }
        }

        foreach ($category in $Run.Counts.Keys) {
            $Run.Totals[$category] = [int]$Run.Totals[$category] + $Run.Counts[$category]
        }
        return $result
    }

    function Get-ReplacementCount {
        [int](($Run.Counts.Values | Measure-Object -Sum).Sum)
    }

    function Read-ScrubConfig {
        if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            if (-not $Restore) {
                Write-Warning (("No config at '{0}', so only the generic patterns apply. Run -NewConfig, then add " +
                    'your domains and host name patterns.') -f $ConfigPath)
            }
            return
        }

        try {
            $content = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "The config at '$ConfigPath' is not valid JSON: $($_.Exception.Message)"
        }
        $names = @($content.PSObject.Properties.Name)

        if ($names -contains 'Domains') {
            foreach ($value in @($content.Domains)) { if ($value) { $Config.Domains.Add([string]$value) } }
        }
        if ($names -contains 'HostnamePatterns') {
            foreach ($value in @($content.HostnamePatterns)) {
                if (-not $value) { continue }
                Test-RegexPattern -Pattern $value -Source "HostnamePatterns in '$ConfigPath'"
                $Config.HostPatterns.Add([string]$value)
            }
        }
        if ($names -contains 'LiteralTerms' -and $content.LiteralTerms) {
            foreach ($property in $content.LiteralTerms.PSObject.Properties) {
                $Config.Terms[$property.Name] = [string]$property.Value
            }
        }
        if ($names -contains 'ExtraPatterns' -and $content.ExtraPatterns) {
            foreach ($property in $content.ExtraPatterns.PSObject.Properties) {
                if ($property.Name -notmatch '^[A-Za-z][A-Za-z0-9_]*$') {
                    throw "ExtraPatterns in '$ConfigPath': '$($property.Name)' is not usable as a category name. Use letters, digits and underscores."
                }
                Test-RegexPattern -Pattern $property.Value -Source "ExtraPatterns.$($property.Name) in '$ConfigPath'"
                $Config.Extra[$property.Name] = [string]$property.Value
            }
        }
    }

    function Read-ScrubMap {
        if (-not (Test-Path -LiteralPath $MapPath -PathType Leaf)) { return }

        try {
            $content = Get-Content -LiteralPath $MapPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw (("The map at '{0}' could not be read: {1} Without it, earlier output cannot be restored; " +
                'repair the file rather than deleting it.') -f $MapPath, $_.Exception.Message)
        }

        # Enumerate from a variable, never @(... | ConvertFrom-Json): Windows PowerShell
        # emits a JSON array as one object, which @() would wrap as a single entry.
        foreach ($entry in @($content)) {
            if ($null -eq $entry) { continue }
            $names = @($entry.PSObject.Properties.Name)
            if ($names -notcontains 'Category' -or $names -notcontains 'Original' -or $names -notcontains 'Placeholder') {
                throw "The map at '$MapPath' has an entry without Category, Original and Placeholder. Repair the file."
            }
            $Map.Entries.Add([pscustomobject]@{
                    Category    = [string]$entry.Category
                    Original    = [string]$entry.Original
                    Placeholder = [string]$entry.Placeholder
                })
            $Map.Lookup[('{0}|{1}' -f $entry.Category, ([string]$entry.Original).ToLowerInvariant())] = [string]$entry.Placeholder
            $issuedKey = ([string]$entry.Placeholder).ToLowerInvariant()
            if (-not $Map.Issued.ContainsKey($issuedKey)) { $Map.Issued[$issuedKey] = [string]$entry.Original }
        }

        # Counters resume from the number of entries; Get-Placeholder skips any number already in use.
        foreach ($group in ($Map.Entries | Group-Object -Property Category)) {
            $Map.Counters[$group.Name] = $group.Count
        }
    }

    function Save-ScrubMap {
        # Write beside the map and swap it in, so an interrupted run cannot leave a
        # truncated map behind; a lost map makes earlier output unrestorable.
        $directory = Split-Path -Path $MapPath -Parent
        if (-not (Test-Path -LiteralPath $directory)) {
            $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
        }
        $temporary = "$MapPath.tmp"
        $json = ConvertTo-Json -InputObject $Map.Entries.ToArray() -Depth 3
        [IO.File]::WriteAllText($temporary, $json, $Utf8NoBom)
        [IO.File]::Move($temporary, $MapPath, $true)
        $Map.Dirty = $false
    }

    try {
        if ($Restore -and $ReportOnly) {
            throw '-ReportOnly lists what a scrub would replace; it cannot be combined with -Restore.'
        }

        $DataDirectory = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($DataDirectory)
        $ConfigPath = if ($ConfigPath) { $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ConfigPath) }
        else { Join-Path -Path $DataDirectory -ChildPath 'config.json' }
        $MapPath = if ($MapPath) { $PSCmdlet.GetUnresolvedProviderPathFromPSPath($MapPath) }
        else { Join-Path -Path $DataDirectory -ChildPath 'map.json' }

        foreach ($file in @($ConfigPath, $MapPath)) {
            if (Test-InGitWorkTree -Directory (Split-Path -Path $file -Parent)) {
                Write-Warning (("'{0}' is inside a git working tree. It holds real values once used; keep it " +
                    'outside every repository so it cannot be committed.') -f $file)
            }
        }

        if ($NewConfig) {
            if (Test-Path -LiteralPath $ConfigPath) {
                throw "A config already exists at '$ConfigPath'. Edit it, or delete it first to start again from the template."
            }
            if ($PSCmdlet.ShouldProcess($ConfigPath, 'Create template config')) {
                $template = [ordered]@{
                    Domains          = @('corp.example-replace-me.com')
                    HostnamePatterns = @('\b(?:LT|PC|WS)-[A-Z0-9]{6,10}\b')
                    LiteralTerms     = [ordered]@{ 'Replace Me Corp' = 'Contoso'; 'ProjectCodename' = '' }
                    ExtraPatterns    = [ordered]@{
                        SERIAL = '\b(?=[A-Z0-9]*\d)[A-Z0-9]{7}\b(?#example only - tighten or remove)'
                    }
                }
                $null = New-Item -ItemType Directory -Path (Split-Path -Path $ConfigPath -Parent) -Force -ErrorAction Stop
                [IO.File]::WriteAllText($ConfigPath, ($template | ConvertTo-Json -Depth 4), $Utf8NoBom)
                Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
            }
            exit $ExitSuccess
        }

        Read-ScrubConfig
        foreach ($value in @($Domain)) { if ($value) { $Config.Domains.Add($value) } }
        foreach ($value in @($HostnamePattern)) { if ($value) { $Config.HostPatterns.Add($value) } }
        foreach ($value in @($LiteralTerm)) { if ($value -and -not $Config.Terms.ContainsKey($value)) { $Config.Terms[$value] = '' } }

        if (-not $SkipLocalIdentity) {
            $identity = @([Environment]::MachineName, [Environment]::UserName, [Environment]::UserDomainName, $env:USERDNSDOMAIN)
            foreach ($value in $identity) {
                if ($value -and $value.Length -ge 4 -and -not $Config.Terms.ContainsKey($value)) { $Config.Terms[$value] = '' }
            }
            if ($env:USERDNSDOMAIN) { $Config.Domains.Add($env:USERDNSDOMAIN) }
        }

        $uniqueDomains = @($Config.Domains | ForEach-Object { $_.Trim().TrimStart('.') } | Where-Object { $_ } |
                Sort-Object -Unique)
        $Config.Domains.Clear()
        foreach ($value in $uniqueDomains) { $Config.Domains.Add($value) }

        Read-ScrubMap
        if ($Restore -and $Map.Entries.Count -eq 0) {
            throw (("No map at '{0}', so there is nothing to restore from. Restore on the device, and with the " +
                '-DataDirectory, that did the scrubbing.') -f $MapPath)
        }
    }
    catch {
        # Continue, not Stop, so that the exit code below is what the caller sees.
        Write-Error -Message "Startup failed: $($_.Exception.Message)" -ErrorAction Continue
        exit $ExitFailure
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Text' -and $null -ne $InputObject) {
        foreach ($line in $InputObject) { $Buffer.Add($line) }
    }
}

end {
    try {
        $mode = $Restore ? 'restored' : 'scrubbed'
        # Output is only released after the map is saved: text carrying a placeholder
        # the map does not know can never be restored.
        $pending = [System.Collections.Generic.List[object]]::new()

        if ($Clipboard) {
            $text = Get-Clipboard -Raw -ErrorAction Stop
            if ([string]::IsNullOrEmpty($text)) { throw 'The clipboard is empty or holds no text.' }
            $result = Convert-Text -Text $text -Label 'clipboard'
            $pending.Add([pscustomobject]@{ Source = 'clipboard'; Target = 'clipboard'; Text = $result; Count = Get-ReplacementCount })
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'File') {
            $targetDirectory = $OutputDirectory ? $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputDirectory) : $null
            foreach ($item in @(Get-Item -Path $Path -ErrorAction Stop | Where-Object { -not $_.PSIsContainer })) {
                $text = [IO.File]::ReadAllText($item.FullName)
                $result = Convert-Text -Text $text -Label $item.Name
                $directory = $targetDirectory ?? $item.DirectoryName
                $target = Join-Path -Path $directory -ChildPath ('{0}.{1}{2}' -f $item.BaseName, $mode, $item.Extension)
                $pending.Add([pscustomobject]@{ Source = $item.FullName; Target = $target; Text = $result; Count = Get-ReplacementCount })
            }
        }
        else {
            if ($Buffer.Count -eq 0) { throw 'No input. Pass -Path or -Clipboard, or pipe text in.' }
            $result = Convert-Text -Text ($Buffer -join [Environment]::NewLine) -Label 'input'
            $pending.Add([pscustomobject]@{ Source = 'input'; Target = $null; Text = $result; Count = Get-ReplacementCount })
        }

        if ($ReportOnly) {
            $Run.Found.Values
        }
        else {
            if ($Map.Dirty -and $PSCmdlet.ShouldProcess($MapPath, 'Save placeholder map')) {
                Save-ScrubMap
            }

            foreach ($item in $pending) {
                if ($null -eq $item.Target) {
                    $item.Text
                    continue
                }
                if (-not $PSCmdlet.ShouldProcess($item.Target, "Write $mode text")) { continue }

                if ($item.Target -eq 'clipboard') {
                    Set-Clipboard -Value $item.Text -ErrorAction Stop
                }
                else {
                    $directory = Split-Path -Path $item.Target -Parent
                    if (-not (Test-Path -LiteralPath $directory)) {
                        $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
                    }
                    [IO.File]::WriteAllText($item.Target, $item.Text, $Utf8NoBom)
                }
                [pscustomobject]@{
                    Source       = $item.Source
                    Destination  = $item.Target
                    Mode         = $mode
                    Replacements = $item.Count
                }
                if (Test-Path -LiteralPath $DataDirectory) {
                    Write-ScrubLog ('{0} {1} -> {2}' -f $mode, (Split-Path -Path $item.Source -Leaf), (Split-Path -Path $item.Target -Leaf))
                }
            }
        }

        $summary = @($Run.Totals.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join ', '
        Write-Verbose ('Replacements: {0}' -f ($summary ? $summary : 'nothing matched'))
        if (-not $ReportOnly -and -not $WhatIfPreference -and (Test-Path -LiteralPath $DataDirectory)) {
            Write-ScrubLog ('counts: {0}' -f ($summary ? $summary : 'nothing matched'))
        }
        exit $Run.ExitCode
    }
    catch {
        Write-Error -Message "Failed: $($_.Exception.Message)" -ErrorAction Continue
        if (Test-Path -LiteralPath $DataDirectory) { Write-ScrubLog "error: $($_.Exception.GetType().Name)" }
        exit $ExitFailure
    }
}
