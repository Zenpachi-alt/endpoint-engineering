# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-AutopilotHardwareHash.ps1: the CSV it writes, how it
    merges into a shared file, what it refuses, the file names it builds, and
    its exit code when it is started as a file.

.DESCRIPTION
    Functions: the script's functions are loaded from its syntax tree, without
    its main block, and run under Set-StrictMode -Version Latest as they do in
    the script. The two CIM reads go to a mock of Get-CimInstance, so nothing
    is read from the device. What the parameters refuse is checked against the
    script's own param block, so none of its code runs at all.

    The script, run as a file: started as a technician starts it, with
    powershell.exe -File in a process of its own, through the remediation test
    harness. The elevation check and the functions that read Win32_BIOS and
    MDM_DevDetail_Ext01 are replaced by stand-ins that answer as each test
    describes. Everything else runs as written, the main block included: the
    CSV it writes, repeated -Append runs against one file, the warnings,
    -WhatIf, and exit codes 0 and 1. Every file goes to TestDrive.

    Windows only, like the script. Serial numbers, hardware hashes and user
    names are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Intune\Windows\Autopilot -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. Started as a file, the script always runs in
                    Windows PowerShell 5.1, whichever host runs Pester.
    Context       : Any user. Nothing needs administrator rights: the
                    elevation check is one of the stand-ins.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    $script:OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-AutopilotHardwareHash.ps1'

    # Every top-level function of the script and the column names they read,
    # without its main block. The script runs under Set-StrictMode -Version
    # Latest, so each function gets it as its first statement here too:
    # without it, reading a property that is not there passes in a test and
    # stops the script on a device.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Get-AutopilotHardwareHash.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $text = $statement.Extent.Text
            $at = $statement.Body.ParamBlock.Extent.EndOffset - $statement.Extent.StartOffset
            . ([scriptblock]::Create($text.Substring(0, $at) + "`nSet-StrictMode -Version Latest`n" + $text.Substring($at)))
        }
        elseif ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $statement.Left.Extent.Text -match '^\$(\w+Column)$') {
            Set-Variable -Name $Matches[1] -Scope Script -Value (& ([scriptblock]::Create($statement.Right.Extent.Text)))
        }
    }
    $script:LogFile = $null

    # The script's own param block, attributes included, returning what it
    # bound, so that what the parameters refuse is tested without any of the
    # script's code running.
    $paramBlock = $syntaxTree.ParamBlock
    $script:Binding = [scriptblock]::Create(
        ((@($paramBlock.Attributes | ForEach-Object { $_.Extent.Text }) + $paramBlock.Extent.Text) -join "`n") + "`n`$PSBoundParameters")

    $script:Header = 'Device Serial Number,Windows Product ID,Hardware Hash'

    function Get-TestSerial {
        # A made-up serial number in the shape OEMs use.
        'PF{0}' -f (Get-Random -Minimum 10000000 -Maximum 99999999)
    }

    function Get-TestHash {
        # A made-up hardware hash: random bytes as padded base64, the form
        # DeviceHardwareData takes, about as long as a real one.
        $bytes = New-Object -TypeName byte[] -ArgumentList 3000
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
        [System.Convert]::ToBase64String($bytes)
    }

    function Get-TestUser {
        # A made-up user principal name in the documentation domain.
        'user{0}@{1}' -f (Get-Random -Minimum 100 -Maximum 999), 'contoso.com'
    }

    function Get-TestDevice {
        # A made-up device, and its record as the script builds it.
        param ([string]$Tag = '', [string]$User = '')

        $serial = Get-TestSerial
        $hash = Get-TestHash
        [pscustomobject]@{
            Serial = $serial
            Hash   = $hash
            Record = ConvertTo-AutopilotRecord -SerialNumber $serial -HardwareHash $hash -Tag $Tag -User $User
        }
    }

    function Get-TestFolder {
        # A new, empty folder in TestDrive.
        $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $folder
        $folder
    }

    function Read-CsvLine {
        # The lines of a file, as an array even when there is one.
        param ([string]$Path)
        @(Get-Content -LiteralPath $Path)
    }

    function Get-CompactText {
        # Text without white space. The console wraps warnings and errors, so
        # a run's output is compared this way.
        param ([string]$Text)
        $Text -replace '\s', ''
    }

    #region Remediation test harness 1.0.0 - canonical copy in Templates/Remediation/ExampleSetting.Tests.ps1
    # Paste this region unchanged into the BeforeAll block of a remediation
    # package's tests. Templates/Remediation/README.md describes how to use it.

    function ConvertTo-StubbedScript {
        <#
            Writes a copy of a script in which the named functions are replaced
            by stand-ins, and returns the copy's path. The parameters, the main
            block and every other function run as written.

            A stand-in keeps the original's attributes and parameters, records
            each call in $Fake.Calls, and then runs its body from -Stub. A body
            of $null returns the next result queued for the function in
            $Fake.Results. $Fake is the device the test passed to
            Invoke-RemediationScript, and changes a stand-in makes to it are
            returned to the test.
        #>
        param (
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [System.Collections.IDictionary]$Stub,

            [Parameter(Mandatory)]
            [string]$Destination
        )

        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "$Path does not parse: $($parseErrors[0].Message)" }
        if ($null -eq $syntaxTree.ParamBlock) { throw "$Path has no param block for the stand-ins to follow." }

        $text = $syntaxTree.Extent.Text
        if ($text -match '\$Fake\b') { throw "$Path already uses `$Fake, which the stand-ins need." }

        $functions = @($syntaxTree.FindAll({ param ($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false))
        $edits = New-Object -TypeName System.Collections.Generic.List[object]

        foreach ($name in $Stub.Keys) {
            $matching = @($functions | Where-Object { $_.Name -eq $name })
            if ($matching.Count -ne 1) {
                throw "$Path defines $($matching.Count) functions named '$name'; a stand-in needs exactly one."
            }

            $original = $matching[0]
            $paramBlock = $original.Body.ParamBlock
            $signature = if ($null -eq $paramBlock) {
                "[CmdletBinding()]`nparam ()"
            }
            else {
                (@($paramBlock.Attributes | ForEach-Object { $_.Extent.Text }) + $paramBlock.Extent.Text) -join "`n"
            }

            $body = if ($null -eq $Stub[$name]) { "Get-FakeResult -Name '$name'" } else { $Stub[$name].ToString() }

            $edits.Add([pscustomobject]@{
                    Start = $original.Extent.StartOffset
                    End   = $original.Extent.EndOffset
                    Text  = "function $name {`n$signature`nAdd-FakeCall -Name '$name' -Parameter `$PSBoundParameters`ntry {`n$body`n}`nfinally {`nSave-Fake`n}`n}"
                })
        }

        # The device the test describes, and the functions the stand-ins use,
        # placed straight after the param block so the stand-ins can use them.
        $prelude = @'


# ---- Inserted by ConvertTo-StubbedScript: this copy is for tests only. ----
$Fake = Import-Clixml -LiteralPath $env:REMEDIATION_TEST_FAKE

function Save-Fake {
    $Fake | Export-Clixml -LiteralPath $env:REMEDIATION_TEST_FAKE -Depth 5
}

function Add-FakeCall {
    param ([string]$Name, [System.Collections.IDictionary]$Parameter)

    $arguments = @{}
    foreach ($key in $Parameter.Keys) { $arguments[$key] = [string]$Parameter[$key] }
    $Fake.Calls = @($Fake.Calls) + @{ Name = $Name; Parameters = $arguments }
    Save-Fake
}

function Get-FakeResult {
    param ([string]$Name)

    if (-not $Fake.Results.ContainsKey($Name)) { throw "The test queued no result for $Name." }
    $queue = @($Fake.Results[$Name])
    $made = @($Fake.Calls | Where-Object { $_.Name -eq $Name }).Count
    $next = $queue[[Math]::Min($made, $queue.Count) - 1]
    if ($next -is [System.Collections.IDictionary] -and $next.Contains('Throw')) { throw [string]$next['Throw'] }
    return $next
}
# ---- End of inserted code. ----
'@
        $edits.Add([pscustomobject]@{
                Start = $syntaxTree.ParamBlock.Extent.EndOffset
                End   = $syntaxTree.ParamBlock.Extent.EndOffset
                Text  = $prelude
            })

        # From the end backwards, so every offset still points where it did.
        foreach ($edit in @($edits | Sort-Object -Property Start -Descending)) {
            $text = $text.Substring(0, $edit.Start) + $edit.Text + $text.Substring($edit.End)
        }

        # Written without a BOM, ASCII-only, like the script it came from.
        [System.IO.File]::WriteAllText($Destination, $text, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
        return $Destination
    }

    function Invoke-RemediationScript {
        <#
            Runs a script as the Intune management extension does and returns
            ExitCode, Output (the non-empty STDOUT lines), Error (STDERR, with
            the console's line wrapping undone), and
            Fake: the device after the run, with every stand-in call in Calls
            as Name and Parameters. -Fake is needed for a stubbed script, where
            Results holds what each stand-in returns by function name: one
            value, or a list used in turn whose last item repeats. A value of
            @{ Throw = '<message>' } makes the stand-in throw instead.
        #>
        param (
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter()]
            [string[]]$ArgumentList = @(),

            [Parameter()]
            [hashtable]$Fake,

            [Parameter()]
            [switch]$Use32BitHost,

            [Parameter()]
            [int]$TimeoutSeconds = 120
        )

        # A 32-bit process sees SysWOW64 as System32; Sysnative reaches the
        # real one.
        $folder = if ($Use32BitHost) { 'SysWOW64' }
        elseif ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' }
        else { 'System32' }
        $executable = Join-Path -Path $env:SystemRoot -ChildPath "$folder\WindowsPowerShell\v1.0\powershell.exe"

        $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Path) + $ArgumentList
        $quoted = foreach ($argument in $arguments) {
            if ($argument -notmatch '[\s"]') { $argument; continue }
            # A backslash before the closing quote would escape it.
            '"' + (($argument -replace '"', '\"') -replace '(\\+)$', '$1$1') + '"'
        }

        $info = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $info.FileName = $executable
        $info.Arguments = $quoted -join ' '
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true

        $fakePath = $null
        if ($Fake) {
            $state = @{ Calls = @(); Results = @{} }
            foreach ($key in $Fake.Keys) { $state[$key] = $Fake[$key] }
            $fakePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('RemediationFake-' + [guid]::NewGuid().ToString('n') + '.xml')
            $state | Export-Clixml -LiteralPath $fakePath -Depth 5
            $info.EnvironmentVariables['REMEDIATION_TEST_FAKE'] = $fakePath
        }

        try {
            $process = [System.Diagnostics.Process]::Start($info)
            $outputTask = $process.StandardOutput.ReadToEndAsync()
            $errorTask = $process.StandardError.ReadToEndAsync()

            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                $process.Kill()
                throw "$Path did not finish within $TimeoutSeconds seconds."
            }
            $process.WaitForExit()

            [pscustomobject]@{
                ExitCode = $process.ExitCode
                Output   = @($outputTask.Result -split '\r?\n' | Where-Object { $_ -ne '' })
                Error    = ($errorTask.Result -replace '\s+', ' ').Trim()
                Fake     =if ($fakePath) { Import-Clixml -LiteralPath $fakePath } else { $null }
            }
        }
        finally {
            if ($fakePath -and (Test-Path -LiteralPath $fakePath)) { Remove-Item -LiteralPath $fakePath -Force }
        }
    }

    function Get-FakeCall {
        # The stand-in calls a run made, in order, optionally of one function.
        # PowerShell unrolls a single call into the hashtable itself, so index
        # the result as @(Get-FakeCall ...)[0].
        param ([Parameter(Mandatory)][object]$Run, [string]$Name)

        @($Run.Fake.Calls | Where-Object { -not $Name -or $_.Name -eq $Name })
    }
    #endregion Remediation test harness
}

Describe 'What the parameters refuse' -Skip:(-not $script:OnWindows) {

    It 'refuses a group tag containing <Case>' -ForEach @(
        @{ Case = 'a comma'; Value = 'North,South' }
        @{ Case = 'a double quote'; Value = 'North"South' }
        @{ Case = 'a line feed'; Value = "North`nSouth" }
        @{ Case = 'a carriage return'; Value = "North`rSouth" }
        @{ Case = 'a line feed at the end'; Value = "North`n" }
    ) {
        { & $script:Binding -GroupTag $Value } | Should -Throw -ExpectedMessage "*parameter 'GroupTag'*"
    }

    It 'refuses a group tag longer than 255 characters' {
        { & $script:Binding -GroupTag ('x' * 256) } | Should -Throw -ExpectedMessage "*parameter 'GroupTag'*"
    }

    It 'accepts a group tag of <Case>' -ForEach @(
        @{ Case = 'one word'; Value = 'Kiosk' }
        @{ Case = 'words, digits and dashes'; Value = 'North-01 Floor 2' }
        @{ Case = '255 characters'; Value = ('x' * 255) }
        @{ Case = 'nothing'; Value = '' }
    ) {
        (& $script:Binding -GroupTag $Value)['GroupTag'] | Should -BeExactly $Value
    }

    It 'refuses an assigned user that <Case>' -ForEach @(
        @{ Case = 'contains a comma'; Value = 'first,last@{0}' }
        @{ Case = 'contains a double quote'; Value = 'first"last@{0}' }
        @{ Case = 'contains a line feed'; Value = "first`nlast@{0}" }
        @{ Case = 'ends with a line feed'; Value = "user@{0}`n" }
        @{ Case = 'is not a user principal name'; Value = 'user' }
        @{ Case = 'has a domain with no suffix'; Value = 'user@contoso' }
        @{ Case = 'has two @ signs'; Value = 'user@@{0}' }
    ) {
        { & $script:Binding -AssignedUser ($Value -f 'contoso.com') } | Should -Throw -ExpectedMessage "*parameter 'AssignedUser'*"
    }

    It 'accepts an assigned user that is a user principal name, or nothing' {
        $user = Get-TestUser

        (& $script:Binding -AssignedUser $user)['AssignedUser'] | Should -BeExactly $user
        (& $script:Binding -AssignedUser '')['AssignedUser'] | Should -BeExactly ''
    }
}

Describe 'The functions' -Skip:(-not $script:OnWindows) {

    Context 'ConvertTo-AutopilotRecord' {

        It 'names the columns as Intune does, in its order, with Windows Product ID blank' {
            $record = ConvertTo-AutopilotRecord -SerialNumber (Get-TestSerial) -HardwareHash (Get-TestHash) -Tag 'Kiosk' -User (Get-TestUser)

            @($record.PSObject.Properties | ForEach-Object { $_.Name }) |
                Should -Be @('Device Serial Number', 'Windows Product ID', 'Hardware Hash', 'Group Tag', 'Assigned User')
            $record.'Windows Product ID' | Should -BeExactly ''
        }
    }

    Context 'Export-AutopilotCsv' {

        BeforeEach {
            $script:File = Join-Path -Path $TestDrive -ChildPath "$([guid]::NewGuid().ToString('n')).csv"
        }

        It 'writes the three required columns, unquoted, when no device has a group tag or a user' {
            $first = Get-TestDevice
            $second = Get-TestDevice

            Export-AutopilotCsv -Record $first.Record, $second.Record -Path $script:File

            Read-CsvLine -Path $script:File | Should -Be @(
                $script:Header
                "$($first.Serial),,$($first.Hash)"
                "$($second.Serial),,$($second.Hash)"
            )
        }

        It 'adds Group Tag when any device has one, and leaves it empty for the others' {
            $tagged = Get-TestDevice -Tag 'Kiosk'
            $untagged = Get-TestDevice

            Export-AutopilotCsv -Record $tagged.Record, $untagged.Record -Path $script:File

            Read-CsvLine -Path $script:File | Should -Be @(
                "$script:Header,Group Tag"
                "$($tagged.Serial),,$($tagged.Hash),Kiosk"
                "$($untagged.Serial),,$($untagged.Hash),"
            )
        }

        It 'adds Assigned User on its own, straight after Hardware Hash, when no device has a group tag' {
            $user = Get-TestUser
            $device = Get-TestDevice -User $user

            Export-AutopilotCsv -Record $device.Record -Path $script:File

            Read-CsvLine -Path $script:File | Should -Be @("$script:Header,Assigned User", "$($device.Serial),,$($device.Hash),$user")
        }

        It 'writes both, Group Tag first, in the order Intune documents' {
            $user = Get-TestUser
            $device = Get-TestDevice -Tag 'Kiosk' -User $user

            Export-AutopilotCsv -Record $device.Record -Path $script:File

            Read-CsvLine -Path $script:File |
                Should -Be @("$script:Header,Group Tag,Assigned User", "$($device.Serial),,$($device.Hash),Kiosk,$user")
        }

        It 'writes UTF-8 without a byte order mark, which Intune would read as part of the first column name' {
            Export-AutopilotCsv -Record (Get-TestDevice).Record -Path $script:File

            $bytes = [System.IO.File]::ReadAllBytes($script:File)
            $bytes[0] | Should -Be ([byte][char]'D')
        }

        It 'refuses <Case> in <Column>, naming the column, and leaves the file as it was' -ForEach @(
            @{ Case = 'a comma'; Column = 'Group Tag'; Tag = 'North,South' }
            @{ Case = 'a double quote'; Column = 'Group Tag'; Tag = 'North"South' }
            @{ Case = 'a line feed'; Column = 'Assigned User'; User = "first`nlast" }
            @{ Case = 'a carriage return'; Column = 'Device Serial Number'; Serial = "PF`r1" }
        ) {
            Set-Content -LiteralPath $script:File -Value 'The file as it was.'
            $values = @{ SerialNumber = (Get-TestSerial); HardwareHash = (Get-TestHash); Tag = ''; User = '' }
            if ($Tag) { $values.Tag = $Tag }
            if ($User) { $values.User = $User }
            if ($Serial) { $values.SerialNumber = $Serial }
            $record = ConvertTo-AutopilotRecord @values

            { Export-AutopilotCsv -Record $record -Path $script:File } |
                Should -Throw -ExpectedMessage "Column '$Column' contains a comma, a double quote or a line break, which cannot be written to the unquoted CSV*"
            Read-CsvLine -Path $script:File | Should -Be @('The file as it was.')
        }
    }

    Context 'Merge-AutopilotRecord' {

        BeforeAll {
            function ConvertTo-CsvRow {
                # Lines of a CSV as Import-Csv returns them.
                param ([string[]]$Line)
                @($Line | ConvertFrom-Csv)
            }
        }

        It 'adds a device that is not in the file after the devices that are' {
            $old = Get-TestDevice
            $rows = ConvertTo-CsvRow -Line "$script:Header,Group Tag", "$($old.Serial),,$($old.Hash),North"
            $new = Get-TestDevice

            $merge = Merge-AutopilotRecord -ExistingRow $rows -NewRecord $new.Record -SerialNumber $new.Serial

            $merge.Replaced | Should -BeFalse
            $merge.Dropped | Should -Be 0
            @($merge.Record | ForEach-Object { $_.'Device Serial Number' }) | Should -Be @($old.Serial, $new.Serial)
            $merge.Record[0].'Hardware Hash' | Should -BeExactly $old.Hash
            $merge.Record[0].'Group Tag' | Should -BeExactly 'North'
        }

        It 'replaces a device collected again rather than adding it twice, whatever the case and spacing of its serial number' {
            $other = Get-TestDevice
            $again = Get-TestDevice
            $rows = ConvertTo-CsvRow -Line $script:Header, " $($again.Serial.ToLowerInvariant()) ,,$(Get-TestHash)", "$($other.Serial),,$($other.Hash)"

            $merge = Merge-AutopilotRecord -ExistingRow $rows -NewRecord $again.Record -SerialNumber $again.Serial

            $merge.Replaced | Should -BeTrue
            @($merge.Record | ForEach-Object { $_.'Device Serial Number' }) | Should -Be @($other.Serial, $again.Serial)
            $merge.Record[1].'Hardware Hash' | Should -BeExactly $again.Hash
        }

        It 'drops and counts the rows with no serial number or no hardware hash' {
            $kept = Get-TestDevice
            $rows = ConvertTo-CsvRow -Line @(
                $script:Header
                "$($kept.Serial),,$($kept.Hash)"
                ",,$(Get-TestHash)"
                "   ,,$(Get-TestHash)"
                "$(Get-TestSerial),,"
                "$(Get-TestSerial),,   "
            )
            $new = Get-TestDevice

            $merge = Merge-AutopilotRecord -ExistingRow $rows -NewRecord $new.Record -SerialNumber $new.Serial

            $merge.Dropped | Should -Be 4
            @($merge.Record | ForEach-Object { $_.'Device Serial Number' }) | Should -Be @($kept.Serial, $new.Serial)
        }

        It 'drops every row of a file that has no Hardware Hash column' {
            $rows = ConvertTo-CsvRow -Line 'Device Serial Number,Windows Product ID', "$(Get-TestSerial),"
            $new = Get-TestDevice

            $merge = Merge-AutopilotRecord -ExistingRow $rows -NewRecord $new.Record -SerialNumber $new.Serial

            $merge.Dropped | Should -Be 1
            @($merge.Record) | Should -HaveCount 1
        }

        It 'keeps the group tag and user of every other device, and reads a file without those columns' {
            $user = Get-TestUser
            $tagged = Get-TestDevice
            $plain = Get-TestDevice
            $tagRows = ConvertTo-CsvRow -Line "$script:Header,Group Tag,Assigned User", "$($tagged.Serial),,$($tagged.Hash),Kiosk,$user"
            $plainRows = ConvertTo-CsvRow -Line $script:Header, "$($plain.Serial),,$($plain.Hash)"
            $new = Get-TestDevice

            $merge = Merge-AutopilotRecord -ExistingRow (@($tagRows) + @($plainRows)) -NewRecord $new.Record -SerialNumber $new.Serial

            $merge.Record[0].'Group Tag' | Should -BeExactly 'Kiosk'
            $merge.Record[0].'Assigned User' | Should -BeExactly $user
            $merge.Record[1].'Group Tag' | Should -BeExactly ''
            $merge.Record[1].'Assigned User' | Should -BeExactly ''
        }

        It 'starts a file from no rows' {
            $new = Get-TestDevice

            $merge = Merge-AutopilotRecord -ExistingRow @() -NewRecord $new.Record -SerialNumber $new.Serial

            @($merge.Record) | Should -HaveCount 1
            $merge.Replaced | Should -BeFalse
            $merge.Dropped | Should -Be 0
        }
    }

    Context 'ConvertTo-SafeFileName' {

        It '<Case>' -ForEach @(
            @{ Case = 'keeps a serial number that is already safe'; Name = 'PF{0}'; Expected = 'PF{0}' }
            @{ Case = 'turns spaces and slashes into dashes'; Name = 'PF {0}/A1'; Expected = 'PF-{0}-A1' }
            @{ Case = 'turns characters Windows refuses in a file name into dashes'; Name = 'PF\{0}:A*1?'; Expected = 'PF-{0}-A-1' }
            @{ Case = 'collapses runs of dashes and trims them from the ends'; Name = ' -PF  {0}- '; Expected = 'PF-{0}' }
            @{ Case = 'trims a trailing dot, which Windows drops from a file name'; Name = 'To be filled by O.E.M.'; Expected = 'To-be-filled-by-O.E.M' }
        ) {
            $number = Get-Random -Minimum 10000000 -Maximum 99999999

            ConvertTo-SafeFileName -Name ($Name -f $number) | Should -BeExactly ($Expected -f $number)
        }

        It 'falls back to UNKNOWN for <Case>' -ForEach @(
            @{ Case = 'nothing'; Name = '' }
            @{ Case = 'spaces'; Name = '   ' }
            @{ Case = 'slashes'; Name = '///' }
            @{ Case = 'dots'; Name = '...' }
        ) {
            ConvertTo-SafeFileName -Name $Name | Should -BeExactly 'UNKNOWN'
        }

        It 'cuts a long serial number to 64 characters, and trims a dash left at the cut' {
            ConvertTo-SafeFileName -Name ('PF' + ('X' * 100)) | Should -BeExactly ('PF' + ('X' * 62))
            ConvertTo-SafeFileName -Name (('X' * 63) + ' Y') | Should -BeExactly ('X' * 63)
        }

        It 'leaves no character that Windows refuses in a file name' {
            $invalid = [System.IO.Path]::GetInvalidFileNameChars()
            $name = 'PF' + (-join $invalid) + (Get-TestSerial)

            (ConvertTo-SafeFileName -Name $name).IndexOfAny($invalid) | Should -Be -1
        }
    }

    Context 'Get-DeviceSerialNumber' {

        It 'reads the serial number from Win32_BIOS, trimmed' {
            $serial = Get-TestSerial
            $script:Bios = [pscustomobject]@{ SerialNumber = "  $serial  " }
            Mock Get-CimInstance { $script:Bios }

            Get-DeviceSerialNumber | Should -BeExactly $serial
            Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter { $ClassName -eq 'Win32_BIOS' }
        }

        It 'says WMI may be corrupt when Win32_BIOS returns nothing' {
            Mock Get-CimInstance { }

            { Get-DeviceSerialNumber } | Should -Throw -ExpectedMessage 'Win32_BIOS returned nothing. WMI may be corrupt on this device.'
        }

        It 'refuses a device whose BIOS serial number is <Case>' -ForEach @(
            @{ Case = 'empty'; Bios = @{ SerialNumber = '' } }
            @{ Case = 'only spaces'; Bios = @{ SerialNumber = '   ' } }
            @{ Case = 'missing'; Bios = @{ Manufacturer = 'Example' } }
        ) {
            $script:Bios = [pscustomobject]$Bios
            Mock Get-CimInstance { $script:Bios }

            { Get-DeviceSerialNumber } | Should -Throw -ExpectedMessage 'This device reports no BIOS serial number. Autopilot requires one*'
        }
    }

    Context 'Get-DeviceHardwareHash' {

        It 'reads DeviceHardwareData from MDM_DevDetail_Ext01 in the MDM namespace, trimmed' {
            $hash = Get-TestHash
            $script:DevDetail = [pscustomobject]@{ DeviceHardwareData = " $hash`r`n" }
            Mock Get-CimInstance { $script:DevDetail }

            Get-DeviceHardwareHash | Should -BeExactly $hash
            Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter {
                $Namespace -eq 'root/cimv2/mdm/dmmap' -and $ClassName -eq 'MDM_DevDetail_Ext01' -and
                $Filter -eq "InstanceID='Ext' AND ParentID='./DevDetail'"
            }
        }

        It 'names the class, the cause and what to check when the query fails' {
            Mock Get-CimInstance { throw 'Access denied' }

            { Get-DeviceHardwareHash } | Should -Throw -ExpectedMessage 'Could not query MDM_DevDetail_Ext01: Access denied.*confirm the device runs a supported build and that the script is elevated.'
        }

        It 'explains a missing instance, as on a virtual machine without a virtual TPM' {
            Mock Get-CimInstance { }

            { Get-DeviceHardwareHash } | Should -Throw -ExpectedMessage 'MDM_DevDetail_Ext01 returned no instance*virtual machine without a virtual TPM*'
        }

        It 'refuses a DeviceHardwareData that is <Case>' -ForEach @(
            @{ Case = 'empty'; DevDetail = @{ DeviceHardwareData = '' } }
            @{ Case = 'missing'; DevDetail = @{ DeviceID = 'Example' } }
        ) {
            $script:DevDetail = [pscustomobject]$DevDetail
            Mock Get-CimInstance { $script:DevDetail }

            { Get-DeviceHardwareHash } | Should -Throw -ExpectedMessage 'DeviceHardwareData is empty.*'
        }
    }
}

Describe 'The script, run as a file' -Skip:(-not $script:OnWindows) {

    BeforeAll {
        # The stand-ins: the elevation check, and the two functions that read
        # the device. Each returns what the test queues for it.
        $stubs = [ordered]@{
            'Test-Elevated'          = $null
            'Get-DeviceSerialNumber' = $null
            'Get-DeviceHardwareHash' = $null
        }
        $script:Stubbed = ConvertTo-StubbedScript -Path $script:ScriptPath -Stub $stubs `
            -Destination (Join-Path -Path $TestDrive -ChildPath 'Get-AutopilotHardwareHash.ps1')

        function Invoke-Collector {
            # Runs the script as a file on a stand-in device that is elevated
            # and reports -Serial and -Hash, writing to -Folder and logging
            # beside it. Returns the run with the folder, the files in it, the
            # log, and STDOUT and STDERR as compact text.
            param (
                [string]$Serial,
                [string]$Hash,
                [string[]]$Argument = @(),
                [string]$Folder = (Get-TestFolder),
                [hashtable]$Result = @{}
            )

            $results = @{
                'Test-Elevated'          = $true
                'Get-DeviceSerialNumber' = $Serial
                'Get-DeviceHardwareHash' = $Hash
            }
            foreach ($key in $Result.Keys) { $results[$key] = $Result[$key] }

            $logDirectory = "$Folder-Logs"
            $arguments = @('-OutputPath', $Folder, '-LogDirectory', $logDirectory, '-NoBeep') + $Argument
            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $arguments -Fake @{ Results = $results }

            $files = @()
            if (Test-Path -LiteralPath $Folder -PathType Container) {
                $files = @(Get-ChildItem -LiteralPath $Folder -File | Sort-Object -Property Name)
            }

            $run | Add-Member -NotePropertyName Folder -NotePropertyValue $Folder
            $run | Add-Member -NotePropertyName Files -NotePropertyValue $files
            $run | Add-Member -NotePropertyName LogDirectory -NotePropertyValue $logDirectory
            $run | Add-Member -NotePropertyName LogPath -NotePropertyValue (Join-Path -Path $logDirectory -ChildPath 'Get-AutopilotHardwareHash.log')
            $run | Add-Member -NotePropertyName Text -NotePropertyValue (Get-CompactText -Text (@($run.Output) -join ''))
            $run | Add-Member -NotePropertyName ErrorText -NotePropertyValue (Get-CompactText -Text $run.Error)
            $run
        }
    }

    Context 'one file per device' {

        It 'writes AutopilotHWID-<serial>-<time>.csv with the three columns, says so, and exits 0' {
            $serial = Get-TestSerial
            $hash = Get-TestHash

            $run = Invoke-Collector -Serial $serial -Hash $hash

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Files | Should -HaveCount 1
            $run.Files[0].Name | Should -Match "^AutopilotHWID-$serial-\d{8}-\d{6}\.csv$"
            Read-CsvLine -Path $run.Files[0].FullName | Should -Be @($script:Header, "$serial,,$hash")
            $run.Output | Should -Be @("Collected $serial to $($run.Files[0].FullName).")
            $run.Error | Should -BeNullOrEmpty
            $run.LogPath | Should -FileContentMatch ('\[INFO\] .*Hardware hash collected: {0} characters\.' -f $hash.Length)
        }

        It 'stamps the group tag and the assigned user it is given' {
            $serial = Get-TestSerial
            $hash = Get-TestHash
            $user = Get-TestUser

            $run = Invoke-Collector -Serial $serial -Hash $hash -Argument '-GroupTag', 'Kiosk', '-AssignedUser', $user

            $run.ExitCode | Should -Be 0 -Because $run.Error
            Read-CsvLine -Path $run.Files[0].FullName | Should -Be @("$script:Header,Group Tag,Assigned User", "$serial,,$hash,Kiosk,$user")
        }

        It 'adds Assigned User without Group Tag when it is given only a user' {
            $serial = Get-TestSerial
            $hash = Get-TestHash
            $user = Get-TestUser

            $run = Invoke-Collector -Serial $serial -Hash $hash -Argument '-AssignedUser', $user

            Read-CsvLine -Path $run.Files[0].FullName | Should -Be @("$script:Header,Assigned User", "$serial,,$hash,$user")
        }

        It 'names the file after the serial number made safe, and keeps the serial number itself in the CSV' {
            $number = Get-Random -Minimum 10000000 -Maximum 99999999
            $serial = "PF $number/A1"
            $hash = Get-TestHash

            $run = Invoke-Collector -Serial $serial -Hash $hash

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Files[0].Name | Should -Match "^AutopilotHWID-PF-$number-A1-\d{8}-\d{6}\.csv$"
            Read-CsvLine -Path $run.Files[0].FullName | Should -Be @($script:Header, "$serial,,$hash")
        }

        It 'warns that <Serial> looks like an unset placeholder, and still collects' -ForEach @(
            @{ Serial = 'To be filled by O.E.M.'; FileName = 'To-be-filled-by-O.E.M' }
            @{ Serial = 'System Serial Number'; FileName = 'System-Serial-Number' }
            @{ Serial = 'Default string'; FileName = 'Default-string' }
            @{ Serial = '0000000'; FileName = '0000000' }
        ) {
            $run = Invoke-Collector -Serial $Serial -Hash (Get-TestHash)

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Text | Should -BeLike (Get-CompactText -Text "*WARNING: Serial number '$Serial' looks like an unset OEM placeholder rather than a real serial.*")
            $run.Files[0].Name | Should -BeLike "AutopilotHWID-$FileName-*.csv"
            $run.LogPath | Should -FileContentMatch '\[WARN\] .*looks like an unset OEM placeholder'
        }

        It 'does not warn about a real serial number' {
            $run = Invoke-Collector -Serial (Get-TestSerial) -Hash (Get-TestHash)

            $run.Output | Should -HaveCount 1
            $run.Output[0] | Should -BeLike 'Collected *'
        }
    }

    Context 'with -Append' {

        It 'merges repeated runs into one AutopilotHWID.csv, and replaces a device collected again rather than adding it twice' {
            $folder = Get-TestFolder
            $file = Join-Path -Path $folder -ChildPath 'AutopilotHWID.csv'
            $first = Get-TestSerial
            $second = Get-TestSerial
            $secondHash = Get-TestHash
            $newHash = Get-TestHash

            $runs = @(
                Invoke-Collector -Folder $folder -Serial $first -Hash (Get-TestHash) -Argument '-Append', '-GroupTag', 'North'
                Invoke-Collector -Folder $folder -Serial $second -Hash $secondHash -Argument '-Append', '-GroupTag', 'South'
                Invoke-Collector -Folder $folder -Serial $first -Hash $newHash -Argument '-Append', '-GroupTag', 'North'
            )

            @($runs | ForEach-Object { $_.ExitCode }) | Should -Be @(0, 0, 0) -Because (@($runs | ForEach-Object { $_.Error }) -join ' ')
            @($runs | ForEach-Object { $_.Output }) | Should -Be @(
                "Added $first in $file (1 device(s) total)."
                "Added $second in $file (2 device(s) total)."
                "Replaced $first in $file (2 device(s) total)."
            )
            @($runs[2].Files | ForEach-Object { $_.Name }) | Should -Be @('AutopilotHWID.csv')
            Read-CsvLine -Path $file | Should -Be @("$script:Header,Group Tag", "$second,,$secondHash,South", "$first,,$newHash,North")
        }

        It 'drops the rows already in the file that have no serial number or no hash, and says how many' {
            $folder = Get-TestFolder
            $file = Join-Path -Path $folder -ChildPath 'AutopilotHWID.csv'
            $kept = Get-TestSerial
            $keptHash = Get-TestHash
            Set-Content -LiteralPath $file -Value @($script:Header, "$kept,,$keptHash", ",,$(Get-TestHash)", "$(Get-TestSerial),,")
            $serial = Get-TestSerial
            $hash = Get-TestHash

            $run = Invoke-Collector -Folder $folder -Serial $serial -Hash $hash -Argument '-Append'

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Text | Should -BeLike (Get-CompactText -Text "*WARNING: Dropped 2 unusable row(s) already present in '$file'.*")
            $run.Text | Should -BeLike (Get-CompactText -Text "*Added $serial in $file (2 device(s) total).*")
            Read-CsvLine -Path $file | Should -Be @($script:Header, "$kept,,$keptHash", "$serial,,$hash")
            $run.LogPath | Should -FileContentMatch '\[WARN\] \[PID \d+\] Dropped 2 row\(s\)'
        }

        It 'exits 1, and leaves the file as it was, when a row already in it cannot be written back unquoted' {
            # A value quoted because it holds a comma, as a spreadsheet saves it.
            $folder = Get-TestFolder
            $file = Join-Path -Path $folder -ChildPath 'AutopilotHWID.csv'
            Set-Content -LiteralPath $file -Value @("$script:Header,Group Tag", "$(Get-TestSerial),,$(Get-TestHash),`"North,South`"")
            $before = [System.IO.File]::ReadAllText($file)

            $run = Invoke-Collector -Folder $folder -Serial (Get-TestSerial) -Hash (Get-TestHash) -Argument '-Append'

            $run.ExitCode | Should -Be 1
            $run.ErrorText | Should -BeLike (Get-CompactText -Text "*Autopilot hash collection failed: Column 'Group Tag' contains a comma, a double quote or a line break*")
            [System.IO.File]::ReadAllText($file) | Should -BeExactly $before
        }
    }

    Context 'what it refuses' {

        It 'exits 1, reading nothing and writing nothing, when it is not elevated' {
            $run = Invoke-Collector -Serial (Get-TestSerial) -Hash (Get-TestHash) -Result @{ 'Test-Elevated' = $false }

            $run.ExitCode | Should -Be 1
            $run.ErrorText | Should -BeLike (Get-CompactText -Text '*Autopilot hash collection failed: This script must run elevated.*')
            $run.Files | Should -HaveCount 0
            @(Get-FakeCall -Run $run | ForEach-Object { $_.Name }) | Should -Be @('Test-Elevated')
            $run.LogPath | Should -FileContentMatch '\[ERROR\] .*must run elevated'
        }

        It 'exits 1 without writing when the serial number contains <Case>' -ForEach @(
            @{ Case = 'a comma'; Serial = 'PF{0},A1' }
            @{ Case = 'a double quote'; Serial = 'PF{0}"A1' }
            @{ Case = 'a line break'; Serial = "PF{0}`nA1" }
        ) {
            $run = Invoke-Collector -Serial ($Serial -f (Get-Random)) -Hash (Get-TestHash)

            $run.ExitCode | Should -Be 1
            $run.ErrorText | Should -BeLike (Get-CompactText -Text '*Autopilot hash collection failed: Serial number contains a comma, a double quote or a line break*')
            $run.Files | Should -HaveCount 0
        }

        It 'exits 1 before reading the device when -GroupTag contains a comma' {
            $run = Invoke-Collector -Serial (Get-TestSerial) -Hash (Get-TestHash) -Argument '-GroupTag', 'North,South'

            $run.ExitCode | Should -Be 1
            $run.ErrorText | Should -BeLike "*parameter'GroupTag'*"
            $run.ErrorText | Should -Not -BeLike '*Autopilothashcollectionfailed*'
            Get-FakeCall -Run $run | Should -HaveCount 0
            $run.Files | Should -HaveCount 0
        }

        It 'exits 1 and passes on the reason when the hardware hash cannot be read' {
            $reason = 'MDM_DevDetail_Ext01 returned no instance, so the device exposes no Autopilot hardware hash.'

            $run = Invoke-Collector -Serial (Get-TestSerial) -Result @{ 'Get-DeviceHardwareHash' = @{ Throw = $reason } }

            $run.ExitCode | Should -Be 1
            $run.ErrorText | Should -BeLike (Get-CompactText -Text "*Autopilot hash collection failed: $reason*")
            $run.Files | Should -HaveCount 0
        }

        It 'exits 1 when -OutputPath is not a folder' {
            $missing = Join-Path -Path $TestDrive -ChildPath 'NoSuchFolder'

            $run = Invoke-Collector -Folder $missing -Serial (Get-TestSerial) -Hash (Get-TestHash)

            $run.ExitCode | Should -Be 1
            $run.ErrorText | Should -BeLike (Get-CompactText -Text "*OutputPath '$missing' does not exist or is not a directory.*")
        }
    }

    Context 'with -WhatIf' {

        It 'names the file it would write, writes nothing, not even its log, and exits 0' {
            $serial = Get-TestSerial

            $run = Invoke-Collector -Serial $serial -Hash (Get-TestHash) -Argument '-WhatIf'

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Files | Should -HaveCount 0
            Test-Path -LiteralPath $run.LogDirectory | Should -BeFalse
            $target = Get-CompactText -Text "What if: Performing the operation `"Write Autopilot hardware hash`" on target `"$($run.Folder)\AutopilotHWID-$serial-"
            $run.Text | Should -Match ([regex]::Escape($target) + '\d{8}-\d{6}\.csv"')
        }

        It 'leaves a shared file as it was under -Append' {
            $folder = Get-TestFolder
            $file = Join-Path -Path $folder -ChildPath 'AutopilotHWID.csv'
            $null = Invoke-Collector -Folder $folder -Serial (Get-TestSerial) -Hash (Get-TestHash) -Argument '-Append'
            $before = [System.IO.File]::ReadAllText($file)

            $run = Invoke-Collector -Folder $folder -Serial (Get-TestSerial) -Hash (Get-TestHash) -Argument '-Append', '-WhatIf'

            $run.ExitCode | Should -Be 0 -Because $run.Error
            [System.IO.File]::ReadAllText($file) | Should -BeExactly $before
            $run.Text | Should -BeLike (Get-CompactText -Text "*What if: Performing the operation `"Write Autopilot hardware hash`" on target `"$file`".*")
        }
    }
}
