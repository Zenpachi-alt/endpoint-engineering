# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Import-AutopilotDeviceIdentity.ps1: how it reads and
    checks the CSV, including one the collector wrote, what it sends for each
    device, what it waits for and reports, and what it refuses before it signs
    in.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without its main
    block, and tested on their own. A CSV is written with the collector's own
    functions, from Intune/Windows/Autopilot/Get-AutopilotHardwareHash.ps1,
    and read back through this script's, so a change to either side of the
    format fails here.

    The main block runs as the script runs it, after its own param block,
    settings and constants, so -WhatIf, -Confirm and the parameters' checks
    are the script's. Connect-GraphSession and Invoke-GraphRequestWithRetry
    are replaced by a stand-in service held in memory, which answers each
    device as the test describes, and Start-Sleep and Get-Date by a clock that
    moves only when the script waits, so a timeout of minutes passes at once.
    Each exit in the main block becomes a throw that carries its code, so a
    run ends where the script would end, without ending the test run. Nothing
    reaches Graph and no module is needed.

    The script is also started as a file, in a child process, for its exit
    code and its message when it refuses a request before signing in. The
    tests that get past its module check are skipped where
    Microsoft.Graph.Authentication is not installed.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Autopilot\Import-AutopilotDeviceIdentity.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Microsoft.Graph.Authentication 2.0.0 or later, optional,
                    for the tests of the script run as a file that get past
                    its module check.
#>

BeforeDiscovery {
    # The script loads the module before anything else, so it gets as far as
    # its own checks only where the module is installed for the PowerShell
    # that runs the tests.
    $script:ModuleAvailable = [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
            Where-Object { $_.Version -ge [version]'2.0.0' })
}

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Import-AutopilotDeviceIdentity.ps1'
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $collectorPath = Join-Path -Path $repositoryRoot -ChildPath 'Intune/Windows/Autopilot/Get-AutopilotHardwareHash.ps1'

    function Get-ScriptDefinition {
        # A script's top-level assignments to the variables -Variable matches,
        # then its top-level functions, without its main block. The script
        # runs under Set-StrictMode -Version Latest, so each function gets it
        # as its first statement here too.
        param ([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Variable)

        $parseErrors = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "$Path does not parse: $($parseErrors[0].Message)" }

        $statements = @($tree.EndBlock.Statements)
        foreach ($statement in $statements) {
            if ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $statement.Left.Extent.Text -match "^\`$($Variable)$") {
                $statement.Extent.Text
            }
        }
        foreach ($statement in $statements) {
            if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $text = $statement.Extent.Text
                $at = $statement.Body.ParamBlock.Extent.EndOffset - $statement.Extent.StartOffset
                $text.Substring(0, $at) + "`nSet-StrictMode -Version Latest`n" + $text.Substring($at)
            }
        }
    }

    # This script's functions and the column names they read. The stand-ins
    # for its Graph helpers are defined later, where they are needed.
    foreach ($definition in (Get-ScriptDefinition -Path $script:ScriptPath -Variable '\w+Column')) {
        . ([scriptblock]::Create($definition))
    }

    # The collector's, kept apart: Write-CollectorCsv runs them in a scope of
    # their own, so that they replace nothing of this script's.
    $script:CollectorDefinitions = @(Get-ScriptDefinition -Path $collectorPath -Variable '\w+Column')

    $script:ImportUri = 'https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities'
    $script:Header = 'Device Serial Number,Windows Product ID,Hardware Hash'

    function Get-TestSerial {
        # A made-up serial number in the shape OEMs use.
        'PF{0}' -f (Get-Random -Minimum 10000000 -Maximum 99999999)
    }

    function Get-TestHash {
        # A made-up hardware hash: random bytes as base64, the form the
        # collector reads from DeviceHardwareData. 3000 bytes need no padding;
        # another length does.
        param ([int]$Length = 3000)

        $bytes = New-Object -TypeName byte[] -ArgumentList $Length
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
        [System.Convert]::ToBase64String($bytes)
    }

    function Get-TestUser {
        # A made-up user principal name in the documentation domain.
        'user{0}@{1}' -f (Get-Random -Minimum 100 -Maximum 999), 'contoso.com'
    }

    function Get-TestDevice {
        # A made-up device, as the collector reads it.
        param ([string]$Tag = '', [string]$User = '')

        [pscustomobject]@{ Serial = (Get-TestSerial); Hash = (Get-TestHash); Tag = $Tag; User = $User }
    }

    function Get-TestFolder {
        # A new, empty folder in TestDrive.
        $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $folder
        $folder
    }

    function Write-TestCsv {
        # Writes lines to devices.csv in a new folder and returns its path.
        param ([string[]]$Line)

        $path = Join-Path -Path (Get-TestFolder) -ChildPath 'devices.csv'
        Set-Content -LiteralPath $path -Value $Line
        $path
    }

    function Write-DeviceCsv {
        # Writes devices in the layout Intune documents, every column
        # included, and returns the path.
        param ([object[]]$Device)

        Write-TestCsv -Line (@("$script:Header,Group Tag,Assigned User") +
            @($Device | ForEach-Object { '{0},,{1},{2},{3}' -f $_.Serial, $_.Hash, $_.Tag, $_.User }))
    }

    function Write-CollectorCsv {
        # Writes devices with the collector's own functions, as it writes
        # them: a record for each, merged into what the file already holds,
        # as -Append does. Returns the path.
        param ([Parameter(Mandatory)][object[]]$Device)

        $path = Join-Path -Path (Get-TestFolder) -ChildPath 'AutopilotHWID.csv'
        & {
            param ($Entries, $File)

            foreach ($definition in $script:CollectorDefinitions) { . ([scriptblock]::Create($definition)) }

            foreach ($entry in $Entries) {
                $record = ConvertTo-AutopilotRecord -SerialNumber $entry.Serial -HardwareHash $entry.Hash -Tag $entry.Tag -User $entry.User
                $existing = @()
                if (Test-Path -LiteralPath $File) { $existing = @(Import-Csv -LiteralPath $File) }
                $merge = Merge-AutopilotRecord -ExistingRow $existing -NewRecord $record -SerialNumber $entry.Serial
                Export-AutopilotCsv -Record $merge.Record -Path $File
            }
        } $Device $path
        $path
    }

    function Read-Device {
        # A CSV read as the main block reads it, through the script's parser.
        param ([string]$Path, [hashtable]$Option = @{})

        Import-AutopilotCsvRow -Row @(Import-Csv -LiteralPath $Path) @Option
    }

    function ConvertTo-CsvRow {
        # Lines of a CSV as Import-Csv returns them.
        param ([string[]]$Line)
        @($Line | ConvertFrom-Csv)
    }

    function Get-GraphFailure {
        # The exception the real helper throws: the status in Data.
        param ([int]$StatusCode, [string]$Message)

        $exception = [System.Exception]::new("HTTP $StatusCode from Graph after 1 attempt(s): $Message")
        $exception.Data['StatusCode'] = $StatusCode
        $exception
    }
}

Describe 'Reading the CSV' {

    Context 'Import-AutopilotCsvRow' {

        It 'reads each device, trimmed, whatever the case and spacing of the column names' {
            $hash = Get-TestHash
            $serial = Get-TestSerial
            $user = Get-TestUser
            $rows = ConvertTo-CsvRow -Line ' device serial number ,windows product id,HARDWARE HASH,Group tag,assigned USER', " $serial ,, $hash , Kiosk , $user "

            $parsed = Import-AutopilotCsvRow -Row $rows

            $parsed.Problem | Should -HaveCount 0
            $parsed.Device | Should -HaveCount 1
            $parsed.Device[0].SerialNumber | Should -BeExactly $serial
            $parsed.Device[0].HardwareHash | Should -BeExactly $hash
            $parsed.Device[0].GroupTag | Should -BeExactly 'Kiosk'
            $parsed.Device[0].AssignedUser | Should -BeExactly $user
        }

        It 'reads a CSV without the optional columns' {
            $device = Get-TestDevice

            $parsed = Import-AutopilotCsvRow -Row (ConvertTo-CsvRow -Line $script:Header, "$($device.Serial),,$($device.Hash)")

            $parsed.Device[0].GroupTag | Should -BeExactly ''
            $parsed.Device[0].AssignedUser | Should -BeExactly ''
        }

        It 'reports a row with <Case> by its line number, and skips it' -ForEach @(
            @{ Case = 'no serial number'; Line = ',,{1}'; Expected = "Line 3: no 'Device Serial Number'." }
            @{ Case = 'no hardware hash'; Line = '{0},,'; Expected = "Line 3: serial '{0}' has no 'Hardware Hash'." }
            @{ Case = 'a hash that is not base64'; Line = '{0},,{1}!'; Expected = "Line 3: serial '{0}' has a 'Hardware Hash' that is not valid base64." }
            @{ Case = 'a hash without its base64 padding'; Line = '{0},,{2}'; Expected = "Line 3: serial '{0}' has a 'Hardware Hash' that is not valid base64." }
        ) {
            $good = Get-TestDevice
            $serial = Get-TestSerial
            $values = $serial, (Get-TestHash), (Get-TestHash -Length 3001).TrimEnd('=')
            $rows = ConvertTo-CsvRow -Line $script:Header, "$($good.Serial),,$($good.Hash)", ($Line -f $values)

            $parsed = Import-AutopilotCsvRow -Row $rows

            $parsed.Problem | Should -Be @($Expected -f $values)
            @($parsed.Device | ForEach-Object { $_.SerialNumber }) | Should -Be @($good.Serial)
            $parsed.Duplicate | Should -Be 0
        }

        It 'collapses a serial number listed twice, whatever its case, keeping the last reading in the first one''s place' {
            $first = Get-TestDevice
            $second = Get-TestDevice
            $newHash = Get-TestHash
            $rows = ConvertTo-CsvRow -Line @(
                $script:Header
                "$($first.Serial),,$($first.Hash)"
                "$($second.Serial),,$($second.Hash)"
                "$($first.Serial.ToLowerInvariant()),,$newHash"
            )

            $parsed = Import-AutopilotCsvRow -Row $rows

            $parsed.Duplicate | Should -Be 1
            $parsed.Problem | Should -HaveCount 0
            @($parsed.Device | ForEach-Object { $_.SerialNumber }) | Should -Be @($first.Serial.ToLowerInvariant(), $second.Serial)
            $parsed.Device[0].HardwareHash | Should -BeExactly $newHash
        }

        It 'keeps an earlier reading when a later one of the same serial number is unusable' {
            $device = Get-TestDevice

            $parsed = Import-AutopilotCsvRow -Row (ConvertTo-CsvRow -Line $script:Header, "$($device.Serial),,$($device.Hash)", "$($device.Serial),,")

            $parsed.Device[0].HardwareHash | Should -BeExactly $device.Hash
            $parsed.Problem | Should -HaveCount 1
            $parsed.Duplicate | Should -Be 0
        }

        It 'applies a group tag override to every device, over the CSV' {
            $rows = ConvertTo-CsvRow -Line "$script:Header,Group Tag", "$(Get-TestSerial),,$(Get-TestHash),North", "$(Get-TestSerial),,$(Get-TestHash),"

            $parsed = Import-AutopilotCsvRow -Row $rows -TagOverride 'Kiosk'

            @($parsed.Device | ForEach-Object { $_.GroupTag }) | Should -Be @('Kiosk', 'Kiosk')
        }

        It 'keeps the CSV''s group tags when the override is blank' {
            $rows = ConvertTo-CsvRow -Line "$script:Header,Group Tag", "$(Get-TestSerial),,$(Get-TestHash),North"

            (Import-AutopilotCsvRow -Row $rows -TagOverride '  ').Device[0].GroupTag | Should -BeExactly 'North'
        }

        It 'returns no device and no problem for no rows' {
            $parsed = Import-AutopilotCsvRow -Row @()

            $parsed.Device | Should -HaveCount 0
            $parsed.Problem | Should -HaveCount 0
            $parsed.Duplicate | Should -Be 0
        }
    }

    Context 'a CSV written by the collector' {

        It 'reads a device with no group tag or user, and sends neither' {
            $device = Get-TestDevice

            $parsed = Read-Device -Path (Write-CollectorCsv -Device $device)

            $parsed.Problem | Should -HaveCount 0
            $parsed.Device | Should -HaveCount 1
            $parsed.Device[0].SerialNumber | Should -BeExactly $device.Serial
            $parsed.Device[0].HardwareHash | Should -BeExactly $device.Hash
            @((ConvertTo-ImportBody -Device $parsed.Device[0]).Keys | Sort-Object) | Should -Be @('@odata.type', 'hardwareIdentifier', 'serialNumber')
        }

        It 'reads the group tag and the assigned user the collector stamps' {
            $device = Get-TestDevice -Tag 'Kiosk' -User (Get-TestUser)

            $parsed = Read-Device -Path (Write-CollectorCsv -Device $device)

            $parsed.Device[0].GroupTag | Should -BeExactly 'Kiosk'
            $parsed.Device[0].AssignedUser | Should -BeExactly $device.User
        }

        It 'reads an assigned user the collector wrote without a Group Tag column' {
            $device = Get-TestDevice -User (Get-TestUser)
            $path = Write-CollectorCsv -Device $device

            (Get-Content -LiteralPath $path)[0] | Should -BeExactly "$script:Header,Assigned User"
            $parsed = Read-Device -Path $path
            $parsed.Device[0].GroupTag | Should -BeExactly ''
            $parsed.Device[0].AssignedUser | Should -BeExactly $device.User
        }

        It 'reads a file the collector appended to, with each device once and the latest reading of one collected again' {
            $first = Get-TestDevice -Tag 'North'
            $second = Get-TestDevice
            $again = [pscustomobject]@{ Serial = $first.Serial; Hash = (Get-TestHash); Tag = 'North'; User = '' }

            $parsed = Read-Device -Path (Write-CollectorCsv -Device $first, $second, $again)

            $parsed.Problem | Should -HaveCount 0
            $parsed.Duplicate | Should -Be 0
            @($parsed.Device | ForEach-Object { $_.SerialNumber }) | Should -Be @($second.Serial, $first.Serial)
            $parsed.Device[1].HardwareHash | Should -BeExactly $again.Hash
            @($parsed.Device | ForEach-Object { $_.GroupTag }) | Should -Be @('', 'North')
        }
    }
}

Describe 'Building the request' {

    Context 'ConvertTo-ImportBody' {

        It 'sends the serial number and the hash, typed as an imported device identity' {
            $device = [pscustomobject]@{ SerialNumber = (Get-TestSerial); HardwareHash = (Get-TestHash); GroupTag = ''; AssignedUser = '' }

            $body = ConvertTo-ImportBody -Device $device

            $body['@odata.type'] | Should -BeExactly '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
            $body['serialNumber'] | Should -BeExactly $device.SerialNumber
            $body['hardwareIdentifier'] | Should -BeExactly $device.HardwareHash
        }

        It 'leaves out a blank group tag and user rather than sending them empty' {
            $device = [pscustomobject]@{ SerialNumber = (Get-TestSerial); HardwareHash = (Get-TestHash); GroupTag = ' '; AssignedUser = '' }

            $body = ConvertTo-ImportBody -Device $device

            $body.ContainsKey('groupTag') | Should -BeFalse
            $body.ContainsKey('assignedUserPrincipalName') | Should -BeFalse
        }

        It 'sends the group tag and the user when there are some' {
            $user = Get-TestUser
            $device = [pscustomobject]@{ SerialNumber = (Get-TestSerial); HardwareHash = (Get-TestHash); GroupTag = 'Kiosk'; AssignedUser = $user }

            $body = ConvertTo-ImportBody -Device $device

            $body['groupTag'] | Should -BeExactly 'Kiosk'
            $body['assignedUserPrincipalName'] | Should -BeExactly $user
        }
    }

    Context 'Get-ImportAdvice' {

        It 'explains <ErrorName>' -ForEach @(
            @{ ErrorName = 'ZtdDeviceAlreadyAssigned'; Expected = 'Already registered to Autopilot, in this tenant or another one.*' }
            @{ ErrorName = 'ZtdDeviceNotFound'; Expected = 'The service could not match the hardware hash. Re-collect it on the device*' }
            @{ ErrorName = 'ZtdDuplicateDevice'; Expected = 'A device with this serial number is already being imported*' }
            @{ ErrorName = 'ZtdSomethingElse'; Expected = "Service reported 'ZtdSomethingElse'. See the Autopilot registration troubleshooting guidance." }
        ) {
            Get-ImportAdvice -ErrorName $ErrorName | Should -BeLike $Expected
        }

        It 'has nothing to say when there is no error' {
            Get-ImportAdvice -ErrorName '' | Should -BeExactly ''
        }
    }
}

Describe 'The main block' {

    BeforeAll {
        # The script as it runs, but for its module check and its final
        # catch: its param block, its settings and constants, and the body of
        # its main try. -WhatIf, -Confirm, $PSBoundParameters and the
        # parameters' checks are therefore the script's own. Each exit becomes
        # a throw that Invoke-Main reads back as the exit code, because an
        # exit here would end the test run.
        $parseErrors = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "Import-AutopilotDeviceIdentity.ps1 does not parse: $($parseErrors[0].Message)" }
        $try = $tree.EndBlock.Statements[-1]
        if ($try -isnot [System.Management.Automation.Language.TryStatementAst]) { throw 'The main block is not a try statement.' }

        $body = $try.Body.Extent.Text
        $exits = @($try.Body.FindAll({ param ($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
        if ($exits.Count -eq 0) { throw 'The main block has no exit statement, so the tests read no exit code.' }
        foreach ($exit in @($exits | Sort-Object -Property { $_.Extent.StartOffset } -Descending)) {
            $start = $exit.Extent.StartOffset - $try.Body.Extent.StartOffset
            $code = if ($exit.Pipeline) { $exit.Pipeline.Extent.Text } else { '0' }
            $body = $body.Substring(0, $start) + "throw (Get-ExitSignal -Code ($code))" + $body.Substring($start + $exit.Extent.Text.Length)
        }

        # Everything at the top level but the functions and the two try
        # statements, the module check and the main block.
        $settings = @($tree.EndBlock.Statements |
                Where-Object {
                    $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $_ -isnot [System.Management.Automation.Language.TryStatementAst]
                } |
                ForEach-Object { $_.Extent.Text })

        $paramBlock = $tree.ParamBlock
        $script:MainBlock = [scriptblock]::Create((@(
                    @($paramBlock.Attributes | ForEach-Object { $_.Extent.Text })
                    $paramBlock.Extent.Text
                    $settings
                    $body.Substring(1, $body.Length - 2)
                ) -join "`n"))

        function Get-ExitSignal {
            # What an exit in the main block becomes here: an exception that
            # carries the code.
            param ([int]$Code)

            $signal = [System.Exception]::new("exit $Code")
            $signal.Data['ExitCode'] = $Code
            $signal
        }

        function Invoke-Main {
            # Runs the script with these arguments as far as its exit, and
            # separates what it returns, warns and reports. A run is
            # confirmed unless it passes -WhatIf or -Confirm itself.
            param ([Parameter(Mandatory)][hashtable]$Argument)

            $arguments = @{} + $Argument
            if (-not $arguments.ContainsKey('WhatIf') -and -not $arguments.ContainsKey('Confirm')) { $arguments['Confirm'] = $false }

            $all = [System.Collections.Generic.List[object]]::new()
            $exitCode = $null
            $failure = $null
            try {
                & $script:MainBlock @arguments 2>&1 3>&1 | ForEach-Object { $all.Add($_) }
            }
            catch {
                if ($_.Exception.Data.Contains('ExitCode')) {
                    $exitCode = $_.Exception.Data['ExitCode']
                }
                else {
                    # The script's catch reports this, and exits 1.
                    $failure = $_.Exception.Message
                    $exitCode = 1
                }
            }

            [pscustomobject]@{
                ExitCode = $exitCode
                Failure  = $failure
                Rows     = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.ErrorRecord] })
                Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
                Errors   = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.Exception.Message })
            }
        }

        function Get-Row {
            # The returned record of one device, by serial number.
            param ($Run, [string]$Serial)

            $rows = @($Run.Rows | Where-Object { $_.SerialNumber -eq $Serial })
            if ($rows.Count -ne 1) { throw "Expected one record for $Serial, got $($rows.Count)." }
            $rows[0]
        }

        function Initialize-StandInService {
            # A service that refuses nothing and completes every import at its
            # first status check, until Add-Outcome says otherwise.
            $script:SignIns = [System.Collections.Generic.List[object]]::new()
            $script:Requests = [System.Collections.Generic.List[object]]::new()
            $script:Imports = @{}
            $script:Outcomes = @{}
            $script:Clock = [datetime]::new(2026, 10, 1, 9, 0, 0, [DateTimeKind]::Utc)
        }

        function Add-Outcome {
            # What the service does with one serial number: fail its
            # submission, or accept it without an id; then fail some status
            # checks, report it pending for some, and give its final state.
            param (
                [Parameter(Mandatory)][string]$Serial,
                [string]$Status = 'complete',
                [string]$ErrorName = '',
                [int]$ErrorCode = 0,
                [int]$FailedChecks = 0,
                [int]$PendingChecks = 0,
                [AllowEmptyString()][string]$PendingStatus = 'pending',
                [System.Exception]$SubmitFailure,
                [switch]$NoId
            )

            $registrationId = $null
            if ($Status -eq 'complete') { $registrationId = [guid]::NewGuid().ToString() }

            $script:Outcomes[$Serial.ToUpperInvariant()] = [pscustomobject]@{
                Status         = $Status
                ErrorName      = $ErrorName
                ErrorCode      = $ErrorCode
                FailedChecks   = $FailedChecks
                PendingChecks  = $PendingChecks
                PendingStatus  = $PendingStatus
                SubmitFailure  = $SubmitFailure
                NoId           = $NoId.IsPresent
                RegistrationId = $registrationId
            }
        }

        function Get-Outcome {
            param ([string]$Serial)

            if (-not $script:Outcomes.ContainsKey($Serial.ToUpperInvariant())) { Add-Outcome -Serial $Serial }
            $script:Outcomes[$Serial.ToUpperInvariant()]
        }

        function Get-StatusCheck {
            # The status checks sent for one serial number.
            param ([string]$Serial)

            @($script:Requests | Where-Object {
                    $_.Method -eq 'GET' -and $script:Imports[($_.Uri -split '/')[-1]].Serial -eq $Serial
                })
        }

        # Signs nothing in: the stand-in service needs no session.
        function Connect-GraphSession {
            param ($Scope, $TenantId, [switch]$UseDeviceCode)

            $script:SignIns.Add([pscustomobject]@{
                    Scope          = $Scope
                    TenantId       = $TenantId
                    UseDeviceCode  = $UseDeviceCode.IsPresent
                    RequestsBefore = $script:Requests.Count
                })
            $false
        }

        # Defined after the script's functions, so it replaces the helper. It
        # takes only the parameters the script passes, so a new one fails here.
        function Invoke-GraphRequestWithRetry {
            param ([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', [hashtable]$Body, [int]$MaximumAttempt)

            $script:Requests.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body; MaximumAttempt = $MaximumAttempt })

            if ($Method -eq 'POST' -and $Uri -eq $script:ImportUri) {
                $outcome = Get-Outcome -Serial $Body['serialNumber']
                if ($outcome.SubmitFailure) { throw $outcome.SubmitFailure }
                if ($outcome.NoId) { return [pscustomobject]@{ serialNumber = $Body['serialNumber'] } }

                $id = [guid]::NewGuid().ToString()
                $script:Imports[$id] = [pscustomobject]@{ Serial = $Body['serialNumber']; Checks = 0 }
                return [pscustomobject]@{ id = $id; serialNumber = $Body['serialNumber']; state = [pscustomobject]@{ deviceImportStatus = 'unknown' } }
            }

            $id = ($Uri -split '/')[-1]
            if ($Method -ne 'GET' -or $Uri -ne "$script:ImportUri/$id" -or -not $script:Imports.ContainsKey($id)) {
                throw "The stand-in service has no $Method at $Uri"
            }

            $import = $script:Imports[$id]
            $import.Checks++
            $outcome = Get-Outcome -Serial $import.Serial

            if ($import.Checks -le $outcome.FailedChecks) { throw (Get-GraphFailure -StatusCode 503 -Message 'ServiceUnavailable') }

            $state = if ($import.Checks -le $outcome.FailedChecks + $outcome.PendingChecks) {
                [pscustomobject]@{ deviceImportStatus = $outcome.PendingStatus }
            }
            else {
                [pscustomobject]@{
                    deviceImportStatus   = $outcome.Status
                    deviceRegistrationId = $outcome.RegistrationId
                    deviceErrorCode      = $outcome.ErrorCode
                    deviceErrorName      = $outcome.ErrorName
                }
            }

            [pscustomobject]@{ id = $id; serialNumber = $import.Serial; state = $state }
        }

        # The clock: it stands still until the script waits, so a timeout of
        # minutes passes at once.
        Mock Start-Sleep { $script:Clock = $script:Clock.AddSeconds($Seconds) }
        Mock Get-Date {
            if ($Format) { return $script:Clock.ToString($Format, [cultureinfo]::InvariantCulture) }
            $script:Clock
        }
    }

    BeforeEach {
        Initialize-StandInService
        $script:First = Get-TestDevice -Tag 'North'
        $script:Second = Get-TestDevice -User (Get-TestUser)
        $script:Csv = Write-DeviceCsv -Device $script:First, $script:Second
    }

    Context 'before anything is sent' {

        It 'refuses a -CsvPath that is not a file' {
            $run = Invoke-Main -Argument @{ CsvPath = $TestDrive }

            $run.Failure | Should -BeLike "*CsvPath '$TestDrive' does not exist or is not a file.*"
            $script:SignIns | Should -HaveCount 0
        }

        It 'fails before signing in when the CSV holds no rows' {
            $file = Write-TestCsv -Line $script:Header

            $run = Invoke-Main -Argument @{ CsvPath = $file }

            $run.ExitCode | Should -Be 1
            $run.Failure | Should -BeExactly "'$file' contains no rows."
            $script:SignIns | Should -HaveCount 0
            $script:Requests | Should -HaveCount 0
        }

        It 'fails before signing in when no row can be imported, after a warning for each' {
            $serial = Get-TestSerial
            $file = Write-TestCsv -Line $script:Header, ",,$(Get-TestHash)", "$serial,,"

            $run = Invoke-Main -Argument @{ CsvPath = $file }

            $run.ExitCode | Should -Be 1
            $run.Failure | Should -BeExactly "No importable device found in '$file'. 2 row(s) were unusable; see the warnings above."
            $run.Warnings | Should -Be @("Line 2: no 'Device Serial Number'.", "Line 3: serial '$serial' has no 'Hardware Hash'.")
            $script:SignIns | Should -HaveCount 0
        }

        It 'returns a notSubmitted record for each device under -WhatIf, sends nothing, and exits 0' {
            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv; WhatIf = $true }

            $run.ExitCode | Should -Be 0
            @($run.Rows | ForEach-Object { $_.SerialNumber }) | Should -Be @($script:First.Serial, $script:Second.Serial)
            @($run.Rows | ForEach-Object { $_.Status } | Select-Object -Unique) | Should -Be @('notSubmitted')
            @($run.Rows | ForEach-Object { $_.Advice } | Select-Object -Unique) | Should -Be @('Reported by -WhatIf. Nothing was sent to the tenant.')
            $run.Rows[0].GroupTag | Should -BeExactly 'North'
            $run.Rows[1].AssignedUser | Should -BeExactly $script:Second.User
            $script:SignIns | Should -HaveCount 0
            $script:Requests | Should -HaveCount 0
        }

        It 'still reports the rows it cannot use and the duplicates it collapses under -WhatIf' {
            $serial = Get-TestSerial
            $file = Write-TestCsv -Line @(
                $script:Header
                "$($script:First.Serial),,$($script:First.Hash)"
                "$serial,,"
                "$($script:First.Serial),,$(Get-TestHash)"
            )

            $run = Invoke-Main -Argument @{ CsvPath = $file; WhatIf = $true }

            $run.Rows | Should -HaveCount 1
            $run.Warnings | Should -Be @(
                "Line 3: serial '$serial' has no 'Hardware Hash'."
                'Collapsed 1 duplicate serial number(s); the last occurrence of each was kept.'
            )
        }
    }

    Context 'submitting' {

        It 'signs in once, with its one scope, before sending anything' {
            $tenantId = [guid]::NewGuid().ToString()

            $null = Invoke-Main -Argument @{ CsvPath = $script:Csv; TenantId = $tenantId; UseDeviceCode = $true }

            $script:SignIns | Should -HaveCount 1
            $script:SignIns[0].RequestsBefore | Should -Be 0
            [string[]]@($script:SignIns[0].Scope.Keys) | Should -Be @('DeviceManagementServiceConfig.ReadWrite.All')
            @($script:SignIns[0].Scope['DeviceManagementServiceConfig.ReadWrite.All']) | Should -HaveCount 0
            $script:SignIns[0].TenantId | Should -Be $tenantId
            $script:SignIns[0].UseDeviceCode | Should -BeTrue
        }

        It 'posts one request per device to the v1.0 import endpoint, with the body built from its row' {
            $null = Invoke-Main -Argument @{ CsvPath = $script:Csv; MaximumRetryCount = 3 }

            $posts = @($script:Requests | Where-Object { $_.Method -eq 'POST' })
            $posts | Should -HaveCount 2
            @($posts | ForEach-Object { $_.Uri } | Select-Object -Unique) | Should -Be @($script:ImportUri)
            @($script:Requests | ForEach-Object { $_.MaximumAttempt } | Select-Object -Unique) | Should -Be @(3)
            $posts[0].Body['serialNumber'] | Should -BeExactly $script:First.Serial
            $posts[0].Body['hardwareIdentifier'] | Should -BeExactly $script:First.Hash
            $posts[0].Body['groupTag'] | Should -BeExactly 'North'
            $posts[0].Body.ContainsKey('assignedUserPrincipalName') | Should -BeFalse
            $posts[1].Body['assignedUserPrincipalName'] | Should -BeExactly $script:Second.User
            $posts[1].Body.ContainsKey('groupTag') | Should -BeFalse
        }

        It 'registers a serial number listed twice once, with its last reading, and says so' {
            $newHash = Get-TestHash
            $file = Write-DeviceCsv -Device $script:First, $script:Second, ([pscustomobject]@{ Serial = $script:First.Serial; Hash = $newHash; Tag = ''; User = '' })

            $run = Invoke-Main -Argument @{ CsvPath = $file }

            $posts = @($script:Requests | Where-Object { $_.Method -eq 'POST' })
            @($posts | ForEach-Object { $_.Body['serialNumber'] }) | Should -Be @($script:First.Serial, $script:Second.Serial)
            $posts[0].Body['hardwareIdentifier'] | Should -BeExactly $newHash
            $run.Warnings | Should -Contain 'Collapsed 1 duplicate serial number(s); the last occurrence of each was kept.'
        }

        It 'applies -GroupTag to every device, over the CSV' {
            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv; GroupTag = 'Kiosk' }

            @($script:Requests | Where-Object { $_.Method -eq 'POST' } | ForEach-Object { $_.Body['groupTag'] }) | Should -Be @('Kiosk', 'Kiosk')
            @($run.Rows | ForEach-Object { $_.GroupTag }) | Should -Be @('Kiosk', 'Kiosk')
        }

        It 'refuses an empty -GroupTag before signing in' {
            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv; GroupTag = '' }

            $run.Failure | Should -BeLike "*parameter 'GroupTag'*"
            $script:SignIns | Should -HaveCount 0
        }
    }

    Context 'waiting and reporting' {

        It 'returns a complete record for each device, and exits 0, when every import completes' {
            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv }

            $run.ExitCode | Should -Be 0
            $run.Errors | Should -HaveCount 0
            @($run.Rows[0].PSObject.Properties | ForEach-Object { $_.Name }) |
                Should -Be @('SerialNumber', 'GroupTag', 'AssignedUser', 'Status', 'ErrorCode', 'ErrorName', 'Advice', 'RegistrationId')
            @($run.Rows | ForEach-Object { $_.Status }) | Should -Be @('complete', 'complete')
            $run.Rows[0].RegistrationId | Should -Be (Get-Outcome -Serial $script:First.Serial).RegistrationId
            $run.Rows[0].Advice | Should -BeExactly ''
        }

        It 'checks every -PollIntervalSeconds while the service reports the status ''<Status>'', then returns the final state' -ForEach @(
            @{ Status = 'unknown' }
            @{ Status = 'pending' }
            @{ Status = 'Pending' }
            @{ Status = '' }
        ) {
            Add-Outcome -Serial $script:First.Serial -PendingChecks 2 -PendingStatus $Status

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv; PollIntervalSeconds = 20 }

            $run.ExitCode | Should -Be 0
            Get-StatusCheck -Serial $script:First.Serial | Should -HaveCount 3
            Get-StatusCheck -Serial $script:Second.Serial | Should -HaveCount 1
            Should -Invoke Start-Sleep -Times 3 -Exactly -ParameterFilter { $Seconds -eq 20 }
            (Get-Row -Run $run -Serial $script:First.Serial).Status | Should -Be 'complete'
        }

        It 'keeps checking a device whose status could not be read, and warns' {
            Add-Outcome -Serial $script:First.Serial -FailedChecks 1

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv }

            $run.Warnings | Should -Be @("Could not read the import state for $($script:First.Serial): HTTP 503 from Graph after 1 attempt(s): ServiceUnavailable")
            (Get-Row -Run $run -Serial $script:First.Serial).Status | Should -Be 'complete'
            $run.ExitCode | Should -Be 0
        }

        It 'reports a device still pending after -TimeoutMinutes as timedOut, and does not fail for it' {
            Add-Outcome -Serial $script:First.Serial -PendingChecks 1000

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv; TimeoutMinutes = 1; PollIntervalSeconds = 15 }

            $run.ExitCode | Should -Be 0
            Should -Invoke Start-Sleep -Times 4 -Exactly
            $row = Get-Row -Run $run -Serial $script:First.Serial
            $row.Status | Should -Be 'timedOut'
            $row.Advice | Should -BeExactly 'Still pending after 1 minute(s). The service usually finishes regardless; check the Autopilot devices list in Intune.'
            (Get-Row -Run $run -Serial $script:Second.Serial).Status | Should -Be 'complete'
        }

        It 'reports a device already registered as a skip, not a failure, and exits 0' {
            Add-Outcome -Serial $script:First.Serial -Status 'error' -ErrorName 'ZtdDeviceAlreadyAssigned' -ErrorCode 806

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv }

            $run.ExitCode | Should -Be 0
            $run.Errors | Should -HaveCount 0
            $row = Get-Row -Run $run -Serial $script:First.Serial
            $row.Status | Should -Be 'error'
            $row.ErrorCode | Should -Be 806
            $row.ErrorName | Should -Be 'ZtdDeviceAlreadyAssigned'
            $row.Advice | Should -BeLike 'Already registered to Autopilot*'
        }

        It 'returns every record, then exits 1, when a device ends in the state <Status>' -ForEach @(
            @{ Status = 'error'; ErrorName = 'ZtdDeviceNotFound'; Advice = 'The service could not match the hardware hash*' }
            @{ Status = 'partial'; ErrorName = ''; Advice = '' }
        ) {
            Add-Outcome -Serial $script:Second.Serial -Status $Status -ErrorName $ErrorName

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv }

            $run.ExitCode | Should -Be 1
            $run.Rows | Should -HaveCount 2
            $run.Errors | Should -Be @('1 device(s) failed to import. Inspect the Status, ErrorName and Advice of the returned objects.')
            (Get-Row -Run $run -Serial $script:Second.Serial).Advice | Should -BeLike $Advice
        }

        It 'records a device it could not submit as submitFailed, goes on with the next, and exits 1' {
            Add-Outcome -Serial $script:First.Serial -SubmitFailure (Get-GraphFailure -StatusCode 400 -Message 'BadRequest')

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv }

            $run.ExitCode | Should -Be 1
            $run.Warnings | Should -Contain "Could not submit $($script:First.Serial): HTTP 400 from Graph after 1 attempt(s): BadRequest"
            $row = Get-Row -Run $run -Serial $script:First.Serial
            $row.Status | Should -Be 'submitFailed'
            $row.Advice | Should -BeExactly 'HTTP 400 from Graph after 1 attempt(s): BadRequest'
            (Get-Row -Run $run -Serial $script:Second.Serial).Status | Should -Be 'complete'
            Get-StatusCheck -Serial $script:First.Serial | Should -HaveCount 0
        }

        It 'records an import the service accepted without an id as submitFailed, since it cannot be followed' {
            Add-Outcome -Serial $script:First.Serial -NoId

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv }

            $run.ExitCode | Should -Be 1
            (Get-Row -Run $run -Serial $script:First.Serial).Advice |
                Should -BeExactly 'Graph accepted the request but returned no import id, so the outcome cannot be tracked.'
        }

        It 'writes the records to -ReportPath as well as returning them' {
            $folder = Get-TestFolder

            $run = Invoke-Main -Argument @{ CsvPath = $script:Csv; ReportPath = $folder }

            $files = @(Get-ChildItem -LiteralPath $folder -File)
            $files | Should -HaveCount 1
            $files[0].Name | Should -Match '^AutopilotImport-\d{8}-\d{6}\.csv$'
            @(Import-Csv -LiteralPath $files[0].FullName | ForEach-Object { $_.SerialNumber }) | Should -Be @($script:First.Serial, $script:Second.Serial)
            $run.Rows | Should -HaveCount 2
        }
    }

    Context 'a CSV written by the collector' {

        It 'registers each device of a file the collector appended to once, with its latest reading' {
            $again = [pscustomobject]@{ Serial = $script:First.Serial; Hash = (Get-TestHash); Tag = 'North'; User = '' }
            $file = Write-CollectorCsv -Device $script:First, $script:Second, $again

            $run = Invoke-Main -Argument @{ CsvPath = $file }

            $run.ExitCode | Should -Be 0
            $run.Warnings | Should -HaveCount 0
            $posts = @($script:Requests | Where-Object { $_.Method -eq 'POST' })
            @($posts | ForEach-Object { $_.Body['serialNumber'] }) | Should -Be @($script:Second.Serial, $script:First.Serial)
            $posts[1].Body['hardwareIdentifier'] | Should -BeExactly $again.Hash
            $posts[1].Body['groupTag'] | Should -BeExactly 'North'
            $posts[0].Body['assignedUserPrincipalName'] | Should -BeExactly $script:Second.User
        }
    }
}

Describe 'The script, run as a file' {

    BeforeAll {
        $script:ValidCsv = Write-DeviceCsv -Device (Get-TestDevice)

        function Invoke-ScriptFile {
            # Starts the script with -File in a child process of the
            # PowerShell running the tests, so that its exit ends that process
            # and not the test run. Returns the exit code, and STDOUT and
            # STDERR as one text without white space, because the host wraps
            # long errors, and without terminal escape sequences, because
            # PowerShell 7 may colour the labels of a list, as it does in CI.
            # Every case here ends before the script signs in; the timeout is
            # there in case one does not.
            param ([string[]]$Argument)

            $quoted = foreach ($item in @('-NoProfile', '-NonInteractive', '-File', $script:ScriptPath) + $Argument) {
                if ($item -notmatch '[\s"]') { $item; continue }
                # A backslash before the closing quote would escape it.
                '"' + (($item -replace '"', '\"') -replace '(\\+)$', '$1$1') + '"'
            }

            $info = New-Object -TypeName System.Diagnostics.ProcessStartInfo
            $info.FileName = (Get-Process -Id $PID).Path
            $info.Arguments = $quoted -join ' '
            $info.UseShellExecute = $false
            $info.CreateNoWindow = $true
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true

            $process = [System.Diagnostics.Process]::Start($info)
            $outputTask = $process.StandardOutput.ReadToEndAsync()
            $errorTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(120000)) {
                $process.Kill()
                throw 'The script did not finish within 120 seconds.'
            }
            $process.WaitForExit()

            $escapeSequence = "$([char]27)\[[0-9;?]*[A-Za-z]"
            [pscustomobject]@{
                ExitCode = $process.ExitCode
                Text     = (($outputTask.Result + $errorTask.Result) -replace $escapeSequence, '') -replace '\s', ''
            }
        }
    }

    # PowerShell refuses these before the script's first line, so they need
    # no module: the error names the parameter and is not the script's own.
    It 'does not start with <Case>' -ForEach @(
        @{ Case = 'a -CsvPath that does not exist'; Argument = @('-CsvPath', '<missing>'); Named = 'CsvPath' }
        @{ Case = 'a -TenantId that is neither an ID nor a domain'; Argument = @('-TenantId', 'not_a_tenant'); Named = 'TenantId' }
        @{ Case = '-TimeoutMinutes 0'; Argument = @('-TimeoutMinutes', '0'); Named = 'TimeoutMinutes' }
        @{ Case = '-PollIntervalSeconds 4'; Argument = @('-PollIntervalSeconds', '4'); Named = 'PollIntervalSeconds' }
        @{ Case = '-MaximumRetryCount 11'; Argument = @('-MaximumRetryCount', '11'); Named = 'MaximumRetryCount' }
        @{ Case = 'a -ReportPath that does not exist'; Argument = @('-ReportPath', '<missing>'); Named = 'ReportPath' }
    ) {
        $missing = Join-Path -Path $TestDrive -ChildPath 'NoSuchFolder'
        $arguments = @($Argument | ForEach-Object { $_ -replace '^<missing>$', $missing })
        if ($Named -ne 'CsvPath') { $arguments = @('-CsvPath', $script:ValidCsv) + $arguments }

        $run = Invoke-ScriptFile -Argument $arguments

        $run.ExitCode | Should -Be 1
        $run.Text | Should -BeLike "*'$Named'*"
        $run.Text | Should -Not -BeLike '*Scriptfailed*'
        $run.Text | Should -Not -BeLike '*couldnotbeloaded*'
    }

    It 'does not start without -CsvPath, and does not wait for one' {
        $run = Invoke-ScriptFile -Argument @()

        $run.ExitCode | Should -Be 1
        $run.Text | Should -BeLike '*missingmandatoryparameters:CsvPath*'
    }

    Context 'past the module check' -Skip:(-not $script:ModuleAvailable) {

        It 'exits 1 and gives the reason, not an error of its own, when the CSV holds no rows' {
            $file = Write-TestCsv -Line $script:Header

            $run = Invoke-ScriptFile -Argument '-CsvPath', $file

            $run.ExitCode | Should -Be 1
            $run.Text | Should -BeLike "*Scriptfailed:'$($file -replace '\s', '')'containsnorows.*"
        }

        It 'exits 1 after a warning for each row when no row can be imported' {
            $file = Write-TestCsv -Line $script:Header, ",,$(Get-TestHash)", "$(Get-TestSerial),,"

            $run = Invoke-ScriptFile -Argument '-CsvPath', $file

            $run.ExitCode | Should -Be 1
            $run.Text | Should -BeLike "*Line2:no'DeviceSerialNumber'.*"
            $run.Text | Should -BeLike '*Scriptfailed:Noimportabledevicefoundin*2row(s)wereunusable*'
        }

        It 'exits 0 under -WhatIf, says in one What-if line what it would register, and returns each device as notSubmitted' {
            $file = Write-DeviceCsv -Device (Get-TestDevice), (Get-TestDevice)

            $run = Invoke-ScriptFile -Argument '-CsvPath', $file, '-WhatIf'

            $run.ExitCode | Should -Be 0
            $run.Text | Should -BeLike "*Whatif:Performingtheoperation`"RegisterwithWindowsAutopilot`"ontarget`"2device(s)from'devices.csv'`".*"
            # Its own, and none from the Graph module loading under -WhatIf.
            [regex]::Matches($run.Text, 'Whatif:').Count | Should -Be 1 -Because $run.Text
            [regex]::Matches($run.Text, 'Status:notSubmitted').Count | Should -Be 2 -Because $run.Text
        }
    }
}
