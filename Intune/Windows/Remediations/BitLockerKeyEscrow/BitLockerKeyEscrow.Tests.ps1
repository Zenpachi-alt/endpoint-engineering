# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for the BitLockerKeyEscrow package: how the join state and
    protector IDs are read, how evidence of escrow is judged, and the exit
    code and output line of both scripts in every situation they handle.

.DESCRIPTION
    Shared region: the BitLockerKeyEscrow region must be identical in both
    scripts.

    Pure functions: ConvertFrom-DsregcmdStatus, ConvertTo-ProtectorKey and
    Get-EscrowFinding read no state and are tested directly. Runs anywhere.

    Detection and remediation: each script runs as the Intune management
    extension runs it, in Windows PowerShell 5.1 with -File, with the parts
    that touch the device replaced by stand-ins: the elevation check, the
    join state, the volumes and their protector IDs, the BitLocker Management
    log, the registry record, and the backup itself. The backup stand-in
    writes the event 845 or 846 a device would, so the remediation's
    confirmation logic runs as written. Nothing reaches Entra ID and nothing
    on the device changes. Windows only.

    Protector IDs are generated at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Intune\Windows\Remediations\BitLockerKeyEscrow -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. The scripts under test always run in Windows
                    PowerShell 5.1, whichever host runs Pester.
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
    $script:DetectionPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-BitLockerKeyEscrow.ps1'
    $script:RemediationPath = Join-Path -Path $PSScriptRoot -ChildPath 'Repair-BitLockerKeyEscrow.ps1'

    function Get-SharedRegion {
        # The lines from '#region <Name>' to '#endregion <Name>', or $null
        # unless the file holds exactly one such block.
        param ([string]$Path, [string]$Name)

        $lines = @((Get-Content -LiteralPath $Path -Raw) -split '\r?\n')
        $escaped = [regex]::Escape($Name)
        $starts = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -cmatch "^\s*#region $escaped\b") { $i } })
        $ends = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -cmatch "^\s*#endregion $escaped\s*$") { $i } })

        if ($starts.Count -ne 1 -or $ends.Count -ne 1 -or $ends[0] -le $starts[0]) { return $null }

        , $lines[$starts[0]..$ends[0]]
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

    function Get-TestId {
        # A protector ID in the form the scripts use: upper case, no braces.
        [guid]::NewGuid().ToString('D').ToUpperInvariant()
    }

    function Get-TestVolume {
        param (
            [string]$MountPoint = 'C:',
            [ValidateSet('OperatingSystem', 'FixedData')][string]$VolumeType = 'OperatingSystem',
            [string[]]$ProtectorId = @()
        )

        [pscustomobject]@{ MountPoint = $MountPoint; VolumeType = $VolumeType; ProtectorIds = @($ProtectorId) }
    }

    function Get-TestEvent {
        # An event as Get-EscrowEvent returns it: 845 names a protector, 846 an error.
        param (
            [ValidateSet(845, 846)][int]$Id = 845,
            [string]$ProtectorId,
            [string]$MountPoint = 'C:',
            [double]$DaysAgo = 3,
            [string]$ErrorCode
        )

        @{
            Id             = $Id
            TimeCreatedUtc = [datetime]::UtcNow.AddDays(-$DaysAgo)
            MountPoint     = $MountPoint
            ProtectorId    = if ($Id -eq 845) { $ProtectorId } else { $null }
            ErrorCode      = if ($Id -eq 846) { $ErrorCode } else { $null }
        }
    }

    function Get-FakeDevice {
        # An elevated, Entra joined device, described by the arguments.
        # -Escrow says what a backup of each protector does: Confirmed writes
        # event 845, Refused event 846, Silent nothing, Throws fails the call.
        param (
            [object[]]$Volume = @(),
            [object[]]$EscrowEvent = @(),
            [hashtable]$Registry = @{},
            [hashtable]$Escrow = @{},
            [hashtable]$Result = @{},
            [switch]$RegistryUnreadable,
            [switch]$RegistryUnwritable
        )

        $results = @{
            'Test-IsElevated'    = $true
            'Get-EntraJoinState' = [pscustomobject]@{ AzureAdJoined = $true; DomainJoined = $false }
        }
        foreach ($key in $Result.Keys) { $results[$key] = $Result[$key] }

        @{
            Results            = $results
            Volumes            = @($Volume)
            Events             = @($EscrowEvent)
            Registry           = $Registry
            Escrow             = $Escrow
            RegistryUnreadable = $RegistryUnreadable.IsPresent
            RegistryUnwritable = $RegistryUnwritable.IsPresent
        }
    }

    $script:Stubs = [ordered]@{
        'Test-IsElevated'       = $null
        'Get-EntraJoinState'    = $null
        'Get-EscrowVolume'      = {
            if ($Fake.Results.ContainsKey('Get-EscrowVolume')) { Get-FakeResult -Name 'Get-EscrowVolume' }
            foreach ($item in @($Fake.Volumes)) { $item }
        }
        'Get-EscrowEvent'       = {
            foreach ($item in @($Fake.Events)) {
                if ($Since -eq [datetime]::MinValue -or $item.TimeCreatedUtc -ge $Since.ToUniversalTime()) { [pscustomobject]$item }
            }
        }
        'Get-RecordedEvidence'  = {
            if ($Fake.RegistryUnreadable) { throw 'Requested registry access is not allowed.' }
            $copy = @{}
            foreach ($key in @($Fake.Registry.Keys)) { $copy[$key] = $Fake.Registry[$key] }
            return $copy
        }
        'Set-RecordedEvidence'  = {
            if ($Fake.RegistryUnwritable) { throw 'Access to the registry key is denied.' }
            if ($Value) { $Fake.Registry[$ProtectorId] = $Value } else { $Fake.Registry.Remove($ProtectorId) }
        }
    }

    $script:StubbedDetection = ConvertTo-StubbedScript -Path $script:DetectionPath -Stub $script:Stubs `
        -Destination (Join-Path -Path $TestDrive -ChildPath 'Test-BitLockerKeyEscrow.ps1')

    $remediationStubs = [ordered]@{
        'Invoke-KeyEscrow' = {
            switch ([string]$Fake.Escrow[$ProtectorId]) {
                'Confirmed' {
                    $Fake.Events = @($Fake.Events) + @{ Id = 845; TimeCreatedUtc = [datetime]::UtcNow; MountPoint = $MountPoint; ProtectorId = $ProtectorId; ErrorCode = $null }
                }
                'Refused' {
                    $Fake.Events = @($Fake.Events) + @{ Id = 846; TimeCreatedUtc = [datetime]::UtcNow; MountPoint = $MountPoint; ProtectorId = $null; ErrorCode = '0x80072EE7' }
                }
                'Silent' { }
                'Throws' { throw 'The stand-in failed.' }
                default { throw "The test gave no escrow outcome for $ProtectorId." }
            }
        }
    }
    foreach ($key in $script:Stubs.Keys) { $remediationStubs[$key] = $script:Stubs[$key] }
    $script:StubbedRemediation = ConvertTo-StubbedScript -Path $script:RemediationPath -Stub $remediationStubs `
        -Destination (Join-Path -Path $TestDrive -ChildPath 'Repair-BitLockerKeyEscrow.ps1')

    $script:LogArguments = @('-LogDirectory', (Join-Path -Path $TestDrive -ChildPath 'Logs'))
    # 0: check for the confirming event once, so a missing one fails at once.
    $script:RepairArguments = $script:LogArguments + @('-ConfirmationTimeoutSeconds', '0')
}

Describe 'The BitLockerKeyEscrow region' {

    It 'is identical in the detection and the remediation script' {
        $detection = Get-SharedRegion -Path $script:DetectionPath -Name 'BitLockerKeyEscrow'
        $remediation = Get-SharedRegion -Path $script:RemediationPath -Name 'BitLockerKeyEscrow'

        $detection | Should -Not -BeNullOrEmpty
        $remediation | Should -Not -BeNullOrEmpty

        $length = [Math]::Max($detection.Count, $remediation.Count)
        for ($i = 0; $i -lt $length; $i++) {
            $expected = if ($i -lt $detection.Count) { $detection[$i] } else { '<end of region>' }
            $actual = if ($i -lt $remediation.Count) { $remediation[$i] } else { '<end of region>' }

            if ($actual -cne $expected) {
                throw ("Repair-BitLockerKeyEscrow.ps1 differs from Test-BitLockerKeyEscrow.ps1 at line {0} of the BitLockerKeyEscrow region.`n" +
                    "  Test-:   {1}`n  Repair-: {2}`nChange the region in both scripts, and raise its version.") -f ($i + 1), $expected, $actual
            }
        }
    }
}

Describe 'Functions that read no state' {

    BeforeAll {
        . ([scriptblock]::Create(((Get-SharedRegion -Path $script:DetectionPath -Name 'BitLockerKeyEscrow') -join [Environment]::NewLine)))

        $script:DeviceState = @'
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : {0}
          EnterpriseJoined : NO
              DomainJoined : {1}
                DomainName : CONTOSO
           Virtual Desktop : NOT SET
               Device Name : DESKTOP-EXAMPLE
'@
    }

    Context 'ConvertFrom-DsregcmdStatus' {

        It 'reads <Case>' -ForEach @(
            @{ Case = 'an Entra joined device'; Entra = 'YES'; Domain = 'NO' }
            @{ Case = 'a hybrid joined device'; Entra = 'YES'; Domain = 'YES' }
            @{ Case = 'a domain joined device'; Entra = 'NO'; Domain = 'YES' }
            @{ Case = 'a device joined to neither'; Entra = 'NO'; Domain = 'NO' }
        ) {
            $state = ConvertFrom-DsregcmdStatus -Text ($script:DeviceState -f $Entra, $Domain)

            $state.AzureAdJoined | Should -Be ($Entra -eq 'YES')
            $state.DomainJoined | Should -Be ($Domain -eq 'YES')
        }

        It 'throws, rather than answering "not joined", for output it cannot read: <Case>' -ForEach @(
            @{ Case = 'no output'; Text = '' }
            @{ Case = 'an error message'; Text = 'The request is not supported.' }
            @{ Case = 'a value that is not YES or NO'; Text = "AzureAdJoined : JA`r`nDomainJoined : NEIN" }
        ) {
            { ConvertFrom-DsregcmdStatus -Text $Text } | Should -Throw
        }
    }

    Context 'ConvertTo-ProtectorKey' {

        It 'returns the GUID in upper case without braces, from <Case>' -ForEach @(
            @{ Case = 'the form the cmdlets use'; Wrap = '{{{0}}}'; Lower = $false }
            @{ Case = 'the form Entra ID shows'; Wrap = '{0}'; Lower = $true }
            @{ Case = 'the form with spaces around it'; Wrap = '  {0} '; Lower = $false }
        ) {
            $id = [guid]::NewGuid().ToString('D')
            $text = $Wrap -f $(if ($Lower) { $id.ToLowerInvariant() } else { $id.ToUpperInvariant() })

            ConvertTo-ProtectorKey -Id $text | Should -BeExactly $id.ToUpperInvariant()
        }

        It 'refuses a value that is not a GUID' {
            { ConvertTo-ProtectorKey -Id 'C:' } | Should -Throw
        }
    }

    Context 'ConvertFrom-EscrowEventXml' {

        BeforeAll {
            # Shaped as EventLogRecord.ToXml() writes an event, with the data
            # fields the provider's manifest defines for 845 and 846.
            function Get-EventXml {
                param ([int]$Id, [string]$Data)

                "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
                "<Provider Name='Microsoft-Windows-BitLocker-API'/><EventID>$Id</EventID><Version>0</Version><Level>4</Level>" +
                "<TimeCreated SystemTime='2026-09-20T10:00:00.0000000Z'/><Channel>Microsoft-Windows-BitLocker/BitLocker Management</Channel>" +
                "</System><EventData>$Data</EventData></Event>"
            }
        }

        It 'reads the volume and the protector from event 845' {
            $id = [guid]::NewGuid().ToString('D')
            $trace = [guid]::NewGuid().ToString('D')
            $xml = Get-EventXml -Id 845 -Data ("<Data Name='VolumeMountPoint'>C:</Data><Data Name='ProtectorGUID'>{{{0}}}</Data><Data Name='TraceGUID'>{{{1}}}</Data>" -f $id, $trace)

            $data = ConvertFrom-EscrowEventXml -Xml $xml

            $data.MountPoint | Should -Be 'C:'
            $data.ProtectorId | Should -BeExactly $id.ToUpperInvariant()
            $data.ErrorCode | Should -BeNullOrEmpty
        }

        It 'reads the error of event 846 written as <Case>' -ForEach @(
            @{ Case = 'a signed decimal'; Raw = '-2147012889' }
            @{ Case = 'lower-case hex'; Raw = '0x80072ee7' }
        ) {
            $trace = [guid]::NewGuid().ToString('D')
            $xml = Get-EventXml -Id 846 -Data ("<Data Name='VolumeMountPoint'>D:</Data><Data Name='TraceGUID'>{{{0}}}</Data><Data Name='ErrorCode'>{1}</Data>" -f $trace, $Raw)

            $data = ConvertFrom-EscrowEventXml -Xml $xml

            $data.MountPoint | Should -Be 'D:'
            $data.ProtectorId | Should -BeNullOrEmpty
            $data.ErrorCode | Should -BeExactly '0x80072EE7'
        }

        It 'fails on a protector field that is not a GUID, rather than counting it' {
            $xml = Get-EventXml -Id 845 -Data "<Data Name='VolumeMountPoint'>C:</Data><Data Name='ProtectorGUID'>not a guid</Data>"

            { ConvertFrom-EscrowEventXml -Xml $xml } | Should -Throw
        }
    }

    Context 'Get-EscrowFinding' {

        BeforeAll {
            $script:A = Get-TestId
            $script:B = Get-TestId
            $script:C = Get-TestId
        }

        It 'reports NotEncrypted, exit 0, when no volume is encrypted' {
            $finding = Get-EscrowFinding -Volume @() -EscrowedId @()

            $finding.Token | Should -Be 'NotEncrypted'
            $finding.ExitCode | Should -Be 0
            $finding.Line | Should -Be 'NotEncrypted: no OS or fixed data volume is encrypted with BitLocker.'
        }

        It 'reports Escrowed, exit 0, when every recovery password has evidence' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData -ProtectorId $script:B))

            $finding = Get-EscrowFinding -Volume $volumes -EscrowedId @($script:A, $script:B)

            $finding.Token | Should -Be 'Escrowed'
            $finding.ExitCode | Should -Be 0
            $finding.Line | Should -Be "Escrowed: C: escrowed {$($script:A)}; D: escrowed {$($script:B)}."
            $finding.Missing | Should -BeNullOrEmpty
        }

        It 'reports NoEscrowEvidence, exit 1, and names what is missing, even when other volumes are fine' {
            $volumes = @((Get-TestVolume -ProtectorId @($script:A, $script:C)), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData -ProtectorId $script:B))

            $finding = Get-EscrowFinding -Volume $volumes -EscrowedId @($script:A, $script:B)

            $finding.Token | Should -Be 'NoEscrowEvidence'
            $finding.ExitCode | Should -Be 1
            $finding.Line | Should -Be "NoEscrowEvidence: C: escrowed {$($script:A)}, no escrow evidence for {$($script:C)}; D: escrowed {$($script:B)}."
            @($finding.Missing) | Should -HaveCount 1
            $finding.Missing[0].MountPoint | Should -Be 'C:'
            $finding.Missing[0].ProtectorId | Should -Be $script:C
        }

        It 'reports NoRecoveryPassword, exit 0, for a volume with nothing to escrow' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData))

            $finding = Get-EscrowFinding -Volume $volumes -EscrowedId @($script:A)

            $finding.Token | Should -Be 'NoRecoveryPassword'
            $finding.ExitCode | Should -Be 0
            $finding.Line | Should -Be "NoRecoveryPassword: C: escrowed {$($script:A)}; D: no recovery password."
        }

        It 'puts a missing backup before a missing recovery password' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData))

            $finding = Get-EscrowFinding -Volume $volumes -EscrowedId @()

            $finding.Token | Should -Be 'NoEscrowEvidence'
            $finding.ExitCode | Should -Be 1
        }
    }
}

Describe 'Test-BitLockerKeyEscrow.ps1' -Skip:(-not $script:OnWindows) {

    BeforeEach {
        $script:A = Get-TestId
        $script:B = Get-TestId
    }

    Context 'exit code' {

        It 'exits 0 with Escrowed when event 845 names the protector, and records it' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -EscrowEvent (Get-TestEvent -ProtectorId $script:A)

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Escrowed: C: escrowed {$($script:A)}.")
            $run.Fake.Registry.ContainsKey($script:A) | Should -BeTrue
        }

        It 'exits 1 with NoEscrowEvidence when no event names the protector' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -EscrowEvent (Get-TestEvent -ProtectorId $script:B)

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("NoEscrowEvidence: C: no escrow evidence for {$($script:A)}.")
        }

        It 'exits 0 when the event has rolled off the log but the backup was recorded' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Registry @{ $script:A = '2026-01-01T00:00:00.0000000Z' }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Escrowed: C: escrowed {$($script:A)}.")
        }

        It 'does not count event 846, a failed backup, as evidence' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -EscrowEvent (Get-TestEvent -Id 846 -ErrorCode '0x80072EE7')

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
        }

        It 'exits 1 for a fixed data volume without evidence, although the OS volume has it' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData -ProtectorId $script:B))
            $device = Get-FakeDevice -Volume $volumes -EscrowEvent (Get-TestEvent -ProtectorId $script:A)

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("NoEscrowEvidence: C: escrowed {$($script:A)}; D: no escrow evidence for {$($script:B)}.")
        }

        It 'exits 0 with NoRecoveryPassword for a volume that has nothing to escrow' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData))
            $device = Get-FakeDevice -Volume $volumes -EscrowEvent (Get-TestEvent -ProtectorId $script:A)

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("NoRecoveryPassword: C: escrowed {$($script:A)}; D: no recovery password.")
        }

        It 'exits 0 with NotEncrypted when no volume is encrypted' {
            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake (Get-FakeDevice)

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @('NotEncrypted: no OS or fixed data volume is encrypted with BitLocker.')
        }

        It 'exits 0 with NotApplicable, without reading the volumes, on a device not joined to Entra ID' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) `
                -Result @{ 'Get-EntraJoinState' = [pscustomobject]@{ AzureAdJoined = $false; DomainJoined = $true } }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @('NotApplicable: the device is not joined to Microsoft Entra ID, so no key can be backed up there.')
            Get-FakeCall -Run $run -Name 'Get-EscrowVolume' | Should -BeNullOrEmpty
        }

        It 'checks a hybrid joined device like an Entra joined one' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) `
                -Result @{ 'Get-EntraJoinState' = [pscustomobject]@{ AzureAdJoined = $true; DomainJoined = $true } }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
        }

        It 'exits 2 without reading anything when it has no administrator rights' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Result @{ 'Test-IsElevated' = $false }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2 -Because $run.Error
            $run.Output | Should -Be @('Detection failed: administrator rights are required.')
            Get-FakeCall -Run $run -Name 'Get-EscrowVolume' | Should -BeNullOrEmpty
        }

        It 'exits 2, never 1, when <Function> throws' -ForEach @(
            @{ Function = 'Get-EntraJoinState' }
            @{ Function = 'Get-EscrowVolume' }
        ) {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Result @{ $Function = @{ Throw = 'The stand-in failed.' } }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2
            $run.Output | Should -BeNullOrEmpty
            $run.Error | Should -Match 'Detection failed: The stand-in failed\.'
        }

        It 'exits 2, never 1, when the record cannot be read' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -RegistryUnreadable

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2
        }
    }

    Context 'the record of backups' {

        It 'forgets protectors the device no longer has, and keeps the others' {
            $gone = Get-TestId
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) `
                -Registry @{ $script:A = '2026-01-01T00:00:00.0000000Z'; $gone = '2025-01-01T00:00:00.0000000Z' }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Fake.Registry.ContainsKey($gone) | Should -BeFalse
            $run.Fake.Registry[$script:A] | Should -Be '2026-01-01T00:00:00.0000000Z'
        }

        It 'still decides when the record cannot be written' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -EscrowEvent (Get-TestEvent -ProtectorId $script:A) -RegistryUnwritable

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Escrowed: C: escrowed {$($script:A)}.")
        }
    }
}

Describe 'Repair-BitLockerKeyEscrow.ps1' -Skip:(-not $script:OnWindows) {

    BeforeEach {
        $script:A = Get-TestId
        $script:B = Get-TestId
    }

    Context 'exit code' {

        It 'exits 0 once event 845 confirms the backup, and records it' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Confirmed' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Escrowed: C: {$($script:A)}.")
            $call = @(Get-FakeCall -Run $run -Name 'Invoke-KeyEscrow')
            $call | Should -HaveCount 1
            $call[0].Parameters.MountPoint | Should -Be 'C:'
            $call[0].Parameters.ProtectorId | Should -Be $script:A
            $run.Fake.Registry.ContainsKey($script:A) | Should -BeTrue
        }

        It 'backs up only the protectors without evidence' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData -ProtectorId $script:B))
            $device = Get-FakeDevice -Volume $volumes -EscrowEvent (Get-TestEvent -ProtectorId $script:A) -Escrow @{ $script:B = 'Confirmed' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Escrowed: D: {$($script:B)}.")
            @(Get-FakeCall -Run $run -Name 'Invoke-KeyEscrow' | ForEach-Object { $_.Parameters.ProtectorId }) | Should -Be @($script:B)
        }

        It 'exits 1 with the error code when event 846 refuses the backup' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Refused' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Remediation failed: C: {$($script:A)}: event 846 reports error 0x80072EE7.")
            $run.Fake.Registry.ContainsKey($script:A) | Should -BeFalse
        }

        It 'exits 1 when no event confirms the backup in time' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Silent' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Remediation failed: C: {$($script:A)}: no event 845 confirmed the backup within 0 seconds.")
        }

        It 'exits 1 when the backup call fails' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Throws' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Remediation failed: C: {$($script:A)}: The stand-in failed.")
        }

        It 'exits 1 when one backup fails, and still records the one that succeeded' {
            $volumes = @((Get-TestVolume -ProtectorId $script:A), (Get-TestVolume -MountPoint 'D:' -VolumeType FixedData -ProtectorId $script:B))
            $device = Get-FakeDevice -Volume $volumes -Escrow @{ $script:A = 'Confirmed'; $script:B = 'Refused' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Remediation failed: D: {$($script:B)}: event 846 reports error 0x80072EE7. Escrowed: C: {$($script:A)}.")
            $run.Fake.Registry.ContainsKey($script:A) | Should -BeTrue
        }

        It 'ignores a failure logged before the attempt started' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) `
                -EscrowEvent (Get-TestEvent -Id 846 -ErrorCode '0x80072EE7' -DaysAgo 1) -Escrow @{ $script:A = 'Confirmed' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
        }

        It 'exits 0 without a backup when every protector already has evidence' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Registry @{ $script:A = '2026-01-01T00:00:00.0000000Z' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @('Nothing to escrow: every recovery password already has evidence of escrow.')
            Get-FakeCall -Run $run -Name 'Invoke-KeyEscrow' | Should -BeNullOrEmpty
        }

        It 'exits 1 without a backup on a device not joined to Entra ID' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Confirmed' } `
                -Result @{ 'Get-EntraJoinState' = [pscustomobject]@{ AzureAdJoined = $false; DomainJoined = $false } }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Not repaired: the device is not joined to Microsoft Entra ID, so no key can be backed up there.')
            Get-FakeCall -Run $run -Name 'Invoke-KeyEscrow' | Should -BeNullOrEmpty
        }

        It 'exits 1 without a backup when it has no administrator rights' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Confirmed' } -Result @{ 'Test-IsElevated' = $false }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Remediation failed: administrator rights are required.')
            Get-FakeCall -Run $run -Name 'Invoke-KeyEscrow' | Should -BeNullOrEmpty
        }

        It 'exits 0 when the backup succeeded but the record cannot be written' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Confirmed' } -RegistryUnwritable

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:RepairArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
        }
    }

    Context '-WhatIf' {

        It 'sends nothing and records nothing' {
            $device = Get-FakeDevice -Volume (Get-TestVolume -ProtectorId $script:A) -Escrow @{ $script:A = 'Confirmed' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList ($script:RepairArguments + @('-WhatIf')) -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Contain 'No change made (WhatIf or declined confirmation).'
            Get-FakeCall -Run $run -Name 'Invoke-KeyEscrow' | Should -BeNullOrEmpty
            Get-FakeCall -Run $run -Name 'Set-RecordedEvidence' | Should -BeNullOrEmpty
        }
    }
}
