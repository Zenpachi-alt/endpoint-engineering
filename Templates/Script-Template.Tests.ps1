# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for the Graph helpers region of Script-Template.ps1, and the
    check that every copy of that region still matches it.

.DESCRIPTION
    Three parts.

    Copies: every script under Graph/, and any other script that carries the
    region, must hold a copy identical to the template's. This is what keeps
    one implementation across scripts that each run on their own. A failure
    names the file and the first line that differs.

    Behaviour: the helpers run against stand-ins for the Microsoft Graph SDK
    cmdlets, so retry, paging and scope checks are tested without the module
    or a tenant. Runs under Windows PowerShell 5.1 as well as PowerShell 7.

    Real SDK: when PowerShell 7 and Microsoft.Graph.Authentication are
    present, the helpers run in a child process against the real SDK and a
    stand-in for Graph on localhost that throttles and pages. This proves what
    the stand-ins cannot - that the SDK's own retry really is off during a
    request, and that no helper is shadowed by an alias the SDK exports. It is
    skipped when either is missing; CI installs the module, so it runs there.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Templates -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. The real-SDK tests need PowerShell 7 and are
                    skipped under 5.1.
    Graph scopes  : None. Nothing reaches a tenant: the real-SDK tests sign in
                    with a made-up token to a server on localhost.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Microsoft.Graph.Authentication 2.0.0 or later, optional,
                    for the real-SDK tests.
#>

BeforeDiscovery {
    $repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
    $templatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Script-Template.ps1'
    $graphRoot = (Join-Path -Path $repositoryRoot -ChildPath 'Graph') + [System.IO.Path]::DirectorySeparatorChar

    # Every script under Graph/ must carry the region, and a script elsewhere
    # that carries it must keep it current.
    $script:Copies = @(
        Get-ChildItem -Path $repositoryRoot -Filter '*.ps1' -Recurse -File |
            Where-Object { $_.FullName -ne $templatePath -and $_.Name -notlike '*.Tests.ps1' } |
            Where-Object {
                $_.FullName.StartsWith($graphRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
                (Get-Content -LiteralPath $_.FullName) -contains '#region Graph helpers'
            } |
            ForEach-Object {
                @{
                    Path = $_.FullName
                    Name = $_.FullName.Substring($repositoryRoot.Length + 1) -replace '\\', '/'
                }
            }
    )

    $script:SdkAvailable = $PSVersionTable.PSEdition -eq 'Core' -and
        [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
                Where-Object { $_.Version -ge [version]'2.0.0' })
}

BeforeAll {
    $script:TemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Script-Template.ps1'

    function Get-HelperRegion {
        # The lines from '#region Graph helpers' to '#endregion Graph helpers',
        # or $null unless the file holds exactly one such block.
        param ([string]$Path)

        $lines = @((Get-Content -LiteralPath $Path -Raw) -split '\r?\n')
        $starts = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -ceq '#region Graph helpers') { $i } })
        $ends = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -ceq '#endregion Graph helpers') { $i } })

        if ($starts.Count -ne 1 -or $ends.Count -ne 1 -or $ends[0] -le $starts[0]) { return $null }

        , $lines[$starts[0]..$ends[0]]
    }
}

Describe 'Copies of the Graph helpers' {

    BeforeAll {
        $script:MasterRegion = Get-HelperRegion -Path $script:TemplatePath
    }

    It 'the template holds exactly one Graph helpers region' {
        @($script:MasterRegion).Count | Should -BeGreaterThan 2
    }

    It '<Name> matches the template' -ForEach $script:Copies {
        $copy = Get-HelperRegion -Path $Path

        if ($null -eq $copy) {
            throw "$Name has no single '#region Graph helpers' ... '#endregion Graph helpers' block. Copy the region from Templates/Script-Template.ps1."
        }

        $length = [Math]::Max($copy.Count, $script:MasterRegion.Count)
        for ($i = 0; $i -lt $length; $i++) {
            $expected = if ($i -lt $script:MasterRegion.Count) { $script:MasterRegion[$i] } else { '<end of region>' }
            $actual = if ($i -lt $copy.Count) { $copy[$i] } else { '<end of region>' }

            if ($actual -cne $expected) {
                throw ("{0} differs from the template at line {1} of the region.`n  template: {2}`n  copy:     {3}`n" +
                    "Paste the region from Templates/Script-Template.ps1 over this copy.") -f $Name, ($i + 1), $expected, $actual
            }
        }
    }
}

Describe 'Graph helpers' {

    BeforeAll {
        Add-Type -AssemblyName System.Net.Http

        $script:Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
        $script:TenantA = [guid]::NewGuid().ToString()
        $script:TenantB = [guid]::NewGuid().ToString()

        $script:Responses = New-Object -TypeName 'System.Collections.Generic.Queue[object]'
        $script:Requests = New-Object -TypeName 'System.Collections.Generic.List[object]'
        $script:SignIns = New-Object -TypeName 'System.Collections.Generic.List[object]'
        $script:Sleeps = New-Object -TypeName 'System.Collections.Generic.List[int]'
        $script:Notices = New-Object -TypeName 'System.Collections.Generic.List[string]'

        # Stand-ins for the Microsoft.Graph.Authentication cmdlets the helpers
        # call. Each queued response is an exception to throw, or an object
        # carrying Status, Headers and Content.
        function Invoke-MgGraphRequest {
            [CmdletBinding()]
            param ($Method, $Uri, $Body, $OutputType, $StatusCodeVariable, $ResponseHeadersVariable, [switch]$SkipHttpErrorCheck)

            $script:Requests.Add([pscustomobject]@{
                    Method             = $Method
                    Uri                = $Uri
                    Body               = $Body
                    OutputType         = $OutputType
                    SkipHttpErrorCheck = $SkipHttpErrorCheck.IsPresent
                    SdkMaxRetry        = $script:SdkMaxRetry
                })

            $next = $script:Responses.Dequeue()
            if ($next -is [System.Exception]) { throw $next }

            # The real cmdlet sets these in its caller's scope, and ignores
            # -WhatIf; Set-Variable would honour it without -WhatIf:$false.
            Set-Variable -Name $StatusCodeVariable -Value $next.Status -Scope 1 -WhatIf:$false
            Set-Variable -Name $ResponseHeadersVariable -Value $next.Headers -Scope 1 -WhatIf:$false
            $next.Content
        }

        function Get-MgRequestContext {
            [pscustomobject]@{ MaxRetry = $script:SdkMaxRetry }
        }

        function Set-MgRequestContext {
            [CmdletBinding(SupportsShouldProcess)]
            param ([int]$MaxRetry)

            if ($PSCmdlet.ShouldProcess('Graph request context', "Set MaxRetry to $MaxRetry")) {
                $script:SdkMaxRetry = $MaxRetry
            }
        }

        function Get-MgContext {
            $script:Context
        }

        function Connect-MgGraph {
            [CmdletBinding()]
            param ([string[]]$Scopes, [string]$TenantId, [switch]$NoWelcome, [switch]$UseDeviceCode)

            $script:SignIns.Add([pscustomobject]@{
                    Scopes        = $Scopes
                    TenantId      = $TenantId
                    NoWelcome     = $NoWelcome.IsPresent
                    UseDeviceCode = $UseDeviceCode.IsPresent
                })
            $script:Context = $script:ContextAfterSignIn
        }

        function Disconnect-MgGraph {
            [CmdletBinding()]
            param ()

            $script:Disconnected = $true
            $script:Context = $null
        }

        function Get-StandInResponse {
            param ([int]$Status, [string]$Content = '{}', [string]$RetryAfter)

            $headers = @{}
            if ($RetryAfter) { $headers['Retry-After'] = @($RetryAfter) }
            [pscustomobject]@{ Status = $Status; Headers = $headers; Content = $Content }
        }

        function Get-StandInContext {
            param ([string]$AuthType = 'Delegated', [string[]]$Scopes = @(), [string]$TenantId = $script:TenantA)

            $account = if ($AuthType -eq 'Delegated') { 'admin@contoso.com' } else { $null }
            [pscustomobject]@{
                AuthType = $AuthType
                Scopes   = $Scopes
                TenantId = $TenantId
                Account  = $account
                AppName  = 'Contoso automation'
            }
        }

        function Invoke-Captured {
            # Runs a command and separates what it returns from what it warns.
            param ([scriptblock]$Command)

            $all = @(& $Command 3>&1)
            [pscustomobject]@{
                Output   = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
                Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)
            }
        }

        $script:ThrottleBody = '{"error":{"code":"TooManyRequests","message":"slow down"}}'
        $script:ReadScope = [ordered]@{
            'DeviceManagementManagedDevices.Read.All' = @('DeviceManagementManagedDevices.ReadWrite.All')
        }

        . ([scriptblock]::Create(((Get-HelperRegion -Path $script:TemplatePath) -join [Environment]::NewLine)))

        Mock Start-Sleep { $script:Sleeps.Add($Seconds) }
    }

    BeforeEach {
        $script:Responses.Clear()
        $script:Requests.Clear()
        $script:SignIns.Clear()
        $script:Sleeps.Clear()
        $script:Notices.Clear()
        $script:SdkMaxRetry = 3
        $script:Context = $null
        $script:ContextAfterSignIn = $null
        $script:Disconnected = $false
    }

    Context 'Invoke-GraphRequestWithRetry' {

        It 'returns the parsed body of a successful response' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"id":"one"}'))

            $result = Invoke-GraphRequestWithRetry -Uri $script:Uri

            $result.id | Should -Be 'one'
            $script:Requests.Count | Should -Be 1
            $script:Requests[0].OutputType | Should -Be 'Json'
            $script:Requests[0].SkipHttpErrorCheck | Should -BeTrue
        }

        It 'keeps timestamps as the text Graph sent where PowerShell allows it' {
            $keepsText = $PSVersionTable.PSEdition -eq 'Desktop' -or
                (Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')
            if (-not $keepsText) {
                Set-ItResult -Skipped -Because 'PowerShell 7.0 to 7.4 always turn timestamps into DateTime'
            }

            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"lastSyncDateTime":"2026-09-20T10:11:12Z"}'))

            (Invoke-GraphRequestWithRetry -Uri $script:Uri).lastSyncDateTime | Should -BeExactly '2026-09-20T10:11:12Z'
        }

        It 'waits the Retry-After the service sends, then returns the answer' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 429 -RetryAfter '7' -Content $script:ThrottleBody))
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"id":"one"}'))

            $run = Invoke-Captured { Invoke-GraphRequestWithRetry -Uri $script:Uri }

            $run.Output[0].id | Should -Be 'one'
            $script:Requests.Count | Should -Be 2
            $script:Sleeps | Should -Be @(7)
            $run.Warnings | Should -HaveCount 1
            $run.Warnings[0] | Should -Match 'HTTP 429 .* Waiting 7 second\(s\) before attempt 2 of 5'
        }

        It 'backs off exponentially, with jitter, when there is no Retry-After' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 503))
            $script:Responses.Enqueue((Get-StandInResponse -Status 503))
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"id":"one"}'))

            $null = Invoke-GraphRequestWithRetry -Uri $script:Uri -OnRetry { param ($Message) $script:Notices.Add($Message) }

            $script:Sleeps.Count | Should -Be 2
            $script:Sleeps[0] | Should -BeIn 2, 3, 4
            $script:Sleeps[1] | Should -BeIn 4, 5, 6
        }

        It 'gives up after -MaximumAttempt, with the status and the Graph error in the exception' {
            1..3 | ForEach-Object {
                $script:Responses.Enqueue((Get-StandInResponse -Status 429 -RetryAfter '1' -Content $script:ThrottleBody))
            }

            $failure = { Invoke-GraphRequestWithRetry -Uri $script:Uri -MaximumAttempt 3 -OnRetry { param ($Message) $script:Notices.Add($Message) } } |
                Should -Throw -PassThru

            $failure.Exception.Data['StatusCode'] | Should -Be 429
            $failure.Exception.Message | Should -Match 'after 3 attempt\(s\): TooManyRequests: slow down'
            $script:Requests.Count | Should -Be 3
            $script:Notices.Count | Should -Be 2
        }

        It 'does not retry a status that would only repeat, such as 404' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 404 -Content '{"error":{"code":"ResourceNotFound","message":"gone"}}'))

            $failure = { Invoke-GraphRequestWithRetry -Uri $script:Uri } | Should -Throw -PassThru

            $failure.Exception.Data['StatusCode'] | Should -Be 404
            $failure.Exception.Message | Should -Match 'ResourceNotFound: gone'
            $script:Requests.Count | Should -Be 1
            $script:Sleeps.Count | Should -Be 0
        }

        It 'retries a GET that got no response at all' {
            $script:Responses.Enqueue([System.Net.Http.HttpRequestException]::new('No connection could be made'))
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"id":"one"}'))

            $result = Invoke-GraphRequestWithRetry -Uri $script:Uri -OnRetry { param ($Message) $script:Notices.Add($Message) }

            $result.id | Should -Be 'one'
            $script:Notices[0] | Should -Match '^No response from GET'
        }

        It 'never resends a POST that got no response, because it may have landed' {
            $script:Responses.Enqueue([System.Net.Http.HttpRequestException]::new('The response ended prematurely'))

            $failure = { Invoke-GraphRequestWithRetry -Uri $script:Uri -Method POST -Body @{ serialNumber = 'x' } } |
                Should -Throw -PassThru

            $failure.Exception.Data['StatusCode'] | Should -Be 0
            $failure.Exception.InnerException | Should -BeOfType [System.Net.Http.HttpRequestException]
            $script:Requests.Count | Should -Be 1
        }

        It 'resends a POST after HTTP <Status>: <Resent>' -ForEach @(
            @{ Status = 429; Resent = $true }
            @{ Status = 503; Resent = $true }
            @{ Status = 500; Resent = $false }
            @{ Status = 502; Resent = $false }
            @{ Status = 504; Resent = $false }
        ) {
            $script:Responses.Enqueue((Get-StandInResponse -Status $Status -RetryAfter '1'))
            $script:Responses.Enqueue((Get-StandInResponse -Status 201 -Content '{"id":"new"}'))

            $call = { Invoke-GraphRequestWithRetry -Uri $script:Uri -Method POST -Body @{ serialNumber = 'x' } -OnRetry { param ($Message) $script:Notices.Add($Message) } }

            if ($Resent) {
                (& $call).id | Should -Be 'new'
                $script:Requests.Count | Should -Be 2
            }
            else {
                $call | Should -Throw "*HTTP $Status from POST*"
                $script:Requests.Count | Should -Be 1
            }
        }

        It 'fails at once on an error that is not about the network, such as not being signed in' {
            $script:Responses.Enqueue([System.InvalidOperationException]::new('Authentication needed. Please call Connect-MgGraph.'))

            { Invoke-GraphRequestWithRetry -Uri $script:Uri } | Should -Throw '*Authentication needed*'

            $script:Requests.Count | Should -Be 1
            $script:Sleeps.Count | Should -Be 0
        }

        It 'switches the SDK retry off for the request and restores it afterwards' {
            $script:SdkMaxRetry = 5
            $script:Responses.Enqueue((Get-StandInResponse -Status 200))

            $null = Invoke-GraphRequestWithRetry -Uri $script:Uri

            $script:Requests[0].SdkMaxRetry | Should -Be 0
            $script:SdkMaxRetry | Should -Be 5
        }

        It 'restores the SDK retry when the request fails too' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 404))

            { Invoke-GraphRequestWithRetry -Uri $script:Uri } | Should -Throw

            $script:SdkMaxRetry | Should -Be 3
        }

        It 'switches the SDK retry off even when the calling script runs with -WhatIf' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 200))

            $WhatIfPreference = $true
            $null = Invoke-GraphRequestWithRetry -Uri $script:Uri
            $WhatIfPreference = $false

            $script:Requests[0].SdkMaxRetry | Should -Be 0
            $script:SdkMaxRetry | Should -Be 3
        }

        It 'hands retry notices to -OnRetry instead of warning' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 429 -RetryAfter '1'))
            $script:Responses.Enqueue((Get-StandInResponse -Status 200))

            $run = Invoke-Captured {
                Invoke-GraphRequestWithRetry -Uri $script:Uri -OnRetry { param ($Message) $script:Notices.Add($Message) }
            }

            $run.Warnings | Should -HaveCount 0
            $script:Notices | Should -HaveCount 1
        }
    }

    Context 'Get-GraphCollection' {

        It 'follows @odata.nextLink until the service stops sending one' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content ('{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"' + $script:Uri + '?$skiptoken=2"}')))
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"value":[{"id":"c"}]}'))

            $items = Get-GraphCollection -Uri $script:Uri

            @($items | ForEach-Object { $_.id }) | Should -Be @('a', 'b', 'c')
            $script:Requests[1].Uri | Should -Be ($script:Uri + '?$skiptoken=2')
        }

        It 'returns a List, not $null, for an empty collection' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"value":[]}'))

            $items = Get-GraphCollection -Uri $script:Uri

            $items.GetType().Name | Should -Be 'List`1'
            $items.Count | Should -Be 0
        }

        It 'returns a List that still behaves once stored in an object property' {
            # Backup-IntuneConfiguration.ps1 does exactly this. A List built
            # with New-Object made the if-expression below throw "Argument
            # types do not match" on both 5.1 and 7.
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"value":[{"id":"a"},{"id":"b"}]}'))

            $holder = [pscustomobject]@{ Items = $null }
            $holder.Items = Get-GraphCollection -Uri $script:Uri
            $count = if ($null -ne $holder.Items) { @($holder.Items).Count } else { '' }

            $count | Should -Be 2
        }

        It 'refuses a response that is not a collection' {
            $script:Responses.Enqueue((Get-StandInResponse -Status 200 -Content '{"id":"one"}'))

            { Get-GraphCollection -Uri $script:Uri } | Should -Throw "*no 'value' list*"
        }
    }

    Context 'Connect-GraphSession' {

        It 'reuses a session that already holds the scope, and says it opened none' {
            $script:Context = Get-StandInContext -Scopes 'DeviceManagementManagedDevices.Read.All'

            Connect-GraphSession -Scope $script:ReadScope | Should -BeFalse
            $script:SignIns.Count | Should -Be 0
        }

        It 'accepts a broader scope listed as an alternative' {
            $script:Context = Get-StandInContext -Scopes 'DeviceManagementManagedDevices.ReadWrite.All'

            Connect-GraphSession -Scope $script:ReadScope | Should -BeFalse
            $script:SignIns.Count | Should -Be 0
        }

        It 'signs in when there is no session, asking only for the narrowest scopes' {
            $script:ContextAfterSignIn = Get-StandInContext -Scopes 'DeviceManagementManagedDevices.Read.All'

            Connect-GraphSession -Scope $script:ReadScope -TenantId $script:TenantA -UseDeviceCode | Should -BeTrue

            $script:SignIns[0].Scopes | Should -Be @('DeviceManagementManagedDevices.Read.All')
            $script:SignIns[0].TenantId | Should -Be $script:TenantA
            $script:SignIns[0].UseDeviceCode | Should -BeTrue
            $script:SignIns[0].NoWelcome | Should -BeTrue
        }

        It 'signs in again when the session belongs to another tenant' {
            $script:Context = Get-StandInContext -Scopes 'DeviceManagementManagedDevices.Read.All' -TenantId $script:TenantA
            $script:ContextAfterSignIn = Get-StandInContext -Scopes 'DeviceManagementManagedDevices.Read.All' -TenantId $script:TenantB

            Connect-GraphSession -Scope $script:ReadScope -TenantId $script:TenantB | Should -BeTrue
            $script:SignIns[0].TenantId | Should -Be $script:TenantB
        }

        It 'replaces a delegated session that lacks a scope, and says so' {
            $script:Context = Get-StandInContext -Scopes 'User.Read'
            $script:ContextAfterSignIn = Get-StandInContext -Scopes 'User.Read', 'DeviceManagementManagedDevices.Read.All'

            $run = Invoke-Captured { Connect-GraphSession -Scope $script:ReadScope }

            $run.Output | Should -Be @($true)
            $run.Warnings[0] | Should -Match 'lacks DeviceManagementManagedDevices\.Read\.All'
        }

        It 'fails and disconnects when consent does not cover a scope' {
            $script:ContextAfterSignIn = Get-StandInContext -Scopes 'User.Read'

            { Connect-GraphSession -Scope $script:ReadScope } |
                Should -Throw '*consent does not cover DeviceManagementManagedDevices.Read.All*'
            $script:Disconnected | Should -BeTrue
        }

        It 'never replaces an app-only session, and names the permission to grant' {
            $script:Context = Get-StandInContext -AuthType 'AppOnly' -Scopes 'User.Read.All'

            { Connect-GraphSession -Scope $script:ReadScope } |
                Should -Throw '*AppOnly Graph session*lacks DeviceManagementManagedDevices.Read.All*'
            $script:SignIns.Count | Should -Be 0
        }

        It 'continues with a warning when an app-only session lists no permissions' {
            $script:Context = Get-StandInContext -AuthType 'AppOnly'

            $run = Invoke-Captured { Connect-GraphSession -Scope $script:ReadScope }

            $run.Output | Should -Be @($false)
            $run.Warnings[0] | Should -Match 'cannot be verified'
        }
    }
}

Describe 'Graph helpers against the real SDK' -Skip:(-not $script:SdkAvailable) {

    BeforeAll {
        # Runs in a child process so that its made-up sign-in and its SDK
        # settings never touch a Graph session in the process running Pester.
        $liveCheck = @'
param ([Parameter(Mandatory)][string]$TemplatePath)

$ErrorActionPreference = 'Stop'

try {
    Import-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0

    $lines = @((Get-Content -LiteralPath $TemplatePath -Raw) -split '\r?\n')
    $first = [array]::IndexOf($lines, '#region Graph helpers')
    $last = [array]::IndexOf($lines, '#endregion Graph helpers')
    $regionText = $lines[$first..$last] -join "`n"
    . ([scriptblock]::Create($regionText))

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($regionText, [ref]$null, [ref]$null)
    $helperNames = @($ast.FindAll({ param ($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
            ForEach-Object Name)
    $sdkNames = @(Get-Command -Module Microsoft.Graph.Authentication | ForEach-Object Name)

    # A stand-in for Graph on a free local port.
    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = $probe.LocalEndpoint.Port
    $probe.Stop()

    $hits = [hashtable]::Synchronized(@{})
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://localhost:$port/")
    $listener.Start()

    $server = Start-ThreadJob -ArgumentList $listener, $hits, $port -ScriptBlock {
        param ($listener, $hits, $port)
        while ($listener.IsListening) {
            try { $context = $listener.GetContext() } catch { break }
            $path = $context.Request.Url.AbsolutePath
            $hits[$path] = 1 + [int]$hits[$path]
            $response = $context.Response
            $body = '{"error":{"code":"TooManyRequests","message":"slow down"}}'
            switch ($path) {
                '/v1.0/throttled' { $response.StatusCode = 429; $response.Headers.Add('Retry-After', '1') }
                '/v1.0/flaky' {
                    if ($hits[$path] -eq 1) { $response.StatusCode = 429; $response.Headers.Add('Retry-After', '1') }
                    else { $response.StatusCode = 200; $body = '{"id":"one"}' }
                }
                '/v1.0/page1' {
                    $response.StatusCode = 200
                    $body = '{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"http://localhost:' + $port + '/v1.0/page2"}'
                }
                '/v1.0/page2' { $response.StatusCode = 200; $body = '{"value":[{"id":"c"}]}' }
                default { $response.StatusCode = 404; $body = '{"error":{"code":"NotFound","message":"no such path"}}' }
            }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response.ContentType = 'application/json'
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
            $response.Close()
        }
    }

    try {
        # A made-up, unsigned token. The SDK decodes it for the session and
        # sends it to localhost; nothing verifies it.
        $encode = { param ($text) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        $claims = @{ tid = [guid]::Empty.ToString(); scp = 'User.Read'; exp = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() } |
            ConvertTo-Json -Compress
        $token = '{0}.{1}.{2}' -f (& $encode '{"alg":"none"}'), (& $encode $claims), (& $encode 'unsigned')
        Connect-MgGraph -AccessToken (ConvertTo-SecureString -String $token -AsPlainText -Force) -NoWelcome

        $base = "http://localhost:$port/v1.0"
        $notices = [System.Collections.Generic.List[string]]::new()
        $onRetry = { param ($Message) $notices.Add($Message) }

        $result = [ordered]@{
            Collisions     = @($helperNames | Where-Object { $sdkNames -contains $_ })
            MaxRetryBefore = (Get-MgRequestContext).MaxRetry
        }

        try {
            $null = Invoke-GraphRequestWithRetry -Uri "$base/throttled" -MaximumAttempt 2 -OnRetry $onRetry
            $result.ThrottleStatus = 'none'
        }
        catch {
            $result.ThrottleStatus = $_.Exception.Data['StatusCode']
        }
        $result.ThrottleHits = [int]$hits['/v1.0/throttled']

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $result.FlakyId = (Invoke-GraphRequestWithRetry -Uri "$base/flaky" -OnRetry $onRetry).id
        $result.FlakySeconds = $timer.Elapsed.TotalSeconds
        $result.FlakyHits = [int]$hits['/v1.0/flaky']

        $result.PagedCount = (Get-GraphCollection -Uri "$base/page1" -OnRetry $onRetry).Count
        $result.MaxRetryAfter = (Get-MgRequestContext).MaxRetry

        $null = Disconnect-MgGraph
        $result | ConvertTo-Json -Compress
    }
    finally {
        $listener.Stop()
        $server | Stop-Job -PassThru | Remove-Job -Force
    }
}
catch {
    Write-Error -Message "Real-SDK check failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
'@

        $childPath = Join-Path -Path $TestDrive -ChildPath 'Invoke-LiveHelperCheck.ps1'
        [System.IO.File]::WriteAllText($childPath, $liveCheck)

        $output = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $childPath -TemplatePath $script:TemplatePath 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "The real-SDK check exited with $LASTEXITCODE.`n$($output -join "`n")"
        }

        $script:Live = [string]$output[-1] | ConvertFrom-Json
    }

    It 'names no helper after a command the SDK exports, which would shadow it' {
        @($script:Live.Collisions) | Should -HaveCount 0
    }

    It 'switches the SDK retry off: a throttled request reaches the server -MaximumAttempt times, not four times more' {
        $script:Live.ThrottleHits | Should -Be 2
        $script:Live.ThrottleStatus | Should -Be 429
    }

    It 'waits the Retry-After the server sends, then returns the answer' {
        $script:Live.FlakyHits | Should -Be 2
        $script:Live.FlakySeconds | Should -BeGreaterOrEqual 1
        $script:Live.FlakyId | Should -Be 'one'
    }

    It 'follows @odata.nextLink through the SDK' {
        $script:Live.PagedCount | Should -Be 3
    }

    It 'leaves the SDK retry setting as it found it' {
        $script:Live.MaxRetryAfter | Should -Be $script:Live.MaxRetryBefore
    }
}
