<#
    Windows PowerShell 5.1 compatibility check.

    Applies only to scripts that declare '#Requires -Version 5.1' - in practice,
    anything that runs on an Intune-managed device, where Windows PowerShell is
    the only host guaranteed to be present. Admin-side tooling targets
    PowerShell 7 and is not checked against this file.

    Local use:
        Invoke-ScriptAnalyzer -Path .\Templates\Remediation\Test-ExampleSetting.ps1 `
            -Settings .\PSScriptAnalyzerSettings.WindowsPowerShell.psd1

    CI selects the files to check by reading the #Requires line, so a script is
    held to 5.1 only while it says it targets 5.1.
#>
@{
    IncludeRules = @(
        'PSUseCompatibleSyntax'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @(
                '5.1'
            )
        }
    }
}
