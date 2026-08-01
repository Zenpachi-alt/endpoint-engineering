# Repository conventions

Personal endpoint-management engineering repo: Microsoft Intune, Windows
Autopilot, Microsoft Graph. Public-facing — assume every file is read by someone
outside my organisation.

## General

- **Never commit real identifiers.** No tenant IDs, object/policy/app GUIDs,
  UPNs, email addresses, internal hostnames, domain names, IP addresses, device
  serials, keys, or secrets — including in examples, comments, and sample output.
  Use obvious placeholders: `<TenantId>`, `<GroupId>`, `user@contoso.com`,
  `00000000-0000-0000-0000-000000000000`.
- **Organise by domain and platform, never by file type.** A script, its payload,
  its detection counterpart, and its README are one unit in one folder.
- **No empty folders.** A folder is created by the first real file that belongs
  in it.
- **Every folder has a `README.md`** stating what it contains and how it is used.
- **Every script documents its prerequisites and required permissions** — modules,
  licensing, API permissions, and the role needed to run it.
- **Error handling is mandatory.** No silent failures. Every failure surfaces an
  actionable message, and scripts that can fail exit non-zero.
- Folders are PascalCase. Scripts are `Verb-Noun.ps1`. Supporting files take the
  name of the script or unit they belong to.

## PowerShell

- Approved verb-noun naming (`Get-Verb`), PascalCase parameters,
  `[CmdletBinding()]` on every script.
- `SupportsShouldProcess` on anything that writes, changes, or deletes — and
  actually gate the change behind `$PSCmdlet.ShouldProcess()`.
- Typed, validated parameters. Use `Mandatory`, `ValidateSet`,
  `ValidateNotNullOrEmpty`, `ValidatePattern`, `ValidateScript` rather than
  discovering bad input halfway through a run.
- `try`/`catch`/`finally` with `-ErrorAction Stop` on every cmdlet inside a
  `try`. Never use `SilentlyContinue` to hide an error.
- `Write-Error`, `Write-Warning`, `Write-Verbose`, `Write-Output`. No bare
  `Write-Host` for errors, and never for data on the pipeline.
- Microsoft Graph PowerShell SDK or direct Graph REST (`Invoke-MgGraphRequest`)
  only. **Never MSOnline or AzureAD** — both are deprecated.
- Request the narrowest Graph scopes that work, and verify the granted scopes
  after connecting rather than assuming consent succeeded.
- Comment-based help is required and must declare, under `.NOTES`:
  - `Graph scopes` — every scope the script requests
  - `Admin consent` — required or not
  - `Licensing` — e.g. Microsoft Intune Plan 1, Microsoft Entra ID P1/P2
  - `Modules` — every module the script depends on
- Start from `Templates/Script-Template.ps1`.

<!-- Sections for other languages (batch, Bash/zsh) are added when the first
     file in that language lands. Do not add them pre-emptively. -->
