# Graph

Admin-side tooling run from a workstation against a tenant through Microsoft
Graph. Whatever workload a script touches — Intune, Entra ID, Autopilot — if you
run it yourself against the tenant, it lives here. Artifacts that are deployed to
a device, or that run on one, belong under `Intune/` instead.

| Folder | Contains |
| --- | --- |
| `Autopilot/` | Registering and reporting on Windows Autopilot device identities. |
| `Configuration/` | Backup and reporting over Intune configuration objects: remediations, scripts, profiles, compliance policies, Windows update policies. |
| `Devices/` | Managed device reporting and inventory. |

## Conventions for everything in this folder

- **One copy of the Graph plumbing, in every script.** Each script carries the
  `#region Graph helpers` block from `Templates/Script-Template.ps1`, unchanged,
  so it still runs when copied out on its own. A test fails while any copy
  differs from the template's; see [`Templates/README.md`](../Templates/README.md).
  The conventions below are what those helpers implement.
- **Read-only unless stated.** Anything that writes gates the change behind
  `ShouldProcess` and defaults to report-only.
- **Narrowest scopes.** Request only what the script calls, and verify the
  granted scopes after connecting rather than assuming consent succeeded.
  A broader scope the administrator already holds is accepted in place of the
  narrow one.
- **Reuse an existing session.** Connect only when there is no usable session,
  and disconnect only a session the script opened itself.
- **Page properly.** Follow `@odata.nextLink` until it is absent. A script that
  reads one page and stops is a script that silently under-reports.
- **Expect throttling.** Retry on 429 and 5xx, waiting the `Retry-After` value
  when the service sends one and backing off exponentially when it does not.
  Retry a POST only on 429 and 503, which mean the service did not act on it.
  The Graph SDK's own hidden retry is switched off per request, so there is one
  retry loop, not two stacked.
- **v1.0 by default.** Use beta only when a property or endpoint exists nowhere
  else, and say so in the script's `.NOTES`.
- **Microsoft Graph only.** Never MSOnline or AzureAD; both are deprecated.

## Output is tenant data

These scripts return real device names, user principal names and serial numbers.
That is the point of them, and it is also why the output belongs nowhere near
this repository. Write reports outside the working tree, and remember that
`Tools/Test-SensitiveContent.ps1` will stop a commit containing them.
