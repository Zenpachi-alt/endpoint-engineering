# Intune

Artifacts that run on a device or are deployed to one. If Intune delivers it, or
a technician runs it on the endpoint itself, it lives here. Tooling you run from
a workstation against the tenant belongs under `Graph/` instead, whatever
workload it touches.

| Folder | Contains |
| --- | --- |
| `Windows/` | Everything targeting Windows endpoints. |

Platform folders are created by the first artifact that belongs in them, so
macOS, iOS and Android appear here only once there is something to put in them.

## What everything here has in common

- **Windows PowerShell 5.1.** It is what ships with Windows. PowerShell 7 has to
  be deployed separately and cannot be assumed on a device.
- **No module dependencies.** Scripts run before, and independently of,
  anything installed on the endpoint.
- **Logging to disk**, under `%ProgramData%\EndpointEngineering\Logs`, rotated
  to a single `.old` copy. A logging failure is reported but never fails a run.
- **Meaningful exit codes.** Every script documents what each code means, and
  every failure path produces an actionable message.
- **ASCII-only, UTF-8 without BOM.** Intune rejects a BOM when script signature
  enforcement is on, and Windows PowerShell 5.1 misreads non-ASCII characters in
  a UTF-8 file without one. Staying ASCII removes the question.

New work starts from `Templates/Remediation/`, which carries the logging, exit
code and error handling structure these constraints imply.
