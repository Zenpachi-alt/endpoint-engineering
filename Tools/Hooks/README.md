# Hooks

Versioned git hooks. `Tools/Install-GitHook.ps1` points `core.hooksPath` here,
so a fresh clone gets the same checks by running one command instead of copying
files into `.git/hooks` by hand.

| Hook | Runs | Does |
| --- | --- | --- |
| `pre-commit` | Before a commit is created | Runs `Tools/Test-SensitiveContent.ps1 -Staged` and blocks the commit on any finding. |

Hooks are POSIX shell scripts with LF line endings (enforced by
`.gitattributes`) and are executed by the shell that ships with Git for
Windows. They locate PowerShell themselves, preferring `pwsh` and falling back
to Windows PowerShell.

`git commit --no-verify` skips them. CI runs the same scan, so a skipped hook
surfaces on the next push.
