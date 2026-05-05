# Hayabusa-native rules

These 193 detection rules were imported from the [Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)
project (commit shipped with Hayabusa v3.9.0, 2026-04-29).

## Coverage gain

They surface Windows audit data that mainstream SigmaHQ rules don't track:
service installation patterns (EID 7045) for AnyDesk / TeamViewer / Atera /
ScreenConnect / NetSupport, MSIX/AppX deployment, BITS jobs, PowerShell-
Classic engine activity, code-integrity events, NTLM auth, scheduled tasks,
WindowsLogonStartup. About 19 are HIGH-severity, 1 CRITICAL, 44 MEDIUM,
25 LOW, 101 INFORMATIONAL (observability tier).

## Default behavior

Muninn's default `--min-level low` excludes the 101 INFORMATIONAL rules
from execution. Pass `--min-level informational` to enable them when you
want full Hayabusa-style observability (`Admin Logon`, `MSI Install`,
`PwSh Engine Started`, etc).

## License

Hayabusa rules ship under the **Detection Rule License (DRL) 1.1**
([SigmaHQ/sigma/LICENSE.Detection.Rules.md](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md))
— the same license SigmaHQ rules use. Compatible with Muninn's AGPL-3.0
binary distribution (rules are data, not linked code).

Original authors: Zach Mathis, Fukusuke Takahashi, and the Yamato Security
contributors. We have **not modified** the rule contents — see git log for
the import commit (v0.7.3).
