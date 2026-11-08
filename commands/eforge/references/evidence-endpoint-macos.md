---
description: "macOS Endpoint Security (eslogger) evidence reference"
---

# macOS Endpoint Evidence

Read this reference for macOS hosts and Endpoint Security (`eslogger`) records.

Each macOS host writes `<host>/eslogger.ndjson`: one Apple `es_message_t`-shaped JSON record per
line with `schema_version`, `version`, nanosecond `time`, `mach_time`, `thread`, per-host
`seq_num`, `global_seq_num`, integer `event_type` (Apple `es_event_type_t`), `event.<name>`, and
the acting `process`. Processes carry `audit_token` (`pid`, `pidversion`, `asid`, ...),
`signing_id`, `team_id`, `cdhash`, `codesigning_flags`, and `is_platform_binary`.

| Event | Source | Contract |
| --- | --- | --- |
| `fork`, `exec`, `exit` | `process_create`, `process_terminate` | `fork` (subject = parent) then `exec` (subject = pre-exec image, launched program in `event.exec.target` with full `args` and `cwd`). |
| `create`, `open`, `write`, `rename`, `unlink` | file events | Owned by the acting process. |
| `openssh_login`, `openssh_logout` | SSH sessions to a Mac | Logout renders only for a session whose login rendered. |
| `lw_session_lock`, `lw_session_unlock` | workstation lock/unlock | Local console (loginwindow) sessions only. |
| `sudo`, `su` | sudo/su process creates | Emitted alongside the exec. |
| `btm_launch_item_add` | plist create under LaunchAgents/LaunchDaemons | Reported by `backgroundtaskmanagementd` with the writer as `instigator`. |

Apple platform binaries are Apple-signed; unknown code defaults to ad-hoc signing with no Team ID.
There are deliberately no network-connect events: correlate macOS egress with Zeek. PIDs wrap below
99999 and `pidversion` is a per-boot counter.
