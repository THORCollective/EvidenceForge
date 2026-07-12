# macOS Endpoint Security (eslogger) Support — Design

**Date:** 2026-07-11
**Status:** Validated with maintainer (Sydney), ready for implementation planning
**Deadline driver:** OBTS v9 CFP (July 31) needs a citable recorded hunt loop on
generated ESF data. Phase A must land by ~July 25.

## Goal

Add `macos` as a third first-class `os_category` and a new `eslogger` log format
that emits authentic `eslogger`-style NDJSON per macOS host. Event coverage is
driven by the three OBTS hunts and Nebulock's macos-coresigma ESF rule set
(<https://github.com/Nebulock-Inc/macos-coresigma>), so a collector → ECS →
Sigma pipeline can detect storyline attacks in the generated data.

**Must-support hunts:**

1. **AMOS/Atomic Stealer** — `osascript` exec with full argv, file `open` of
   `~/Library/Keychains/login.keychain-db`, exfil POST via network egress.
2. **DPRK BeaverTail** — `npm` → `node` process ancestry chain, `node` network
   egress.
3. **CloudMensis-style persistence** — plist `create` in `~/Library/LaunchAgents`
   plus `btm_launch_item_add`.

**ESF differentiators that cannot be cut** (they are the talk's thesis): full
argv, code-signing identity (signing ID, team ID, CDHash, platform-binary flag),
BTM launch-item events, TCC-relevant file access.

## Architecture

Two-layer split, per AGENTS.md rules 1a/1b:

1. **Canonical layer (most of the work).** macOS hosts flow through the existing
   world model → action bundles → `SecurityEvent` pipeline. Process execution,
   file operations, network connections, SSH sessions, and logon/logoff reuse
   existing bundles, extended to be macOS-aware (per-OS process pools, `launchd`
   ancestry, macOS path defaults). No private emitter pipeline.
2. **Emitter layer.** One new `ESLoggerEmitter` (host-multiplexed like eCAR; one
   `eslogger_<host>.ndjson` per macOS host) plus
   `config/formats/eslogger.yaml`. The emitter is a pure renderer of existing
   contexts; ES-native envelope fields are derived deterministically.

## Event & Field Model

**Envelope** mirrors real `eslogger` output per NDJSON line: `schema_version`,
`time` (+ `mach_time` derived from it), per-client `seq_num`/`global_seq_num`,
`event_type` integer, an `event` object keyed by type name, and the full acting
`process` object — audit token (pid, pidversion, euid/ruid, auid, session id),
`ppid`, `parent_audit_token`, `executable.path`, tty, `start_time`, and
code-signing identity (`signing_id`, `team_id`, `cdhash`,
`is_platform_binary`, `codesigning_flags`).

- Audit-token fields derive from existing StateManager session/process state.
- `pidversion` and CDHashes come from `_stable_seed`, never `hash()`.

**Code signing is data-driven** (realism rule #2): new
`config/activity/macos_signing.yaml` maps known binaries → signing IDs
(`com.apple.curl`, platform-binary flags) and third-party apps → team IDs, with
a cached loader. Storyline malware defaults to ad-hoc/unsigned — exactly what
the hunts key on.

**Canonical mapping (Phase A):**

| Canonical context | ES events rendered |
|---|---|
| `ProcessContext` | `exec` (full argv, cwd), `fork`, `exit` |
| `FileContext` | `create`, `open`, `write`, `rename`, `unlink` |
| `AuthContext` | `openssh_login`/`openssh_logout`, `lw_session` lock/unlock |
| privilege events | `sudo`, `su` |

**No network events, deliberately.** ESF has no TCP connect event; real ES
clients pair with NetworkExtension. BeaverTail's "node → egress" hunt
correlates ES `exec` with the existing Zeek conn/dns output for the same host —
authentic and a stronger cross-source hunting story.

**BTM via causal expansion:** a new causal rule auto-generates
`btm_launch_item_add` whenever a plist is created under
`LaunchAgents`/`LaunchDaemons`. CloudMensis persistence needs only a file-create
storyline event. TCC coverage rides on sensitive-file `open`/`write` to
`TCC.db` in Phase A; native `tcc_modify` is Phase B.

## World Model & Baseline

- `os_category` gains `"macos"` across `HostContext`, scenario models,
  validation OS-gating, and `WorldModel` capability resolution.
- macOS systems are primarily workstation-role; `assigned_user`/`primary_system`
  personas work unchanged. The Hawkes temporal model reuses persona
  `risk_profile` as-is (timing machinery is OS-agnostic).
- Reused bundles, macOS-aware: process execution (parents root at `launchd`
  pid 1; interactive apps under `Terminal`/`Dock`/`loginwindow`), SSH (macOS
  ships `sshd`), browser sessions (Safari/Chrome UAs riding existing
  proxy/Zeek paths), file transfers. Every OS fallback path gets a macOS branch
  (`/usr/bin/zsh`, realism rule #3).
- **Baseline noise tier (modest, data-driven YAML):**
  - System daemons: Spotlight (`mds`/`mdworker_shared`), Time Machine
    (`backupd`), `softwareupdated`, `cfprefsd`, `cloudd`/`bird` iCloud file
    churn, `trustd` (whose OCSP checks correlate with existing `zeek_ocsp`).
  - User activity: app launches from `/Applications`, zsh commands via the
    existing shell-command bundle, browser traffic.
  - Periodic launchd jobs with per-host jitter and probabilistic skips
    (realism rule #5 — no exact-hour ticks).
- **Out of scope for Phase A:** macOS lateral-movement patterns, red herrings,
  unified-log output, kext/XPC/XProtect/Gatekeeper/cs_invalidated events.

## Scenario Surface

Systems declare `os: macos`; no new storyline event types needed for Phase A.
AMOS = `process` events + file `open` + `connection`; BeaverTail = `process`
chain + `connection`s; CloudMensis = file `create` (causal rule adds the BTM
event).

Per the AGENTS.md event/schema change checklist, the PR updates:
`docs/reference/scenario-reference.md`, `docs/reference/EVIDENCE_FORMATS.md`,
`README.md`, `docs/ARCHITECTURE.md` (emitter tree, causal rules),
`docs/design/event-model-prd.md`, skills (`commands/eforge/scenario.md`,
`validate.md`), `src/evidenceforge/validation/schema.py` (OS-gating),
evaluation rules (co-occurrence: exec↔fork; causal pairs: plist-create↔btm),
and `scenarios/COVERAGE-TEST-PROMPT.md`.

## Testing

- Unit: emitter field rendering per event type (validated against real eslogger
  captures from talk prep), signing-YAML loader, BTM causal rule, determinism
  (same seed → identical NDJSON).
- Integration: small macOS scenario generated end-to-end in `tmp_path`.
- A demo scenario in `scenarios/` reproducing all three hunts doubles as test
  fixture and recording asset.
- Run with `uv run pytest --no-cov` for feature validation; coverage gate only
  at release.

## Phased Delivery

- **Phase A (~July 25, one PR to `dev`):** `macos` os_category; eslogger
  emitter (exec/fork/exit, file ops, openssh/lw_session, sudo/su); BTM causal
  rule; `macos_signing.yaml`; modest baseline; three-hunt demo scenario; docs,
  skills, validation, evaluation updates.
- **Phase B (post-CFP fast-follow):** `mmap`/`mprotect`, `signal`, `setuid`,
  `tcc_modify`; richer baseline daemons; evaluation-dimension scoring for
  eslogger; Elastic ingest guide; consider CoreSigma long-tail events
  (kext, XPC, XProtect, Gatekeeper).

## Mechanics

Feature branch `macos-eslogger` off `origin/dev`; conventional commits; no
version bump on the feature branch; `uv run ruff check .` +
`uv run ruff format --check .` + `uv run pytest --no-cov` before commits; one
worklog under `docs/worklog/` for the effort; durable TODO.md backlog line for
Phase B.
