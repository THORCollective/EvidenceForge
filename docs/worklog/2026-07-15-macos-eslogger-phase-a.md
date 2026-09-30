# macOS eslogger Support — Phase A

## Status

Complete. All 22 acceptance facts hold (see `goals/macos-eslogger-phase-a/facts.md`). 34
commits landed on `macos-eslogger` (branched from `origin/dev` via
`ac41659d`, currently at `3e0fb4c2`), no version bump. Ready for PR to `dev`
on the `THORCollective/EvidenceForge` fork.

## Current Handoff

Nothing outstanding for Phase A itself. Next steps for whoever picks this up:

- Open the PR from `macos-eslogger` to `dev` on `THORCollective/EvidenceForge`
  (this fork's release conventions for `dev`→`main` haven't been decided yet —
  see plan risk #5; a simplified/no-bump flow is fine for this fork's own
  `dev`, per this effort's own "no version bump on the feature branch" rule).
- Phase B is deferred and tracked in `docs/plans/2026-07-11-macos-eslogger-design.md`'s
  "Phased Delivery" section: `mmap`/`mprotect`, `signal`, `setuid`, `tcc_modify`
  ES events; richer baseline daemons; evaluation-dimension scoring for eslogger
  (Event Presence / Temporal Integrity pillars currently have no eslogger
  matcher — co-occurrence and causal-pair scoring do); an Elastic ingest guide;
  CoreSigma long-tail events (kext, XPC, XProtect, Gatekeeper).
- Known, accepted gaps (deliberately out of Phase A scope, not bugs):
  - No macOS-equivalent of the Linux shell-command action bundle (bash-history
    + correlated process telemetry for ambient baseline shell noise) — macOS
    attacker/storyline commands render correctly via ordinary process
    exec/fork/exit, but macOS baseline users get no zsh-history-equivalent
    ambient noise texture yet.
  - `config/formats/eslogger.yaml`'s "Format Constraints" evaluation dimension
    doesn't fully match the emitter's real nested output shape (co-occurrence
    and causal-pair rules do match, since Task 11 validated field names against
    real emitter output — only the schema-conformance dimension has drift).
  - Two small path pools (macOS preference-plist paths, trust-store paths) are
    hardcoded tuples in `baseline.py` rather than YAML, judged proportionate
    for their size/single-consumer scope (Task 13b) — revisit if either grows
    or gains a second consumer.
  - `_MACOS_EVENT_TYPES`/`_LINUX_EVENT_TYPES` in `validation/schema.py` are
    currently identical sets (`{"ssh_session"}`), so one of the four
    OS-gating warnings documented in `commands/eforge/validate.md` is presently
    unreachable — correct future-proofing per Task 10's review, not dead code
    to delete.

## Decisions

Durable decisions future agents should not need to rediscover:

- **macOS SSH session identity** reuses the ES audit-token `session_id` in
  place of Linux's `logind_session_id` — there is no macOS `logind` analog.
  Implemented via `StateManager.next_macos_audit_session_id`, parallel to
  (not merged with) `next_linux_logind_session_id`, since the Linux auth-plan
  dispatch methods are genuinely syslog-content-specific and don't generalize
  cleanly (Task 5).
- **AMOS payload signing**: `/usr/bin/osascript` stays legitimately
  Apple-signed (real AMOS never re-signs it, and it's used by countless benign
  automations). The malicious payload is modeled as a distinct, unsigned
  dropper process at `/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper`
  (a real AMOS distribution lure), which execs signed `osascript` as a child
  only for the password prompt while the dropper itself owns keychain access
  and egress (Task 8's fix, exercised in Task 12's demo scenario). This is the
  scenario-authoring convention for any future AMOS-style storyline content.
- **`process_create` → two ES lines**: `fork` (subject = parent) then `exec`
  (subject = child, carries full `argv`/`cwd`), matching real `eslogger`
  output — not a single collapsed event (Task 9).
- **File-create causal-engine hook**: `file_create` events bypass the causal
  expansion engine everywhere except through a new, deliberately narrow
  `_maybe_expand_file_create` helper (cheap `"LaunchAgents"`/`"LaunchDaemons"`
  substring pre-check before any `ExpansionContext` construction), wired into
  4 dispatch sites rather than the plan's originally-named 2, after
  confirming each site pays the identical negligible hot-path cost (Task 7).
- **`btm_launch_item_add` is causal-only**: scenario authors write a `file`
  `create` event under `LaunchAgents`/`LaunchDaemons`; the BTM event is never
  hand-authored (Task 7, exercised end-to-end in Task 12).
- **Two functionally significant plan gaps were discovered mid-effort and
  closed as scoped follow-ups**, not silently worked around:
  - No `type: file` storyline event existed despite the design doc assuming
    one — added (Task 11b) with the convention that `path` is matched as a
    literal/raw string (no `~` expansion) and that file events should always
    be given a resolvable actor process (a PID-less file event degrades
    gracefully but is unrealistic).
  - No evaluation parser existed for `eslogger.ndjson` — added (Task 11c)
    with a fully recursive field-flattener (eslogger's nested `event.<type>.*`/
    `process.*` shape needed more than eCAR's one-level `properties` flatten).
  - No macOS baseline system-daemon noise generator existed despite being a
    named acceptance fact — added (Task 13b) for all 6 named daemons
    (Spotlight, Time Machine, softwareupdated, cfprefsd, cloudd/bird, trustd),
    including a root-cause fix attributing macOS OCSP-fetch connections to
    `trustd` instead of the originating app.
- **A genuine pre-existing correctness bug was found and root-cause-fixed
  during Task 12** (not a demo-construction workaround): the eslogger emitter
  was rendering *every* macOS `logoff` (interactive/network/cached logon
  types, plus RDP-on-macOS sessions incorrectly mintable by a baseline
  generator) as an orphan `openssh_logout` with no matching `openssh_login`.
  Fixed by gating `openssh_logout` rendering on having actually rendered a
  matching `openssh_login` for that session, and by gating RDP generation to
  Windows-only. Both fixes carry independent regression tests.

## Validation

- `uv run pytest --no-cov` — 5076 passed, 41 skipped, 0 failed (final full-suite
  run, ~518s) as of commit `3e0fb4c2`.
- `uv run ruff check .` and `uv run ruff format --check .` — clean throughout;
  verified before every commit in this effort.
- `eforge validate scenarios/macos-eslogger-demo/scenario.yaml` — passes with
  no errors.
- `eforge generate scenarios/macos-eslogger-demo/scenario.yaml -o ./output` —
  real CLI smoke-check, exit 0, verified during Task 12.
- Determinism: `tests/integration/test_macos_eslogger_scenario.py` regenerates
  the demo scenario twice with the same seed and asserts byte-identical
  `eslogger.ndjson` output.

## References

- Design doc: `docs/plans/2026-07-11-macos-eslogger-design.md`
- Goal/plan/facts: `goals/macos-eslogger-phase-a/{goal,plan,facts}.md`
- Demo/evidence artifact: `scenarios/macos-eslogger-demo/` (`scenario.yaml` +
  `README.md`) — the three-hunt (AMOS/Atomic Stealer, DPRK BeaverTail,
  CloudMensis-style persistence) reference dataset cited by the OBTS v9 CFP
  draft.
- Full commit range: `ac41659d..3e0fb4c2` on `macos-eslogger` (34 commits).
- Key new modules: `src/evidenceforge/generation/emitters/eslogger.py`
  (the emitter), `src/evidenceforge/generation/activity/macos_signing.py`
  (code-signing identity loader), `src/evidenceforge/evaluation/parsers/eslogger.py`
  (evaluation parser), `config/activity/macos_signing.yaml`,
  `config/formats/eslogger.yaml`.

## OBTS Readiness Pass (2026-09-26)

A pre-talk review (OBTS v9, November 2026) found the Phase A output was not
presentation-ready despite a green suite. Fixed on `macos-eslogger`:

- **ES schema fidelity** — `event_type` integers were guessed; 9 of 17 were
  wrong vs Apple's `ESTypes.h` (write rendered as `NOTIFY_IOKIT_OPEN`). Records
  now follow `es_message_t`/`es_process_t`/`es_event_*_t` from the macOS SDK
  headers: launched program in `event.exec.target`, pre-exec image as the exec
  subject, no top-level `pid`, uint32 `codesigning_flags`, envelope
  `version`/`thread`/`action`, nanosecond `time`, 24 MHz `mach_time`, BTM
  reported by `backgroundtaskmanagementd` with an `instigator`.
- **PIDs/pidversion** — macOS used the Linux allocator (PIDs like 582169);
  now a time-derived allocator that wraps below 99999. `pidversion` follows
  XNU's per-boot `nextpidversion` instead of a per-slot counter starting at 0.
- **Code signing** — generator and YAML disagreed on daemon paths, so Apple
  daemons rendered unsigned. Paths/identifiers verified with `codesign -dv` on
  macOS 15.7; anything on the sealed system volume is a platform binary; the
  default identity is ad-hoc linker-signed (what Apple Silicon runs).
- **Process tree** — macOS fell into Linux parent fallbacks (persistent root
  `sshd`/`zsh`). Apps now descend from launchd; shells come from
  Terminal → `login -pf` → `zsh`; macOS parent chains nest strictly in time.
- **Linux/Windows leaks on macOS** — `/home/<user>` cwd, Windows VS Code
  project paths, `cat /etc/shadow` / AWS IMDS suspicious-noise commands.
- **Demo storyline** — AMOS exfil was owned by a fabricated `curl` started
  before the dropper. New `process_ref` on `file`/`connection` events and
  `working_directory` on `process` events let the scenario run AMOS in its
  real order (prompt → keychain → exfil by the dropper) and BeaverTail as
  node-runs-npm → `sh -c` → node postinstall.
- **Pre-existing leak** — generation wrote scenario host mappings into the
  module-global `REVERSE_DNS`, so a prior run in the same process changed the
  next run's output. Reset per generation.

### Open items before the talk

- Capture ~30 s of real `eslogger` on a Mac (`sudo eslogger exec fork open
  create write btm_launch_item_add --format json`) and diff field-by-field;
  the current shape is header-derived, not capture-verified. Unmodeled:
  `es_file_t.stat`, exec `env`/`fds`.
- coreSigma side: its collector only reads live `eslogger` (needs a replay
  shim), its `ESF_EVENT_TYPE_MAP` disagrees with `ESTypes.h` (exit/write/
  unlink/rename), its file-path extraction reads `event.target` rather than
  `event.<name>.target`, and it has no rules for keychain access by
  non-platform code, unsigned parent → `osascript`, BTM launch items, or
  per-user LaunchAgents. Coordinate with its maintainers.
- ES volume is still tiny (~100 events/host/day); real hosts emit thousands per
  minute. Raise baseline ES density before presenting it as a hunt.
- Latent cross-OS issue left in place: non-macOS `_ensure_parent_chain`
  computes ancestor times from the original child, so an ancestor can start
  after its child; macOS now nests correctly.
- Validator still warns "no prior logon" for storyline actors whose sessions
  come from baseline (visible in a live `eforge validate`).

## Upstream v2.1.2 Sync (2026-09-28)

Merged `Cisco-Talos/EvidenceForge` `main` (v2.1.2, 946 commits, v1.12 -> v2.1.2) into the macOS
work on branch `macos-eslogger-upstream-sync` (merge, not rebase: `macos-eslogger` is pushed).
Upstream's 2.0 architecture moved or replaced most of what the branch touched, so the port was
semantic rather than textual:

- **Canonical events** — `SecurityEvent` is gone; producers build `OccurrenceBuilder` and publish
  through `dispatch_builder`/`prepare_builder`, and emitters receive sealed `CanonicalOccurrence`.
  `EventKind` and `FormatKind` are closed enums with per-kind contracts (`events/contracts.py`):
  added `file_open/write/rename/unlink`, `privilege_elevation`, `btm_launch_item_add`, and
  `ESLOGGER` as a consumer of process, file-create, logoff, SSH-session, and lock/unlock kinds.
- **Source catalog** — `eslogger` is a macOS host source (`events/source_catalog.py`) with process,
  auth, session, file, and SSH capabilities and deliberately no network capability.
- **Storyline** — typed events dispatch through `engine/typed_handlers/`; the `file` event is
  `typed_handlers/file.py`; `process_ref` on connections and `working_directory` live in the
  network/process handlers.
- **Process execution** — lives in `actions/process_execution_service.py` and
  `actions/process_support/`. macOS parent rules (launchd for app bundles, Terminal -> login ->
  zsh, time-nested ancestors, per-session shells) are in `process_support/parents.py`; macOS cwd
  derivation is `process_support/actors.py::derive_macos_current_directory`. Parents must share
  the child's session on macOS as on Windows (`queries._parent_process_matches_logon`), which
  upstream's lifecycle registry enforces. macOS no longer fabricates a process-owned image create.
- **Boot trees** — planned as a `_BootHostSpec` (`emitter_setup._build_macos_boot_host_spec`).
- **PIDs** — macOS reuses upstream's logical allocator (reorder lanes, reservations, checkpoint
  sealing) with its own ring (100..99998, start 250-400). `pidversion` derives from the
  process's `pid_logical_position`. `create_process(os_category=...)` is back for macOS.
- **SSH** — macOS destinations share the Linux auth timing plan but skip syslog; the session id is
  the ES audit-session id. macOS Remote Login is now opt-in: a Mac accepts SSH only with an `ssh`
  service or a server role (was: every Mac).
- **Evaluation** — co-occurrence rules moved into `config/formats/eslogger.yaml` validators
  (warning severity); `eslogger` is a native validation route. Two causal-pair tests had been
  passing vacuously (0/0 scored 100); they now parse through `ESLoggerParser`.
- **Checkpoints/behavior** — `_macos_audit_session_counters` is in the checkpoint owner inventory;
  generation-behavior manifest revision 155 records the change. Re-hash the manifest after any
  generation-code edit (`generation_behavior_surface_digest`) or `eforge generate` refuses to run.
- **Dropped** — `reset_reverse_dns` (upstream no longer writes scenario hosts into `REVERSE_DNS`).

### Open items after the sync

- The eslogger emitter keeps its own seq counters and openssh-login set outside checkpoint state,
  so resuming a macOS run from a checkpoint is not yet proven byte-identical.
- Screen lock/unlock and cfprefsd `write` churn are probabilistic and did not fire in the current
  demo seed (they did pre-merge); the hunts do not depend on them.
- `has_implicit_ssh_client_owner` returns False for macOS sources (compatibility SSH path only).
- `eforge eval` on the demo after the sync: schema, constraints, co-occurrence, causal ordering,
  and storyline trace coverage are 100%. Event presence, temporal integrity, and pivot
  linkability stay at the pre-merge values (40/40/low): ES records carry uids rather than
  usernames, so the evaluator cannot match storyline actors to eslogger rows. Fix in the
  evaluator (uid -> username mapping) before quoting eval scores in the talk.

## SIEM Verification in Splunk (2026-09-29)

Ingested a fresh `eforge generate --target splunk` run of the demo (17/51/50 ES records on
DESIGN/DEV/IT, 2,887 Zeek rows) into local Splunk 10.2.3 (Docker, amd64 under Rosetta). The kit
lives in `scenarios/macos-eslogger-demo/splunk/` (compose, `obts_macos_hunt` app, `run_hunts.py`).
Neither `--target` has an eslogger parser: `eslogger` is target-invariant NDJSON
(`output_targets.py`), and the external-parser harnesses cover only Zeek/Windows/syslog/etc., so
the app supplies its own `macos:eslogger` sourcetype. All records parse (`_time` from the ns
envelope `time`, µs kept), and all 15 saved searches return the expected beat:

- **AMOS**: launchd → ad-hoc/no-Team-ID `CleanMyMacX Helper` → signed `osascript` with the fake
  dialog in argv → the dropper (not osascript) opens `login.keychain-db` → Zeek TLS to
  193.42.33.14 (`gateway.macos-analytics.top`, 2.45 MB out) 0.30 s after the keychain open.
- **BeaverTail**: `node npm install` → `sh -c node scripts/postinstall.js` → `node` (pid/ppid
  join) → DNS `api.ipcheck-beaver.cc` → TLS 45.128.199.72 3.6 s later.
- **CloudMensis**: ad-hoc `cloudsyncd` creates `~/Library/LaunchAgents/com.apple.cloudsyncd.plist`,
  then `btm_launch_item_add` from `backgroundtaskmanagementd` with `instigator` pid = writer pid.
- **SSH**: `openssh_login`/`openssh_logout` (554 s) matches the Zeek 22/tcp conn from MAC-IT-01
  (556 s, SF), with login 3 s after the TCP open.

Hunter friction (handled in the app; worth a slide): the ES↔Zeek join needs an asset lookup
(ES has no IP or hostname; host comes from the directory); on `exec` the `process` is the parent
image; `event_type` needs an int→name lookup; JSON null extracts as `"null"`; `map` can't be used
in saved searches; `bitand()` returned nothing on 10.2.3.

### Realism findings (not fixed; generator changes need a proposal first)

1. **ssh client parented by sshd** (MAC-IT-01): `/usr/bin/ssh` is exec'd from a fork of the local
   `sshd` listener (ppid 327) instead of the `zsh` spawned 2 s earlier in Terminal. A hunter
   reads that as sshd spawning an outbound ssh, which looks like a lateral-movement relay.
2. **Windows DNS behavior on Macs**: all three Macs query `isatap`, `wpad`, and suffix-appended
   `login.microsoftonline.com.clearwater-studio.test` (devolution), sent unicast to public
   resolvers. ISATAP is Windows-only; `.local` goes over mDNS, not 1.1.1.1.
3. **No internal resolver**: Macs send internal names (`printer01.clearwater-studio.test`) to
   1.1.1.1/8.8.8.8 and get NXDOMAIN. That's a scenario topology choice; adding a DNS server
   system would fix it.
4. **launchd children carry a tty**: all 16 launchd→exec records (Firefox, VS Code, backupd,
   cloudd, the AMOS dropper) have `tty` `/dev/ttys00N`; the fork child also inherits a tty
   launchd doesn't have. Real launchd-spawned processes have `tty: null`.
5. **Exit `ppid` is 0**: 14 of 22 `exit` records report `ppid: 0` (e.g. the dropper, which had
   ppid 1 at exec).
6. **npm exits before its lifecycle script**: `node npm install` (31022) exits at 14:51:21.667,
   before its `sh` (14:51:28) and the postinstall `node` (14:52:00). Real npm waits.
   `~/Library/Caches/7D515BC0.tmp` is created by the waiting `sh`, not the postinstall `node`.
7. **sshd exec argv is a proctitle**: `args: ["sshd:", "riley.chen", "[priv]"]`. That is the
   setproctitle string `ps` shows; exec argv would be the real `sshd` command line.
8. **`global_seq_num` order ≠ time order**: 2/5/5 seq→time inversions per host, and file lines are
   in seq order. Real eslogger delivers in increasing message time.
9. **Synthetic tells**: an exit cascade 1 µs apart (git, zsh, login, Terminal at
   14:20:37.035461–464), and three envelope times at `.000000xxx`
   (`15:44:00.000000352Z` openssh_logout, `15:54:42.000000953Z`).
10. Volume is still low (≤51 ES records/Mac/2 h), so every hunt query returns exactly the answer.
    Realistic density would make the stacking query (`OBTS 01`) earn its place.

Nuance for the talk: macOS `/bin/sh` is bash in sh mode, and `sh -c "<single command>"` usually
execs in place. Real telemetry can show the postinstall `node` on the same pid as the `sh`, which
breaks a pid/ppid chain join like `BeaverTail 2`.
