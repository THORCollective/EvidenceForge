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
