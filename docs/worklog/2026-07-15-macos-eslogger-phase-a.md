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
