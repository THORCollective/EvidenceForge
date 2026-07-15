# Plan: macOS eslogger Support — Phase A

Repo: `THORCollective/EvidenceForge` (fork of `Cisco-Talos/EvidenceForge`), branch `macos-eslogger`, local checkout `/Users/sydney/sans/EvidenceForge-thor`. Upstream design doc: `docs/plans/2026-07-11-macos-eslogger-design.md`. Facts: `goals/macos-eslogger-phase-a/facts.md`.

## Solution approach

Add `macos` as a first-class `os_category` and a new host-multiplexed `ESLoggerEmitter` (`eslogger_<host>.ndjson`, modeled directly on `EcarEmitter`) that renders existing canonical events (process, file, auth, connection-adjacent) into authentic macOS Endpoint Security NDJSON — no private generation pipeline. Work proceeds bottom-up: fix the (currently triplicated, inconsistent) `os_category` detection first since everything else keys off it, then wire world-model/state-manager macOS support, then data-driven pools, then the emitter itself, then the one new causal rule (BTM), then validation/evaluation/docs, then the three-hunt demo scenario that doubles as the integration test and the CFP evidence artifact.

Two explicit engineering decisions this plan makes (flagged as risks below, not left ambiguous): (1) macOS SSH-session identity reuses the ES audit-token `session_id` in place of Linux's `logind` session id — there is no macOS `logind` equivalent, and ES already carries a natural per-session identifier; (2) the BTM causal rule requires a new causal-engine hook point on `file_create` dispatch (today file_create bypasses the causal engine entirely), scoped tightly by a path-substring `matches()` check so it is zero-cost for every non-LaunchAgents file event.

## Steps

### 1. Consolidate `os_category` detection to recognize macOS
Three independent implementations exist and must all learn macOS patterns (`macos`, `mac os`, `darwin`, `osx`), and one has a latent bug worth fixing while we're in there:
- `generation/activity/helpers.py:34-57` (`_get_os_category`, canonical/most-imported) — add macOS branch.
- `validation/schema.py:81-82,121-135` (`_WINDOWS_PATTERNS`/`_LINUX_PATTERNS`/`_get_os_category`) — add `_MACOS_PATTERNS` + branch.
- `generation/activity/suspicious_benign.py:512-517` (`_get_os_category`) — currently `if "windows" ... else return "linux"` with **no unknown fallback at all**; add explicit macOS branch here as a real bug fix, not just an addition.
- `evaluation/visibility.py` — schema.py's comment says this "mirrors" it; update in lockstep.

**Verification:** unit test asserting all four call sites return `"macos"` for `"macOS 14.5"` / `"Darwin"` / `"macOS Sonoma"` strings; existing windows/linux classification tests unaffected.

### 2. World model & state manager macOS wiring
- `generation/world_model.py:320` — `supports_ssh = os_category in ("linux", "macos")`.
- `generation/world_model.py:344` (`_resolve_service_defaults`) — add a macOS branch (today macOS falls into the Linux-shaped else).
- `generation/world_model.py:844` (`_find_windows_interactive_session`) — generalize beyond Windows-only, or add a parallel macOS interactive-session-reuse path (loginwindow-rooted).
- `generation/world_model.py:946` — decide macOS's bucket for interactive-logon timing jitter (mirror the linux branch is the recommended default).
- `generation/state_manager.py:804-817` (`_initialize_pid_allocator`) — macOS currently falls into the Linux-shaped PID range; add explicit macOS branch.
- `generation/state_manager.py:991-993` (`create_process`) — path-separator heuristic (`"\\" in image` → windows, else linux) needs a real macOS check since macOS paths are also forward-slash; use `os_category` from the system, not path-sniffing, wherever available.
- New: `pidversion` tracking. Nothing in the codebase tracks this today (confirmed zero hits) — add a `StateManager`-owned counter/dict (e.g. `_pidversion: dict[tuple[system, pid], int]`, bumped on PID reuse) since ES's audit token requires it and it is durable per-PID-slot state, not a rendering-time value.

**Verification:** unit tests for `WorldModel._compile_host` with an `os: macos` system (asserts `supports_ssh=True`, service defaults populated); state-manager unit test asserting macOS PID allocation range and `pidversion` increments correctly on PID reuse.

### 3. macOS process ancestry seeding
Add `_seed_macos_process_tree` in `generation/engine/emitter_setup.py`, mirrored on the existing `_seed_linux_process_tree` (rooted at `RunningProcess(pid=1, image="/usr/lib/systemd/systemd", ...)`, `emitter_setup.py:816-827`), rooted instead at `launchd` pid 1, and dispatched from `_seed_system_process_trees` (`emitter_setup.py:563-589`) when `os_category == "macos"`.

**Verification:** integration-style unit test: every process on a generated macOS host has `launchd` (pid 1) as its ultimate ancestor.

### 4. Data-driven macOS pools (realism rule #2/#3)
- `config/activity/spawn_rules.yaml` — new top-level `macos:` section (alongside existing `windows:`/`linux:`); `generation/activity/spawn_rules.py:90` — generalize the `os_key = "windows" if ... else "linux"` ternary to a 3-way dispatch, add `get_reverse_index_macos()`.
- EDR file/path pools (`generation/activity/edr_pools.py:217-278,665,743`) — add `file_paths_macos`/`paths_macos` YAML keys and branch logic (currently hard binary windows/linux).
- `generation/activity/application_catalog.py` — add `platforms.macos` entries to catalog YAML data so `has_catalog_entry`/`is_system_type_allowed`/`is_persona_allowed` recognize macOS apps.
- `generation/activity/proxy_user_agents.py:151-153,236-250,306-307,349,364-368` — macOS currently silently falls to the Windows UA pool; add a macOS pool (Safari/Chrome-on-macOS UAs per the design doc) and branch on it explicitly.
- `generation/engine/baseline.py:3547-3552` (`user_agent_pool_by_os` dict) — add `"macos": "browser_macos"`.
- `generation/engine/storyline.py:2432-2435` — the Windows-path-separator OS-inference repair heuristic assumes forward-slash implies Linux; needs to check `os_category` explicitly since macOS paths are also forward-slash, to avoid mis-repairing macOS process images.
- `generation/activity/timing_profiles.py:212` — 3-way `os_key` dispatch alongside spawn_rules.
- Default shell `/usr/bin/zsh` — land wherever bash/shell-exe fallbacks are chosen (edr_pools service-account/profile-template logic, application_catalog image-path resolution, the Linux shell-command bundle).
- `generation/activity/traffic_profiles.py` is already OS-agnostic (string equality against YAML `os` tags, not a binary branch) — just add `macos`-tagged entries to the relevant YAML, no Python change needed.

**Verification:** one unit test per loader (spawn rules returns a macOS parent config; edr_pools returns macOS paths for a macOS process; proxy UA pool returns a Safari/Chrome-macOS string; storyline repair heuristic doesn't corrupt a macOS image path).

### 5. SSH bundle: macOS as a valid target (and source)
- `generation/actions/ssh_session.py:496` — source-side client process is only materialized for Linux sources (`ensure_linux_ssh_client_process`); add a macOS-source equivalent (macOS ships `ssh` in Terminal).
- `generation/actions/ssh_session.py:712,665` (`_prepare_linux_auth_plan`/`_plan_linux_auth`) — hard-gated `!= "linux"` returns `None`, meaning a macOS target today gets transport but zero destination-side auth/session evidence. Widen the gate to include macOS, and for session identity, **reuse the ES audit-token `session_id`** (rather than inventing a macOS `logind` concept) as the macOS analog of `logind_session_id` — this maps cleanly onto the design doc's `AuthContext` → `lw_session` lock/unlock mapping.

**Verification:** integration test: an SSH session targeting a macOS host produces destination-side `openssh_login` (eslogger) evidence, not just the TCP/22 transport.

### 6. FileContext action expansion
- `events/contexts.py:252-257` (`FileContext.action`) — today only `create`/`modify`/`delete`/`read` exist. Add `open`/`write`/`rename`/`unlink` (design doc's ES file-event mapping needs `open` for AMOS's keychain-file access and `unlink`/`rename` for completeness).
- `generation/activity/generator.py:324-329` (`_FILE_ACTION_EVENT_TYPES`) — add corresponding `event_type` entries (`file_open`, `file_write`, `file_rename`, `file_unlink`).
- Touch points that build `FileContext` events: `generator.py:11283-11311` (guaranteed process-image file-create), `edr_pools.py`-driven probabilistic side effects (`generator.py:11330-11394`), `generation/actions/file_transfer.py:780,900,1095,1161`.

**Verification:** unit test asserting `action="open"` dispatches as `event_type="file_open"` and renders correctly in eslogger output; existing create/modify/delete/read tests unaffected.

### 7. BTM causal rule (plist create → `btm_launch_item_add`)
- `generation/causal/engine.py` (`ExpansionContext` dataclass, `engine.py:40-87`) — add a `file_path: str | None` field, threaded through `_build_expansion_context`.
- **New causal-engine hook**: today file_create events are dispatched directly (`self.dispatcher.dispatch(...)`), bypassing `_expand_and_emit` entirely — the only 3 existing call sites are `"logon"` (`generator.py:9282`), `"connection"` (`generator.py:17250`), `"create_remote_thread"` (`generator.py:24524`). Add a 4th: `self._expand_and_emit("file_create", ctx_with_file_path)` at the point(s) that build file-create `SecurityEvent`s (`generator.py:11283`, `file_transfer.py:780`). Scope the risk by keeping the new rule's `matches()` a tight path-substring check (`"LaunchAgents" in file_path or "LaunchDaemons" in file_path`) so it is a no-op for every other file_create in the system — this preserves the "auto-generate consequents uniformly" causal-engine principle without broad blast radius.
- `generation/causal/rules.py` — new `PlistCreateBeforeBtmLaunchItem` rule (priority similar to `DnsBeforeConnection`, template at `rules.py:130-174`), `expand()` returns an `ExpandedEvent(method="_emit_btm_launch_item_add", kwargs={...}, timing=..., description=...)`.
- `generation/causal/registry.py:36-47` — register the new rule in `default_rules()`.
- `generation/activity/generator.py` — implement `_emit_btm_launch_item_add(...)`, building the new ES-only event/context and dispatching it (eslogger-only; no other emitter renders BTM).

**Verification:** unit test at the causal-rule level (`matches()`/`expand()` in isolation); integration test on the CloudMensis demo system: a storyline plist `create` event under `LaunchAgents` produces both the file_create event and a derived `btm_launch_item_add` in eslogger output, with correct after-create timing.

### 8. `config/activity/macos_signing.yaml` + loader
Follow `generation/activity/tls_issuers.py` (`tls_issuers.py:1-45`) exactly: module-level `_MACOS_SIGNING_PATH = get_activity_directory() / "macos_signing.yaml"`, `_CACHED_SIGNING: dict[str, Any] | None = None`, a `_merge_macos_signing(default, overlay)` merge function (keyed list merge via `merge_keyed_list`), and `load_macos_signing()` following the identical cache-check-then-`load_with_overlay` pattern. YAML maps known binaries → `signing_id`/`team_id`/`is_platform_binary`; third-party apps → team IDs. Storyline malware (AMOS `osascript` payload, BeaverTail's `node`/`npm`) defaults to unsigned/ad-hoc. Wire the lookup into the emitter's process-object rendering (step 9) and derive `cdhash`/`pidversion` via `_stable_seed` (`utils/rng.py:57-63`) or `stable_uuid` (`utils/rng.py:66-74`), scoped by a key including binary path + team ID — never `hash()`, never a globally-seeded RNG.

**Verification:** unit test for loader caching + lookup (known binary → expected signing id; unknown/malware binary → unsigned defaults); determinism test (same binary + same seed → same CDHash across two runs).

### 9. `ESLoggerEmitter` + `config/formats/eslogger.yaml`
- New `generation/emitters/eslogger.py`, subclassing `HostMultiplexEmitter` (template: `EcarEmitter`, `emitters/ecar.py:207`) with `_log_filename = "eslogger.ndjson"`. `can_handle()` OS-gates on `event.src_host.os_category == "macos"` in addition to the supported-type-set check (eCAR's pattern at `ecar.py:253-267`, no OS gate needed there since it's cross-platform — eslogger does need one).
- Dispatch table (eCAR pattern, `ecar.py:269-293`) mapping canonical event types → `_render_*` methods: `process_create`→`exec`+`fork`, `process_terminate`→`exit`, `file_create/open/write/rename/unlink`→matching ES file events, `logon`(SSH)→`openssh_login`/`openssh_logout`, lock/unlock→`lw_session`, privilege-elevation→`sudo`/`su`. **No `connection` event type in `_supported_types`** — deliberate, per the design doc (ESF has no TCP-connect event; network correlation happens via existing Zeek conn/dns for the same host).
- Envelope fields (`schema_version`, `time`+derived `mach_time`, per-host `seq_num`/`global_seq_num`, `event_type`, full `process` object with audit token) built directly as a dict (eCAR bypasses Jinja2 entirely at `ecar.py:2984-3053`, builds JSON in Python — same approach here). `seq_num`/`global_seq_num` are per-host-writer format-native counters (not shared cross-source truth), so they can live emitter-local, analogous to how eCAR owns its own record ordering.
- `config/formats/eslogger.yaml` — mirror `config/formats/ecar.yaml` shape: `category: host`, `fields: [...]`, `output: {format: json, file_extension: ".ndjson", template: "{}"}` placeholder.
- Registration: `generation/emitters/__init__.py` (import + `__all__`), `generation/engine/emitter_setup.py`: `_build_emitter_classes()` add `"eslogger": ESLoggerEmitter` (~line 126), `_HOST_FORMATS` add `"eslogger"` (~line 155-163) so it routes through the per-host-FQDN-directory branch.

**Verification:** `test_eslogger_emitter.py` (per-event-type field rendering, mirroring eCAR's approach), `test_eslogger_spec_compliance.py` (structural/envelope conformance, mirroring `test_ecar_spec_compliance.py`), determinism test (same seed → byte-identical NDJSON, fact-18).

### 10. Validation OS-gating
- `validation/schema.py:81-82` — add `_MACOS_PATTERNS` (see step 1).
- `validation/schema.py:85-96` (`_OS_BOUND_FORMATS`/`_OS_EXPECTED_FORMATS`) — add `"eslogger": "macos"` and `"macos": {"eslogger"}`.
- `validation/schema.py:111` (`_LINUX_EVENT_TYPES = {"ssh_session"}`) — decide whether `ssh_session` becomes valid for macOS too (yes, per step 5) — likely needs a parallel `_MACOS_EVENT_TYPES` set or broadening this one, not a straight rename, since not all "linux event types" are meaningful on macOS.
- `validation/schema.py:2073,2240` (`if os_cat != "linux" and spec.surface in LINUX_ONLY_SURFACES`) — audit this "not linux" gate carefully: it will silently start including macOS in "Linux-only surface" exclusions unless explicitly special-cased. This needs a real decision per surface, not a blanket fix — flagged as a risk below.

**Verification:** unit tests for `_get_os_category` macOS recognition; validation test that a scenario with a macOS system + `eslogger` format passes; a scenario with a macOS system + `windows_event_security` format produces the expected OS-mismatch warning.

### 11. Evaluation rules
- `config/evaluation/co_occurrence.yaml` — new `eslogger:` top-level key (template: existing `ecar:` section, `co_occurrence.yaml:173-268`), e.g. exec events require `argv`/`signing_id` present.
- `config/evaluation/causal_pairs.yaml` — new pairs: exec↔fork process lifecycle (template: "eCAR process create before process terminate", `causal_pairs.yaml:80-94`); plist-create↔btm_launch_item_add (template: "eCAR login before process create", `causal_pairs.yaml:48-64`, using `allow_missing_prior`-style semantics since BTM is causal-engine-generated).

**Verification:** run the evaluation suite / `eforge evaluate` against the Phase A demo scenario output and confirm no unexpected co-occurrence/causal-pair violations.

### 12. Three-hunt demo scenario
New scenario under `scenarios/` with macOS systems reproducing AMOS/Atomic Stealer, DPRK BeaverTail, and CloudMensis-style persistence per the design doc's per-hunt event lists (all expressible with existing `process`/`connection`/`file` storyline event types — no new storyline event types needed). Doubles as the recording asset and as `tests/integration/test_macos_eslogger_scenario.py` (small scenario generated end-to-end in `tmp_path`, per existing integration-test convention — flat directory, no subdirectories).

**Verification:** `eforge generate` succeeds; integration test asserts `eslogger_<host>.ndjson` + Zeek conn/dns exist with expected per-hunt event counts; regenerating with the same seed produces byte-identical eslogger output (fact-18).

### 13. Docs & skills checklist
- `docs/reference/EVIDENCE_FORMATS.md` — new `## eslogger Format (macOS Endpoint Security)` section (template: eCAR section, lines 254-282: File/Format line, record-structure prose, correlation prose, object/action table, Known Limitations).
- `docs/reference/scenario-reference.md` — macOS `os:` example in the Systems section (line ~213-226); Event Types table (line 782-828) likely needs no new rows (no new storyline types), just Description-column mentions where eslogger now renders existing types.
- `docs/ARCHITECTURE.md` — add `ESLoggerEmitter` as a sibling leaf in the emitter tree (line ~594-618), document the BTM causal rule under the Causal Expansion Engine section (line ~744).
- `docs/design/event-model-prd.md` — Event Type Catalog table (line 223-250) Description-column updates only (e.g. `process_create` row gains "eslogger" alongside existing "(4688, syslog, eCAR)").
- `commands/eforge/scenario.md` — likely no event-type-list change (no new types); add a macOS `os:` example if useful.
- `commands/eforge/validate.md` — add guidance if the new OS-gating (step 10) produces macOS-specific warning messages.
- `scenarios/COVERAGE-TEST-PROMPT.md` — bump "9 log format groups" to 10 (add eslogger, line ~85-89); add macOS systems to the per-system OS mix description (line ~14-23).

**Verification:** manual read-through against this checklist; grep for "macos"/"eslogger" across the listed files to confirm each was touched (fact-19 — not automatable beyond presence-checking, final judgment is a human read).

### 14. Worklog + mechanics
Create `docs/worklog/2026-07-14-macos-eslogger-phase-a.md` tracking this effort per the project's memory workflow. Conventional commits throughout; no version bump on this feature branch; `uv run ruff check .` + `uv run ruff format --check .` + `uv run pytest --no-cov` clean before every commit.

**Verification:** worklog file exists and is committed; CI-equivalent local checks pass before each commit.

### 15. CFP abstract/outline (non-code deliverable)
Draft the OBTS v9 talk abstract/outline, referencing all three hunts and citing the generated three-hunt demo scenario (step 12) as evidence of a working, citable hunt loop. Not gated by automated tests — verified by your own review.

**Verification:** manual review/approval; no automated check.

## Risks / open questions

1. **Schedule risk is real and was explicitly not reduced** — the interview's cut-list answer was "nothing, all of Phase A is the floor," and `os_category` alone touches ~30 files. Recommend front-loading steps 1-3 (foundation) and step 9 (emitter core) first since nearly everything else is either gated by them or independently parallelizable (steps 4, 8, 10, 11, 13 can proceed once step 1 lands).
2. **File-create causal-engine hook (step 7)** is a genuine architecture change, not a pure addition — today file_create bypasses the causal engine entirely by design. Adding a hook here needs care to confirm it doesn't introduce ordering/perf regressions on the existing (very hot) file-create path. The tight `matches()` path-substring gate should make this safe, but it's worth a second look during implementation, not just at design time.
3. **macOS SSH-session identity (step 5)** — reusing the ES audit-token `session_id` in place of `logind_session_id` is this plan's proposed resolution, but it hasn't been validated against real eslogger `lw_session`/auth-session semantics. Flagged for a sanity check against whatever real eslogger schema references are available (per the interview: none exist yet, so this is validated against documented schema only, not real captures — accept some risk here).
4. **`LINUX_ONLY_SURFACES` "not linux" gating (step 10, `schema.py:2073,2240`)** — this pattern will silently start affecting macOS validation the moment `_get_os_category` recognizes "macos" (step 1 ships). Needs an explicit per-surface decision, not a blanket flip, before step 1 merges — otherwise macOS scenarios could pass or fail validation unpredictably in the gap between steps 1 and 10.
5. **Fork/PR mechanics** — this work now lives on `THORCollective/EvidenceForge` rather than upstream `Cisco-Talos/EvidenceForge`. AGENTS.md's `dev`→`main` release conventions (version bump, changelog, tag automation) are Cisco-Talos-specific; whether this fork adopts the same flow, a simplified one, or targets an eventual upstream PR back to Cisco-Talos is an open question for you, not assumed by this plan.
6. **No real eslogger captures available** (per interview) — unit tests validate emitter output against eslogger's documented schema/public examples only. If real captures surface before July 25, swapping them in as fixtures is a low-risk follow-up, not a blocker.
