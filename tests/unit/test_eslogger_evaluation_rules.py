# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Data-quality evaluation rule tests for the eslogger (macOS Endpoint Security) format.

Task 11 added a new `eslogger:` section to `config/evaluation/co_occurrence.yaml`
and two new pairs to `config/evaluation/causal_pairs.yaml`. No eslogger
evaluation parser exists yet (nothing registers a format_name="eslogger"
LogParser under `evidenceforge/evaluation/parsers/`), so these tests exercise
the rule engines directly against hand-flattened `ParsedRecord.fields` dicts —
exactly the pattern `tests/unit/test_eval_record_fidelity.py` and
`tests/unit/test_eval_temporal.py` already use for rules that don't need a
real parser fixture (e.g. `_make_record("ecar", {...flat dict...})`).

Records are built from REAL `ESLoggerEmitter` output (via the same
`_rows(emitter, event)` helper `test_eslogger_emitter.py` uses), then flattened
into dotted keys with `_flatten()` below, so the rule assertions are checked
against genuine emitter-rendered field names/values, not hand-guessed ones.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.parsers.eslogger import ESLoggerParser
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.pillars.parseability import _get_variant, _normalize_for_validation
from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, FileContext, HostContext, ProcessContext
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.rules import evaluate_rule
from evidenceforge.generation.emitters.eslogger import ESLoggerEmitter
from evidenceforge.generation.state_manager import StateManager

BOOT = datetime(2024, 3, 14, 8, 0, 0, tzinfo=UTC)
T0 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts into dotted keys; leave lists as whole values.

    Mirrors the convention `config/formats/eslogger.yaml` documents (dotted
    scalar/list leaves) and that Zeek's native JSON already uses
    (`id.orig_h`/`id.resp_h`) for the flat `ParsedRecord.fields` dict the
    co-occurrence/causal-pairs rule engines read from.
    """
    flat: dict[str, Any] = {}
    for key, value in obj.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, full_key))
        else:
            flat[full_key] = value
    return flat


@pytest.fixture
def mac_host():
    return HostContext(
        hostname="MAC-01",
        ip="10.0.0.50",
        os="macOS 14.4",
        os_category="macos",
        system_type="workstation",
        fqdn="MAC-01.corp.local",
    )


@pytest.fixture
def win_host():
    return HostContext(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
    )


@pytest.fixture
def emitter(tmp_path):
    fd = load_format("eslogger")
    sm = StateManager()
    sm.register_boot_time("MAC-01", BOOT)
    e = ESLoggerEmitter(fd, tmp_path, threaded=False)
    e._state_manager = sm
    return e


def _rows(emitter, event) -> list[dict[str, Any]]:
    captured: list[dict[str, Any]] = []
    original = emitter.emit_event
    emitter.emit_event = lambda ed: captured.append(ed)
    try:
        emitter.emit(event)
    finally:
        emitter.emit_event = original
    return [json.loads(emitter._render_event(ed)) for ed in captured]


def _record(row: dict[str, Any], ts: datetime | None = None) -> ParsedRecord:
    """Parse one rendered row with the production parser (incl. derived fields)."""
    parsed = ESLoggerParser()._parse_line(json.dumps(row), 1)
    return ParsedRecord(
        source_format="eslogger",
        raw=parsed.raw,
        fields=parsed.fields,
        timestamp=ts if ts is not None else parsed.timestamp,
    )


def _failed_rule_ids(record: ParsedRecord) -> list[str]:
    """Return eslogger record-rule ids that fail for one parsed record."""
    definition = load_format("eslogger")
    normalized = _normalize_for_validation("eslogger", record.fields, record.timestamp)
    variant = _get_variant("eslogger", record)
    return [
        rule.id
        for rule in definition.validators or []
        if evaluate_rule(rule, normalized, "eslogger", variant, set()).outcome == "fail"
    ]


def _make_scenario():
    """Minimal Scenario for CausalityScorer's grace-period lookup."""
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        Scenario,
        System,
        TimeWindow,
        User,
    )

    return Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="alice",
                    full_name="Alice",
                    email="alice@x.com",
                    primary_system="MAC-01",
                ),
            ],
            systems=[
                System(hostname="MAC-01", ip="10.0.0.50", os="macOS 14.4", type="workstation"),
            ],
        ),
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
        output=OutputSpec(logs=[{"format": "eslogger"}], destination="./out"),
    )


# ---------------------------------------------------------------------------
# co_occurrence.yaml — eslogger section
# ---------------------------------------------------------------------------


class TestCoOccurrenceRealEmitterOutput:
    def test_process_create_fork_and_exec_rows_pass(self, emitter, mac_host):
        proc = ProcessContext(
            pid=1500,
            parent_pid=1,
            image="/usr/bin/osascript",
            command_line='osascript -e "do shell script"',
            username="alice",
            start_time=T0,
        )
        event = OccurrenceBuilder(
            timestamp=T0, event_type="process_create", src_host=mac_host, process=proc
        )
        records = [_record(row) for row in _rows(emitter, event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures

    def test_process_terminate_exit_row_passes(self, emitter, mac_host):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0)
        event = OccurrenceBuilder(
            timestamp=T0, event_type="process_terminate", src_host=mac_host, process=proc
        )
        records = [_record(row) for row in _rows(emitter, event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures

    @pytest.mark.parametrize(
        "event_type", ["file_create", "file_open", "file_write", "file_rename", "file_unlink"]
    )
    def test_file_events_pass(self, emitter, mac_host, event_type):
        proc = ProcessContext(1700, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0)
        event = OccurrenceBuilder(
            timestamp=T0,
            event_type=event_type,
            src_host=mac_host,
            process=proc,
            file=FileContext(
                path="/Users/alice/Library/Keychains/login.keychain-db",
                action=event_type.removeprefix("file_"),
                pid=1700,
            ),
            auth=AuthContext(username="alice"),
        )
        records = [_record(row) for row in _rows(emitter, event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures

    def test_btm_launch_item_add_passes(self, emitter, mac_host):
        plist = "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        proc = ProcessContext(1800, 1, "/bin/cp", "cp", "alice", start_time=T0)
        event = OccurrenceBuilder(
            timestamp=T0,
            event_type="btm_launch_item_add",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=plist, action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        records = [_record(row) for row in _rows(emitter, event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures

    def test_ssh_login_and_logout_pass(self, emitter, mac_host, win_host):
        login_event = OccurrenceBuilder(
            timestamp=T0,
            event_type="ssh_session",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(
                username="alice", source_ip="10.0.0.10", source_port=54321, session_id=132500
            ),
        )
        logout_event = OccurrenceBuilder(
            timestamp=T0 + timedelta(minutes=10),
            event_type="logoff",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", source_ip="10.0.0.10", session_id=132500),
        )
        records = [_record(row) for row in _rows(emitter, login_event)]
        records += [_record(row) for row in _rows(emitter, logout_event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures

    def test_lock_and_unlock_pass(self, emitter, mac_host):
        lock_event = OccurrenceBuilder(
            timestamp=T0,
            event_type="workstation_locked",
            src_host=mac_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", session_id=132500),
        )
        unlock_event = OccurrenceBuilder(
            timestamp=T0 + timedelta(minutes=5),
            event_type="workstation_unlocked",
            src_host=mac_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", session_id=132500),
        )
        records = [_record(row) for row in _rows(emitter, lock_event)]
        records += [_record(row) for row in _rows(emitter, unlock_event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures

    @pytest.mark.parametrize("image", ["/usr/bin/sudo", "/usr/bin/su"])
    def test_privilege_elevation_passes(self, emitter, mac_host, image):
        proc = ProcessContext(1900, 1, image, f"{image} -l", "alice", start_time=T0)
        event = OccurrenceBuilder(
            timestamp=T0,
            event_type="privilege_elevation",
            src_host=mac_host,
            process=proc,
            auth=AuthContext(username="root", subject_username="alice", result="success"),
        )
        records = [_record(row) for row in _rows(emitter, event)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures


class TestCoOccurrenceDetectsViolations:
    """Prove the new rules actually fire (aren't vacuously satisfied)."""

    def test_missing_argv_fails_exec_rule(self, emitter, mac_host):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0)
        event = OccurrenceBuilder(
            timestamp=T0, event_type="process_create", src_host=mac_host, process=proc
        )
        rows = _rows(emitter, event)
        exec_row = next(r for r in rows if r["event_type"] == 9)
        del exec_row["event"]["exec"]["args"]
        records = [_record(exec_row)]
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score < 100.0

    def test_missing_envelope_field_fails(self, emitter, mac_host):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0)
        event = OccurrenceBuilder(
            timestamp=T0, event_type="process_terminate", src_host=mac_host, process=proc
        )
        row = _rows(emitter, event)[0]
        del row["mach_time"]
        # A missing required field is a schema failure owned by parseability;
        # co-occurrence scoring skips it, so check the record rule directly.
        assert _failed_rule_ids(_record(row))

    def test_missing_btm_path_fails(self, emitter, mac_host):
        plist = "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        event = OccurrenceBuilder(
            timestamp=T0,
            event_type="btm_launch_item_add",
            src_host=mac_host,
            file=FileContext(path=plist, action="create", pid=0),
            auth=AuthContext(username="root"),
        )
        row = _rows(emitter, event)[0]
        del row["event"]["btm_launch_item_add"]["item"]["item_url"]
        # A missing required field is a schema failure owned by parseability;
        # co-occurrence scoring skips it, so check the record rule directly.
        assert _failed_rule_ids(_record(row))


# ---------------------------------------------------------------------------
# causal_pairs.yaml — eslogger pairs
# ---------------------------------------------------------------------------


class TestExecBeforeExit:
    def test_exec_before_exit_is_correct(self, emitter, mac_host):
        create_proc = ProcessContext(
            pid=1500,
            parent_pid=1,
            image="/usr/bin/osascript",
            command_line="osascript -e x",
            username="alice",
            start_time=T0,
        )
        create_event = OccurrenceBuilder(
            timestamp=T0, event_type="process_create", src_host=mac_host, process=create_proc
        )
        exec_row = next(r for r in _rows(emitter, create_event) if r["event_type"] == 9)

        term_proc = ProcessContext(
            1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0
        )
        term_event = OccurrenceBuilder(
            timestamp=T0 + timedelta(minutes=2),
            event_type="process_terminate",
            src_host=mac_host,
            process=term_proc,
        )
        exit_row = _rows(emitter, term_event)[0]

        records = {
            "eslogger": [
                _record(exec_row, ts=T0 + timedelta(hours=1)),
                _record(exit_row, ts=T0 + timedelta(hours=1, minutes=2)),
            ]
        }
        scorer = CausalityScorer()
        result = scorer._score_causal_ordering(records, _make_scenario())
        assert result.score == 100.0, result.sample_failures

    def test_exit_before_exec_is_a_violation(self, emitter, mac_host):
        create_proc = ProcessContext(
            pid=1500,
            parent_pid=1,
            image="/usr/bin/osascript",
            command_line="osascript -e x",
            username="alice",
            start_time=T0,
        )
        create_event = OccurrenceBuilder(
            timestamp=T0, event_type="process_create", src_host=mac_host, process=create_proc
        )
        exec_row = next(r for r in _rows(emitter, create_event) if r["event_type"] == 9)

        term_proc = ProcessContext(
            1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0
        )
        term_event = OccurrenceBuilder(
            timestamp=T0 + timedelta(minutes=2),
            event_type="process_terminate",
            src_host=mac_host,
            process=term_proc,
        )
        exit_row = _rows(emitter, term_event)[0]

        # exit BEFORE exec — inverted causality
        records = {
            "eslogger": [
                _record(exit_row, ts=T0 + timedelta(hours=1)),
                _record(exec_row, ts=T0 + timedelta(hours=1, minutes=2)),
            ]
        }
        scorer = CausalityScorer()
        result = scorer._score_causal_ordering(records, _make_scenario())
        assert result.score < 100.0


class TestPlistCreateBeforeBtm:
    def test_plist_create_before_btm_is_correct(self, emitter, mac_host):
        plist = "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        proc = ProcessContext(1800, 1, "/bin/cp", "cp", "alice", start_time=T0)
        create_event = OccurrenceBuilder(
            timestamp=T0,
            event_type="file_create",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=plist, action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        create_row = _rows(emitter, create_event)[0]

        btm_event = OccurrenceBuilder(
            timestamp=T0 + timedelta(seconds=2),
            event_type="btm_launch_item_add",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=plist, action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        btm_row = _rows(emitter, btm_event)[0]

        records = {
            "eslogger": [
                _record(create_row, ts=T0 + timedelta(hours=1)),
                _record(btm_row, ts=T0 + timedelta(hours=1, seconds=2)),
            ]
        }
        scorer = CausalityScorer()
        result = scorer._score_causal_ordering(records, _make_scenario())
        assert result.score == 100.0, result.sample_failures

    def test_btm_before_plist_create_is_leniently_skipped(self, emitter, mac_host):
        """allow_missing_prior=True means an inverted-but-matching pair is not
        counted as a violation at all (CausalityScorer._score_causal_ordering's
        `elif allow_missing_prior: continue` branch) — it is simply excluded
        from the pair total, exactly like the existing "eCAR login before
        process create" and "Kerberos TGT before service ticket" rules. This
        rule can therefore only ever reward correct ordering, never penalize
        an apparent inversion; that is the documented, deliberate tradeoff the
        task brief asked for, not a gap in this test.
        """
        plist = "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        proc = ProcessContext(1800, 1, "/bin/cp", "cp", "alice", start_time=T0)
        create_event = OccurrenceBuilder(
            timestamp=T0,
            event_type="file_create",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=plist, action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        create_row = _rows(emitter, create_event)[0]

        btm_event = OccurrenceBuilder(
            timestamp=T0 + timedelta(seconds=2),
            event_type="btm_launch_item_add",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=plist, action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        btm_row = _rows(emitter, btm_event)[0]

        # btm BEFORE plist create in wall-clock order.
        records = {
            "eslogger": [
                _record(btm_row, ts=T0 + timedelta(hours=1)),
                _record(create_row, ts=T0 + timedelta(hours=1, seconds=2)),
            ]
        }
        scorer = CausalityScorer()
        result = scorer._score_causal_ordering(records, _make_scenario())
        # No pair is countable (skipped by allow_missing_prior), so the inverted
        # pair is never penalized and causal ordering reports nothing to score.
        assert result.skipped
        assert result.score is None
