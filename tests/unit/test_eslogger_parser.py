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

"""Tests for the eslogger (macOS Endpoint Security) evaluation parser.

Task 11 wrote `co_occurrence.yaml`/`causal_pairs.yaml` rules for eslogger but
discovered no `LogParser` existed to let `eforge evaluate` discover/parse real
`eslogger.ndjson` output. This module exercises the new `ESLoggerParser`
against real `ESLoggerEmitter` output (written to disk through the real
per-host-FQDN writer pipeline, not hand-constructed dicts) to prove the parser
+ discovery + rule engines work together end-to-end.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.evaluation.parsers import ParsedRecord, discover_log_files
from evidenceforge.evaluation.parsers.eslogger import ESLoggerParser
from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer
from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import FileContext, HostContext, ProcessContext
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.eslogger import ESLoggerEmitter
from evidenceforge.generation.state_manager import StateManager

BOOT = datetime(2024, 3, 14, 8, 0, 0, tzinfo=UTC)
T0 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


def _mac_host() -> HostContext:
    return HostContext(
        hostname="MAC-01",
        ip="10.0.0.50",
        os="macOS 14.4",
        os_category="macos",
        system_type="workstation",
        fqdn="MAC-01.corp.local",
    )


def _write_real_eslogger_output(base_dir: Path) -> Path:
    """Emit a real process_create event through ESLoggerEmitter to disk.

    Returns the path to the per-host eslogger.ndjson file the real writer
    pipeline produced (base_dir/<fqdn>/eslogger.ndjson, mirroring eCAR's
    per-host directory routing).
    """
    fd = load_format("eslogger")
    sm = StateManager()
    sm.register_boot_time("MAC-01", BOOT)
    emitter = ESLoggerEmitter(fd, base_dir, threaded=False)
    emitter._state_manager = sm

    host = _mac_host()
    proc = ProcessContext(
        pid=1500,
        parent_pid=1,
        image="/usr/bin/osascript",
        command_line='osascript -e "do shell script"',
        username="alice",
        start_time=T0,
    )
    emitter.emit(
        SecurityEvent(timestamp=T0, event_type="process_create", src_host=host, process=proc)
    )
    emitter.close()

    out_path = base_dir / "MAC-01.corp.local" / "eslogger.ndjson"
    assert out_path.exists(), f"expected real emitter output at {out_path}"
    return out_path


class TestCanParse:
    def test_matches_eslogger_ndjson(self):
        parser = ESLoggerParser()
        assert parser.can_parse(Path("eslogger.ndjson")) is True

    def test_matches_regardless_of_directory(self):
        parser = ESLoggerParser()
        assert parser.can_parse(Path("/out/MAC-01.corp.local/eslogger.ndjson")) is True

    def test_rejects_other_filenames(self):
        parser = ESLoggerParser()
        assert parser.can_parse(Path("ecar.json")) is False
        assert parser.can_parse(Path("eslogger.json")) is False
        assert parser.can_parse(Path("eslogger.ndjson.bak")) is False


class TestParsesRealEmitterOutput:
    def test_parses_all_lines(self, tmp_path):
        path = _write_real_eslogger_output(tmp_path)
        parser = ESLoggerParser()
        records = list(parser.parse_file(path))
        # process_create renders a fork + exec pair (see ESLoggerEmitter
        # docstring for _render_process_create).
        assert len(records) == 2
        assert all(isinstance(r, ParsedRecord) for r in records)
        assert all(r.source_format == "eslogger" for r in records)
        assert all(not r.parse_errors for r in records)

    def test_flattens_envelope_and_nested_fields(self, tmp_path):
        path = _write_real_eslogger_output(tmp_path)
        parser = ESLoggerParser()
        records = list(parser.parse_file(path))
        exec_record = next(r for r in records if r.fields.get("event_type") == 9)

        # Envelope fields (top-level, no nesting).
        assert exec_record.fields["schema_version"] is not None
        assert exec_record.fields["seq_num"] == 2
        assert exec_record.fields["global_seq_num"] == 2

        # Nested "process.*"/"process.audit_token.*" flattened to dotted keys.
        assert exec_record.fields["process.pid"] == 1500
        assert "process.audit_token.pid" in exec_record.fields
        assert exec_record.fields["process.signing_id"] is not None

        # "event.exec.*" flattened; the list-valued "args" leaf is preserved
        # as a list, not further flattened.
        assert isinstance(exec_record.fields["event.exec.args"], list)
        assert exec_record.fields["event.exec.args"]

    def test_extracts_timestamp(self, tmp_path):
        path = _write_real_eslogger_output(tmp_path)
        parser = ESLoggerParser()
        records = list(parser.parse_file(path))
        assert all(r.timestamp == T0 for r in records)

    def test_file_event_nested_path_flattened(self, tmp_path):
        fd = load_format("eslogger")
        sm = StateManager()
        sm.register_boot_time("MAC-01", BOOT)
        emitter = ESLoggerEmitter(fd, tmp_path, threaded=False)
        emitter._state_manager = sm
        host = _mac_host()
        proc = ProcessContext(1700, 1, "/usr/bin/osascript", "osascript", "alice", start_time=T0)
        emitter.emit(
            SecurityEvent(
                timestamp=T0,
                event_type="file_create",
                src_host=host,
                process=proc,
                file=FileContext(
                    path="/Users/alice/Library/LaunchAgents/com.evil.persist.plist",
                    action="create",
                    pid=1700,
                ),
            )
        )
        emitter.close()
        path = tmp_path / "MAC-01.corp.local" / "eslogger.ndjson"
        record = next(iter(ESLoggerParser().parse_file(path)))
        assert (
            record.fields["event.create.destination.path"]
            == "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        )


class TestParseErrors:
    def test_malformed_json_line_records_parse_error(self, tmp_path):
        path = tmp_path / "eslogger.ndjson"
        path.write_text("{not valid json\n", encoding="utf-8")
        records = list(ESLoggerParser().parse_file(path))
        assert len(records) == 1
        assert records[0].parse_errors
        assert records[0].timestamp is None

    def test_invalid_time_field_records_parse_error(self, tmp_path):
        path = tmp_path / "eslogger.ndjson"
        path.write_text(json.dumps({"time": "not-a-timestamp"}) + "\n", encoding="utf-8")
        records = list(ESLoggerParser().parse_file(path))
        assert len(records) == 1
        assert any("timestamp" in e.lower() for e in records[0].parse_errors)

    def test_blank_lines_skipped(self, tmp_path):
        path = tmp_path / "eslogger.ndjson"
        path.write_text("\n\n" + json.dumps({"time": "2024-03-15T10:00:00.000000Z"}) + "\n\n")
        records = list(ESLoggerParser().parse_file(path))
        assert len(records) == 1


class TestDiscovery:
    def test_discovers_eslogger_under_per_host_directory(self, tmp_path):
        _write_real_eslogger_output(tmp_path)
        files = discover_log_files(tmp_path)
        assert "eslogger" in files
        assert files["eslogger"] == [tmp_path / "MAC-01.corp.local" / "eslogger.ndjson"]


class TestEndToEndWithCoOccurrenceRules:
    """Real emitter -> real parser -> real co_occurrence.yaml rule engine."""

    def test_real_output_passes_co_occurrence_rules(self, tmp_path):
        path = _write_real_eslogger_output(tmp_path)
        records = list(ESLoggerParser().parse_file(path))
        scorer = PlausibilityScorer()
        result = scorer._score_co_occurrence({"eslogger": records})
        assert result.score == 100.0, result.sample_failures
