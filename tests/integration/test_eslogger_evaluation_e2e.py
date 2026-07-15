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

"""End-to-end check that `eforge eval` can discover and score real eslogger output.

Task 11 added `eslogger:` co-occurrence rules and eslogger causal_pairs, but no
`LogParser` existed yet to let the real `eforge eval` CLI pipeline discover
`eslogger.ndjson` files at all (Task 11 had to fall back to hand-flattened
`ParsedRecord` fixtures in `test_eslogger_evaluation_rules.py`). This test runs
the full `eforge generate` -> `eforge eval` pipeline against a minimal macOS
scenario and confirms the new `ESLoggerParser` lets those rules actually run.

NOTE: this scenario's overall acceptance is expected to FAIL. Manual runs
during this task's development surfaced two pre-existing, unrelated gaps that
this task does not fix (out of scope for a self-contained parser addition):
  - `src/evidenceforge/formats/validator.py`'s spec-conformance checker flags
    many "Unknown field" warnings and a `process.team_id: Expected string, got
    NoneType` failure against every eslogger record — `config/formats/
    eslogger.yaml`'s declared field schema does not yet match
    `ESLoggerEmitter`'s actual nested output shape (team_id is documented as
    legitimately nullable in co_occurrence.yaml).
  - The causality pillar's "Event Presence"/"Temporal Integrity" dimensions
    report 0/100 because whatever per-format storyline-trace matcher those
    dimensions use has no eslogger case yet.
Neither gap involves `co_occurrence.yaml`/`causal_pairs.yaml` or this parser;
this test only asserts on the co-occurrence pillar, which is what Task 11's
new rules populate.
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app

runner = CliRunner()

_SCENARIO_YAML = """
version: "1.0"
name: eslogger-eval-e2e
description: "Minimal macOS scenario for eslogger evaluation parser end-to-end test"

environment:
  description: "Single macOS workstation"
  domain: corp.local

  users:
    - username: alice
      full_name: "Alice Example"
      email: "alice@corp.local"
      primary_system: MAC-01
      enabled: true

  systems:
    - hostname: MAC-01
      ip: 10.0.0.50
      os: "macOS 14.4"
      type: workstation
      assigned_user: alice

time_window:
  start: "2024-03-15T10:00:00Z"
  duration: "10m"

baseline_activity:
  description: "Minimal baseline activity"
  intensity: low
  variation: low

storyline:
  - id: evt-osascript
    time: "+1m"
    actor: alice
    system: MAC-01
    activity: "Run a shell script via osascript"
    events:
      - type: process
        process_name: "/usr/bin/osascript"
        command_line: 'osascript -e "do shell script \\"whoami\\""'

output:
  logs:
    - format: eslogger
  destination: "./output"
  compression: false
"""


def test_eforge_eval_discovers_and_scores_real_eslogger_output(tmp_path: Path) -> None:
    scenario_file = tmp_path / "scenario.yaml"
    scenario_file.write_text(_SCENARIO_YAML, encoding="utf-8")
    output_dir = tmp_path / "output"

    gen_result = runner.invoke(
        app,
        ["generate", str(scenario_file), "--output", str(output_dir)],
    )
    assert gen_result.exit_code == EXIT_SUCCESS, gen_result.stdout

    eslogger_files = list(output_dir.rglob("eslogger.ndjson"))
    assert eslogger_files, (
        f"expected eslogger.ndjson under {output_dir}, found: {gen_result.stdout}"
    )
    assert eslogger_files[0].stat().st_size > 0

    eval_result = runner.invoke(
        app,
        [
            "eval",
            str(output_dir),
            "--scenario",
            str(scenario_file),
            "--format",
            "json",
        ],
    )
    assert eval_result.exit_code == EXIT_SUCCESS, eval_result.stdout

    report = json.loads(eval_result.stdout)

    # The eslogger source must actually be discovered and parsed (not
    # silently skipped because no parser was registered for it).
    assert report["source_counts"].get("eslogger", 0) > 0

    plausibility = next(p for p in report["pillars"] if p["name"] == "Plausibility")
    co_occurrence = next(s for s in plausibility["sub_scores"] if s["key"] == "co_occurrence")

    # Task 11's new eslogger co_occurrence.yaml rules must run through the
    # real parser + PlausibilityScorer pipeline and pass cleanly against real
    # emitter output.
    assert co_occurrence["score"] == 100.0, co_occurrence["sample_failures"]
    assert "co-occurrence checks pass" in co_occurrence["details"]
