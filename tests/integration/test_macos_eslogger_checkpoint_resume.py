"""The macOS eslogger demo scenario survives checkpoint suspension and resume."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.support.output_equivalence import deterministic_bundle_files

pytestmark = pytest.mark.slow

_SCENARIO = Path("scenarios/macos-eslogger-demo/scenario.yaml")
_SYNC_HOUR = 1


def _run_cli(*arguments: str, environment: dict[str, str]) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "evidenceforge", *arguments],
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_macos_eslogger_demo_suspended_and_resumed_matches_uncheckpointed(
    tmp_path: Path,
) -> None:
    # Arrange
    output = tmp_path / "suspended"
    control = tmp_path / "control"
    sync = tmp_path / "sync"
    sync.mkdir()
    environment = os.environ.copy()
    for name in (
        "EFORGE_TEST_CHECKPOINT_SYNC_DIR",
        "EFORGE_TEST_CHECKPOINT_SYNC_HOUR",
        "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT",
    ):
        environment.pop(name, None)
    environment["PYTHONUTF8"] = "1"
    suspended_environment = environment | {
        "EFORGE_TEST_CHECKPOINT_SYNC_DIR": str(sync),
        "EFORGE_TEST_CHECKPOINT_SYNC_HOUR": str(_SYNC_HOUR),
        "EFORGE_TEST_CHECKPOINT_SYNC_TIMEOUT": "300",
    }

    # Act: suspend at the first hourly checkpoint, then resume to completion.
    with (tmp_path / "generation-output.txt").open("w+b") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                str(_SCENARIO),
                "--output",
                str(output),
                "--seed",
                "42",
                "--target",
                "splunk",
                "--checkpoint-hours",
                "1",
            ],
            env=suspended_environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            marker = sync / f"{_SYNC_HOUR:020d}.ready"
            deadline = time.monotonic() + 600
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            log.seek(0)
            assert marker.exists(), log.read().decode("utf-8", errors="replace")
            cursor = json.loads(marker.read_bytes())
            assert cursor["completed_simulated_hours"] == _SYNC_HOUR
            _run_cli("checkpoint", "suspend", str(output), environment=environment)
            (sync / f"{_SYNC_HOUR:020d}.continue").touch()
            process.wait(timeout=600)
            log.seek(0)
            assert process.returncode == 0, log.read().decode("utf-8", errors="replace")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)

    status = json.loads(
        _run_cli("checkpoint", "status", str(output), "--json", environment=environment)
    )
    assert status["state"] == "resumable"
    _run_cli("generate", "--output", str(output), "--resume", environment=environment)
    _run_cli(
        "generate",
        str(_SCENARIO),
        "--output",
        str(control),
        "--seed",
        "42",
        "--target",
        "splunk",
        "--checkpoint-hours",
        "0",
        environment=environment,
    )

    # Assert
    assert not (output / ".eforge-generation").exists()
    resumed_files = deterministic_bundle_files(output)
    assert resumed_files == deterministic_bundle_files(control)
    assert any(
        b"btm_launch_item_add" in content
        for name, content in resumed_files.items()
        if name.startswith("data/")
    )
