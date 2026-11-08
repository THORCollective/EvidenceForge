# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""macOS suspicious-but-benign CLI noise uses macOS-native commands."""

import random
from datetime import UTC, datetime

from evidenceforge.generation.activity.suspicious_benign import generate_suspicious_cli
from evidenceforge.models.scenario import System, User


def test_generate_suspicious_cli_on_macos_uses_macos_commands():
    user = User(username="dana.reyes", full_name="Dana Reyes", email="dana@example.test")
    mac = System(
        hostname="MAC-01",
        ip="10.20.10.31",
        os="macOS 14.5",
        type="workstation",
        assigned_user="dana.reyes",
    )
    hour = datetime(2024, 6, 11, 14, 0, 0, tzinfo=UTC)

    commands = [
        generate_suspicious_cli(random.Random(seed), [user], [mac], hour) for seed in range(40)
    ]

    for result in commands:
        assert result is not None
        assert "/etc/shadow" not in result["command_line"]
        assert "169.254.169.254" not in result["command_line"]
        assert "journalctl" not in result["command_line"]
        assert result["process_name"].startswith(("/usr/", "/bin/"))
