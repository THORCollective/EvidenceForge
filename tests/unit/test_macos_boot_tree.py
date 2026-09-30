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


"""macOS boot forest: launchd socket-activates sshd per connection."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock

from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin


def _boot_images() -> dict[str, tuple[str, str]]:
    spec = EmitterSetupMixin._build_macos_boot_host_spec(
        Mock(), Mock(hostname="MAC-TEST-01"), datetime(2024, 6, 1, 8, 0, tzinfo=UTC)
    )
    return {p.alias: (p.image, p.username) for p in spec.processes}


def test_macos_boot_forest_has_no_persistent_sshd() -> None:
    # Remote Login is a launchd socket: sshd -i starts per connection, so no
    # sshd is running between connections.
    images = {image for image, _user in _boot_images().values()}
    assert "/usr/sbin/sshd" not in images


def test_macos_boot_forest_has_no_root_login_shell() -> None:
    shells = {
        alias: user
        for alias, (image, user) in _boot_images().items()
        if image.rsplit("/", 1)[-1] in {"zsh", "bash", "sh"}
    }
    assert shells == {}
