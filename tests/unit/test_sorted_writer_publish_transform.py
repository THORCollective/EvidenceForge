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


"""ExternalSortedLineWriter publish-time line transforms (ES client sequence numbers)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter


def _numbering() -> Callable[[str], str]:
    counter = iter(range(1, 1_000_000))

    def transform(line: str) -> str:
        key, _sep, _old = line.partition("|")
        return f"{key}|{next(counter)}"

    return transform


def _writer(path: Path) -> ExternalSortedLineWriter:
    return ExternalSortedLineWriter(
        path,
        sort_key=lambda line: line.partition("|")[0],
        buffer_size=2,
        publish_line_transform=_numbering,
    )


def test_publish_transform_numbers_lines_in_final_sorted_order(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    writer = _writer(out)
    for key in ("c", "a", "b"):
        writer.write(f"{key}|0")
    writer.close()

    assert out.read_text(encoding="utf-8").splitlines() == ["a|1", "b|2", "c|3"]


def test_publish_transform_renumbers_across_incremental_publishes(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    writer = _writer(out)
    writer.write("b|0")
    writer.write("d|0")
    writer.flush()
    assert out.read_text(encoding="utf-8").splitlines() == ["b|1", "d|2"]

    # A later, earlier-sorting row is merged into the published baseline and the
    # whole file is renumbered, so numbering stays contiguous in time order.
    writer.write("a|0")
    writer.write("c|0")
    writer.close()

    assert out.read_text(encoding="utf-8").splitlines() == ["a|1", "b|2", "c|3", "d|4"]
