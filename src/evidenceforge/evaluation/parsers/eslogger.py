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

"""Parser for eslogger (macOS Endpoint Security) NDJSON files."""

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from . import LogParser, ParsedRecord, register_parser


@register_parser
class ESLoggerParser(LogParser):
    format_name = "eslogger"

    def can_parse(self, path: Path) -> bool:
        return path.name == "eslogger.ndjson"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        # eslogger records carry no hostname; the per-host output directory
        # (``data/<host-fqdn>/eslogger.ndjson``) identifies the host.
        hostname = None if path.parent.name in {"data", "logs", "output"} else path.parent.name
        with path.open(encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                yield self._parse_line(line, line_num, hostname=hostname)

    def _parse_line(self, raw: str, line_num: int, hostname: str | None = None) -> ParsedRecord:
        fields: dict[str, Any] = {}
        errors: list[str] = []
        timestamp = None

        try:
            data = json.loads(raw)

            # Flatten nested objects (e.g. "event": {"exec": {...}},
            # "process": {"audit_token": {...}}) into dotted top-level
            # fields, matching co_occurrence.yaml/causal_pairs.yaml's
            # eslogger rules (e.g. "event.exec.args", "process.audit_token.pid").
            fields = _flatten(data, leaf_fields=_declared_leaf_fields())

            # BTM items identify their plist by file:// URL; expose the POSIX
            # path too so it can be correlated with the plist's create event.
            item_url = fields.get("event.btm_launch_item_add.item.item_url")
            if isinstance(item_url, str) and item_url.startswith("file://"):
                fields["event.btm_launch_item_add.item.item_path"] = unquote(item_url[7:])

            # Parse the "time" envelope field: ISO 8601 UTC with a Z suffix.
            # eslogger reports nanoseconds; datetime holds microseconds, so the
            # fraction is truncated to six digits before parsing.
            ts_str = data.get("time")
            if isinstance(ts_str, str):
                try:
                    timestamp = datetime.fromisoformat(_truncate_to_micros(ts_str))
                except ValueError:
                    errors.append(f"Invalid timestamp: {ts_str}")
            elif ts_str is not None:
                errors.append(f"Invalid timestamp: {ts_str!r}")

        except json.JSONDecodeError as e:
            errors.append(f"JSON parse error: {e}")

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
            source_host=hostname,
        )


def _truncate_to_micros(ts: str) -> str:
    """Convert an eslogger ``...SS.fffffffffZ`` timestamp to a parseable form."""
    ts = ts.replace("Z", "+00:00")
    head, dot, rest = ts.partition(".")
    if not dot:
        return ts
    digit_count = len(rest) - len(rest.lstrip("0123456789"))
    digits, suffix = rest[:digit_count], rest[digit_count:]
    return f"{head}.{digits[:6].ljust(6, '0')}{suffix}"


_DECLARED_LEAF_FIELDS: frozenset[str] | None = None


def _declared_leaf_fields() -> frozenset[str]:
    """Return the dotted names the eslogger format declares as scalar/list leaves."""
    global _DECLARED_LEAF_FIELDS
    if _DECLARED_LEAF_FIELDS is None:
        from evidenceforge.formats.loader import load_format

        _DECLARED_LEAF_FIELDS = frozenset(field.name for field in load_format("eslogger").fields)
    return _DECLARED_LEAF_FIELDS


def _flatten(
    obj: dict[str, Any],
    prefix: str = "",
    leaf_fields: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Recursively flatten nested dict values into dot-joined top-level keys.

    Non-dict values (including lists, e.g. ``event.exec.args``) are kept
    as-is rather than recursed into, since eslogger's evaluation rules only
    ever assert presence on list-valued fields.
    """
    flat: dict[str, Any] = {}
    for key, value in obj.items():
        flat_key = f"{prefix}.{key}" if prefix else key
        # A declared leaf keeps its native value even when it is an object, so
        # a wrong-typed field fails validation instead of vanishing.
        if isinstance(value, dict) and flat_key not in leaf_fields:
            flat.update(_flatten(value, flat_key, leaf_fields))
        else:
            flat[flat_key] = value
    return flat
