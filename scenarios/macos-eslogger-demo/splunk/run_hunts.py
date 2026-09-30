#!/usr/bin/env python3
"""Run every OBTS saved search against the local Splunk and print the results.

Usage:
    SPLUNK_PASSWORD='...' python3 run_hunts.py [--only AMOS] [--csv-dir results/]

Stdlib only, so it runs outside the EvidenceForge venv. Talks to the management port
(https://127.0.0.1:8089) with the self-signed container certificate.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE_URL = "https://127.0.0.1:8089"
APP = "obts_macos_hunt"


def _request(path: str, data: dict[str, str] | None = None) -> bytes:
    password = os.environ.get("SPLUNK_PASSWORD")
    if not password:
        sys.exit("set SPLUNK_PASSWORD")
    token = base64.b64encode(f"admin:{password}".encode()).decode()
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body)
    req.add_header("Authorization", f"Basic {token}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
        return resp.read()


def saved_search_names() -> list[str]:
    """Return the app's saved-search names in sorted order."""
    raw = _request(
        f"/servicesNS/nobody/{APP}/saved/searches?output_mode=json&count=0&search=eai:acl.app={APP}"
    )
    return sorted(
        entry["name"] for entry in json.loads(raw)["entry"] if entry["name"].startswith("OBTS")
    )


def run(name: str) -> list[dict[str, object]]:
    """Run one saved search synchronously and return its result rows."""
    try:
        raw: bytes | None = _request(
            f"/servicesNS/nobody/{APP}/search/jobs/export",
            {
                "search": f'| savedsearch "{name}"',
                "output_mode": "json",
                "earliest_time": "0",
                "latest_time": "now",
            },
        )
    except urllib.error.HTTPError as exc:
        print(f"  !! HTTP {exc.code}: {exc.read().decode(errors='replace')[:500]}")
        raw = None
    rows: list[dict[str, object]] = []
    if raw is None:
        return rows
    for line in raw.decode().splitlines():
        if not line.strip():
            continue
        msg = json.loads(line)
        if "result" in msg:
            rows.append(msg["result"])
        for m in msg.get("messages", []):
            if m.get("type") in {"ERROR", "FATAL"}:
                print(f"  !! {m['type']}: {m['text']}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", help="substring filter on search name")
    parser.add_argument("--csv-dir", type=Path, help="also write each result set as CSV")
    args = parser.parse_args()
    failures = 0
    for name in saved_search_names():
        if args.only and args.only.lower() not in name.lower():
            continue
        rows = run(name)
        print(f"\n=== {name}  ({len(rows)} rows)")
        if not rows:
            failures += 1
        for row in rows[:25]:
            visible = {k: v for k, v in row.items() if not k.startswith("_") or k == "_time"}
            print("  " + json.dumps(visible, ensure_ascii=False))
        if args.csv_dir and rows:
            args.csv_dir.mkdir(parents=True, exist_ok=True)
            keys = sorted({k for r in rows for k in r if not k.startswith("_") or k == "_time"})
            safe = "".join(c if c.isalnum() else "_" for c in name).strip("_")
            with (args.csv_dir / f"{safe}.csv").open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
    print(f"\n{failures} search(es) returned no rows")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
