# Splunk hunt kit for the macOS eslogger demo

A local, single-container Splunk that ingests the demo's `eslogger` NDJSON plus Zeek JSON, adds
flat hunter-friendly fields, and ships one saved search per hunt beat. Verified on 2026-09-29
against a fresh `eforge generate --target splunk` run of `../scenario.yaml`: all 15 searches
return the expected beat.

## Run it

```bash
# 1. Generate (eslogger output is identical for every --target; splunk only matters for Zeek/syslog)
uv run eforge generate scenarios/macos-eslogger-demo/scenario.yaml \
  --output /tmp/obts-demo --target splunk --overwrite

# 2. Start Splunk (amd64 image; runs under Rosetta on Apple Silicon, ~3-5 min to healthy)
cd scenarios/macos-eslogger-demo/splunk
export EFORGE_DATA=/tmp/obts-demo/data SPLUNK_PASSWORD='choose-8+-chars'
docker compose -p obts-splunk up -d

# 3. Run every hunt search (stdlib Python; exits 1 if any search returns nothing)
python3 run_hunts.py                      # or: --only AMOS, --csv-dir results/
```

Splunk Web is at http://127.0.0.1:8000 (Free license, so no login). The searches are under
**Settings → Searches, reports, and alerts**, app `OBTS macOS Hunt`; set the time picker to
*All time* (data is dated 2024-06-11). Tear down with `docker compose -p obts-splunk down -v`.

## What the app does

| File | Purpose |
|------|---------|
| `inputs.conf` | `index=macos sourcetype=macos:eslogger`, host = per-Mac directory (`host_segment = 2`); Zeek files into `index=zeek` as `bro:<log>:json`. |
| `props.conf` | `_time` from the envelope `time` (ns ISO-8601, µs kept); `KV_MODE=json`; flat EVAL fields (below); Zeek `src_ip`/`dest_ip` aliases. |
| `lookups/es_event_types.csv` | `event_type` integer → `es_event` name (ESTypes.h codes the emitter uses). |
| `lookups/mac_hosts.csv` | host → `host_short`, `host_ip`, `owner`. **This is the ES↔Zeek join key**: ES has no IP or hostname field. Update it if the scenario's IPs change. |
| `savedsearches.conf` | `OBTS 00/01` orientation, `AMOS 1-5`, `BeaverTail 1-3`, `CloudMensis 1-3`, `SSH 1-2`. |
| `server.conf` | `allowRemoteLogin = always` (Free license otherwise blocks REST, which `run_hunts.py` uses). |

Flat fields (raw nested names still work, e.g. `'event.exec.target.executable.path'`):

- Subject process (for `exec`, the **pre-exec image** = the parent program): `pid ppid uid
  process_path process_name process_signing_id process_team_id process_platform process_signer`
- `exec` target: `target_pid target_path target_name target_signing_id target_team_id
  target_platform target_signer cmdline cwd`
- `fork`: `child_pid`. Files: `file_path` (open/create/write/close/unlink/rename).
- BTM: `btm_item_url btm_item_type btm_executable_path btm_instigator_pid btm_instigator_path
  btm_instigator_signing_id`. SSH: `ssh_src ssh_user ssh_success`.
- `*_signer` is `apple` (platform binary), `adhoc` (CS_ADHOC 0x2 in `codesigning_flags`),
  `developer_id` (has a Team ID), else `other`. `*_team_id` is `none` when ES reports null.

## Hunter notes

- **exec subject is the parent image.** In `es_message_t`, `process` on an `exec` is the forked
  child *before* it execs, so `process_path` is the parent program and `target_path` is what ran.
  The pid is the same on both sides; `ppid` is the real parent pid.
- **ES has no network events.** Every ES→Zeek pivot is host → `host_ip` (lookup) → `id.orig_h`
  plus a time window (`AMOS 4`, `BeaverTail 3`). There is no PID on Zeek rows, so the window is
  the join. The BeaverTail window also catches the developer's browser traffic
  (`news.ycombinator.com`); the beacon is the `api.ipcheck-beaver.cc` DNS → TLS to 45.128.199.72.
- **`map` doesn't work in saved searches**: `savedsearch` treats `$tokens$` as arguments. The
  pivots use `append` + `eventstats` time windows, which fits the demo's small Zeek volume. For
  bigger datasets, narrow the appended Zeek search first.
- **`bitand()`** returned nothing on Splunk 10.2.3, so the CS_ADHOC test is
  `floor(flags/2) % 2 == 1`.
- JSON `null` extracts as the literal string `"null"` (e.g. `process.team_id`).
