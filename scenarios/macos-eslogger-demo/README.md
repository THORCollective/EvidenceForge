# macOS Endpoint Security (eslogger) three-hunt demo

A synthetic macOS dataset that reproduces **three real-world threat hunts** as
authentic **Endpoint Security Framework (ESF)** telemetry — the same
`eslogger`-style NDJSON a macOS collector streams — plus **Zeek** network logs
for cross-source correlation. It is the reference hunt-loop artifact for the
OBTS macOS Endpoint Security talk: a defender can run a collector → ECS → Sigma
pipeline (e.g. [Nebulock macos-coresigma](https://github.com/Nebulock-Inc/macos-coresigma))
over this data and detect all three storylines.

**Nothing here is dangerous to run.** No payload is executed, generation makes
no network calls, and every malicious artifact is a labeled, inert record in
`GROUND_TRUTH.json`.

## Quick start

```bash
eforge validate scenarios/macos-eslogger-demo/scenario.yaml
eforge generate scenarios/macos-eslogger-demo/scenario.yaml -o ./output
```

- `./output/data/<host>.clearwater-studio.test/eslogger.ndjson` — one ESF NDJSON
  stream per macOS host.
- `./output/data/ZEEK-CORE/{conn,dns,ssl,...}.json` — the network sensor's view
  of the hosts' egress.
- `./output/GROUND_TRUTH.json` / `GROUND_TRUTH.md` — the answer key: every
  malicious beat, its MITRE technique, and the exact evidence it should produce.

## The environment

| Host | User | Persona | Role in the demo |
|---|---|---|---|
| `MAC-DESIGN-01` | dana.reyes | marketing | Hunt 1 — AMOS / Atomic Stealer; Chrome keychain red herring |
| `MAC-DEV-01` | sam.okafor | developer | Hunt 2 — DPRK BeaverTail; SSH target |
| `MAC-IT-01` | riley.chen | sysadmin | Hunt 3 — CloudMensis persistence; SSH source |
| `MAC-DEV-02` | jordan.lee | developer | Homebrew and node-gyp red herrings |
| `MAC-SALES-01` | priya.nair | sales | Chrome keychain red herring |
| `MAC-PM-01` | alex.kim | project_manager | Population only |
| `NS-01` | — | Ubuntu resolver | Internal DNS (`roles: [dns_server]`) |

The Macs run `macOS 14.5` on `10.20.10.0/24` and resolve through `NS-01`
(`10.20.1.10`). A core SPAN sensor (`ZEEK-CORE`) records both segments. The
`high` baseline gives each Mac one loginwindow session, app and `zsh` use,
Apple background services (iCloud, software update), and Spotlight, cfprefsd,
trustd and Time Machine daemon churn — roughly 120–260 ES records per Mac over
the two hours, so each hunt stacks against a population of six hosts.

## The three hunts

### 1. AMOS / Atomic Stealer (`MAC-DESIGN-01`)

A trojanized "CleanMyMac X" installer (a documented real-world AMOS lure)
phishes the login password, harvests the login keychain, and exfiltrates it.

| Beat | ESF / Zeek evidence |
|---|---|
| Dropper runs | `exec` whose `target` is `/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper` — **ad-hoc signed, no Team ID** (`team_id: null`, `is_platform_binary: false`, `CS_ADHOC` set in `codesigning_flags`), launched by LaunchServices (`ppid` 1) |
| Fake password prompt | `exec` of `/usr/bin/osascript` — a **genuine, Apple-signed** platform binary (`com.apple.osascript`) whose parent is the dropper, running `display dialog … with hidden answer` |
| Keychain theft | `open` of `~/Library/Keychains/login.keychain-db`, **attributed to the dropper** (not to `osascript`) |
| Exfiltration | Zeek `dns` + `conn` + `ssl`: `10.20.10.31 → 193.42.33.14:443` (`gateway.macos-analytics.top`), ~2.4 MB uploaded by the dropper itself |

**The signal is the code-signing identity.** `osascript` is a legitimate,
ubiquitous macOS automation binary — it stays Apple-signed. The malice lives in
*what spawned it* (a no-Team-ID, ad-hoc signed app) and in the keychain access
and egress that app performs itself. Hunt on: non-platform process with no Team
ID → keychain access → outbound TLS.

### 2. DPRK BeaverTail (`MAC-DEV-01`)

A developer runs `npm install` of a malicious package in their webapp checkout;
its postinstall lifecycle script launches `node`, which beacons to attacker
infrastructure.

| Beat | ESF / Zeek evidence |
|---|---|
| Malicious install | `exec` of `/usr/local/bin/node` with argv `node /usr/local/bin/npm install @clearwater-ui/react-icons-pro` (npm is a node script), `cwd` `~/dev/webapp` |
| Lifecycle script | `exec` of `/bin/sh -c "node scripts/postinstall.js"`, child of npm, `cwd` = the package directory |
| Postinstall payload | `exec` of `node scripts/postinstall.js`, child of `sh` |
| Beacon | Zeek `conn` + `dns` + `ssl`: `10.20.10.32 → 45.128.199.72:443` (`api.ipcheck-beaver.cc`) |

`node` itself is the official, Node.js Foundation Developer ID-signed binary —
signing is not the signal here. The hunt is the **ancestry** (npm → `sh` →
`node` from inside `node_modules`) plus the egress. ESF has **no TCP-connect
event** (real ES clients pair with NetworkExtension), so the `node` egress is
found by correlating the ES `exec` ancestry with the Zeek flow/DNS for the same
host at the same time.

### 3. CloudMensis-style persistence (`MAC-IT-01`)

An ad-hoc signed helper installs a LaunchAgent that masquerades as an Apple
iCloud sync daemon.

| Beat | ESF evidence |
|---|---|
| Helper runs | `exec` of `/Users/Shared/.cloudsync/cloudsyncd --install` from the user's `zsh` (ad-hoc signed, no Team ID) |
| Persistence dropped | `create` of `~/Library/LaunchAgents/com.apple.cloudsyncd.plist` by the helper |
| Background Task Management | `btm_launch_item_add` reported by `backgroundtaskmanagementd`, with the helper as `instigator`, `executable_path` = the plist's program (`launch_program` on the file event), `item_type: 3` (agent), `legacy: true`, and `item_url` pointing at the same plist — **auto-generated by the causal engine**, not declared in the scenario |

The `btm_launch_item_add` event is the modern (macOS 13+) persistence signal.
The scenario author writes **only** the plist `create`; EvidenceForge's causal
expansion emits the BTM event because the file lands under `LaunchAgents`.

### Supporting: legitimate SSH (`MAC-DEV-01`)

The IT admin (`riley.chen`, from `MAC-IT-01`) SSHes into the developer
workstation for maintenance and logs off — a complete `openssh_login` →
`openssh_logout` pair on `MAC-DEV-01` (same audit-session id), included so the
ESF SSH lifecycle is observable end-to-end alongside the malicious beats.

## Red herrings (benign lookalikes)

Each `red_herrings` entry matches a naive version of a hunt query. They are
listed with explanations in the "Red Herrings" section of `GROUND_TRUTH.md`.

| Lookalike | Matches | How a hunter rules it out |
|---|---|---|
| `brew services start postgresql@16` on `MAC-DEV-02`: ad-hoc signed Homebrew Ruby writes `homebrew.mxcl.postgresql@16.plist` (BTM follows) and launchd starts the ad-hoc `postgres` bottle | AMOS 1 (ad-hoc via launchd), CloudMensis 1–3 | Install location (`/opt/homebrew`), plist name is not a `com.apple.*` masquerade, writer launched from the developer's shell |
| Chrome reads `login.keychain-db` on `MAC-DESIGN-01` and `MAC-SALES-01` | AMOS 3 (non-Apple keychain read) | Developer ID with a known Team ID (`EQHXZ8M8AV`); the AMOS dropper has none |
| `npm install bcrypt` on `MAC-DEV-02`: `sh -c "node-gyp rebuild"` → `node` downloads headers from `nodejs.org` | BeaverTail 1–2 (node → `sh -c` → node) | Destination: `nodejs.org` vs a fresh lookalike domain |

The Splunk kit's `AMOS 1b`, `AMOS 3b` and `BeaverTail 3b` saved searches are the
refined versions.

## What to verify

- **Record shape.** Records follow Apple's `es_message_t` layout: `event_type`
  values from `ESTypes.h`, the launched program in `event.exec.target` (the
  exec's `process` is the pre-exec image), PIDs only inside audit tokens, and
  `codesigning_flags` as the `cs_blobs.h` bitmask.
- **Signing identity is the hunt's thesis.** The AMOS dropper and the
  CloudMensis helper are ad-hoc signed with no Team ID; `osascript` and every
  binary on the system volume are Apple platform binaries; third-party apps
  (Chrome, VS Code, node) carry their real vendor Team IDs.
- **Cross-source correlation.** Join the ES `exec` ancestry to the Zeek
  `conn`/`dns` rows for the same host to tie a process to its egress.
- **BTM without authoring it.** Confirm `btm_launch_item_add` appears even
  though the scenario only declares a file `create`.
- **In a SIEM.** `splunk/` is a local Splunk kit (compose file, parsing app,
  one saved search per beat, and `run_hunts.py`) that ingests this output and
  runs each hunt end to end. See `splunk/README.md`.
- **Determinism.** Generation is reproducible: the same scenario yields
  byte-identical `eslogger.ndjson` on every run.

## Notes

- The baseline is intentionally modest (a demo, not a stress test). Raise
  `baseline_activity.intensity`/`variation` for a noisier dataset.
- Attacker IPs/hostnames are illustrative and non-resolving; the `.top`/`.cc`
  C2 names and the `193.42.33.14` / `45.128.199.72` addresses never receive real
  traffic (generation makes no network calls).
- The integration test `tests/integration/test_macos_eslogger_scenario.py`
  regenerates this scenario and asserts every beat above.
