# Splunk Detections-as-Code — Design

**Date:** 2026-09-12
**Status:** approved, pending implementation plan
**Scope:** `projects/defensive/splunk/detections/`, with edits to CI and the architecture docs

---

## 1. Problem

`projects/defensive/splunk/` is the repo's headline detection-engineering project
and contains no detection content. It holds a README, a walkthrough README and
thirteen screenshots. The one detection it shows exists only as a fenced code
block:

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
```

That search has three defects. It has no time window, so it fires on five
failures spread across all recorded history. It references `src_ip`, a
CIM-normalised field, while the walkthrough README uses the raw
`Source_Network_Address` for the same concept. And its threshold of five is
unexplained.

The deeper problem is unverifiability. A search in a markdown file makes a claim
that nothing checks. The lab is torn down, so no detection here can be validated
against live data. Any design that does not solve verification reproduces the
weakness it is meant to fix.

## 2. Goals

- Detections are files with structured metadata, not prose in a README.
- Every detection is machine-validated, and the validation proves something real.
- Detection selection is justified by telemetry the repo's own IaC deploys.
- Thresholds carry recorded reasoning.
- Documented limits are stated plainly rather than left implicit.

## 3. Non-goals

- Standing the lab back up. The lab stays down; CI is the execution environment.
- Sigma rules. Sigma expresses these detections' aggregation and threshold logic
  poorly (Sigma Correlations has patchy backend support), so the SPL would be
  hand-maintained anyway and the Sigma would validate only as syntax.
- Deploying Sysmon. The Sysmon gap is corrected in documentation here, not
  closed. Closing it is separate work.
- CIM normalisation or data-model acceleration.

## 4. Layout

```
projects/defensive/splunk/detections/
├── README.md                  # methodology: how a detection is written, tested, tuned
├── schema.json                # JSON Schema every detection.yml validates against
├── conftest.py                # puts the project root on sys.path
├── requirements-dev.txt
├── lib/
│   ├── loader.py              # discover and parse rules
│   └── splunk_harness.py      # ephemeral Splunk container, fixture load, search
├── tests/
│   ├── test_metadata.py       # layer C, always runs
│   └── test_behaviour.py      # layer A, docker-marked
└── rules/
    └── <rule_id>/
        ├── detection.yml
        ├── search.spl
        ├── savedsearches.conf
        └── events/
            ├── true_positive.jsonl
            └── benign.jsonl
```

This mirrors the per-project convention already used by `honeypot/`,
`network-vulnerability-scanner/` and `pfsense_firewall/`: an empty `conftest.py`
at the project root putting that root on `sys.path`, a `requirements-dev.txt`,
and a `tests/` directory run from inside the project. It therefore joins the CI
test matrix by adding one path.

## 5. `detection.yml` schema

Every field is required unless marked optional. `schema.json` enforces this and
`tests/test_metadata.py` runs it.

| Field | Type | Notes |
|---|---|---|
| `id` | string | Matches `^[a-z0-9_]+$` and equals the directory name |
| `title` | string | One line, human-readable |
| `status` | enum | `draft`, `validated-offline`, `validated-in-lab` |
| `version` | integer | Bumped on logic change |
| `author` | string | |
| `date` | date | ISO 8601 |
| `description` | string | What the detection looks for and why that indicates the technique |
| `attack` | list | Each entry: `tactic`, `technique` (e.g. `T1110.001`), `name` |
| `data_source.log` | string | e.g. `Windows Security` |
| `data_source.event_codes` | list[int] | |
| `data_source.audit_subcategory` | string | The subcategory in `ad_gpos.yml` that produces it |
| `data_source.required_fields` | list[string] | Must all appear in the fixtures |
| `data_source.prerequisites` | list[string] | Optional. Telemetry settings the detection needs that the lab does not currently enable |
| `logic.window` | string | e.g. `15m` |
| `logic.threshold` | integer | |
| `logic.rationale` | string | Why this threshold and window, not another |
| `false_positives` | list | Each entry: `scenario`, `guidance` |
| `response` | string | What an analyst does on a true positive |
| `references` | list[string] | URLs |

`status` is deliberately three-valued. Every detection shipped by this work is
`validated-offline`: its logic is executed against fixtures in CI, and it has
never seen live lab data. Recording that distinction in the file is the honest
alternative to implying validation that did not happen.

## 6. Detections

Each maps to an audit subcategory that
`projects/defensive/windows_server_with_AD/ansible/vars/gpos.yml` actually
deploys. This is the selection criterion, and it is what ties the AD project to
the Splunk project.

| Rule | ATT&CK | Event | Audit subcategory |
|---|---|---|---|
| `win_bruteforce_smb_4625` | T1110.001 Password Guessing | 4625 | Logon |
| `win_account_lockout_4740` | T1110 Brute Force | 4740 | Account Lockout |
| `win_kerberoasting_4769` | T1558.003 Kerberoasting | 4769 | Kerberos Service Ticket Operations |
| `win_suspicious_process_4688` | T1059.001 PowerShell | 4688 | Process Creation |

### 6.1 `win_bruteforce_smb_4625`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4625 Logon_Type=3
| bucket _time span=15m
| stats count AS failure_count,
        dc(Account_Name) AS distinct_accounts,
        values(Account_Name) AS targeted_accounts
        BY _time, Source_Network_Address
| where failure_count >= 5
```

`Logon_Type=3` restricts to network logons, which is what SMB authentication
produces and what the walkthrough's `smbclient` loop generated. It also excludes
interactive mistyped-password noise.

**Threshold rationale.** `gpos.yml` sets `lockout_threshold: 5` and
`lockout_observation_window_minutes: 15`. Five failures from one source inside
fifteen minutes is precisely the activity the domain lockout policy exists to
stop, so the detection threshold is derived from the environment's own policy
rather than chosen arbitrarily. If the policy changes, the rationale field says
what the detection's threshold should change to.

**Windowing limit.** `bucket` produces tumbling, not sliding, windows: an attack
straddling a boundary can split into two sub-threshold buckets. The scheduled
search compensates by dispatching over a window wider than its interval
(§7). The alternative, `streamstats` with a sliding window, costs materially
more at search time for a marginal gain at lab scale. This trade-off is recorded
in `detections/README.md`.

### 6.2 `win_account_lockout_4740`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4740
| bucket _time span=1h
| stats dc(Account_Name) AS accounts_locked,
        values(Account_Name) AS locked_accounts
        BY _time, Caller_Computer_Name
| where accounts_locked >= 3
```

Deliberately not "alert on any lockout", which in a domain with
`lockout_threshold: 5` is routine user error. Three or more *distinct* accounts
locked from one caller within an hour is a password-spraying shape, which
single-account lockouts are not. This is the corroborating detection for 6.1
rather than a duplicate of it.

### 6.3 `win_kerberoasting_4769`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4769
    Ticket_Encryption_Type=0x17 Ticket_Options=0x40810000 Failure_Code=0x0
| where NOT match(Service_Name, "\$$") AND Service_Name!="krbtgt"
| bucket _time span=10m
| stats dc(Service_Name) AS services_requested,
        values(Service_Name) AS services
        BY _time, Account_Name, Client_Address
| where services_requested >= 5
```

RC4 (`0x17`) service-ticket requests are the Kerberoasting signature: the
attacker requests RC4 because the resulting ticket is cheaper to crack offline
than AES. Machine accounts (trailing `$`) and `krbtgt` are excluded as normal
Kerberos operation. One RC4 request is unremarkable; five distinct SPNs from one
principal in ten minutes is SPN enumeration followed by bulk roasting.

### 6.4 `win_suspicious_process_4688`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4688
    (New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe")
| where match(Process_Command_Line, "(?i)\s-e(nc|ncoded|ncodedcommand)?\s")
     OR match(Process_Command_Line, "(?i)-w(indowstyle)?\s+hidden")
     OR match(Process_Command_Line, "(?i)(FromBase64String|IEX|Invoke-Expression|DownloadString)")
| table _time, Computer, Account_Name, Creator_Process_Name,
        New_Process_Name, Process_Command_Line
```

**Prerequisite the lab does not meet.** 4688 records `Process_Command_Line` only
when `ProcessCreationIncludeCmdLine_Enabled=1` is set. `gpos.yml` enables the
Process Creation subcategory but does not set that value, so this detection
would return nothing in the lab as currently configured. This is recorded in the
detection's `prerequisites` field and in `detections/README.md`, together with
the registry setting that would close it:

```yaml
- path: "HKLM:\\Software\\Policies\\Microsoft\\Windows\\System"
  name: ProcessCreationIncludeCmdLine_Enabled
  type: dword
  value: 1
```

Applying that to `gpos.yml` is out of scope here and left as a follow-up. A
detection that declares its telemetry prerequisite is more useful than one that
silently assumes it.

## 7. `savedsearches.conf`

One stanza per rule, carrying what turns a search into an alert:

```conf
[Homelab - SMB Brute-Force (T1110.001)]
search = <contents of search.spl>
cron_schedule = */15 * * * *
dispatch.earliest_time = -20m@m
dispatch.latest_time = now
enableSched = 1
counttype = number of events
relation = greater than
quantity = 0
alert.severity = 4
alert.suppress = 1
alert.suppress.fields = Source_Network_Address
alert.suppress.period = 60m
action.email = 0
```

The dispatch window (20m) deliberately exceeds the schedule interval (15m). The
overlap is the mitigation for the tumbling-window limit in §6.1: an attack near
a bucket boundary is re-evaluated by the next run. Suppression on the grouping
field stops one persistent scanner generating an alert every interval.

`search.spl` is the single source of truth for the query. The conf stanza
duplicates it, so `test_metadata.py` asserts the two match; a rule whose conf
has drifted from its `.spl` fails.

## 8. Validation

### Layer C — metadata, always runs

Pure Python, no Docker, runs in the existing CI matrix on 3.11 and 3.12:

1. Every `detection.yml` validates against `schema.json`.
2. `id` equals its directory name.
3. Every `attack.technique` matches `^T\d{4}(\.\d{3})?$` and appears in
   `detections/attack_techniques.txt`, a vendored list of valid ATT&CK
   technique IDs. Vendored rather than fetched, so CI does not depend on
   network access or MITRE's uptime.
4. Every `data_source.required_fields` entry appears in every true-positive
   fixture.
5. Every field referenced in `search.spl` is either a required field or a field
   the search itself creates, catching typos like `src_ip` for
   `Source_Network_Address`.
6. The `search` value in `savedsearches.conf` matches `search.spl`.
7. Each rule has at least one true-positive and one benign fixture.

### Layer A — behaviour, separate CI job

`splunk_harness.py` starts a `splunk/splunk` container, waits for the management
port, creates a test index, loads a rule's fixtures via HEC, runs `search.spl`
through the REST search API, and returns the result rows. `test_behaviour.py`
then asserts, per rule:

- the search returns at least one row when true-positive fixtures are loaded
- the search returns zero rows when only benign fixtures are loaded

Each rule runs against a freshly-created index so fixtures cannot leak between
tests. The container starts once per session, not once per rule.

**Index substitution.** `search.spl` names the production index
(`index=wineventlog`), but fixtures load into a per-rule test index
(`test_<rule_id>`) for isolation. The harness therefore rewrites the leading
`index=` term before dispatching the search, and asserts the SPL contains
exactly one `index=` token so the rewrite cannot silently miss or double-apply.
The alternative — naming the test index `wineventlog` and cleaning it between
rules — was rejected because a failed cleanup leaks fixtures into the next
rule's assertions, and a leaked true positive makes a broken detection pass.
The substitution is the only edit the harness makes to a rule's SPL, and
`test_metadata.py` already asserts the file matches its `savedsearches.conf`
stanza, so the searched query and the shipped query cannot diverge in any other
respect.

### The limit, stated plainly

Fixtures are JSON with normalised field names, ingested to a test index. Layer A
therefore proves **detection logic** — thresholds, grouping, filtering,
windowing, exclusions. It does **not** prove Windows Event XML field extraction,
which is the Splunk Add-on for Windows' responsibility, nor that the lab's real
events populate these fields.

The higher-fidelity alternative — raw Event XML fixtures plus installing the
Windows TA into the container — was considered and rejected: materially more
moving parts and container flakiness for fidelity that does not change whether
the detection logic is correct. `detections/README.md` states this boundary
directly. A documented limit is rigour; an undocumented one is a hole.

## 9. CI changes

Two edits to `.github/workflows/ci.yml`:

1. Add `projects/defensive/splunk/detections` to the existing `test` matrix, so
   layer C runs on every push across both Python versions.
2. Add a `detection-tests` job: Ubuntu, Docker, layer A only, via
   `pytest -m docker`. It is a separate job so container flakiness never reds
   the main build, and it does not gate the CI badge.

The `docker` marker is registered in the root `pyproject.toml` under
`[tool.pytest.ini_options]`, and layer A tests are deselected by default
(`addopts = "-ra -m 'not docker'"`) so that `pytest` inside the detections
project stays fast and Docker-free unless the marker is asked for explicitly.

## 10. Documentation corrections

Sysmon is asserted as implemented in four places and deployed in none. There is
no Sysmon configuration, no Ansible task installing it, and no `inputs.conf`
collecting `Microsoft-Windows-Sysmon/Operational` anywhere in the repo.

| File | Change |
|---|---|
| `docs/defensive-architecture.md` | Flow #1 payload becomes Windows Security event logs only; Sysmon moves to an illustrative row; prose in the layer summary updated |
| `docs/diagrams/defensive-architecture.html` | `SYSMON` node label and `sysmon · security log` caption corrected |
| `docs/diagrams/defensive-architecture.svg` | Re-exported from the corrected HTML |
| Both alt-texts | "Only the Windows Server Sysmon feed is implemented today" corrected |
| `README.md` | Project table: "Windows/Sysmon telemetry" corrected; Sysmon removed from that row's key-tech list |

The repo's status labelling is one of its strengths. This is the one place it
overstates, and leaving it while adding rigour elsewhere would be inconsistent.

## 11. Risks

| Risk | Mitigation |
|---|---|
| Splunk container is slow or flaky in CI | Isolated job; does not gate the badge or the main build |
| `splunk/splunk` image tag drift changes behaviour | Pin an explicit image tag |
| Vendored ATT&CK ID list goes stale | Small, rarely-changing, and a stale entry fails loudly rather than silently |
| Fixture field names drift from real Windows events | Documented limit (§8); required fields are derived from Microsoft's documented 4625/4740/4769/4688 schemas and cited in `references` |

## 12. Success criteria

- Four detections, each with metadata, SPL, alert config and fixtures.
- Layer C passes on every push; layer A passes against real Splunk.
- Every threshold has recorded reasoning.
- Every detection is `validated-offline`, and the README explains what that
  does and does not mean.
- No claim in the repo asserts telemetry that is not deployed.
