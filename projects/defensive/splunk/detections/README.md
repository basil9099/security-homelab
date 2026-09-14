# Detections as Code

Four Splunk detection rules, each defined as a directory of plain-text files
rather than a rule pasted into the Splunk UI: metadata (`detection.yml`), the
search itself (`search.spl`), the scheduled-alert configuration
(`savedsearches.conf`), and fixture events (`events/`) used to test the logic.
Two test layers check every rule in CI. The metadata tests run on every push
to `main` and every pull request. The behaviour tests run on pushes to `main`
and on pull requests that change the detections project, the `detections.yml`
workflow or the root `pyproject.toml`, and on manual dispatch. See sections 3
through 5 for what each one actually proves.

---

## 1. What this is

```
detections/
├── schema.json                          # JSON Schema for detection.yml
├── attack_techniques.txt                # allow-list of valid ATT&CK technique IDs
├── lib/
│   ├── loader.py                        # discovers rules, parses .conf, field-reference check
│   └── splunk_harness.py                # ephemeral Splunk container for behaviour tests
├── tests/
│   ├── test_metadata.py                 # Layer C — no Splunk, no Docker
│   └── test_behaviour.py                # Layer A — needs Docker
└── rules/
    ├── win_bruteforce_smb_4625/
    ├── win_account_lockout_4740/
    ├── win_kerberoasting_4769/
    └── win_suspicious_process_4688/
        ├── detection.yml                # ATT&CK mapping, logic rationale, false positives, response
        ├── search.spl                   # the SPL, as one source of truth
        ├── savedsearches.conf           # schedule, dispatch window, suppression
        └── events/
            ├── true_positive.jsonl      # events the rule must fire on
            └── benign.jsonl             # events the rule must stay silent on
```

Each rule's `search.spl` is the single source of truth for its query. A test
fails if `savedsearches.conf` drifts from it.

---

## 2. Why the detections are these four

The lab's own IaC decides what telemetry exists, so the detections are picked
to match it rather than an external list. `projects/defensive/windows_server_with_AD/ansible/vars/gpos.yml`
enables five audit subcategories under `advanced_audit_policy`: Logon, Logoff,
Account Lockout, Process Creation and Kerberos Service Ticket Operations.

| Rule | ATT&CK | Audit subcategory | Window | Threshold |
|---|---|---|---|---|
| `win_bruteforce_smb_4625` | T1110.001 | Logon | 15m | 5 |
| `win_account_lockout_4740` | T1110.003 | User Account Management (not enabled by the lab GPO; see section 7) | 1h | 3 |
| `win_kerberoasting_4769` | T1558.003 | Kerberos Service Ticket Operations | 10m | 5 |
| `win_suspicious_process_4688` | T1059.001 | Process Creation | 0m (per-event) | 1 |

Three rules read events from subcategories the GPO enables:
`win_bruteforce_smb_4625` from Logon, `win_kerberoasting_4769` from Kerberos
Service Ticket Operations, and `win_suspicious_process_4688` from Process
Creation, which carries its own command-line prerequisite (section 7).
`win_account_lockout_4740` needs User Account Management, which the GPO does
not enable (section 7). The Account Lockout subcategory the GPO does enable
generates event 4625, not 4740. No rule uses Logoff: there is no attack pattern
in scope for this project that a logoff event alone would surface.

---

## 3. How a detection is validated

Two independent test layers, both under `tests/`:

- **Layer C — metadata (`test_metadata.py`, 38 tests, no Splunk, no Docker).**
  Checks that `detection.yml` matches `schema.json`, that `status` is
  `validated-offline` (section 4), that every ATT&CK technique ID is real,
  that `savedsearches.conf` has not drifted from `search.spl`, that the
  scheduled search is actually scheduled and suppressed, and that every field
  the search reads is declared in `required_fields` (section 8). Runs in
  `ci.yml` on every push to `main` and every pull request.

- **Layer A — behaviour (`test_behaviour.py`, 8 tests, needs Docker).**
  Starts a real, ephemeral Splunk container, ingests each rule's
  `true_positive.jsonl` into a fresh index, runs the rule's actual SPL against
  it, and asserts it returns rows; then does the same with `benign.jsonl` and
  asserts it returns none. Two tests per rule. Deselected by default because
  it pulls a multi-GB image; see sections 4 and 5 for what it does and does
  not prove.

Running them, from `projects/defensive/splunk/detections/`:

```bash
pip install -r requirements-dev.txt

pytest              # Layer C — the 38 metadata tests
pytest -m docker    # Layer A — the 8 behaviour tests; needs Docker
```

---

## 4. What `validated-offline` means

Every rule's `status` is `validated-offline`: its logic is checked by tests,
but it has never seen live lab data. `test_behaviour.py` (Layer A) provisions
a throwaway Splunk container in CI, loads a rule's fixture events into it, and
runs that rule's real SPL against them — an execution, not an eyeball review
of the query text. That container is never connected to, and never receives a
single event from, the lab described elsewhere in this repo.

The behaviour tests run in the `Detection behaviour tests` workflow
(`.github/workflows/detections.yml`). They were written without Docker
available locally, so that workflow was their first execution: they first ran,
and passed, on the pull request that added them. The workflow badge in the
repository README shows the latest result. The metadata tests (38, section 3)
need no Docker and no Splunk, and run in `ci.yml` on every push to `main` and
every pull request.

No rule here is `status: validated-in-lab`, and none can be: the lab that
would generate live data for it is torn down. `validated-in-lab` remains a
valid value in `schema.json` for a future rule tested against a running lab,
but nothing in this repository has earned it.

---

## 5. The limit of the behaviour tests

The fixtures in `events/*.jsonl` are JSON objects carrying the field names the
rules read (`EventCode`, `LogonType`, `IpAddress`, and so on), posted directly
to Splunk's HTTP Event Collector with a `source` value the rules' filter
matches. Splunk indexes them and the rule's SPL reads those same field names
back out.

That proves the detection **logic**: whether the threshold, the grouping key,
the window, the exclusion filters and the suppression settings behave the way
the rule claims. It does not prove **field extraction** — that a real Windows
4625/4740/4769/4688 event, delivered as raw Event XML through a Universal
Forwarder, actually yields a field called `IpAddress` with that exact name and
shape. That extraction is the Splunk Add-on for Windows' job, not this
project's, and the fixtures bypass it entirely by starting from
already-extracted JSON. The gap is not hypothetical: an earlier version of
these rules read field names that would have left them silent against
XML-rendered events, and neither test layer could notice. See
[Field names](#field-names).

A higher-fidelity alternative was considered: ship raw Event XML fixtures and
install the Windows TA in the test container, so the tests exercise the same
extraction path production would. That setup would also verify field
extraction, which the JSON fixtures cannot, and it would have caught that
field-name mismatch. It was still rejected for its complexity: a second app to
provision and version inside an already multi-GB ephemeral container. Field
names are instead checked against Microsoft's event documentation and Splunk's
field reference. The boundary is documented here rather than hidden: these
tests do not prove the lab's real events populate these fields as named, only
that the logic is correct once they do.

### Field names

The lab forwarded XML-rendered Security events, so the searches read the event
XML's own `Data Name` fields, such as `TargetUserName`, `IpAddress`,
`TicketEncryptionType`, `NewProcessName` and `CommandLine`. Two fields in the
rules' `required_fields` are not `Data Name` fields: `EventCode`, which is
Splunk's extracted name for the XML `<EventID>`, and `Computer` (read by
`win_suspicious_process_4688`), which comes from the XML `<System>` section.

An earlier version of these rules read classic `WinEventLog` names instead,
such as `Account_Name` and `Source_Network_Address`. Splunk's field reference
does not list those for XML-rendered Security events, so the rules would have
been silent against the lab's telemetry. That does not hold for every classic
name: Splunk aliases some of them on XML events, such as `Logon_Type`.

Each search selects events with
`(source="XmlWinEventLog:Security" OR sourcetype="XmlWinEventLog:Security")`,
which matches XML Security events under both naming schemes the Splunk Add-on
for Microsoft Windows has used. From add-on 5.0.0 onward, XML Security events
carry the source `XmlWinEventLog:Security` and the shared sourcetype
`XmlWinEventLog`, the sourcetype the Splunk project README (`../README.md`,
section 4.1) records the lab ingesting. In 4.8.4 and earlier, they carry the
sourcetype `XmlWinEventLog:Security` and the source `WinEventLog:Security`.
Classic Security events match neither clause under either scheme. The filter
keys on `source` from 5.0.0 onward and on `sourcetype` in 4.8.4 and earlier,
so for the filter, the add-on version the lab ran does not need to be known.

That version independence covers the filter only, not the field names. The
rules read raw `Data Name` fields rather than the add-on's aliases, such as
`user` or `src_ip`, because the raw names come from the event XML itself.
Splunk's field reference lists them as extracted for current add-on versions;
whether add-on 4.8.4 and earlier extracted them was not checked.

One name misleads: in 4740 events, `TargetDomainName` holds the caller
computer's name, the computer the logon attempts came from, not a domain.
`win_account_lockout_4740` groups by it for that reason.

What was checked, and against what: the field names against Microsoft's event
documentation and Splunk's field reference, and the `source` and `sourcetype`
values against Splunk's add-on upgrade documentation. None of it was checked
against live data, because the lab is torn down, and the JSON fixtures cannot
prove extraction: a green behaviour-test run shows the logic works on events
that already carry these fields, not that a forwarded event yields them.

---

## 6. Tumbling vs sliding windows

Three of the four rules group events with `bucket _time span=<window>`, which
produces **tumbling** windows: fixed, non-overlapping buckets aligned to clock
boundaries, whatever time range the search covers. An attack that straddles a
boundary (three failed logons at 14:59, three more at 15:01, for a bucket span
of 15m) splits into two buckets, each under the threshold, on every run, and no
dispatch window merges them. The rule stays silent even though six failures
happened in two minutes. This is an accepted limit.

Each rule's scheduled search dispatches over a window wider than its run
interval:

| Rule | cron_schedule | dispatch.earliest_time | Overlap beyond interval |
|---|---|---|---|
| `win_bruteforce_smb_4625` | `*/15 * * * *` | `-20m@m` | 5 min |
| `win_account_lockout_4740` | `5 * * * *` (hourly at :05) | `-75m@m` | 15 min |
| `win_kerberoasting_4769` | `*/10 * * * *` | `-15m@m` | 5 min |
| `win_suspicious_process_4688` | `*/5 * * * *` | `-10m@m` | 5 min |

What the overlap buys depends on the schedule. `win_account_lockout_4740` runs
at :05, so its 75-minute window covers the hour bucket that closed five minutes
earlier whole, counting every event from that hour that is indexed by the time
the search runs; a 60-minute window would cut that bucket at :05.
`win_bruteforce_smb_4625` and `win_kerberoasting_4769` run on their bucket
boundaries, so the bucket that has just closed is covered whole either way. For
them the overlap only re-reads the last five minutes of the bucket before it: a
late-indexed event from those five minutes is still counted, but only against
that five-minute slice, and late events from earlier in that bucket are not
re-read.

`win_suspicious_process_4688` has no `bucket` at all — its threshold is one
event, so tumbling-window splitting does not apply to it (row in the table
above for completeness only).

Two alternatives were not chosen. `streamstats` with a time window gives a true
sliding window, but it re-evaluates the aggregation over every incoming event
rather than once per bucket, which costs more at search time. Dropping `bucket`
would make each run's dispatch window the window. That removes clock-boundary
splits for the scheduled alert, and a burst no longer than the overlap would
always fall inside one run's window, though longer bursts can still fall across
two runs. But the SPL would no longer encode the window, so neither ad-hoc
hunting over a wide range nor the fixture tests, which search a fixed, wide
range, would exercise it. That is why `bucket` is kept.

---

## 7. The 4688 and 4740 prerequisites

Two rules depend on audit settings the lab's own GPO does not currently
configure. Each records its gap in `data_source.prerequisites` in its
`detection.yml`.

### `win_suspicious_process_4688`: command-line logging

`win_suspicious_process_4688` depends on a Windows setting the lab's own GPO
does not currently enable. From its `detection.yml`:

> Requires ProcessCreationIncludeCmdLine_Enabled=1. Without it, 4688 is logged but
> CommandLine is empty and this detection returns nothing. The lab's audit
> GPO (projects/defensive/windows_server_with_AD/ansible/vars/gpos.yml) enables the
> Process Creation subcategory but does NOT set this value, so this detection would
> not fire in the lab as currently configured. Closing the gap needs this registry
> setting under the Homelab - Audit Policy GPO - path
> HKLM:\Software\Policies\Microsoft\Windows\System, name
> ProcessCreationIncludeCmdLine_Enabled, type dword, value 1.

As a `registry_settings` entry in the style `gpos.yml` already uses:

```yaml
- path: "HKLM:\\Software\\Policies\\Microsoft\\Windows\\System"
  name: ProcessCreationIncludeCmdLine_Enabled
  type: dword
  value: 1
```

This entry is not currently in `gpos.yml`. Adding it is what would let
`win_suspicious_process_4688` fire in the lab as deployed.

### `win_account_lockout_4740`: User Account Management auditing

`win_account_lockout_4740` depends on an audit subcategory the lab's own GPO
does not configure. From its `detection.yml`:

> Event 4740 is logged under the Audit User Account Management subcategory
> (Success). The lab's audit GPO
> (projects/defensive/windows_server_with_AD/ansible/vars/gpos.yml) does not
> configure that subcategory, so whether 4740 is logged in the lab depends on the
> domain controller's default audit policy, which was not verified. The
> Account Lockout subcategory the GPO does enable generates event 4625, not 4740.
> Closing the gap needs User Account Management (Success) added to the GPO's
> advanced_audit_policy list.

As an `advanced_audit_policy` entry in the style `gpos.yml` already uses:

```yaml
- subcategory: "User Account Management"
  success: true
  failure: false
```

This entry is not currently in `gpos.yml`. Adding it is what would make 4740
logging in the lab independent of the domain controller's default audit policy.

---

## 8. Field-reference checking is a heuristic

`lib/loader.py`'s `spl_field_references` (exercised by
`test_spl_only_reads_declared_fields`) catches a search reading a field that
is not declared in `data_source.required_fields`. Case plays no part in
deciding what counts as a field, so a lowercase name such as `src_ip` is
reported like any other. It works by regular expression, not by parsing SPL,
and it recognises exactly these shapes:

- `field=value` filters, any case
- arguments to these aggregation functions only: `dc`, `values`, `count`,
  `min`, `max`, `latest`, `earliest`
- the first argument of `match(field, ...)`
- field lists after `BY` and `table`

Names created with `AS` are subtracted from whatever it finds, and a fixed
set of names Splunk itself provides — `_time`, `index`, `sourcetype`,
`source`, `host`, `span`, `earliest`, `latest` — are never flagged as
undeclared.

Known blind spots:

- **Any other aggregation function.** `sum`, `avg`, `list`, `distinct_count`,
  `perc95`, and anything else not in the list above is invisible to the
  check. A field referenced only inside one of those would not be caught if
  it were missing from `required_fields` or misspelled.
- **`field!=value` filters.** The `!` breaks the regular expression, so a
  typo that appears only in a `!=` comparison passes unnoticed.
- **Other comparison operators.** A field compared with `>`, `<`, `>=`, `<=`
  or `==`, as in `where Field > 5`, is not recognised; only `=` is.
- **Other functions.** A field that appears only as a bare argument to a
  function not listed above, such as `like(Field, "a%")`, `len(Field)` or
  `lower(Field)`, is not recognised.
- **`rename Old AS New`.** `Old` is not recognised as a field the search
  reads, and `New` counts as a name the search creates, so a misspelled `Old`
  passes.
- **String literals.** Quoted strings are scanned like the rest of the search,
  so a regular expression such as `match(Field, "foo=bar")` reports `foo` as a
  field, a false positive that fails `test_spl_only_reads_declared_fields`
  loudly rather than hiding a gap.
- **`eval` assignments.** The name an `eval` assigns, such as `y` in
  `eval y=1`, is reported as a field the search reads, a loud false positive.

A rule whose SPL uses a shape outside this list needs its `required_fields`
checked by hand — the test passing is not proof the metadata is complete for
that rule.

---

## 9. How to add a detection

1. Create a directory under `rules/` named for the rule, e.g.
   `rules/win_new_detection_1234/`.
2. Write five files in it:
   - `detection.yml` — matching `schema.json`. Quote the `date` field
     (`date: "2026-09-12"`), or YAML parses it as a date object instead of a
     string and validation fails.
   - `search.spl` — the SPL, exactly as it should run.
   - `savedsearches.conf` — the alert stanza. Its `search` key must match
     `search.spl` after whitespace normalisation, or
     `test_savedsearch_query_matches_search_spl` fails.
   - `events/true_positive.jsonl` — one JSON object per line, one per event,
     that the rule must fire on. Must include every field listed in
     `data_source.required_fields`.
   - `events/benign.jsonl` — events, in the same shape, that the rule must
     stay silent on.

   In both fixture files, every `_time` must fall inside the harness's fixed
   search window, 2026-01-01 to 2027-01-01 UTC (`SEARCH_EARLIEST` and
   `SEARCH_LATEST` in `lib/splunk_harness.py`). The behaviour tests search only
   that range, so an event outside it is never found.
3. From `projects/defensive/splunk/detections/`, run `pytest`. It picks the
   new rule up automatically (`load_rules()` iterates every directory under
   `rules/`) and runs the metadata checks against every rule, including the
   new one (38 checks with today's four rules).
4. Where Docker is available, run `pytest -m docker` to execute the new
   rule's SPL against a real Splunk instance and confirm it fires on
   `true_positive.jsonl` and stays silent on `benign.jsonl`.
