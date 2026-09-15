---
title: "CB-09 — The Port Scan That Was Us"
case_id: "CB-09"
category: "Network"
disposition: "Benign Positive"
outcome_flavor: "False Positive"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook port-scanning.md", "SOC Playbook smb-scanning.md", "SOC Manager's Operating Handbook Part 26"]
---

# CB-09 — The Port Scan That Was Us

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Larchmont Freight," its staff, and every host, account, and IP address named below are
invented; no real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

This case teaches a shape the other Confirmed False Positive case in this book, CB-17, does
not: an alert that earns its High initial severity honestly, on a signature that really does
match how an attacker's early reconnaissance looks, and that only comes down off that
severity through several rounds of pivots, a dead end, and a false lead — not through one
quick lookup. Where CB-17 resolves in under an hour on a privileged-group change that turns
out to have a paper trail SOC just hadn't checked yet, this case's technical disambiguation
takes most of a shift, and the harder problem it surfaces isn't technical at all: the same
internal team has caused this exact page before, and nobody has fixed the reason why. That is
why this case hands off to the SOC Manager's Operating Handbook's Part 26 — Cross-Team
Politics & Stakeholder Alignment, rather than Part 25 — Risk Acceptance & Manager
Decision-Making Under Uncertainty, which is where CB-17 hands off. This case does not
re-derive the fan-out thresholds or scan/no-scan disposition checklist that SOC Playbook
Handbook's `port-scanning.md` and `smb-scanning.md` already own — those mechanics are cited,
not rebuilt. It also does not re-narrate the six single-alert dispositions in the Playbook
Handbook's `25-false-positive-engineering-case-studies.md` companion, none of which is a scan
alert; this is new ground for the series, not a retelling.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-09` |
| Category | Network |
| Disposition | Benign Positive |
| Outcome flavor | False Positive |
| Confidence at close | High, settled |
| Entry point | Standing scan-detection correlation alert |
| Primary log sources | Internal firewall connection log (NetFlow-equivalent), CMDB/asset inventory, EDR process telemetry on the source host, change-ticket (CAB) system, vulnerability-management team's own scan record (via direct contact), Windows Security event log on two sampled targets |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `port-scanning.md`, `smb-scanning.md`; SOC Manager's Operating Handbook Part 26 — Cross-Team Politics & Stakeholder Alignment |
| All times | UTC |

## 1. Alert: a textbook scan signature at 02:14 UTC

**[CONCEPT]** A fan-out scan detection watches for one source touching an unusually large
number of distinct destinations on the same port in a short window — the shape of an
attacker (or a worm) enumerating a network for a specific exploitable service, rather than a
normal client talking to a normal handful of servers. SOC Playbook Handbook `port-scanning.md`
owns the general fan-out math; `smb-scanning.md` owns why TCP/445 specifically is treated as a
higher-severity variant of that same pattern — SMB fan-out is the reconnaissance step that
precedes most lateral-movement and worm-style spread, T1046 (Network Service Discovery)
followed by T1021.002 (SMB/Windows Admin Shares) if a target responds the way the scanner
hoped. This case only needs the reader to know both playbooks already exist; it doesn't
re-derive either one.

Priya Devarajan was solo on the overnight shift at Larchmont Freight, a regional logistics
company running its own SOC on a skeleton night rotation, when the queue paged her at
02:14 UTC. The alert, `PORTSCAN-SMB-004`, had fired at High severity — a threshold the rule
only crosses when the destination count, the port consistency, and the time window all agree
with each other, tuned six months earlier after a near-miss where a lower threshold had let a
real worm-style sweep sit un-escalated for twenty minutes. High severity on this rule meant
something specific had already been checked by the correlation logic itself, not just a
raw connection count.

Ticket `TCK-58821` named one source, `192.0.2.45`, hitting TCP/445 across two subnets Priya
didn't recognize as related to each other at all.

## 2. Two subnets with nothing in common, and the questions that raised

**[ANALYST]** The first thing worth naming, before anything else: why would one source have
any legitimate reason to touch a Finance workstation subnet and an Engineering subnet in the
same six-minute window? Those two business functions at Larchmont Freight didn't share
infrastructure, didn't share a helpdesk queue, and — as far as Priya knew off the top of her
head — didn't share a single application that would make one host need to reach both.

```text
// firewall connection log, filtered to the alert's correlation window
2026-07-09T02:14:02Z src=192.0.2.45 dst=198.51.100.14  dport=445 proto=tcp flags=SYN
2026-07-09T02:14:02Z src=192.0.2.45 dst=198.51.100.15  dport=445 proto=tcp flags=SYN
2026-07-09T02:14:03Z src=192.0.2.45 dst=198.51.100.19  dport=445 proto=tcp flags=SYN
2026-07-09T02:14:47Z src=192.0.2.45 dst=203.0.113.22   dport=445 proto=tcp flags=SYN
2026-07-09T02:14:48Z src=192.0.2.45 dst=203.0.113.23   dport=445 proto=tcp flags=SYN
2026-07-09T02:19:41Z src=192.0.2.45 dst=203.0.113.101  dport=445 proto=tcp flags=SYN
```

The alert's own summary put real numbers behind it: 1,140 connection attempts against 214
distinct destination IPs on TCP/445, all from `192.0.2.45`, in five minutes and 40 seconds,
spanning both the `198.51.100.0/24` Finance workstation range and the `203.0.113.0/24`
Engineering range back to back. The timing — well past midnight, on a Thursday, with almost
no legitimate business traffic on either subnet — cut both ways. It's exactly when an
attacker would choose to move, precisely because nobody's watching. It's also exactly when a
maintenance team schedules something disruptive, precisely because nobody's working.

**Confidence: High, and not yet moving.** The pattern matched `smb-scanning.md`'s
higher-severity signature on every dimension the playbook lists: one source, one port, a wide
destination spread, no plausible single-application explanation visible yet.

**[ANALYST]** Four questions, in order, before Priya pulled anything else. What is
`192.0.2.45` — a user laptop, a server, an appliance? Are these connections just the SYN
handshake and an SMB dialect negotiation, or did any of them get as far as authentication? Has
this source ever done anything like this before, on any night in its history? And is there
any change activity scheduled at Larchmont tonight that would explain scanning across two
unrelated departments at once?

The firewall log answered none of those. It records the connection, not the identity behind
the source IP, not what happened after the handshake, and not whether anyone approved it.
Answering the first question meant a pivot to the CMDB.

## 3. Pivot: from the firewall log to the CMDB

**[PIVOT]** A source IP is not an identity until something maps it to an owned, inventoried
asset. Larchmont's CMDB is the system of record for that mapping, and it was the obvious next
stop before Priya spent any more time characterizing traffic from a host she couldn't yet
name.

### 3.1 The too-broad first query

Priya's first pull was a straight count of everything from `192.0.2.45` on port 445 in the
last 24 hours, to get a sense of scale before narrowing:

```text
// too broad — see next query
src=192.0.2.45 AND dport=445 | last 24h
→ 2,915 matching connection log lines
```

2,900 lines was itself a clue, but not yet a useful one — the firewall's
session table logs a fresh line every time a half-open SYN gets retried after its short
per-destination timeout, so a single destination that never completed a handshake could
account for four or five lines on its own. Raw line count wasn't the same thing as distinct
targets, and it wasn't scoped to the alert's own window.

### 3.2 The narrowed query

Narrowing to distinct destination IPs within the alert's actual 02:14:02Z–02:19:42Z window
gave the number that mattered:

```text
src=192.0.2.45 AND dport=445 | 02:14:02Z–02:19:42Z | dedup by dst
→ 214 distinct destination IPs, 1,140 total connection attempts
```

An average of 5.3 attempts per destination, evenly spread across the window rather than
clustered on a handful of hosts — consistent with a tool retrying a short timeout on
unresponsive hosts, not consistent with a human manually poking a target list one at a time.

The CMDB lookup on `192.0.2.45` came back clean and specific: hostname `VMSCAN-03`, category
"Vulnerability Management — Scan Engine," owning team "Vulnerability Management," located in
the `192.0.2.0/24` appliance farm subnet.

**[HYPOTHESIS]** Knowing the CMDB category doesn't resolve anything by itself. A vulnerability
scanner is exactly the kind of asset an attacker wants to compromise first, precisely because
it already has broad, pre-approved reach into subnets a normal workstation could never touch
without tripping a dozen other alerts. "It's the vuln scanner" is not yet an answer; it's a
second question, sitting on top of the first one.

## 4. Hypothesis check: knowing what it is doesn't mean knowing what happened

**[ANALYST]** Three theories were genuinely live at this point, and Priya wrote all three
down before doing anything else, specifically so she wouldn't let the CMDB's clean-looking
answer quietly become the conclusion without evidence to back it.

> **Hypothesis Board — after the CMDB pivot**
> 1. **A compromised scan engine, being used as a staging point for internal
>    reconnaissance** — still live. A compromised `VMSCAN-03` would produce exactly this
>    traffic shape, and would explain the odd combination of two unrelated subnets: an
>    attacker using an already-trusted appliance to enumerate targets they haven't chosen
>    yet.
> 2. **Unauthorized or off-process use of the scan engine** — still live. No approved change
>    or scan ticket has been found yet for tonight, from anyone.
> 3. **An authorized vulnerability-management sweep that SOC simply wasn't told about** —
>    still live. It matches the asset's documented role, but nothing yet confirms anyone
>    actually approved this specific job.
> **Current confidence:** Low. All three hypotheses are still genuinely live and none of them
> yet has a piece of evidence that outweighs the others. Knowing what the source is narrows
> the field of possible explanations; it does not favor any one of them over the others.

## 5. Pivot: EDR on the scan engine itself

**[PIVOT]** Distinguishing "this appliance is doing its job" from "this appliance has been
turned into someone else's tool" needed host-level evidence: what was actually running on
`VMSCAN-03`, and whether the traffic pattern on the wire looked like a scan job or an
exploitation attempt.

```text
// EDR process telemetry, VMSCAN-03, 2026-07-09T02:12–02:22Z
2026-07-09T02:12:58Z parent=svc_scanhost.exe child=scan_worker.exe --job=weekly-sweep-disabled
2026-07-09T02:13:04Z parent=scan_worker.exe child=smb_probe.exe --mode=fingerprint
2026-07-09T02:20:10Z cpu_avg=71% net_out_avg=38Mbps (baseline for active job: 60-85%, 25-45Mbps)
```

No new binary, no unsigned executable, no privilege-escalation attempt, no outbound connection
to anything outside Larchmont's own management subnets. The process tree was exactly the
vulnerability-management platform's own documented worker chain, and the CPU and network
utilization sat inside that platform's normal range for an active job, not above it.

Priya also sampled two of the 214 targeted hosts' own Security event logs, checking
specifically for Event ID 4624 with a network logon type, to see whether any connection had
gone past the SMB dialect negotiation into an actual authentication attempt — the detail that
would separate a fingerprinting probe from something trying to get in.

```text
// Security event log, sample target 198.51.100.14, window 02:13:55Z-02:14:10Z
(no Event ID 4624 entries in window; SMB session table shows negotiate-only, no session setup)
```

Nothing. Every sampled connection stopped at protocol negotiation — enough to identify the
SMB dialect and any version-specific banner, never far enough to log in. That is the specific
signature `smb-scanning.md` describes for a vulnerability-scanning probe, not for an
exploitation attempt or a T1021.002 lateral-movement hop, both of which need a completed,
authenticated session to do anything.

**Confidence: Low, flat.** The compromised-appliance hypothesis had just lost its best piece
of supporting evidence — nothing on the host or on the wire looked like an attacker using this
box for anything beyond what it was built to do. It wasn't ruled out yet, and neither of the
two surviving alternatives had picked up anything specific pointing at it instead. Three
hypotheses were still tied; one of them was simply weaker than it had been an hour ago.

## 6. Two roads that went nowhere: the missing change ticket and the subnet with a history

**[ANALYST]** The next obvious move was the change-ticket system — if this was an authorized
sweep, Larchmont's CAB process should show an approved change record naming `VMSCAN-03` and
tonight's window. Priya searched by asset tag, then by hostname, then by owning team, across
the last 30 days.

> **Dead End**
> 25 minutes went into this. Zero approved change records existed for `VMSCAN-03` in
> the CAB system in the last 30 days — not tonight's window, not any prior week. For a few
> minutes that looked like real support for "unauthorized use of the scan engine." It wasn't
> support for anything. The CAB system, as the callout below explains, was never the system
> this kind of activity would show up in, and searching it harder wasn't going to produce a
> ticket that was never going to exist there.

> **Evidence Note**
> Larchmont's CAB system captures scheduled, recurring changes — the vulnerability-management
> team's standing weekly sweep is on that calendar, and it showed up the moment Priya searched
> for it. Ad hoc, advisory-driven emergency sweeps triggered directly from the
> vulnerability-management platform's own console don't generate a CAB ticket at all; that
> team's leadership can launch one without going through change management, by design, because
> the whole point is responding to a new critical advisory faster than the weekly CAB cycle
> allows. SOC's visibility into that specific class of activity was zero, not partial — the
> system the analyst would naturally check first simply doesn't cover it.

**[PIVOT]** With the CAB system dead-ended, Priya tried one more fast, independent check
before paging anyone: she cross-referenced `192.0.2.0/24` against Larchmont's own incident
history, on the theory that a subnet with a documented problem in its past deserved extra
scrutiny in its present.

> **False Lead**
> A security review six months earlier had flagged a rogue, unauthorized device on
> `192.0.2.0/24` during an audit — enough of a match to make Priya's stomach drop for a
> minute. It turned out to explain nothing about tonight. That subnet had been fully
> decommissioned and rebuilt after the earlier finding: same address block and VLAN ID,
> reassigned six weeks later to house the new vulnerability-management appliance farm as part
> of an unrelated infrastructure refresh. The historical flag belonged to a device and a
> purpose that no longer existed on that network. Address reuse, not a resurfacing problem,
> was the entire explanation.

Two ways of getting a fast, independent answer had just been tried, and both had come up
empty. Neither one moved any of the three hypotheses from Section 4 forward or back — they
only closed off two paths that were never going to produce an answer on their own.

## 7. Pivot: contacting the vulnerability-management team

**[PIVOT]** Both quick checks had dead-ended. The only source left that could actually confirm
or kill hypothesis 3 was the vulnerability-management team itself. Priya paged the team's
on-call contact directly rather than waiting for morning.

Marcus Webb, the vulnerability-management lead, answered within ten minutes and confirmed it
immediately: a critical, unauthenticated SMB remote-code-execution advisory had been published
four days earlier, and his team had launched an emergency sweep overnight against every subnet
in scope for the 72-hour compliance attestation the advisory triggered — Finance and
Engineering both included, because both ran the affected file-sharing service on a subset of
hosts. He confirmed his own leadership had authorized the job. He also admitted, without much
prompting, that ad hoc emergency sweeps like this one never made it onto the shared calendar
SOC could see — only the recurring weekly job did — and that this wasn't the first time an
emergency sweep had paged the SOC as a High-severity scan alert.

**Confidence: Medium, rising.** Hypothesis 3 finally had a specific, named account behind it,
instead of just being the option nothing yet argued against. It was still one person's word on
a phone call, not yet a piece of evidence Priya could check herself in a system of her own.

> **Analyst's Gut Check**
> "Yes, that's us" from another team is a lead, not a closure. Get a job ID and an exact
> start/stop timestamp from their own console before you close anything, and check it against
> your own log window yourself. A confident phone confirmation and an actual matching audit
> trail are two different levels of evidence, and this book's disposition standard asks for
> the second one, not the first.

### 7.1 Matching the scan to the advisory

**[HYPOTHESIS]** Marcus exported the job record from the vulnerability-management platform's
own console: job ID `VM-SWEEP-20260709-02`, target list of 214 hosts across exactly the two
subnets in question, start time 02:14:00Z, stop time 02:19:44Z. That window matched the
firewall log's observed activity to within two seconds on each end — not an approximate match,
a specific one.

The probe cadence lined up too. The platform's documented throttle rate for this specific
unauthenticated-check module sends one SYN per target, waits roughly 26 milliseconds, and
retries up to five more times — six attempts total — before marking a host unresponsive,
consistent with the 5.3 attempts-per-destination average Priya had already calculated from the
firewall log in Section 3.2, before she had any reason yet to connect it to a specific tool's
throttle setting. A generic attacker scanning tool wouldn't reliably reproduce that exact
retry ceiling and timing; a copy of the same platform running the same check, on a schedule
that happened to avoid SOC's calendar, would.

> **Hypothesis Board — after contact with vulnerability management**
> 1. **A compromised scan engine used for reconnaissance** — ruled out. Clean process
>    telemetry, no authentication attempts on any sampled target, and a probe cadence that
>    matches the platform's own documented throttle rate rather than a generic scanning tool's.
> 2. **Unauthorized or off-process use of the scan engine** — ruled out. The job was
>    authorized by the vulnerability-management team's own leadership in direct response to a
>    named advisory; it just wasn't authorized *to SOC*.
> 3. **An authorized sweep SOC wasn't told about** — supported. Independent job-ID, timestamp,
>    target-list, and probe-cadence evidence all agree with the firewall log, from a source
>    (the vulnerability-management platform's own audit trail) that has no reason to
>    coordinate a story with the firewall.
> **Current confidence:** High, settled. No further evidence collected changed this once the
> job-record cross-check landed.

## 8. Escalation and closure

**[ESCALATION]** Priya closed `TCK-58821` at 04:02 UTC as **Benign Positive** — the alert
fired correctly on a real, wide fan-out scan; the activity itself was an authorized
vulnerability-management response to a genuine advisory, not a security incident. That
disposition took under two hours to reach once the right people were on the phone. The
second decision took longer to think through: whether to also flag, separately, that this was
at least the second time an ad hoc emergency sweep from this same team had generated a
High-severity page with no advance notice to SOC. Priya escalated that specific pattern —
not the ticket, the pattern — to her SOC manager, Dana Ostrowski, the next morning.

> **Manager's Call**
> Whether ad hoc emergency scans should be required to notify SOC in real time before
> launching — and who has the authority to hold the vulnerability-management team to that,
> given that team's own legitimate urgency during an active advisory window — is not a call
> the investigating analyst gets to make alone. It is a cross-team process question with a
> real tradeoff: faster compliance response against SOC's ability to tell an authorized sweep
> from an actual intrusion without a two-hour investigation every time it happens. The SOC
> Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment covers
> exactly this kind of recurring inter-team friction and how a manager negotiates a fix that
> doesn't just win the argument once; this case does not re-derive that doctrine, only marks
> the point where Priya's job — confirm what actually happened tonight — ends and Dana's job —
> make sure this stops costing a full investigation every few months — begins.

> **Blind Spot**
> SOC has no direct, independent visibility into the vulnerability-management platform's own
> scan-scheduling system — no read access to its console, no API feed into the SIEM. Everything
> in Section 7.1 beyond the firewall log itself came from Marcus's account and an export he
> chose to provide, not from a system SOC can query on its own. That's sufficient evidence for
> this specific disposition, because the job ID, timestamps, target list, and probe cadence
> all independently corroborate each other and none of them depend solely on Marcus's word. It
> would not be sufficient if any one of those details had failed to match — and until SOC has
> its own read access into that platform, every future version of this exact scenario starts
> from the same blind spot.

> **What Would Change My Mind**
> This closes at High confidence, settled, but not because no fact could reopen it. If an
> independent pull of the vulnerability-management platform's own audit log — not the export
> Marcus chose to hand over — showed a different job ID or a start time that didn't match the
> firewall log as closely as the exported record claimed, that would be enough to reopen the
> compromised-appliance hypothesis specifically. Equally, if any of the 214 sampled targets
> later surfaced an actual authenticated session or a credential-access attempt in that same
> window, that would matter more than anything else in this case and would override every
> other piece of corroborating evidence collected here.

## 9. Lesson learned

**[LESSON LEARNED]** A fan-out scan detection tuned well enough to fire only on genuine,
severity-worthy patterns will keep rediscovering an organization's own authorized tooling as
an apparent attack for as long as that tooling's schedule lives in a system the detection
layer can't see. The technical fix that generalizes past Larchmont: an automated feed from the
vulnerability-management platform's own scan calendar — recurring and ad hoc alike — into
whatever system maintains the SOC's detection allowlist, so an authorized sweep either
suppresses the alert or annotates it automatically, instead of requiring a full investigation
every time an advisory triggers an emergency response. That's a detection-engineering tuning
change, and it belongs with whoever owns `port-scanning.md` and `smb-scanning.md`'s production
rules, not re-derived in this case.

The deeper lesson is the one Priya escalated to Dana rather than resolved herself: this was not
a one-time miscommunication, it was a recurring gap between two teams that each had a
legitimate reason for how they operate — SOC needs advance notice to triage efficiently;
vulnerability management needs to move fast on a live advisory without waiting on a change
window. A single closed ticket doesn't fix a recurring coordination failure, no matter how
cleanly it closes. That's a people-and-process problem, and it is exactly what the SOC
Manager's Operating Handbook, Part 26 exists to own — this case's job was to hand it off with
the specific pattern named, not to solve it.

---

**Cross-references:** SOC Playbook Handbook `port-scanning.md`, `smb-scanning.md`; SOC
Manager's Operating Handbook Part 26 — Cross-Team Politics & Stakeholder Alignment.
