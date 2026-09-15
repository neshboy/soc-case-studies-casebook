---
title: "CB-19 — Suspicious, Legitimate, and Still Worth a Policy Change"
case_id: "CB-19"
category: "Ambiguous / False-Positive"
disposition: "Benign Positive"
outcome_flavor: "Benign"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# CB-19 — Suspicious, Legitimate, and Still Worth a Policy Change

*This is a synthetic, composite investigation, built by threading together mechanics from
this series' own playbooks and detections into one continuous narrative. "Allenhurst Mutual
Insurance," its staff, and every host, account, and IP address named below are invented; no
real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

This case teaches the specific discomfort of a signature that is technically unambiguous and
still doesn't answer the question that matters. Every piece of evidence in this investigation
agrees: a real directory-replication operation happened, from a host that had no business
performing one, using rights nobody currently at the company remembers granting. That much is
certain almost immediately. What stays uncertain for most of the case is intent, and this case
is built so that the uncertainty survives every pivot except the last one — deliberately the
opposite shape from CB-02, where this same technical signature (a 4662 carrying both
replication control-access-right GUIDs) confirms a real compromise chain within its first two
pivots, well before that case's own closing synthesis. Same mechanism, same playbook territory,
opposite ending, on purpose — a reader who has already read CB-02 should not be able to predict
this case's outcome from the alert alone. This case
does not re-derive what a DCSync-shaped 4662 means, how to scope its blast radius, or the
DS-Replication-Get-Changes control-access-right mechanics — that belongs to the SOC Playbook
Handbook's IAM-020 (`dcsync.md`), cited here, not rebuilt. It also does not re-narrate
`CASE-2602`, "The GuardDuty Slack bot," from the SOC Manager's Operating Handbook — this case
only echoes that case's shadow-tooling failure mode in a different technical guise, on purpose,
because the pattern (an internal team stands up a legitimate tool outside every process built
to track it, and the tool's own normal behavior becomes indistinguishable from an attack) is
general enough to recur across completely different technology stacks. The doctrine for
handling that failure mode once it's confirmed belongs to the SOC Manager's Operating
Handbook's Part 26, cited via the Manager's Call callout, not adjudicated here.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-19` |
| Category | Ambiguous / False-Positive |
| Disposition | Benign Positive |
| Outcome flavor | Benign |
| Confidence at close | High, settled |
| Entry point | Standing high-severity correlation alert (replication-rights activity from an unexpected host) |
| Primary log sources | Domain controller Windows Security event log (`4662`, `4624`, `5136`, `4698`), EDR process and PowerShell script-block telemetry on the source host, internal firewall/flow log, CMDB/asset inventory, AD access-control change history, ITSM ticket and internal wiki records |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook, IAM-020 (`dcsync.md`); SOC Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment (echoing `CASE-2602`, "The GuardDuty Slack bot") |
| All times | UTC |

## 1. Alert and first look: an event that says DCSync, and nothing else yet

**[CONCEPT]** Active Directory's replication protocol lets domain controllers ask each other,
constantly, for whatever objects have changed since the last sync. Two control-access rights on
the domain object govern who's allowed to ask that question at all: DS-Replication-Get-Changes
and DS-Replication-Get-Changes-All. Every domain controller holds both, by design. Almost
nothing else legitimately needs to. A principal outside the domain controllers exercising both
rights together is the exact mechanism behind T1003.006 (OS Credential Dumping: DCSync) — and
it is also, less dramatically, the exact mechanism behind a small category of legitimate offline
credential-hygiene tools that pull password hashes to check them against a breach corpus rather
than to steal them. SOC Playbook Handbook's IAM-020 (`dcsync.md`) owns the full detection and
disposition logic for this signature; this case picks up exactly where that playbook's own
"how do I tell these two apart" section leaves off, because the honest answer is that the
signature alone can't.

At Allenhurst Mutual Insurance, a mid-size regional insurer, the correlation rule built on
IAM-020's logic — `DCSYNC-NONDC-01`, High severity — fired at 03:19 UTC on 2026-09-08. The alert
named one account, `svc-idhygiene`, and one matching event on the primary domain controller,
`DC01.allenhurst-mutual.local` (192.0.2.10). It did not yet name a source host; the rule joins
against the triggering event's own fields, and the field it flags on is the account and the
replication GUIDs, not a resolved workstation.

Deshawn Okafor, Tier 2, picked up the page four minutes later. `DCSYNC-NONDC-01` had fired
exactly six times in the eleven months it had been in production, and five of those had been
Azure AD Connect's own sync account authenticating from an approved connector server — the
sixth had been a genuine credential-theft incident at a sister business unit, contained inside
the hour. A High-severity page on this specific rule did not, in Deshawn's experience so far,
read as noise.

**[ANALYST]** The question in front of Deshawn wasn't whether the replication call happened —
the alert already confirmed that — it was who made it and from where.

### 1.1 The triggering event

```text
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4662
Task Category: Directory Service Access
Computer:      DC01.allenhurst-mutual.local
Time:          2026-09-08 03:14:07 UTC

An operation was performed on an object.

Subject:
    Security ID:       ALLENHURST\svc-idhygiene
    Account Name:       svc-idhygiene
    Account Domain:     ALLENHURST
    Logon ID:           0x3F2A18C7

Object:
    Object Server:      DS
    Object Type:        domainDNS
    Object Name:        DC=allenhurst-mutual,DC=local

Operation:
    Accesses:           Control Access

Properties:
    {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes)
    {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes-All)
```

Both GUIDs, together, against the domain object itself — the same shape IAM-020 documents as
the highest-confidence version of this signature, as opposed to a partial match on only one
right. `svc-idhygiene` wasn't a name Deshawn recognized from any standing runbook.

### 1.2 A query that couldn't answer the real question yet

Event ID 4662 doesn't carry a source IP address; the object-access audit record only ever
records who authenticated as, not from where. Deshawn's first query, to see how unusual this
account's footprint was generally, was broader than it needed to be:

```text
// too broad — see next query
index=win_security host=DC0* Account_Name=svc-idhygiene
| stats count by EventCode
→ 812 events over 30 days, mostly EventCode=4624 (logon) and 4634 (logoff)
```

Eight hundred and twelve events told Deshawn the account logged on somewhere, regularly,
without telling him where or why. The 4662 itself — the actual replication call — only
appeared once in the same window, which mattered more than the raw count: this wasn't a account
constantly hammering replication rights, it was one specific event standing alone against a
much larger background of ordinary authentication.

**Confidence: Medium, rising.** One replication-shaped event, one unfamiliar account, no source
host resolved yet. Nothing here yet distinguished an attacker from a misconfigured legitimate
job — but the signature itself was real, and real replication-rights use outside the domain
controllers is rare enough that Medium was already the honest floor.

## 2. Pivot: from the object-access event to the source host

**[ANALYST]** Before touching a second log source, Deshawn wrote down what he actually needed,
in order: where did this authentication come from, since the event itself won't say; is that
source a domain controller mislabeled in the alert, or genuinely something else; what does
`svc-idhygiene` do, according to whatever documentation exists for it; and has this account
ever exercised these rights before, or is tonight the first time. Each of those pointed at a
different source — the domain controller's own logon events for the first two, the CMDB and
account documentation for the third, and a longer replication-rights history query for the
fourth.

**[PIVOT]** Every logon carries a Logon ID unique to that session, and the same Logon ID
appears on both the 4662 and the corresponding 4624 that opened the session. Deshawn pulled the
matching 4624 on DC01 to answer the "where from" question the 4662 itself couldn't.

### 2.1 The matching logon

```text
Event ID:      4624
Computer:      DC01.allenhurst-mutual.local
Time:          2026-09-08 03:14:02 UTC
Logon Type:    3

New Logon:
    Account Name:       svc-idhygiene
    Account Domain:     ALLENHURST
    Logon ID:           0x3F2A18C7

Network Information:
    Source Network Address: 198.51.100.42
    Source Port:             51422
```

198.51.100.42 wasn't 192.0.2.10 or 192.0.2.11 — Allenhurst's two domain controllers. A CMDB
lookup resolved it in seconds: `IAM-UTIL-07`, a Windows Server 2022 VM tagged "IAM Engineering —
Utility" in the general server subnet, not the hardened domain-controller subnet, and not
tiered as a Tier-0 asset anywhere Deshawn could find. The CMDB's owner field for the host was
blank.

**Confidence: High, rising.** A non-domain-controller host, on a subnet with no business
reason to hold replication rights, using an account with no matching runbook, exercising both
DCSync GUIDs against the domain object at 03:14 — every field IAM-020 lists as a discriminator
for the malicious end of this signature had just come back the wrong way. This wasn't yet a
confirmed attack. It was, for the first time in the case, a confirmed anomaly with no innocent
default explanation sitting in front of it.

### 2.2 What the account is supposed to do

A search of Allenhurst's identity-team documentation for `svc-idhygiene` returned nothing
current — one stale wiki reference, last edited over a year earlier, describing it only as
"password hygiene automation, contact IAM eng." No current owner, no on-call contact, no
runbook entry in the SOC's own knowledge base. An account this privileged with documentation
this thin was, on its own, a second finding independent of whatever tonight's event turned out
to mean.

## 3. Pivot: EDR telemetry on the source host

**[PIVOT]** With a source host identified, the next question was what actually ran on
`IAM-UTIL-07` at 03:14 — a live interactive attacker, a scheduled job, or something in between.

```text
// EDR process telemetry, IAM-UTIL-07 (198.51.100.42), 2026-09-08T03:13:55–03:14:20Z
03:13:58Z  parent=svchost.exe (Schedule)  child=taskeng.exe
03:14:00Z  parent=taskeng.exe             child=powershell.exe
             cmdline: powershell.exe -NoProfile -ExecutionPolicy Bypass
             -File C:\IAMTools\Scripts\Run-HygieneSweep.ps1
03:14:02Z  powershell.exe loads module: C:\IAMTools\Modules\DSInternals\DSInternals.dll
03:14:07Z  net_out: IAM-UTIL-07 → 192.0.2.10:135, then ephemeral RPC port (~41 MB over 6 min)
```

No renamed binary, no unsigned loader, no interactive console session — a scheduled task
launching a signed PowerShell module. The 41-megabyte transfer to DC01 over an RPC session was
consistent with pulling a large slice of the directory, not a narrow, single-account query.

**[HYPOTHESIS]** DSInternals is a publicly available, open-source PowerShell module built for
Active Directory forensics and password auditing — its `Get-ADReplAccount` cmdlet performs the
same DRSUAPI replication call Mimikatz's `lsadump::dcsync` does, by design, because that's the
only way to retrieve a password hash outside a domain controller's own storage. Confirming the
module's authenticity ruled out one narrow theory — this wasn't a disguised credential-dumping
tool with a borrowed name — without resolving the real question. A legitimate tool run by an
attacker who found a standing, unmonitored scheduled task is still an attack.

> **Evidence Note**
> Event ID 4662 never records a source IP on its own — every "where did this replication call
> come from" answer in this case runs through a Logon ID correlation to a separate 4624 on the
> same domain controller. A SIEM correlation rule that joins those two events automatically
> would have resolved the source host inside the original alert; `DCSYNC-NONDC-01` doesn't do
> that join today, which is why Section 2 exists as its own pivot instead of being visible on
> the alert's face.

## 4. Hypothesis check: three theories, one event

**[ANALYST]** By early morning, Deshawn had enough to write down every theory still standing,
specifically so the CMDB's clean-looking category for the host — "IAM Engineering" — didn't
quietly become the answer without evidence behind it.

> **Hypothesis Board — after the EDR pivot**
> 1. **Active compromise using a legitimate tool for cover** — still live. An attacker holding
>    valid credentials for `svc-idhygiene`, or for the host itself, could launch this exact
>    script; nothing yet distinguishes that from its intended operator doing so.
> 2. **A long-dwell backdoor: the replication grant itself was planted, and tonight is just the
>    latest of many quiet runs** — still live. No history yet establishes when or by whom the
>    account was granted DS-Replication-Get-Changes and DS-Replication-Get-Changes-All in the
>    first place.
> 3. **Legitimate, under-governed internal tooling that nobody currently owns** — plausible on
>    the strength of the signed, unmodified DSInternals module and the scheduled-task launch
>    pattern, but weakened by the account's missing documentation, the blank CMDB owner field,
>    and the absence of any matching runbook the SOC could find.
> **Current confidence:** High, flat. All three theories predict a real replication call from
> this host tonight; nothing collected so far separates them.

## 5. Dead end: the login three days earlier

**[ANALYST]** Chasing hypothesis one, Deshawn pulled `IAM-UTIL-07`'s remote-access history for
the prior thirty days, on the theory that a compromised host would show an unfamiliar access
path leading up to tonight.

> **Dead End**
> Twenty-five minutes went into this. VPN logs showed exactly one remote logon to `IAM-UTIL-07`
> in the window, three days earlier, from `203.0.113.77` — an address that had never
> authenticated to this host before and geolocated well outside Allenhurst's normal employee
> footprint. For a few minutes this looked like the initial-access vector the compromise theory
> needed. It wasn't. The VPN account behind that session belonged to an IAM engineer whose last
> working day, per an HR export pulled the same morning, was the following week; travel records
> attached to an expense report matched the address's rough geography to a personal trip, not a
> business location. The session touched nothing on the host beyond a five-minute RDP login and
> logoff — no file access, no process launch logged anywhere near it. Whatever this login was,
> it wasn't how tonight's replication call got here.

The dead end cost real time and closed one specific thread. It also, without anyone noticing
yet, put a departing engineer's name into the case for the first time.

## 6. Pivot: tracing the replication grant back to its source

**[PIVOT]** With the compromise-via-remote-access theory weakened, Deshawn turned to
hypothesis two: when, and by whom, was `svc-idhygiene` actually granted DS-Replication-Get-
Changes and DS-Replication-Get-Changes-All? A live ACL check on the domain object confirmed the
rights were still present, current, and directly assigned — not inherited through a group.

### 6.1 Who granted it, and when

Allenhurst's privileged-access-management platform retains 24 months of directory-object
modification history. A search against the domain object's `nTSecurityDescriptor` attribute
turned up the grant:

```text
Object:        DC=allenhurst-mutual,DC=local
Change type:   ACE added
Grantee:       ALLENHURST\svc-idhygiene
Rights added:  DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
Changed by:    ALLENHURST\j.ferreira-adm
Timestamp:     2025-07-14 16:52:11 UTC
```

`j.ferreira-adm` — an administrative alias, currently disabled in Active Directory. No matching
change ticket existed in the ITSM system for a grant this significant, fourteen months earlier.
An unticketed, direct ACE grant on the domain object, made by an account that no longer exists,
is close to the worst-looking shape hypothesis two could have produced. For a stretch of the
investigation, this read less like an under-governed internal tool and more like a long-dwell
backdoor planted over a year earlier and left alone specifically because nobody was watching an
account nobody owned.

**Confidence: High, flat — but the theory it supports had just shifted.** The case was no
longer only asking "is tonight an attack." It was now also asking whether the entire arrangement
had been hostile from the start.

## 7. Additional evidence: the scheduled task and its name

**[PIVOT]** The task itself deserved the same scrutiny as the grant. Event ID 4698 on
`IAM-UTIL-07` showed the scheduled task's creation record:

```text
Event ID:     4698
Computer:     IAM-UTIL-07
Time:         2025-07-14 17:10:44 UTC
Task Name:    \Optimize-Index
Task content (trigger): Weekly, Tuesday and Thursday, 03:14 UTC
Action:       powershell.exe -File C:\IAMTools\Scripts\Run-HygieneSweep.ps1
```

Created 18 minutes after the ACE grant, by the same disabled admin alias — consistent, not
coincidental. The task's name, "Optimize-Index," had nothing to do with what it actually ran.
A generic, unrelated name on a scheduled task that quietly exercises directory-replication
rights is exactly the disguise pattern IAM-020 flags as a persistence indicator in real DCSync
intrusions — and it is, just as plausibly, the kind of lazy internal naming an engineer gives a
task they never expected anyone outside their own team to read the name of. Deshawn wrote both
readings down rather than picking the more dramatic one by default.

> **Analyst's Gut Check**
> A boring, mismatched task name is not, by itself, evidence of anything. Attackers use bland
> names to blend in; so does every overworked engineer who names a task after whatever they
> were thinking about, not what it does. Treat a mismatched name as a reason to keep digging,
> never as a reason to stop.

## 8. Escalation, and the message that found the missing piece

**[ESCALATION]** By mid-morning, three separate facts were all pointing the same direction at
once: an unticketed, direct replication-rights grant made by a now-disabled admin account; a
scheduled task with a name that didn't describe its own behavior, created by the same account
minutes later; and a departing engineer's unexplained remote session on the same host three
days earlier, even after the travel explanation closed that specific thread. None of it had
flipped to a confirmed benign explanation yet, and IAM-020's own guidance for this exact
signature is not to wait for full attribution before containing exposure. Deshawn escalated to
his shift lead, Renata Solis, and the two agreed to treat `svc-idhygiene` as compromised for
containment purposes while the ownership question stayed open.

> **Manager's Call**
> Whether to immediately disable `svc-idhygiene` and force a credential reset — versus
> constraining it to its current source host and watching it — is a containment-versus-
> continuity tradeoff, not a purely technical one: if this turns out to be a real, currently
> depended-upon compliance job, killing it outright breaks something a regulator may be
> expecting to see evidence of. Renata made the call to reset the account's password, revoke its
> interactive-logon right everywhere except `IAM-UTIL-07`, and reach a human in IAM engineering
> directly rather than opening a ticket and waiting. The SOC Manager's Operating Handbook, Part
> 26 — Cross-Team Politics & Stakeholder Alignment covers this exact tradeoff — acting fast
> enough to contain a possible incident without unilaterally shutting down a tool another team
> may depend on — in full; this case does not re-derive that doctrine, only shows where
> Deshawn's job ends and Renata's begins.

**Confidence: High, flat.** The disposition question — attack, dormant backdoor, or
under-governed tool — was still open. The decision to contain did not require resolving it
first.

**[PIVOT]** Renata's message to IAM engineering's team channel that morning named the account,
the host, and the scheduled task directly, rather than waiting for a routine ticket to surface
in a queue. Owen Baptiste, the current IAM engineering manager, replied within the hour.

He recognized `svc-idhygiene` immediately: an internal weak-password audit, built by Jordan
Ferreira — the engineer named in Section 5's dead end, whose last working day had in fact
already passed by the time this alert fired. The tool pulled password hashes twice weekly via
DSInternals and checked them offline against a breach-password corpus, flagging any employee
account with a reused or previously breached password to the security-awareness team. Owen
pulled up the closed ticket that had authorized building it fourteen months earlier:

```text
Ticket:    IAM-1184
Title:     Stand up automated weak-password sweep — response to Q3 market-conduct exam finding
Opened:    2025-07-02
Closed:    2025-07-18
Closure note: "Sweep deployed on IAM-UTIL-07, running via scheduled task, using
              svc-idhygiene against DC01 replication. Wiki page updated."
```

The ticket matched the technical evidence on every point that mattered: the host, the account,
the mechanism, and a timeline that put the ACE grant and the scheduled-task creation squarely
inside the ticket's own open window — four days before it closed. The regulator's finding
behind it was real too: a market-conduct exam earlier that same year had cited weak and reused
passwords among a sample of Allenhurst's privileged accounts, and this sweep was IAM
engineering's own response, built and shipped, then never handed to anyone else once Jordan
moved to a different role and eventually left the company.

What the ticket didn't show was a corresponding entry in the CMDB's asset-ownership record, a
line item in the SOC's own detection-allowlist, or any handoff when Jordan's role changed —
three separate governance steps that should have happened and didn't, each independently.

> **Hypothesis Board — after reaching IAM engineering**
> 1. **Active compromise using a legitimate tool for cover** — ruled out. The ticket, the
>    process owner's direct confirmation, and the technical timeline all agree with each other,
>    and none of them depends solely on any one source's word.
> 2. **A long-dwell backdoor planted fourteen months ago** — ruled out. The same grant the SOC
>    read as unticketed and suspicious is the ticket's own documented deployment step; the
>    "unticketed" read was a search-tooling gap (the ACE change and the ticket lived in two
>    systems that never cross-referenced each other), not an absence of authorization.
> 3. **Legitimate, under-governed internal tooling that nobody currently owns** — confirmed. Real,
>    business-justified, and running exactly as designed — with no current human owner, no CMDB
>    record, and no SOC allowlist entry, for over a year.
> **Current confidence:** High, settled.

## 9. Decision and closure

**[ESCALATION]** Closed as **Benign Positive**. Confidence: **High, settled**. The replication activity IAM-020's
correlation logic flagged was real, technically exactly what the rule was built to catch, and
entirely authorized — a documented internal control responding to a genuine regulatory finding,
run by a legitimate, signed, open-source tool, on the schedule its own creator set fourteen
months earlier. It is not a security incident.

It is still, in Renata's words to Owen that same day, "the kind of finding that should have cost
us an afternoon, not a morning" — and the reason it cost a morning is itself the finding worth
carrying forward. A service account capable of pulling every password hash in the domain had no
current owner, no CMDB record, no SOC-visible documentation, and no allowlist entry, for over a
year, discovered only because a correlation rule happened to fire on its regularly scheduled,
entirely legitimate behavior. Renata opened a follow-up track, separate from the ticket closure,
covering three concrete changes: reassign and rotate `svc-idhygiene`'s credentials under a named
current owner in IAM engineering; add the account-and-host pair to the SIEM's known-good
allowlist so `DCSYNC-NONDC-01` annotates rather than pages on its next scheduled run; and require
any future grant of DS-Replication-Get-Changes or DS-Replication-Get-Changes-All outside the
domain controllers and Azure AD Connect's own account to be recorded in a dedicated inventory the
SOC can actually query, not just a wiki page and a closed ticket in a system the SOC doesn't
watch.

> **Blind Spot**
> Nothing in this case's evidence set can fully rule out that `svc-idhygiene`'s credentials —
> real, legitimate, and unrotated for fourteen months — were also known to someone other than
> its intended operators at some point in that window. A legitimate account with a long-unrotated
> credential and no active owner is a standing opportunity even when this specific run was
> genuinely benign; closing this case assumes tonight's run was the account's only use, which the
> available log retention cannot confirm further back than 90 days.

> **What Would Change My Mind**
> This closes at High confidence, settled, on the specific question of tonight's run. That
> confidence would not survive a second, unexplained source host or account exercising the same
> replication rights on a schedule that doesn't match the sweep's documented Tuesday/Thursday
> cadence — that would suggest the legitimate grant is being ridden by something else entirely,
> a different case with the same starting signature.

## 10. Lesson learned

**[LESSON LEARNED]** A replication-rights signature answers "did this happen" with high
confidence and answers "should this have happened" with none at all — the mechanism is
identical whether the operator is an attacker or a compliance tool, and no amount of staring
harder at the 4662 itself changes that. The durable fix is never a smarter read of the same
event; it's an inventory the SOC can actually query before an alert like this one ever fires
again, so that the next legitimate, business-justified use of a dual-use mechanism doesn't cost
a morning of incident handling to rediscover what one team already knew the whole time.

That failure mode — a real, legitimate tool, stood up by one team outside every process built
to track it, generating alert noise indistinguishable from an attack until someone reaches an
actual human — is the same one the SOC Manager's Operating Handbook's `CASE-2602`, "The
GuardDuty Slack bot," documents in a completely different technical guise: a homegrown incident-
notification bot there, a fourteen-month-old password-hygiene sweep here. Neither case's fix was
a better detection rule. Both needed a governance owner who didn't exist yet. The SOC Manager's
Operating Handbook, Part 26 owns that doctrine in full; this case's contribution is showing the
same shape arrive through Active Directory replication rights instead of a cloud API key, so a
reader recognizes the pattern the second time, in a domain that looks nothing like the first.

---

**Cross-references:** SOC Playbook Handbook, IAM-020 (`dcsync.md`); SOC Manager's Operating
Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment (echoing `CASE-2602`, "The
GuardDuty Slack bot").
