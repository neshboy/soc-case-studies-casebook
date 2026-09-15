---
title: "CB-17 — The Critical Alert That Was Actually Nothing"
case_id: "CB-17"
category: "Ambiguous / False-Positive"
disposition: "Benign Positive"
outcome_flavor: "False Positive"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook domain-admin-group-modification.md", "SOC Manager's Operating Handbook Part 25"]
---

# CB-17 — The Critical Alert That Was Actually Nothing

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Bellhaven Mutual Insurance," its staff, and every host, account, ticket, and IP address
named below are invented; no real organization, employee, incident, or breach is depicted
or implied.*

## Why this case exists

This case teaches the opposite lesson from the other Confirmed False Positive case in this
book, CB-09. CB-09's alert takes most of a shift to disambiguate, through several pivots, a
dead end, and a false lead, because nothing about that investigation has a single
authoritative record sitting somewhere waiting to be found — the answer has to be assembled
from several partial sources plus a phone call. This case's alert is, on its face, more
severe — Critical, not High, and on the identity plane's most sensitive group — and it
resolves in under an hour, because the one record that actually settles it exists the whole
time, filed and approved before the triggering event even happened, in a system the analyst
already had access to and simply hadn't checked yet. The lesson is that a Critical label
describes how bad a finding would be if it's real, not how long the analyst should expect
verification to take, and that the fastest correct move is sometimes the least dramatic one:
check the paper trail before doing anything else. This case cites SOC Playbook Handbook's
`domain-admin-group-modification.md` for the general mechanics of privileged-group monitoring
and does not re-derive them, and it hands its one open institutional question to SOC
Manager's Operating Handbook, Part 25 — Risk Acceptance & Manager Decision-Making Under
Uncertainty, rather than adjudicating it here — a different kind of manager's-desk problem
than CB-09's cross-team coordination gap, closer to a standing question of who signs off on
living with a known detection blind spot for a while longer. None of the six single-alert
dispositions in the Playbook Handbook's `25-false-positive-engineering-case-studies.md`
companion is a privileged-group-modification alert; this is new ground for the series, not a
retelling.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-17` |
| Category | Ambiguous / False-Positive |
| Disposition | Benign Positive |
| Outcome flavor | False Positive |
| Confidence at close | High, settled |
| Entry point | Critical-severity standing correlation alert (privileged group change outside the approved-change window) |
| Primary log sources | Domain controller Security event log, Tier-0 privileged access workstation (PAW) registry, on-call duty-roster system, ChangeGuard (ITSM/CAB ticketing), certificate-expiry monitoring alert history, Entra/AD conditional-access sign-in log |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `domain-admin-group-modification.md`; SOC Manager's Operating Handbook, Part 25 — Risk Acceptance & Manager Decision-Making Under Uncertainty |
| All times | UTC |

## 1. Alert: a Critical page on a Sunday afternoon

**[CONCEPT]** `domain-admin-group-modification.md` owns the general shape of this detection:
Event ID 4728 fires on any addition to a security-enabled global group, which is far too
noisy to alert on directly, so the playbook's production rule filters to one specific group
SID — Domain Admins, well-known RID 512 — and pairs the membership-add event with a lookup
against an approved-change whitelist. The playbook's reasoning is that legitimate Domain
Admins membership changes are rare enough, and consequential enough, that every one of them
should already have a change ticket filed before it happens. A membership add with no
matching ticket is the specific shape of T1098 (Account Manipulation) —
an attacker's fastest route to durable, blend-in persistence once they already hold any
privileged foothold, because it doesn't require creating a new account or touching anything
that looks unusual on its own. This case only needs the reader to know that rule already
exists; it doesn't re-derive it.

At Bellhaven Mutual Insurance, that rule is `PRIVGROUP-DA-002`, and it is one of a small
handful tuned to page at Critical severity rather than High — a deliberate choice the SOC
made after a tabletop exercise concluded that an unauthorized Domain Admins add was one of
the few findings where minutes, not an hour, could matter. On 2026-08-16, a Sunday, at 14:04
UTC, it fired.

```text
// Domain controller Security event log, BH-DC02
2026-08-16T14:03:47Z EventID=4728 TargetGroup="Domain Admins" TargetGroupSid=S-1-5-21-...-512
  TargetAccount=m.tran-adm SubjectAccount=g.ilupeju-adm SubjectLogonId=0x3F2A9C1
  SourceHost=BH-DC02
```

The ticket, `TCK-71904`, named the whole story in two fields before anyone had looked at a
single log line: a member had just been added to Domain Admins, and no entry in
`PRIVGROUP-DA-002`'s approved-change whitelist matched the account, the group, or the time
window. Owen Marsh, the Tier 1 analyst on Bellhaven's Sunday day shift, picked it up at 14:07
UTC.

## 2. First observation: the account that gained the keys

**[ANALYST]** The subject account, `g.ilupeju-adm`, meant something to Owen immediately —
it belonged to Grace Ilupeju, Bellhaven's IT Operations Director, and it was not her everyday
account. Bellhaven's privileged-access model gives exactly one person at a time a
pre-provisioned, disabled-by-default "break-glass" admin identity, activated only under a
documented emergency-access runbook; Grace held that identity this quarter. The target
account, `m.tran-adm`, belonged to Minh Tran, a senior infrastructure engineer whose
day-to-day privileges sat in a delegated "PKI Operators" group — nowhere near Domain Admins.

Two facts, on their own, before any second data source: a break-glass identity had been
activated, and it had just added a mid-tier engineer's admin account to the single most
sensitive group in the domain. Neither fact says who did it or why. Both are exactly the
shape a real compromise would produce if an attacker had already gotten as far as one
privileged credential and wanted to entrench a second one.

**Confidence: High, and not yet moving.** Everything visible so far matched
`domain-admin-group-modification.md`'s described worst case on every dimension it names: a
privileged actor, a non-obvious target, no ticket the rule's own whitelist could find, and a
weekend timing window with almost nobody else around to notice.

**[ANALYST]** Before touching a second log source, Owen wrote down four questions. Is the
break-glass account's activation itself legitimate, or could it have been triggered by
someone who compromised Grace's own credentials? Did the technical change happen from a host
and in a manner consistent with how break-glass access is actually supposed to be used at
Bellhaven? Is there a ticket anywhere in the organization's systems that the correlation
rule's own whitelist simply failed to match? And is there an independent, unrelated reason
anyone would need emergency Domain Admins access on a Sunday afternoon — something that would
exist whether or not this specific alert had ever fired?

The Security log answered none of those by itself. It records that the change happened and
who the two accounts were; it says nothing about intent, nothing about process, and nothing
about whether anyone with the authority to approve this ever actually did.

## 3. Pivot: from the security log to the Tier-0 PAW registry and the on-call calendar

**[PIVOT]** The fastest way to test "compromised break-glass credential" without waiting on
anything slower was to check where the technical action came from and whether that lined up
with how Grace was supposed to be working that day.

```text
// preceding logon, BH-DC02, correlated by SubjectLogonId 0x3F2A9C1
2026-08-16T14:02:58Z EventID=4624 LogonType=3 TargetAccount=g.ilupeju-adm
  SourceIP=192.0.2.9 AuthenticationPackage=Kerberos MFA=SmartcardRequired:True
```

`192.0.2.9` matched Grace's own entry in Bellhaven's Tier-0 PAW registry — a locked-down,
smartcard-only workstation issued specifically for privileged AD actions, never used for
email, browsing, or anything else. That ruled out the single most common way a break-glass
add gets flagged for the wrong reason: a generic corporate laptop suddenly performing a
Tier-0 action. It didn't rule out a hijacked, already-authenticated session on that same
workstation — smartcard authentication proves who unlocked the session, not that nobody
else was driving it afterward.

A second, independent source closed part of that gap. Bellhaven's on-call duty roster,
queried separately from anything AD-related, showed Grace as the assigned on-call IT
Operations Director for the entire weekend of 2026-08-16, a schedule set nine days earlier
and untouched since.

**[HYPOTHESIS]** Two facts from two systems that don't talk to each other now agreed: the
device was the right device, and the person was the right person to be doing something
privileged that weekend. Neither fact proves this specific action was authorized. Bellhaven's
own on-call director being active on a Sunday, from her own registered admin workstation, is
also exactly what a well-covered social-engineering or session-hijack attempt would try to
look like.

## 4. Hypothesis check: what a clean device and a matching calendar don't prove

**[ANALYST]** Three theories were genuinely live at this point, and Owen named all three
before letting the clean-looking device and calendar match quietly become the answer.

> **Hypothesis Board — after the PAW and on-call pivot**
> 1. **Grace's break-glass credential was compromised, and the attacker used it to add a
>    second, lower-scrutiny account to Domain Admins for persistence** — weakened, not
>    ruled out. The source device and on-call assignment both check out; neither is proof
>    against a hijacked session on an already-authenticated workstation.
> 2. **This is a genuine emergency, but Grace acted outside Bellhaven's own change-control
>    process** — still live. No ticket has been found yet; the correlation rule's own
>    whitelist miss is not, by itself, proof that no ticket exists anywhere.
> 3. **This is a genuine emergency with a real, approved change record that the
>    correlation rule's whitelist simply hasn't ingested yet** — still live and entirely
>    unchecked; nobody has looked at ChangeGuard yet.
> **Current confidence:** Low, falling. All three hypotheses are still genuinely live and
> none of them yet has a piece of evidence that outweighs the others — the compromise theory
> lost its easiest supporting fact, an unfamiliar device, in the very first pivot, but losing
> that fact narrows the field without yet favoring either surviving alternative.

## 5. False lead: the failed logon from a hotel network

**[PIVOT]** Before moving to ChangeGuard, Owen ran one more check on Minh Tran's own
identity — the target account's owner, not the actor — on the theory that if this were a
coordinated compromise, some sign of it should show up on both ends, not just the actor's.

```text
// Entra conditional-access sign-in log, m.tran (standard account, not m.tran-adm)
2026-08-16T12:53:47Z result=Failure reason="Device not compliant" sourceIP=203.0.113.58
  location=Regional-Airport-Hotel-WiFi app=CertMonitoringDashboard
```

For a few minutes, an unfamiliar external IP failing a sign-in attempt an hour and ten
minutes before the Domain Admins change looked like exactly the kind of loose thread a
compromise investigation is supposed to pull on.

> **False Lead**
> The failed sign-in traced to Minh's own personal phone, on hotel WiFi, at a conference he
> was attending that weekend — he'd tried to check Bellhaven's certificate-expiry monitoring
> dashboard from an unmanaged device after getting the first page about the expiring
> certificate, and conditional access correctly blocked it for failing device compliance.
> He called Grace directly afterward instead of trying again. The failed logon wasn't a
> second compromised account; it was the first human step in the exact chain of events that
> produced tonight's alert, from the one person on the ground closest to why any of this
> was happening at all.

## 6. Pivot: from the security log to ChangeGuard

**[PIVOT]** With the compromise theory weakened twice and the target account's own owner
accounted for, the only source left that could actually settle hypotheses 2 and 3 was
Bellhaven's change-ticket system. `PRIVGROUP-DA-002`'s own whitelist lookup had already
failed to find a match; that meant checking whether the whitelist was wrong, not assuming it
was complete.

### 6.1 The too-broad first query

Owen's first search used the obvious term:

```text
// too broad — see next query
ChangeGuard search: text contains "Domain Admins", opened within last 24h
→ 0 results
```

Zero results felt like it supported hypothesis 2 — no ticket, no process followed — for
almost as long as it took to notice the search had a hole in it. ChangeGuard's own ticket
templates describe privileged-access work using Bellhaven's internal terminology, "Tier-0
elevation," not the literal group name a Windows event log uses. A text search built around
the wrong vocabulary was never going to find a ticket that used a different one.

### 6.2 The narrowed query

Searching by target account and record type instead of free text found it in under a minute.

```text
ChangeGuard search: target_account="m.tran-adm" AND record_type="Emergency Change" AND
  opened_after="2026-08-16T00:00:00Z"
→ 1 result: CHG-EMG-88710
```

`CHG-EMG-88710`, opened 13:41 UTC, 22 minutes before the technical change: requester and
approver both Grace Ilupeju, business justification "renew BH-CA01 issuing CA OCSP
responder certificate before 2026-08-17T06:00:00Z expiry; primary authorized operator
(Farrah Doyle) unavailable, hospitalized 2026-08-14," scoped action "add m.tran-adm to
Domain Admins," planned reversal "remove no later than 18:00 UTC same day," invoked
procedure "BG-PROC-04, Break-Glass Emergency Privileged Access," mandatory follow-up "CISO
secondary review within 24 hours of any self-approved break-glass action."

**Confidence: Medium, rising.** Hypothesis 3 finally had a direct, specific piece of
supporting evidence — a ticket, opened before the technical change, naming the same accounts
and the same group — rather than just being the option nothing yet argued against. It wasn't
High yet: a single self-approved ticket is a claim an attacker who does their homework could
also produce, and nothing so far had checked it against a source Grace's own account
couldn't have touched.

> **Evidence Note**
> `PRIVGROUP-DA-002`'s approved-change whitelist is built by a nightly batch job that pulls
> the next seven days of already-scheduled Standard and Normal changes from ChangeGuard at
> 02:00 UTC. Emergency Change records, by definition, don't exist yet when that batch runs —
> they're opened and approved the same day, sometimes the same hour, they're executed. The
> whitelist the correlation rule checked wasn't incomplete by accident; it structurally
> cannot contain same-day emergency approvals, because nothing about the batch's design
> anticipates them. Every legitimate Emergency Change involving Domain Admins will trip this
> exact alert at Critical severity until that's fixed, independent of how well-approved or
> well-documented the change actually is.

## 7. Additional evidence: four sources, one story

**[HYPOTHESIS]** A single ticket, on its own, is a claim, not proof — Bellhaven's own
break-glass runbook allows a self-approved emergency change precisely because waiting for a
second live approver at 2 p.m. on a Sunday defeats the point of having break-glass access at
all, which meant the ticket alone couldn't fully separate "genuine emergency" from "an
attacker who also knows how to write a convincing ticket." What mattered was whether
independent systems, none of which take input from each other, told the same story.

They did. The certificate-monitoring platform's own alert history, queried separately from
ChangeGuard, showed an automated warning fired to Minh's on-call pager at 12:50 UTC — 51
minutes before the ChangeGuard ticket existed — for the exact certificate named in the
ticket's justification, at the exact expiry timestamp the ticket cited. BG-PROC-04's written
runbook, pulled from Bellhaven's internal policy repository, explicitly names self-approval
plus a mandatory 24-hour secondary review as the correct, documented shape of a break-glass
invocation — meaning Grace approving her own emergency change wasn't a deviation from
process, it was the process working as designed. And the technical change itself, the on-call
calendar, the PAW registry match, and now the ticket's own timestamps all lined up within
minutes of each other, across four systems that share no common trust boundary an attacker
could compromise once and use to fake all four.

> **Hypothesis Board — after the ChangeGuard pivot**
> 1. **Compromised break-glass credential, used to add a persistence account** — ruled out.
>    Registered device, matching on-call assignment, a ticket opened before the technical
>    change with timestamps that agree with an independently-sourced monitoring alert the
>    ticket itself couldn't have manufactured.
> 2. **Genuine emergency, outside change control** — ruled out. `CHG-EMG-88710` exists,
>    predates the technical action by 22 minutes, and follows Bellhaven's own written
>    break-glass procedure exactly, including the self-approval step the runbook itself
>    calls for.
> 3. **Genuine, fully approved emergency change the whitelist hadn't ingested yet** —
>    confirmed. Four independent sources — ChangeGuard, the certificate-monitoring alert
>    history, the on-call roster, and the PAW registry — corroborate each other with no
>    contradiction.
> **Current confidence:** High, settled. Nothing collected afterward changed this.

> **Analyst's Gut Check**
> A Critical page's own urgency pushes toward containment thinking first — disable the
> account, isolate the workstation, escalate to incident response. On an alert this book's
> playbook already scopes around a change-ticket whitelist, check that system before any of
> that, by target account and ticket type rather than free text. It's a five-minute look that
> settles more than twenty minutes of device forensics will, if the ticket turns out to
> exist.

## 8. Escalation and closure

**[ESCALATION]** Bellhaven's runbook for a Critical-severity identity finding requires a
second analyst's sign-off before closure, so Owen looped in Sylvia Kwan, the Tier 2 analyst
on shift, who reviewed all four corroborating sources independently before agreeing. At 14:55
UTC, `TCK-71904` closed as **Benign Positive** — the alert fired correctly on a real, sensitive
privileged-group change; the change itself was a fully authorized, properly documented
emergency action, not a security incident. Total time from page to closure: 48 minutes.

Owen flagged one more thing before closing the ticket: Bellhaven's alert history showed two
earlier Critical pages this same quarter that resolved the identical way, against the
identical batch-lag gap, on unrelated Emergency Changes. This was the third time, not the
first.

> **Manager's Call**
> Whether to temporarily reduce `PRIVGROUP-DA-002`'s severity for the specific condition
> "Emergency Change record exists but hasn't yet reached the whitelist" — trading faster,
> calmer investigations against a slower initial response if a real Domain Admins compromise
> is ever paired with a forged or socially engineered Emergency Change record — is a
> risk-acceptance decision, not a tuning call the investigating analyst gets to make alone.
> SOC Manager's Operating Handbook, Part 25 — Risk Acceptance & Manager Decision-Making
> Under Uncertainty gives the four dimensions — dollar exposure, reversibility, blast radius,
> and duration — for deciding whether a call like this sits at the SOC manager's own level or
> needs to go to the CISO, and this case does not re-derive that scorecard. It only marks the
> point where Sylvia's job — confirm this specific page was benign — ends and Bellhaven's SOC
> manager, Lena Marchetti's, job — decide whether three benign Critical pages against the same
> known gap in one quarter is still an acceptable cost to keep absorbing, or a standing risk
> that needs someone's signature either way — begins.

> **Blind Spot**
> Every source that corroborated hypothesis 3 ultimately traces back to ChangeGuard's own
> record and Grace's own account activity across two systems Bellhaven controls, not to a
> fifth source outside that trust boundary. The certificate-monitoring alert corroborates the
> business justification independently, but nothing here cryptographically proves the
> ChangeGuard ticket wasn't altered after the fact by someone with access to both. BG-PROC-04's
> own mandatory 24-hour CISO secondary review exists specifically to catch that gap; it hadn't
> happened yet at the time this ticket closed.

> **What Would Change My Mind**
> This closes at High confidence, settled, on the strength of four independent, mutually
> corroborating sources — not because nothing could reopen it. If the CISO's mandatory
> secondary review of `CHG-EMG-88710` turned up any irregularity — an approval timestamp
> edited after the fact, or Grace's own account of events not matching the ticket she
> ostensibly filed — that would be the one thing specific enough to reopen the compromised-
> credential hypothesis, because it would mean the two systems this case leaned on hardest
> share more of a trust boundary than this investigation assumed.

## 9. Lesson learned

**[LESSON LEARNED]** The technical fix generalizes past Bellhaven directly: a nightly batch
feed from a change-ticket system into a correlation rule's approved-change whitelist will
always miss same-day Emergency Changes, by construction, no matter how well the rest of the
rule is tuned. The fix is a real-time push — ChangeGuard notifying the whitelist the moment
an Emergency Change record is approved, not once a day — and it belongs with whoever owns
`domain-admin-group-modification.md`'s production rule, not re-derived in this case.

The sharper lesson is about pacing, not tooling. A Critical severity label is a statement
about consequence if the finding is real, not a instruction to spend proportionally more
time verifying it. This case's fastest, most correct move — search the ticketing system by
target account and record type before doing anything else — was available in the first five
minutes and would have shortened this investigation further if it had been step one instead
of step six. Not every alarming-looking alert needs an odyssey to close; some of them need
exactly one well-aimed lookup, and the discipline worth building is knowing, quickly, which
kind of alert this is before assuming it's the other one.

---

**Cross-references:** SOC Playbook Handbook `domain-admin-group-modification.md`; SOC
Manager's Operating Handbook, Part 25 — Risk Acceptance & Manager Decision-Making Under
Uncertainty.
