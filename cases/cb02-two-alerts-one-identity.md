---
title: "CB-02 — Two Alerts, One Identity"
case_id: "CB-02"
category: "Identity"
disposition: "True Positive"
outcome_flavor: "Subtle"
confidence_at_close: "High"
entry_point: "cross-ticket-pattern-recognition"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["DEH V2 Part 46", "SOC Playbook Handbook 11-identity-ad-kerberos/dcsync.md (IAM-020)"]
---

# CB-02 — Two Alerts, One Identity

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Corrigan Metalworks," its staff, its vendor, and every host, account, and IP address named
below are invented; no real organization, employee, incident, or breach is depicted or
implied.*

## Why this case exists

This case teaches a specific, uncomfortable variant of the hybrid-identity seam problem: the
correlation rule built to catch exactly this pattern existed, was deployed, and did not fire —
not because the attacker was clever about evasion, but because a mapping table nobody owned
was missing one row. What actually closed this case was an analyst remembering an account name
from a ticket she'd personally closed three days earlier in a different queue, not a system
lighting up. This case does not re-derive the query logic behind `DET-46-01`, `DET-46-02`, or
`DET-46-03` — the Detection Engineering Handbook V2, Part 46, owns all three, and this case
cites them rather than rebuilding them. It also does not re-derive DCSync identification or
containment procedure, which belongs to the SOC Playbook Handbook's IAM-020 (`dcsync.md`). And
it deliberately does not re-narrate Part 46 §8's own worked hybrid-identity compromise chain,
which compresses a similar six-stage idea into six sentences from the detection engineer's
chair, with a different account, a firing correlation rule, and a password reset that this
case's attacker never needed to make. This case runs the same underlying seam through a
different discovery path entirely — two tickets, two queues, no rule between them — and a
different technical mechanism connecting privilege to cloud access.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-02` |
| Category | Identity |
| Disposition | True Positive |
| Outcome flavor | Subtle |
| Confidence at close | High, settled |
| Entry point | Two independently low-priority tickets, connected by one analyst's own pattern recognition, not a rule |
| Primary log sources | Linux auth log (sudo/sshd), Windows Security log (domain controller), Entra ID AuditLogs (OAuth consent), Entra ID SigninLogs |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | Detection Engineering Handbook V2, Part 46 — Identity Compromise Model (`DET-46-01`, `DET-46-02`, `DET-46-03`), narrated, not re-derived; SOC Playbook Handbook, IAM-020 (`dcsync.md`) |
| All times | UTC |

## 1. Two tickets, two queues, no rule between them

### 1.1 Ticket one: an unticketed maintenance session

**[CONCEPT]** Corrigan Metalworks runs a small Linux estate alongside its Windows AD domain —
plant-floor systems, mostly, joined to the domain so a handful of service accounts can
authenticate the same way everywhere. One of those, `svc-plantmes-sync`, exists for exactly one
job: a nightly cron task on `lnx-mes-sync01` (192.0.2.44) that reads a handful of employee and
asset attributes out of Active Directory and pushes them to Faircrest Automation's hosted
manufacturing-execution-system (MES) dashboard. No automated version of `DET-46-02`'s sudo
baseline scoring runs at Corrigan yet — the identity team knows the idea, has read Part 46, and
hasn't built it. What exists instead is a blunter daily digest: a script that greps the
previous day's `auth.log` on service-account-owning hosts for any `sudo` line carrying a `TTY`
field, and files an informational ticket for every hit. Most of those tickets are nothing.

**[ANALYST]** On the morning of 2026-06-09, Priya Anand — Tier 2, day shift, one of two
analysts on Corrigan's SOC rotation — picks up one of those digest tickets. The prior evening's
`auth.log` on `lnx-mes-sync01` shows an interactive session, not the scripted one-liner the
account normally produces:

```text
Jun 08 14:31:40 lnx-mes-sync01 sshd[28839]: Accepted publickey for ctr-mesvendor from 198.51.100.23 port 52210 ssh2: RSA SHA256:...
Jun 08 14:32:07 lnx-mes-sync01 sudo[28841]:   ctr-mesvendor : TTY=pts/2 ; PWD=/home/ctr-mesvendor ; USER=svc-plantmes-sync ; COMMAND=/bin/bash
Jun 08 14:33:52 lnx-mes-sync01 sudo[28907]:   ctr-mesvendor : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/klist
Jun 08 14:35:19 lnx-mes-sync01 sudo[28944]:   ctr-mesvendor : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/ldapsearch -H ldap://192.0.2.10 -Y GSSAPI -b "dc=corriganmw,dc=local" "(objectClass=user)"
```

`ctr-mesvendor` is a shared support login Faircrest's technicians use for exactly this kind of
troubleshooting — an approved, standing arrangement, not a novelty. This isn't `svc-plantmes-sync`
running its own script; it's a Faircrest technician using their own vendor login to become the
service account, which is precisely the legitimate use case the account's sudo rule exists to
support. Priya checks the change-ticket system for anything matching this window. Nothing. She
notes the missing ticket, can't find anything actively wrong in the three commands themselves,
and closes the ticket "administrative — vendor session, unticketed, no indication of misuse."
Confidence: Low. Not because anything specific looked bad, but because nothing specific looked
resolved either.

### 1.2 Ticket two: a routine consent-grant notice

**[ANALYST]** Corrigan's cloud/IAM queue normally belongs to Marcus Chen, Priya's Tier 1
counterpart. Marcus is out from 2026-06-10 through 2026-06-13, and his queue backs up the way
low-priority queues do when nobody's actively clearing them — a batch of "OAuth app
self-consent — informational" notices, most of them harmless by design. Corrigan's tenant
allow-lists self-consent for any account matching its `svc-*` naming convention on the
assumption that these are internal automation identities with nobody behind the keyboard to
phish; the notice exists only so someone occasionally glances at what got granted. Priya starts
working through the backlog on 2026-06-11. Most entries are exactly what they look like: a
reporting tool renewing a token, a helpdesk bot re-consenting after a tenant policy change.

One entry, timestamped three days earlier, is for `svc-plantmes-sync@corriganmw.com`, granting a
new app registration named "MES Reporting Connector" the scopes `Mail.ReadWrite`,
`Files.ReadWrite.All`, and `Directory.Read.All`. Priya's first read is unremarkable: a new
connector for the plant-reporting integration, self-consented by the automation account that's
supposed to own that integration. She's about to clear it the way she's cleared the last dozen.
Confidence: Low — not because anything reads as wrong, but because "looks like the others in the
backlog" isn't the same thing as "checked."

## 2. A name she's seen before, and what it would take to prove it

**[ANALYST]** `svc-plantmes-sync`. Priya stops on the account name — not because the ticket in
front of her says anything alarming, but because she typed that exact string into a change-ticket
search two days earlier and got nothing back. Two tickets, in two queues she doesn't normally
both work in the same week, naming the same account, three hours apart on the same day, is not
something either queue's own triage logic is built to notice — each ticket individually reads as
routine. The digest rule that generated ticket one only ever looks at one host's `auth.log`. The
allow-list rule that generated ticket two only ever looks at consent events. Neither rule has
any reason to compare notes with the other, and nothing in either ticket's own text mentions the
other event.

She pulls up her closed ticket from 2026-06-09 side by side with the open one from 2026-06-11.
Same account, both sides of the hybrid identity — the on-prem `svc-plantmes-sync` and its synced
Entra ID identity `svc-plantmes-sync@corriganmw.com` are, per Corrigan's hybrid-sync
configuration, the same underlying identity wearing two names in two directories. That's not a
coincidence anymore; that's a question, and before touching a third log source she writes down
what she actually needs to know, in order:

- Is the interactive sudo session on 2026-06-08 and the OAuth consent grant later the same day
  actually connected, or did she just notice two unrelated tickets that happen to share an
  account name in an unlucky week?
- If they are connected, what did the vendor session on `lnx-mes-sync01` actually *do* between
  14:32 and 14:35 UTC that could plausibly lead to a cloud consent grant an hour later — the
  three commands she saw were a shell, a Kerberos ticket check, and an LDAP query, none of which
  obviously touches Entra ID at all?
- Does the granted scope — mail, files, and directory read — have any legitimate connection to
  what `svc-plantmes-sync` is documented to do, which is push a handful of AD attributes to a
  vendor dashboard?
- Was this the vendor's technician at the keyboard the whole time, or did the vendor's own
  access get used by someone else?

## 3. Pivot: from the Linux auth log to the Windows Security log

### 3.1 The IP that looked wrong and wasn't

**[PIVOT]** The fourth question is the one Priya can answer fastest, so she starts there: whose
address is 198.51.100.23? Corrigan's own runbook for vendor access lists Faircrest's known
VPN egress range as 198.51.100.128/25 — and 198.51.100.23 isn't in it. For about ten minutes,
this looks like the whole case: an address outside the documented range, on a shared account,
with no matching ticket, reads like unauthorized use of the vendor's own credential from
somewhere else entirely.

It resolves less dramatically than that. Corrigan migrated to a second VPN concentrator on
2026-05-25 to handle failover, and that concentrator's NAT egress is 198.51.100.23 — a fact the
network team hadn't gotten around to adding to the vendor-access runbook. A quick check against
the concentrator's own connection log confirms the session really did authenticate through
Faircrest's own assigned certificate.

> **False Lead**
> The source address outside the documented vendor range looked like the strongest evidence of
> unauthorized external access in the entire case, for about ten minutes. It turned out to be
> Corrigan's own second VPN concentrator, brought online two weeks earlier, whose egress address
> the network team had never added to the vendor-access runbook. The account still authenticated
> with Faircrest's own certificate — this fact narrows the question from "was this external and
> unauthenticated" to "was this genuinely the vendor's technician," which is a different,
> unresolved question, not a closed one.

That narrowing matters more than it looks like it does. Ruling out an unauthenticated outsider
doesn't rule out someone using Faircrest's own valid credential without Faircrest's own
technician actually being the one who typed it.

### 3.2 The 4662 that shouldn't have been there

**[PIVOT]** The LDAP query in the sudo log used `-Y GSSAPI` — Kerberos authentication, not a
bind password — which means whatever ran it authenticated as `svc-plantmes-sync` against Active
Directory at that moment. Priya pivots from the Linux auth log to the domain controller's own
Windows Security log for the same six-minute window, on the theory that a Kerberos-authenticated
LDAP operation from this account should have left a corresponding object-access record.

```text
Domain Controller: DC01 (192.0.2.10)
Log Name:      Security
Event ID:      4662
Time:          2026-06-08 14:41:03 UTC
Account Name:  svc-plantmes-sync
Account Domain: CORRIGANMW
Object Server: DS
Properties:    {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes)
               {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes-All)
```

Event ID 4662 — an operation performed on a directory object — carrying both replication-rights
GUIDs is the same DCSync shape the Detection Engineering Handbook V2's `DET-13-04` and this
book's own `DET-46-03` are built to catch: a principal exercising directory-replication rights
outside a domain controller's own replication traffic, T1003.006 (OS Credential Dumping:
DCSync). `svc-plantmes-sync` has no documented reason to hold those rights at all — its job is
reading a handful of attributes, not replicating the directory. A quick pull of its group
memberships shows it does, in fact, have both GUIDs granted directly on the domain object, dated
to a Linux-estate migration eighteen months earlier. Nobody scoped it down afterward.

**[HYPOTHESIS]** This is the point where a real, falsifiable theory takes shape:
**svc-plantmes-sync's own valid, over-provisioned credential was used — by someone with access to
Faircrest's vendor login, whether or not that was actually a Faircrest employee — to run a
DCSync-shaped directory query, and whatever came out of that query fed a subsequent cloud
action.** It's falsifiable: if the timing, the scope of the later consent grant, or the account's
own history contradict it, it loses to a specific alternative.

> **Dead End**
> Twenty minutes went into pulling ninety days of sudo history for both `svc-plantmes-sync` and
> `ctr-mesvendor` across the Linux estate, on the theory that this might be a pattern the vendor
> had been running unticketed for months. It wasn't. There was exactly one other interactive
> session in the window, forty-five days earlier, running the same three-command shape — and
> that one had a matching, approved change ticket. The vendor's access pattern itself is real and
> normally documented. Whatever happened on 2026-06-08 is the one time the paper trail is
> missing, not evidence of an ongoing, uncontrolled arrangement.

## 4. Hypothesis check: does this match the reset-then-signin shape?

**[HYPOTHESIS]** Priya's next move is to check whether this fits the specific pattern `DET-46-01`
documents: a privileged on-prem action followed by a cloud sign-in for the same synced identity,
joined through the expedited password-hash-sync cycle. That pattern's on-prem half is a
privileged password reset — Event ID 4724 — performed on someone else's behalf. She pulls 4724
events for the domain controller across the whole day. None reference `svc-plantmes-sync` as
either subject or target, and none reference any other account in the window either.

For a few minutes this reads like it rules the hybrid-pivot theory out entirely — no reset, no
`DET-46-01` shape, maybe the 4662 really is just an over-permissioned account doing something
unrelated. Then she remembers the specific caveat Part 46 §3 states about `DET-46-01` itself:
an attacker who already holds DCSync rights doesn't need to reset a password at all. The hash
that Entra ID's password-hash-sync computes for a synced identity is a deterministic function of
the account's own on-prem NTLM hash — a DCSync'd hash converts directly into a working cloud
credential with no 4724 ever generated. The absence of a reset isn't evidence against the
hybrid-pivot theory. It's exactly what the theory predicts if the attacker skipped the step
`DET-46-01` is watching for.

> **Hypothesis Board — after the domain-controller pivot**
> 1. **Legitimate, unticketed vendor maintenance** — weakened. The vendor's own access pattern is
>    real and normally ticketed; this specific session has no matching ticket, and the account
>    used rights ("svc-plantmes-sync"'s replication GUIDs) that have nothing to do with the
>    account's documented job.
> 2. **Two unrelated low-priority tickets, no real connection** — weakened. Same account, same
>    day, a DCSync-shaped directory query roughly an hour before a cloud consent grant is not a
>    coincidence two independent triage rules happened to miss for unrelated reasons.
> 3. **Legitimate internal automation, just a broader scope grant than usual** — still live.
>    Nothing yet directly disproves that the consent grant itself was a sanctioned scope
>    expansion for the reporting integration; that needs the cloud-side evidence, not the
>    on-prem side.
> 4. **Compromised vendor credential used to exercise the account's own over-provisioned DCSync
>    rights, feeding a subsequent cloud pivot** — supported. The rights exist, were exercised
>    outside their documented purpose, and the absence of a password reset matches `DET-46-01`'s
>    own documented blind spot rather than contradicting the theory.
> **Current confidence:** Medium, rising.

## 5. Pivot: from the domain controller to the cloud audit trail

### 5.1 A consent grant with no legitimate reason to exist

**[PIVOT]** With hypothesis three still live, Priya pulls the full AuditLogs entry behind
ticket two rather than trusting the digest notice's summary.

```json
{
  "OperationName": "Consent to application",
  "InitiatedBy": { "user": { "userPrincipalName": "svc-plantmes-sync@corriganmw.com" } },
  "TargetResources": [
    {
      "displayName": "MES Reporting Connector",
      "modifiedProperties": [
        { "displayName": "ConsentAction.Permissions",
          "newValue": "Mail.ReadWrite, Files.ReadWrite.All, Directory.Read.All" }
      ]
    }
  ],
  "TimeGenerated": "2026-06-08T15:47:22Z"
}
```

She checks the account's own documented function against this grant, the same check `DET-46-01`'s
own guidance recommends before escalating: `svc-plantmes-sync` exists to write a handful of
attribute values to Faircrest's dashboard through a narrowly scoped API call the vendor
documented two years ago. That call has never touched mail or files. `Mail.ReadWrite` and
`Files.ReadWrite.All` — T1528 (Steal Application Access Token) — have no connection to the
account's job at all, and `Directory.Read.All` goes well past what a nightly attribute push
needs. Hypothesis three doesn't survive this comparison; a legitimate scope expansion for a
reporting integration doesn't ask for mailbox write access.

### 5.2 A device that had never signed in before

**[PIVOT]** The consent grant needed an authenticated session first, so Priya pulls SigninLogs
for the same identity around the same time.

```text
UserPrincipalName:  svc-plantmes-sync@corriganmw.com
IPAddress:          203.0.113.187
DeviceDetail:        (unregistered — no compliance or Intune record)
AppDisplayName:      MES Reporting Connector
ResultType:          0
CreatedDateTime:     2026-06-08T15:44:10Z
```

203.0.113.187 has never appeared in this identity's sign-in history before — a single check
against ninety days of prior sign-ins for the account turns up nothing from that address, or
from any device without a compliance record. `svc-plantmes-sync` is a non-interactive account;
it has no reason to sign in from an unmanaged device at all, let alone one it's never used
before, T1078.004 (Valid Accounts: Cloud Accounts). Three minutes after this sign-in, the
account consented to the app that requested mail and file access. Sixty-six minutes before that,
the same account exercised directory-replication rights it has no documented reason to hold.
Four independent sources — the Linux auth log, the domain controller's Security log, SigninLogs,
and AuditLogs — now describe one continuous sequence for one identity, with no piece
contradicting another.

## 6. Why the rule never fired, and what happens now

**[CONCEPT]** `DET-46-03` exists specifically to join an on-prem DCSync-shaped 4662 to a
subsequent cloud privilege grant for the same identity, inside a two-hour window — this sequence
fits inside sixty-six minutes. It never fired. Part 46 §1 names the reason this book already
documents for every cross-plane correlation it defines: the join depends on a maintained
`HybridIdentityMap` table resolving the on-prem account to its synced UPN, and a stale or
incomplete mapping table doesn't error when a row is missing — it silently drops that identity
out of the join, which reads as "no cross-plane activity found," not "the join couldn't run."

Priya checks Corrigan's own mapping table for `svc-plantmes-sync`. There's no row. The account
was provisioned during the 2024 Linux-estate migration that also left its replication GUIDs
over-scoped; whoever ran that migration set up hybrid sync for the account correctly enough that
authentication itself worked, and never told the identity team to add it to the table the
correlation tooling actually reads. The rule that should have caught this exact chain was
deployed, tuned, and running the whole time. It had nothing to join against for this one
identity.

> **Evidence Note**
> `DET-46-03` and `DET-46-01` both depend on the same `HybridIdentityMap` table, and neither
> detection's own logic can tell the difference between "this identity had no qualifying
> cross-plane activity" and "this identity has no row in the table at all." Both conditions
> produce the same observable outcome: silence. That means a missing row is invisible from
> inside the alert queue — nothing renders as a gap, an error, or a partial result. The only way
> this surfaced here was an analyst manually checking the table for one specific account after
> already suspecting a connection, not the tooling flagging its own blind spot.

**[ESCALATION]** By late afternoon on 2026-06-11, Priya has four independent, mutually
consistent log sources describing one identity's compromise chain and no surviving alternative
explanation. She escalates to her shift lead and declares an incident, per Part 46 §10's own
triage guidance: once two or more stages in a chain resolve to true positive for the same
identity, the whole identity — on-prem and cloud — gets treated as compromised for containment
purposes, not just whichever side produced the confirming evidence.

Containment that evening covers both planes: `svc-plantmes-sync`'s AD password is force-rotated
and its Kerberos tickets invalidated; the "MES Reporting Connector" app registration is revoked
tenant-wide; the account's active cloud sessions are killed; and its replication-rights GUIDs are
removed pending a documented business justification that, eighteen months later, nobody can
produce. Determining exactly what the DCSync-shaped query returned — which other accounts' data,
if any, was pulled through it — is IAM-020's territory, not this case's: that playbook owns the
procedure for scoping a DCSync exposure's blast radius, T1114 (Email Collection) covering the
motive for the mail scope specifically, and this case hands that scoping work off rather than
improvising it.

> **Hypothesis Board — after the cloud-side pivot**
> 1. **Legitimate, unticketed vendor maintenance** — ruled out. The rights exercised have no
>    connection to the account's documented job, and the vendor's own normal sessions are
>    ticketed.
> 2. **Two unrelated low-priority tickets, no real connection** — ruled out. Four independent
>    log sources now describe one continuous sixty-six-minute sequence for one identity.
> 3. **Legitimate internal automation, broader scope than usual** — ruled out. The granted scope
>    has no overlap with the account's documented function.
> 4. **Compromised vendor credential exercising over-provisioned DCSync rights, feeding a cloud
>    pivot to a malicious app consent** — confirmed. Corroborated across the Linux auth log,
>    the domain controller's Security log, SigninLogs, and AuditLogs, with no unresolved
>    contradiction.
> **Current confidence:** High, settled.

> **Manager's Call**
> Whether and how to notify Faircrest that a session using their vendor credential may not have
> been their own technician is a stakeholder-relationship decision, not a technical one — it
> affects an active vendor contract and needs to happen in a way that preserves the working
> relationship while still getting Faircrest to rotate the shared credential on their end. The
> SOC Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment covers
> that tradeoff; this case does not re-derive it, only marks the point where the analyst's job
> ends and the manager's begins.

## 7. Closure

**[ESCALATION]** Closed as **True Positive**. Confidence: **High, settled**. The compromise chain runs from a
misused vendor credential through an over-provisioned service account's DCSync rights into a
malicious OAuth consent grant, confirmed by four independent, time-consistent log sources with no
surviving contradiction.

> **Blind Spot**
> Event ID 4662 confirms that a directory-replication operation using both replication GUIDs was
> performed; it does not record which specific objects' data the operation returned. Nothing in
> this case's evidence set can distinguish "the attacker pulled `svc-plantmes-sync`'s own hash
> and nothing else" from "the attacker pulled a broader set of account hashes in the same query."
> Closing containment around this one identity assumes the narrower case; confirming that
> assumption needs domain-controller replication metadata that Corrigan's own retention policy
> keeps for thirty days — enough to still check, but not indefinitely.

> **What Would Change My Mind**
> This closure assumes Faircrest's shared credential itself was misused by someone other than
> their technician, rather than a Faircrest technician being the one who ran the DCSync-shaped
> query as an undocumented shortcut. A statement from Faircrest confirming their own technician
> was logged in and active for the full 14:31–14:35 UTC window, corroborated by their side's own
> access log, would shift this case's story from "compromised credential" to "an internal
> Faircrest control failure" — a different root cause with the same technical evidence, and a
> different set of next steps.

## 8. Lesson learned

**[LESSON LEARNED]** The standing correlation rule that should have caught this chain
(`DET-46-03`) was correctly designed, deployed, and tuned — it never had a chance to run, because
the table it depends on had one missing row for eighteen months and nobody was accountable for
noticing. This case's real fix isn't a better query; it's ownership of the `HybridIdentityMap`
table itself, the exact program-level gap Part 46 §11 names generically. Corrigan's identity
team followed this up with `HUNT-46-02` — Part 46's own hybrid-seam coverage audit — run
against every synced identity in the domain, specifically to find other accounts with working
hybrid sign-in but no row in the mapping table. It found three more, all provisioned during the
same 2024 migration.

The second, smaller lesson belongs to the queues themselves, not the identity architecture: two
individually reasonable Low-confidence closures, three days and one queue apart, were the whole
signal here, and nothing but one analyst's memory connected them. That's not a reliable control.

> **Analyst's Gut Check**
> When you close a low-priority ticket "probably fine, no ticket to confirm it," write the
> account name down somewhere the rest of the team can search later — a shared note, a tag, a
> one-line log, anything greppable. Don't count on remembering it in a different queue three days
> later. Priya happened to. The fix that actually scales isn't a better memory; it's a place to
> look it up.

---

**Cross-references:** Detection Engineering Handbook V2, Part 46 — Identity Compromise Model
(`DET-46-01`, `DET-46-02`, `DET-46-03`); SOC Playbook Handbook, IAM-020 (`dcsync.md`); SOC
Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment.
