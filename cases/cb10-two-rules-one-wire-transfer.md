---
title: "CB-10 — Two Rules, One Wire Transfer"
case_id: "CB10"
category: "Web / Email"
disposition: "True Positive"
outcome_flavor: "Subtle"
confidence_at_close: "High"
entry_point: "low-priority-automated-notice"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook suspicious-inbox-rule-creation.md", "SOC Playbook oauth-app-abuse-consent-phishing.md", "SOC Playbook bec.md", "SOC Playbook vendor-impersonation.md", "DEH V2 Part 17", "DEH V2 Part 18"]
---

# CB-10 — Two Rules, One Wire Transfer

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Corvale Industrial Supply," "Ashfield Metal Works," their staff, and every host, account,
and IP address named below are invented; no real organization, employee, incident, or
breach is depicted or implied.*

## Why this case exists

This case teaches how a sub-alert-threshold notice — one that never crossed a standing
detection's own firing condition — can be the first real thread in an active BEC and
wire-fraud operation, and how two inbox rules sitting in two unrelated mailboxes only
become one finding once they're joined on attacker fingerprint rather than on any shared
identity, ticket, or department. It deliberately does not re-narrate Detection Engineering
Handbook V2 Part 17 §9's worked BEC case study, which walks the same category of attack
chain forward, from the phishing link to the fraudulent payment, compressed into the
detection engineer's voice with the chain already known in advance. This case walks
backward, from the analyst's chair, starting at the weakest and most overlooked signal in
the whole chain — and it does not re-derive the mechanics of DET-17-04, HUNT-17-01,
HUNT-17-02, DET-18-01, or DET-18-04, all of which it cites and uses, or the BEC and
vendor-impersonation response doctrine owned by the SOC Playbook Handbook's `bec.md` and
`vendor-impersonation.md`.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-10` |
| Category | Web / Email |
| Disposition | True Positive |
| Outcome flavor | Subtle |
| Confidence at close | High, settled |
| Entry point | Low-priority automated notice, not treated as a "real" alert at first glance |
| Primary log sources | M365 Unified Audit Log (mailbox audit / `New-InboxRule`), Entra ID sign-in log, Entra ID OAuth consent-grant audit log, mailbox content search / message trace, ERP vendor-master change log, Treasury wire-batch log |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook `suspicious-inbox-rule-creation.md`, `oauth-app-abuse-consent-phishing.md`, `bec.md`, `vendor-impersonation.md`; DEH V2 Part 17, Part 18 |
| All times | UTC |

## 1. The notice that didn't become an alert

**[CONCEPT]** Creating an inbox rule is one of the cheapest, highest-value moves available
to an attacker who already has any foothold in a mailbox — no malware, no further
exploitation, just a rule that quietly redirects or hides mail going forward. DEH V2 Part
17 §8 covers the mechanics in full; this case doesn't re-derive them, only uses them. The
standing detection built around that behavior, DET-17-04, targets rules whose action
includes forwarding to an *external* domain combined with a delete- or hide-type action —
the classic exfiltrate-and-cover-your-tracks pattern. Corvale Industrial Supply's tenant
generates 40 to 60 `New-InboxRule` events a day across roughly 1,100 mailboxes, the large
majority of them employees filtering newsletters, vendor receipts, or out-of-office
routing into folders they built themselves. DET-17-04 fires on maybe two or three of those
a week, almost all resolved as personal-forwarding false positives inside an hour.

**[ANALYST]** Owen Castellano, a Tier 1 analyst on Corvale's day shift, wasn't working a
DET-17-04 alert on the morning of 2026-09-01. He was working the informational queue
underneath it — the daily digest of every `New-InboxRule` event that *didn't* meet the
detection's firing condition, a lower-priority feed the team keeps per
`suspicious-inbox-rule-creation.md`'s recommended baseline, mostly so nobody has to argue
later about whether a given rule was reviewed. Most days it's a five-minute scroll. One
entry from the prior afternoon caught his eye anyway:

```text
Operation:      New-InboxRule
UserId:         marisol.reyes@corvaleindustrial.com
ClientIP:       203.0.113.44
ClientAppId:    a19f2b4e-... (Microsoft Graph)
Parameters:
  Name:         .Processed
  Conditions:   From -like "*@ashfieldmetalworks.com*" OR
                Subject -like "*invoice*" -or "*payment*" -or "*wire*" -or "*remittance*"
  Actions:      MoveToFolder -> RSS Feeds
                MarkAsRead
                StopProcessingRules -> $true
```

**[ANALYST]** It didn't forward anything anywhere, so DET-17-04's external-forward gate
never tripped. Nothing about the event was technically an alert. Owen flagged it to Tier 2
anyway, with a one-line note: *"Rule targets one specific vendor domain by name. That's not
what a newsletter-filter rule looks like."*

### 1.1 What the rule was actually built to do

Priya Nandakumar, the Tier 2 analyst who picked it up that afternoon, read the rule the
same way Owen had. **[ANALYST]** A rule built to organize an inbox usually targets a
sender's *type* — a shipping notification, a social-media digest — or a folder the user
already checks. This one names one vendor, by domain, alongside four keywords that all
mean "money," and its actions move the match somewhere almost nobody looks (the RSS Feeds
folder exists in every Outlook mailbox and almost no one uses it), mark it read so it
never shows an unread badge, and stop evaluating any further rule so nothing downstream
gets a second chance to catch it. That's not a filing habit. That's a rule built so its
owner never sees a specific category of message again, without ever noticing anything
went missing.

## 2. What the vendor master answered, and what it didn't

**[ANALYST]** Marisol Reyes works accounts payable at Corvale. Before touching a second
data source, Priya wrote down four questions rather than just start pulling logs:

- Is Marisol's own account the one that created this rule, or does the `ClientIP` and
  `ClientAppId` suggest someone else acting through it?
- Is there an actual, current business relationship with `ashfieldmetalworks.com`, and if
  so, is anything currently in flight with them?
- Did Marisol create this herself, for a reason that has nothing to do with hiding
  anything — a vendor she's annoyed with, a dispute she's tracking manually elsewhere?
- Has anyone else at Corvale reported anything odd involving Ashfield Metal Works in the
  last two or three weeks?

A quick check against the vendor master confirmed Ashfield Metal Works is a real,
long-standing supplier — sheet-metal stock, invoiced roughly twice a month, nothing
unusual about the relationship on paper. Nobody had filed a ticket about them. That left
the first question as the one worth answering with a log, not a guess.

**Confidence: Low.** A rule that targets one vendor by name is odd, but "odd" isn't
evidence of compromise on its own, and nothing pulled so far says whether Marisol built it
herself or someone else did. It's enough to justify one more log, not enough to call
anything yet.

## 3. Pivot: from the rule to the sign-in that created it

**[PIVOT]** The `New-InboxRule` event carries a `ClientIP` and a `ClientAppId`, but it
doesn't say whether the sign-in that produced them looked like Marisol or looked like
someone holding a stolen token. That's a different log. Priya pulled the Entra ID sign-in
log for Marisol's account around the same timestamp.

```kql
SigninLogs
| where UserPrincipalName == "marisol.reyes@corvaleindustrial.com"
| where TimeGenerated between (datetime(2026-08-31T13:30:00Z) .. datetime(2026-08-31T14:30:00Z))
| project TimeGenerated, IPAddress, Location, ClientAppUsed, AuthenticationRequirement,
          ConditionalAccessStatus, ResourceDisplayName
```

### 3.1 The sign-in that shouldn't have worked

The result was one row:

```text
TimeGenerated:              2026-08-31T14:02:11Z
IPAddress:                  203.0.113.44
Location:                   Unresolved / hosting-provider block (AS64512, "Vantage Grid Hosting")
ClientAppUsed:              Browser
AuthenticationRequirement:  singleFactor
ConditionalAccessStatus:    notApplied
ResourceDisplayName:        Office 365 Exchange Online
```

**[ANALYST]** Marisol's normal sign-ins all come from Corvale's known VPN and office
egress ranges in the 198.51.100.0/24 block, always with a fresh MFA challenge — Corvale
enforces per-user MFA tenant-wide, no exceptions. This sign-in shows
`AuthenticationRequirement: singleFactor`, meaning whatever satisfied the login wasn't a
password-plus-MFA prompt at all. That's the signature of a replayed session token rather
than a fresh interactive logon — the same pattern DET-18-04 is built to catch, a session or
refresh token reused from a device and network fingerprint the account has never shown
before. Priya hadn't pulled up DET-18-04's actual production query yet — this was closer to
the raw shape of it, just the underlying idea, run by hand against one account instead of
the tuned tenant-wide version.

> **Evidence Note**
> Corvale's mailbox audit log records when a rule is created or modified — it does not log
> every subsequent time that rule matches and actions a message. There is no per-message
> firing log for inbox rules at this tenant's retention tier. That means this case can
> establish that any Ashfield-domain or payment-keyword message arriving after 14:07 UTC on
> 2026-08-31 would have been silently moved and marked read — not which specific messages
> actually were. The absence of a visible reply from Ashfield in Marisol's inbox after that
> point is consistent with the rule working as designed, not proof of exactly what it
> caught.

**Confidence: Low-Medium, rising.** One hypothesis — a self-service filing rule Marisol
built herself — is now hard to square with a single-factor sign-in from unfamiliar
infrastructure four minutes before the rule was created. It hasn't been ruled out yet,
only weakened.

## 4. Hypothesis check: ruling out OAuth consent abuse

**[HYPOTHESIS]** A single-factor sign-in from an unfamiliar IP has more than one
explanation that doesn't require a stolen session cookie. The most common alternative in a
mailbox this age is an illicit OAuth consent grant — an attacker-controlled application
that requested `Mail.Read` or `Mail.ReadWrite` scope through a phished consent prompt,
which lets it act on the mailbox through the platform's own API without needing to satisfy
a normal sign-in at all. `oauth-app-abuse-consent-phishing.md` owns the triage steps for
that path in full; this case doesn't re-derive them, it just needed to know whether they
applied before going further down the token-replay theory. Priya pulled the OAuth
consent-grant audit trail for Marisol's account over the prior 90 days, in the rough shape
of DET-18-01 rather than the tuned production query.

```text
// too broad — see next query
OAuthConsentEvents
| where UserId == "marisol.reyes@corvaleindustrial.com"
```

That returned 11 rows — every consent grant on the account since the prior June,
including routine ones for calendar-scheduling and a mileage-tracking app nobody had
flagged before. Narrowed to mailbox-scoped permissions and unfamiliar publishers:

```text
OAuthConsentEvents
| where UserId == "marisol.reyes@corvaleindustrial.com"
| where PermissionScopes has_any ("Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite")
| where PublisherVerified == false and PublisherDomain !in (KnownVendorAllowlist)
```

Zero rows. The only mailbox-scoped grant on the account was a PDF-signing add-in,
consented from Marisol's own known IP range six weeks earlier, publisher verified, nothing
unusual about it.

> **Dead End**
> Twenty minutes went into this specifically because a clean OAuth consent trail would
> have meant the mailbox was never actually compromised at all — the rule could have been
> created some other way this case hadn't considered yet. It wasn't. There is no unfamiliar
> application anywhere in this account's consent history. Whatever created the rule did it
> with Marisol's own session, not a rogue app acting through the API on her behalf. The
> "OAuth abuse" hypothesis is done.

**Confidence: Low-Medium, flat.** Ruling out one explanation doesn't automatically raise
confidence in the remaining one — it just removes a competitor. The token-replay theory is
now the only one left standing on the access-vector question, but nothing yet says *why*
someone would want into Marisol's mailbox specifically, or whether anything has actually
gone wrong as a result.

## 5. Chasing the stolen token back to where it was taken

**[PIVOT]** A replayed session token has to come from somewhere — a credential-harvesting
page, almost always, is where a token like this gets stolen in the first place. Priya
pivoted to Marisol's own mailbox content, searching for anything involving Ashfield Metal
Works in the weeks leading up to the sign-in, since the rule's own conditions had already
pointed at that vendor by name.

```text
subject:"invoice" AND from:ashfieldmetalworks.com
```

That returned a single thread: seven messages, spanning 2026-08-12 through 2026-08-27,
all replies on one subject line, `RE: Invoice INV-58821 — Ashfield Metal Works`.

### 5.1 The bank account that changed on message seven

**[ANALYST]** Messages one through six were routine: purchase-order confirmation, a
shipping delay, an invoice restated after a quantity correction. All six referenced the
same bank account on file, ending in `...4471`. Message seven, sent 2026-08-27 at 10:14
UTC from the same real Ashfield sender address, read in part:

```text
Subject: RE: Invoice INV-58821 — Updated Remittance Details

Hi Marisol,

Quick note before this invoice settles — our bank has moved us to a new
processing partner and the account on file needs to change for this and all
future payments. New details are on the attached form; please confirm receipt
and update your records.

Also attaching the updated W-9 for your files — click here to review and
confirm: [Review & Confirm Updated Banking Form]

Thanks,
— Ashfield AP Team
```

**Header excerpt, message seven:**

```text
Authentication-Results: mx.corvaleindustrial.com;
  spf=pass smtp.mailfrom=ap@ashfieldmetalworks.com;
  dkim=pass header.d=ashfieldmetalworks.com;
  dmarc=pass header.from=ashfieldmetalworks.com
Received: from mail.ashfieldmetalworks.com (192.0.2.20)
  by mx.corvaleindustrial.com; Thu, 27 Aug 2026 10:14:02 +0000
```

**[HYPOTHESIS]** Two theories fit this evidence, and they lead to very different next
steps. The first is external domain impersonation — a lookalike of `ashfieldmetalworks.com`
that passes its own SPF/DKIM/DMARC on its own infrastructure, the pattern DET-17-02 targets
and the one `vendor-impersonation.md` treats as the default case. The second is that
Ashfield's own mailbox is genuinely compromised, and message seven is a real message from
real Ashfield infrastructure — thread hijacking, per DEH Part 17 §6, the hardest of the
three BEC paths to catch on header evidence because every technical signal reads clean.

The `Received` chain settles it: `mail.ashfieldmetalworks.com` at 192.0.2.20 is the exact
same sending host every prior message in the thread came from, going back to message one.
This is not a lookalike domain standing up its own infrastructure. This is Ashfield's real
mail server. The domain-impersonation theory doesn't survive that comparison — the fraud
is riding inside a genuinely compromised vendor mailbox, not a spoofed one standing next to
it.

> **Blind Spot**
> Corvale's SOC has no visibility into Ashfield Metal Works' own mail infrastructure or
> logs. This case can show that message seven came from Ashfield's real server; it cannot
> show how that server or that mailbox came to be sending fraudulent content, whether the
> compromise is ongoing on Ashfield's side, or whether any of Ashfield's other customers
> received the same hijacked-thread treatment. Confirming any of that requires Ashfield's
> own IR process, not this tenant's logs — which is exactly the handoff `vendor-impersonation.md`
> exists to manage.

**Confidence: Medium, rising.** There is now a real fraudulent message, in a real thread,
with a changed bank account and a credential-harvesting link sitting in the exact spot
that explains Marisol's stolen session. That link is almost certainly the initial-access
vector into her mailbox. But so far this is one clerk's inbox and one vendor's invoice —
nothing yet says this is bigger than that.

## 6. Pivot: hunting for a matching fingerprint tenant-wide

> **Analyst's Gut Check**
> Once you've found one rule built to hide something, don't close the ticket on that
> mailbox alone — search the tenant for the same fingerprint before you do anything else.
> An attacker who goes to the trouble of building an evidence-hiding rule instead of just
> reading and leaving rarely stops at the first mailbox they get into.

**[PIVOT]** Priya's next question was whether `AS64512` — the same hosting block behind
Marisol's sign-in — showed up anywhere else in the tenant's rule-creation history, in the
rough shape of HUNT-17-02's client-fingerprint approach.

### 6.1 Too broad, then narrow

```text
// too broad — see next query
MailboxAuditEvents
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where TimeGenerated > ago(14d)
```

That returned 612 rows across the tenant — two weeks of ordinary folder-filter creation
by a thousand-plus mailboxes, useless at that scale. Narrowed to the specific ASN and
client fingerprint from Marisol's compromise:

```text
MailboxAuditEvents
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where TimeGenerated > ago(14d)
| where ClientIP startswith "203.0.113."
| where ClientAppId == "a19f2b4e-..."
```

One row. A second inbox rule, created 2026-09-02 at 16:10 UTC, on the mailbox of Diane
Okafor, Corvale's Treasury manager — a different department, a different building, no
reporting relationship to Marisol at all. The `ClientIP` was 203.0.113.77, one address
away from the one that hit Marisol's account, same hosting block, same `ClientAppId`.

Diane's own sign-in log showed the same tell as Marisol's: `AuthenticationRequirement:
singleFactor`, no fresh MFA challenge, roughly six minutes before the rule was created.

> **False Lead**
> Diane had genuinely traveled to a supplier conference in the EU the week before — it was
> on her calendar and her expense report, and for about ten minutes it looked like the
> obvious, boring explanation for an unfamiliar sign-in location. It wasn't. Her actual
> conference travel, cross-checked against her expensed flight itinerary, had her back in
> the country three days before this sign-in, and her registered device fingerprint doesn't
> match `ClientAppId` `a19f2b4e-...` at all — that identifier belongs to the same generic
> API client that created Marisol's rule, not to any mail app on Diane's laptop or phone.
> The travel was real. It isn't what explains this sign-in.

### 6.2 What the second rule was built to hide

Diane's rule didn't target Ashfield Metal Works by name. It targeted Corvale's own ERP
system:

```text
Parameters:
  Name:         Finance Digest
  Conditions:   From -eq "erp-notify@corvaleindustrial.com" -and
                Subject -like "*Vendor Banking Details Changed*"
  Actions:      MoveToFolder -> Archive/2025
                MarkAsRead
```

**[ANALYST]** Corvale's ERP sends an automatic notification to Treasury any time a
vendor's banking details change on file — a standing internal control specifically meant
to catch exactly the kind of change that happened to Ashfield's vendor record on
2026-09-01, the day after AP processed the "updated remittance details" from message
seven. Diane's rule doesn't hide the vendor's own correspondence, because Diane never
corresponds with vendors directly. It hides the one internal notification designed to
catch a fraudulent bank-account change before a payment goes out on it.

## 7. Hypothesis Board: what this actually is

> **Hypothesis Board — after finding the second rule**
> 1. **A benign, self-built filing rule on Marisol's mailbox** — ruled out. A single-factor
>    sign-in from an unfamiliar hosting block, four minutes before a rule that specifically
>    hides one vendor's future replies, is not a filing habit.
> 2. **An isolated, opportunistic compromise of one AP mailbox** — weakened. A second rule,
>    created from adjacent infrastructure two days later, in a different department,
>    targeting the exact internal control that would have caught the fraud, is not what an
>    opportunistic single-mailbox smash-and-grab looks like.
> 3. **A coordinated BEC operation targeting this specific in-flight wire transfer,
>    riding a genuine compromise of Ashfield Metal Works' own mailbox and using it to reach
>    two Corvale mailboxes that together see both sides of the fraud** — supported. Rule one
>    blinds AP to the vendor's own side; rule two blinds Treasury to the internal control
>    that watches for exactly this kind of change. Both were built within a 96-hour window
>    of the same fraudulent bank-account update.
> **Current confidence:** Medium-High, rising.

**[ANALYST]** Two rules, in two departments, each aimed at the one channel that would have
caught the other rule's blind spot, isn't a coincidence worth entertaining seriously
anymore. It's the shape of an attacker who read Marisol's own sent mail once they were
inside her mailbox, learned who in Treasury handles vendor banking changes, and built a
second, targeted phish to get to Diane specifically — reconnaissance conducted from inside
the first compromise, aimed at the second.

## 8. Escalation: a wire that hadn't cleared yet

**[PIVOT]** The last open question wasn't about attribution anymore — it was about time.
Priya pulled Treasury's wire-batch log for anything referencing Ashfield Metal Works.

```text
Batch:          WB-2026-0904-03
Vendor:         Ashfield Metal Works
Invoice:        INV-58821
Amount:         $86,400.00
Account:        ...1198 (updated 2026-09-01)
Status:         Approved, scheduled for release
Release time:   2026-09-04T18:00:00Z
```

It was 15:00 UTC on 2026-09-04. Three hours.

**[ESCALATION]** Priya escalated immediately to the SOC lead and Treasury's on-call
finance contact: hold WB-2026-0904-03 before release, do not action any further
correspondence in the Ashfield thread from either affected mailbox, and begin containment
— force sign-out and credential reset for both Marisol's and Diane's accounts, revoke the
active session tokens rather than relying on a password change alone, and preserve both
inbox rules' audit records before removing them.

> **Manager's Call**
> Whether to contact Corvale's bank fraud-recall desk and notify Ashfield Metal Works
> directly *before* the internal investigation formally confirms every detail, versus
> waiting for full confirmation first, is the incident commander's call, not the
> analyst's — it trades a faster recall window against the risk of alarming a legitimate
> vendor relationship on an incomplete picture. The SOC Manager's Operating Handbook, Part
> 25 — Risk Acceptance & Manager Decision-Making Under Uncertainty covers that tradeoff in
> full; this case does not re-derive it, only shows the point where the analyst's job ends
> and the manager's begins. Corvale's incident commander chose to hold the wire and notify
> the bank immediately, and to notify Ashfield within the hour rather than wait.

Containment steps beyond the wire hold and credential reset — vendor notification
language, bank-recall paperwork, and any customer or regulatory disclosure obligations —
follow `bec.md` and `vendor-impersonation.md`'s standing playbooks; this case hands off to
them rather than re-deriving BEC incident response from scratch.

## 9. Decision and closure

**Disposition: True Positive.** Two Corvale mailboxes were compromised through a stolen
session token, sourced from a credential-harvesting link embedded in a genuinely
compromised vendor's hijacked email thread. Both compromises are independently confirmed
by at least two log sources apiece — a single-factor sign-in from the same hosting block
plus a `New-InboxRule` event carrying the same client fingerprint, for both Marisol's and
Diane's accounts — with no unresolved contradiction between them. The wire transfer to the
fraudulent account was held before release.

**Confidence at close: High, settled.** Both access events, both rules, and the fraudulent
thread content agree with each other independently; nothing in the evidence set points a
different direction.

> **What Would Change My Mind**
> If the bank's own investigation of account `...1198` came back showing it belongs to a
> legitimate, if unusual, receivables-financing arrangement Ashfield itself set up — rather
> than infrastructure under an attacker's control — this would downgrade from BEC fraud to
> an unusual but legitimate vendor-side financing change, badly timed to look identical to
> an attack. Nothing found so far points that direction, and the credential-harvesting link
> in message seven is hard to explain under that theory, but it's the one piece of external
> confirmation this case doesn't yet have.

## 10. Lesson learned

**[LESSON LEARNED]** DET-17-04's external-forward gate is the right control for the attack
it was built to catch, and it correctly did not fire here, because this rule never
forwarded anything — it only hid. That's a real coverage gap, not a tuning artifact: an
attacker who has already learned (or guessed) that hide-only rules don't trip the standing
detection gets the same evidence-suppression outcome without ever touching the condition
DET-17-04 checks. The fix isn't loosening DET-17-04's own threshold — its external-forward
logic is precise for what it targets — it's a companion rule scoped to hide-only actions
(`MoveToFolder` plus `MarkAsRead` plus `StopProcessingRules`, with no forwarding parameter
populated at all) combined with a vendor-domain or payment-keyword condition, which is
exactly the shape this case's first rule had and the standing detection never saw. The
second, cross-mailbox pattern — one rule per department, each blinding the one control that
would have caught the other's blind spot — argues for making HUNT-17-02's client-fingerprint
join a standing, scheduled correlation across every `New-InboxRule` event tenant-wide, not
a one-off hunt run only after a first finding raises the question. Had that correlation
already been running, the second rule would have surfaced within minutes of the first,
not after an analyst thought to go looking for it by hand. Finally: HUNT-17-01's mid-thread
payment-detail diff is exactly the check that would have caught message seven's bank-account
change before AP ever acted on it, without needing the inbox rule, the sign-in log, or
anything else in this case at all — Corvale had never operationalized that hunt as a
standing review step ahead of any vendor-banking-detail update, and this case is the
argument for changing that.

**Cross-references:** SOC Playbook `suspicious-inbox-rule-creation.md`,
`oauth-app-abuse-consent-phishing.md`, `bec.md`, `vendor-impersonation.md`; DEH V2 Part 17
(§6.2 HUNT-17-01, §8 DET-17-04, §8.1 HUNT-17-02), Part 18 (DET-18-01, DET-18-04); SOC
Manager's Operating Handbook Part 25.
