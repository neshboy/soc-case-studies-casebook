---
title: "CB-01 — The Spray That Almost Worked"
case_id: "CB-01"
category: "Identity"
disposition: "True Positive"
outcome_flavor: "Obvious"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook 10-identity-ad-account/password-spraying.md (IAM-003)", "SOC Playbook Handbook suspicious-inbox-rule-creation.md", "SOC Playbook Handbook oauth-app-abuse-consent-phishing.md", "DEH V2 Part 12", "DEH V2 Part 17", "DEH V2 Part 18"]
---

# CB-01 — The Spray That Almost Worked

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative. "Halyard
Systems," its staff, and every host, account, and IP address named below are invented; no real
organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

This case teaches how an analyst answers the question a raw spray alert never answers by
itself: out of dozens of targeted accounts, why did exactly one authenticate, and what does the
attacker do with the unwatched minutes before the alert even fires? It does not
re-narrate the password-spray detection logic itself — the shape of a spray, why a per-account
threshold structurally misses it, and the tuned production query — all of which the Detection
Engineering Handbook V2 Part 12 owns in full (`DET-12-01`, `DET-12-02`, `DET-12-03`). It does
not re-derive standard spray containment steps either; those belong to the SOC Playbook
Handbook's `password-spraying.md` (IAM-003). What this case owns instead is the investigation
between those two documents: the pivot from "a threshold fired" to "one specific account had a
policy gap the other forty-six didn't," and the race to revoke a live OAuth consent grant
before its refresh token outlives the very password reset meant to shut the door.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-01` |
| Category | Identity |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | Standing SIEM correlation alert (spray threshold) |
| Primary log sources | DC Security log, Entra sign-in log, mailbox audit log, Entra AuditLogs (OAuth consent) |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook, `10-identity-ad-account/password-spraying.md` (IAM-003); SOC Playbook Handbook, `suspicious-inbox-rule-creation.md` and `oauth-app-abuse-consent-phishing.md`; DEH V2 Part 12 (`part12-identity-access-and-authentication-detection.md`), Part 17 (`part17-email-detection-engineering.md`), Part 18 (`part18-cloud-identity-and-saas-detection-engineering.md`) |
| All times | UTC |

## 1. A 02:47 threshold alert, and the query behind it

**[ANALYST]** Dana Reyes was 3 hours into a solo overnight shift at Halyard Systems, a
mid-size supply-chain software vendor running a hybrid identity setup — on-premises Active
Directory synced to Entra ID — when the queue produced a Sentinel incident titled `Password
Spray — Tenant Threshold Exceeded`, fired at 02:47 UTC. Halyard's SOC runs this rule as its
tuned version of `DET-12-01`: `FailedAccounts >= 15` and `AttemptsPerAccount <= 3` from a single
source within a 1-hour bin, aimed specifically at the "many accounts, few attempts each"
shape a naive single-account lockout counter cannot see by construction.

The alert's own summary told her most of what she needed to start: source `203.0.113.44`, 47
distinct user principal names, 51 total failed sign-ins in the preceding hour, `AttemptsPerAccount`
of 1.09. Overnight, alone, with no second analyst to sanity-check a read, Reyes's habit was to
re-run the underlying query herself before trusting the summary — the alert's threshold logic
was sound, but she wanted to see the actual rows, not just the count.

Her first query was broader than it needed to be, mostly to get a feel for the
noise floor before narrowing:

```kql
// too broad — see next query
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize count() by UserPrincipalName, IPAddress
```

That returned 4,182 rows — legacy-auth retries, expired-password prompts, MFA timeouts, and
real bad-password attempts all mixed together, none of it isolating the spray shape from
ordinary tenant noise. She narrowed to the result code the alert itself keyed on — `50126`,
Entra ID's "invalid username or password" code, not `50053` (account locked) or any of the
codes for expired credentials or blocked legacy protocols:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126"
| summarize FailedAccounts = dcount(UserPrincipalName),
            TotalAttempts = count(),
            SampleAccounts = make_set(UserPrincipalName, 10)
    by IPAddress, bin(TimeGenerated, 1h)
| extend AttemptsPerAccount = round(1.0 * TotalAttempts / FailedAccounts, 2)
| where FailedAccounts >= 15 and AttemptsPerAccount <= 3
```

One row: `203.0.113.44`, `FailedAccounts` = 47, `TotalAttempts` = 51, `AttemptsPerAccount` =
1.09, window 01:52–02:47. The alert's own numbers checked out. That confirmed the shape but not
the story — a validated 47-account list with one guess each tells her someone built a target
list, not that anyone got in.

## 2. Three questions, asked before the second query

**[ANALYST]** Before pivoting anywhere, Reyes wrote down three questions rather than start
pulling logs at random:

- Is this a real target list, or is `203.0.113.44` just hitting random or stale usernames —
  the kind of noise a credential-stuffing bot throws at any exposed sign-in endpoint?
- Is there a mundane, scheduled explanation — a directory-sync retry storm, a bulk
  password-expiry rollout — that would produce the identical statistical shape without any
  attacker involved at all?
- Did any of the 47 accounts actually succeed, and if so, when, relative to the alert firing
  16 minutes after the window closed?

The third question mattered most given the clock: if something had already succeeded, the
alert's own detection lag meant the attacker had a head start Reyes needed to measure, not
assume away.

Confidence at this point: Low, unresolved. Three explanations — a benign infrastructure event,
ordinary internet noise, and a real targeted spray — were all still on the table, and nothing
yet outweighed the others.

## 3. Ruling out the boring explanations

**[HYPOTHESIS]** The first two questions were both live, falsifiable theories, and Reyes
treated them that way rather than waving them off.

Against the "mundane infrastructure event" theory: Halyard's change calendar showed no
scheduled directory-sync maintenance, no bulk password-expiry policy rollout, and no known
outage in the 01:00–03:00 window. `DET-12-01`'s own documented false-positive trap — a
directory-sync retry storm or department-wide password-expiry policy producing the exact same
many-accounts-few-attempts shape — is real and worth checking every time, but it requires a
calendar entry to explain the timing, and there wasn't one.

Against the "random noise, not a validated list" theory: Reyes cross-referenced all 47 sampled
UPNs against Halyard's live directory. Every one resolved to a real, current employee account —
no typos, no departed-employee usernames, no stale service principals. A bot hitting random or
guessed address patterns produces a mix of hits and misses against a real directory; a 100%
hit rate across 47 samples meant whoever built this list already had it, correct, before the
first attempt landed.

> **Hypothesis Board — after the calendar check and the directory cross-reference**
> 1. **Benign infrastructure event (sync retry, expiry rollout)** — ruled out. No matching
>    entry on the change calendar for the window, and no outage ticket open.
> 2. **Random or stale-username noise, not a targeted list** — ruled out. All 47 sampled UPNs
>    are live, current employee accounts; a guessed or scraped list would not resolve at this
>    rate.
> 3. **Real credential-spray campaign against a validated target list, extent unknown** —
>    favored. No direct evidence of a successful sign-in yet.
> **Current confidence:** Low-Medium, rising.

That left the third question from §2 as the only one still open, and the only one that
mattered for scope.

## 4. Pivot: chasing the successful sign-in

**[PIVOT]** Reyes moved from the alert's own aggregate view to a raw join against
`SigninLogs`, looking for any successful authentication among the 47 targeted accounts in a
wider 2-hour window — closer to the raw shape of `DET-12-03` than its tuned production form,
since she was working from the idea (fail-then-succeed correlation) rather than the standing
rule itself.

Her first attempt assumed the attacker, if successful, would have succeeded from the same
address that did the guessing:

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == "0"
| where IPAddress == "203.0.113.44"
```

Zero rows. That didn't clear anything — it just meant a success, if one existed, came from a
different address. She dropped the IP filter and searched by the account list instead:

```kql
let sprayedAccounts = SigninLogs
    | where TimeGenerated > ago(2h)
    | where ResultType == "50126"
    | where IPAddress == "203.0.113.44"
    | distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == "0"
| where UserPrincipalName in (sprayedAccounts)
```

Two rows, not one. `d.kowalski@halyardsystems.com` succeeded at 02:31 from `203.0.113.51` —
sixteen minutes before the alert even fired. `svc-reports@halyardsystems.com` succeeded at
03:10 from `192.0.2.10`, an internal address.

> **Dead End**
> 20 minutes went into pulling David Kowalski's prior 30 days of sign-in history on the
> theory that this was just an odd-but-legitimate remote login — a sales role with real travel,
> logging in from an unfamiliar network on its own merits. It wasn't. Every prior sign-in in the
> 30-day history came from the same `198.51.100.23` residential range tied to his home office;
> nothing in the history involves `203.0.113.0/24` or anything resembling it. Whatever
> `203.0.113.51` is, it isn't a travel pattern.

The `203.0.113.51` address wasn't the spray's own source, `203.0.113.44` — but it sat in the
same /24, consistent with a single operator working from one hosting-provider allocation and
rotating addresses inside it, exactly the kind of single-source-IP grouping gap `DET-12-01`
already documents as the first thing to break in that query.

> **False Lead**
> `svc-reports@halyardsystems.com`'s 03:10 success looked, for about 10 minutes, like a second
> compromised account. It wasn't. Its sign-in history for the prior 3 weeks showed the
> identical daily pattern: a non-interactive sign-in from `192.0.2.10`, every night, within a
> few minutes of 03:10 — a scheduled reporting job authenticating with its own stored
> credential, coincidentally caught in the spray's 47-account target list. It failed the spray's
> guessed password like everyone else and then succeeded 39 minutes later on its own schedule,
> with its own credential, from an internal address. The two events share a UPN and nothing
> else.

Confidence, updated: Medium, rising. One account had a direct, specific piece of supporting
evidence — a single-factor success sixteen minutes before the alert fired, from a source
outside Kowalski's own 30-day travel pattern — but the plausible alternative (an odd, benign
sign-in this investigation just hadn't found the innocent explanation for yet) wasn't ruled
out until the next pivot confirmed what the attacker actually did with the access.

## 5. Why only one account out of forty-seven

**[HYPOTHESIS]** With Kowalski's account confirmed as the one real success, the next question
was why his account specifically — out of 47 targeted, with presumably similar password
hygiene across the tenant — was the one that let a single guessed password through with no
second factor.

The `SigninLogs` row itself carried the answer in two fields: `AuthenticationRequirement` =
`singleFactorAuthentication`, `ConditionalAccessStatus` = `notApplied`. Halyard's tenant-wide
conditional access policy enforces MFA on every interactive sign-in — except for accounts
inside a 14-day onboarding grace period, a group-based exclusion meant to give new hires a
window to complete MFA enrollment without getting locked out on day one. Kowalski's hire date
was 11 days before the incident. He was still inside that window, and his MFA registration
was still pending.

This is the same category of gap Part 18's `DET-18-03` documents for legacy-authentication
protocol exceptions — a conditional access policy that is correct in its stated intent but has
a scoping hole an attacker doesn't need to know about in advance, only needs to spray widely
enough to find by chance. It isn't the literal legacy-auth rule; it's the same structural
lesson in a different exclusion group.

**[ANALYST]** That answer raised an immediate scope question: how many other accounts sat in
the same exclusion group right now, exposed the same way, that this particular spray simply
hadn't guessed correctly? A quick group-membership pull answered it — three other accounts were
inside the same 14-day onboarding window at that moment, none of them among the 47 targeted.
None of the 47 sprayed accounts overlapped with the exclusion group by anything other than
coincidence; Kowalski's inclusion in both the target list and the exclusion group was exactly
that, a coincidence, not evidence the attacker had enumerated the group in advance. It meant
the immediate incident had one victim, but the underlying gap had three more accounts standing
in front of it the moment this investigation closed — a fact worth carrying into §10 rather
than treating as solved once Kowalski's account was contained.

**[PIVOT]** To check whether the compromise had reached past the cloud identity into anything
on-premises — the same password, after all, authenticates both sides in a synced hybrid tenant
— Reyes pulled the DC Security log for `dkowalski`'s on-prem SamAccountName across the same
window, looking for Event ID 4624 (successful logon) on any domain controller or on-prem
resource:

```text
No 4624 events for dkowalski in window 01:00–04:00.
Prior 4625 events for dkowalski (last occurrence 4 days earlier, 09:14, normal business hours)
```

Nothing. Whatever happened here stayed on the cloud identity surface; no domain-joined VPN
concentrator, file share, or RDP session logged a matching success. That check came back clean
fast and stayed clean — the kind of dead-end-that-isn't the shift needed at least one of.

## 6. Pivot: from the sign-in log to the audit log

**[PIVOT]** A validated password and a single-factor sign-in window told Reyes an attacker had
been inside Kowalski's mailbox and Entra session for some period — the open question was what,
if anything, they'd done with it. Part 17's own applied kill chain for this exact follow-on stage
branches two ways after a credential is live: a malicious inbox rule (`DET-17-04`) or an OAuth
consent grant (`DET-17-03`/`DET-18-01`). She checked both rather than assuming which one applied.

### 6.1 Checking the mailbox audit log for an inbox rule first

**[HYPOTHESIS]** Mailbox audit events for `New-InboxRule` and `Set-InboxRule` operations, scoped
to Kowalski's mailbox across the same window, came back empty — no rule created, modified, or
deleted, and specifically none of the external-forward-plus-evidence-hiding pattern `DET-17-04`
targets. That check took under 2 minutes and closed cleanly: whatever this attacker was doing,
they hadn't gone after mailbox persistence through a rule.

### 6.2 Checking Entra AuditLogs for an OAuth consent grant

**[PIVOT]** She moved from `SigninLogs` to Entra `AuditLogs`, filtering on the OAuth consent
operation the way Part 18's `DET-18-01` illustrates:

```kql
AuditLogs
| where TimeGenerated between (datetime(2026-09-15T02:31:00Z) .. datetime(2026-09-15T03:15:00Z))
| where OperationName == "Consent to application"
| where InitiatedBy has "d.kowalski@halyardsystems.com"
| mv-expand AdditionalDetails
| where AdditionalDetails.Key == "AdminConsent"
```

Zero rows. For a few uncomfortable minutes, that read as good news — no consent grant, nothing
to revoke. It wasn't good news; it was a schema gap. `DET-18-01`'s own documentation flags this
exact failure mode: `mv-expand` on `AdditionalDetails` silently drops any consent event that
doesn't carry an `AdminConsent` key at all, and a user self-consenting to a low-privilege
multi-tenant app is exactly the variant that doesn't. Dropping the `mv-expand` filter and
reading `AdditionalDetails` raw confirmed it — no `AdminConsent` key anywhere in the array,
exactly the gap the documentation warns about — but the rest of the record was intact and had
been sitting there the whole time: `OperationName` "Consent to application," app display name
"QuickSync Reports Sync," publisher unverified, multi-tenant, scopes `Mail.Read`,
`Contacts.Read`, `offline_access`, timestamp 02:38. The missing key was itself the tell: a
self-consent grant never gets tagged with the field an admin-consent-only filter depends on,
which is exactly why the narrower query missed it in the first place.

> **Evidence Note**
> The mailbox audit log's `MailItemsAccessed` events — the closest signal to "did anything
> actually read message content" — carry an ingestion lag of up to 30 minutes in Halyard's
> tenant configuration. At the time Reyes ran this check, roughly 15 minutes after the consent
> grant, none of that window's events had landed yet. An empty result at this point in
> the investigation did not mean nothing happened; it meant the log hadn't started catching up.

That `offline_access` scope was the detail that mattered most: it grants a refresh token good
for extended API access independent of the user's own session or password. Resetting
Kowalski's password alone would not revoke it.

## 7. Closing the loop: infrastructure, app history, and geovelocity

**[ANALYST]** Two more checks rounded out the picture before Reyes escalated. First, a threat
intelligence lookup on `203.0.113.0/24` returned a hosting-provider ASN with no business
relationship to Halyard and prior abuse reports tagged for credential-stuffing tool traffic —
consistent with, though not proof beyond, an attacker-controlled source rather than a
misidentified corporate egress point. She checked this specifically against `DET-12-01`'s
documented false-positive trap for high-volume corporate NAT gateways producing the same
statistical shape by ordinary typo volume; Halyard has no egress relationship with that ASN at
all, so that trap didn't apply here.

Second, she pulled the OAuth app's registration metadata directly rather than trusting scope
alone, per the triage sequence Part 18 lays out for a fired consent alert: creation date 9
days prior, multi-tenant, zero prior consent grants anywhere else in Halyard's tenant. A
brand-new, unverified, multi-tenant app with a single consent grant timed 7 minutes after a
single-factor sign-in during a spray window is not an ambiguous signal on its own merits.

Third, a lighter-weight geovelocity check, closer to `DET-12-04`'s idea than its tuned form —
Reyes didn't pull the standing rule, just compared the two data points by hand. Kowalski's
30-day sign-in history placed him consistently in one metro area on `198.51.100.23`. The
02:31 success geolocated to a different country entirely, with no intervening travel-consistent
sign-in anywhere in the log. On its own, geovelocity proves less than it looks like it proves —
carrier-side NAT and VPN egress both produce the same shape without any compromise at all — so
this corroborated the already-confirmed takeover rather than establishing it independently. The
grace-period gap and the two-source `SigninLogs`/`AuditLogs` agreement already carried that
weight; this was one more data point pointing the same direction, not a fourth pillar the case
needed to stand up.

> **Hypothesis Board — after the AuditLogs pivot**
> 1. **Benign infrastructure event** — ruled out (§3).
> 2. **Random noise, not a validated list** — ruled out (§3).
> 3. **Real account takeover via the onboarding-grace-period gap, followed by an illicit OAuth
>    consent grant** — supported. Two independent log sources (`SigninLogs`, `AuditLogs`) now
>    agree on the same account, the same 7-minute follow-on window, and a scope set with no
>    legitimate business reason for a Sales Ops analyst account to hold `Mail.Read` via a
>    9-day-old app.
> **Current confidence:** Medium-High, rising.

## 8. Handing off at 03:07: escalation and the three-step takedown

**[ESCALATION]** At 03:07, with two independent sources agreeing and no unresolved
contradiction in either, Reyes escalated to Sam Okafor, the on-call IR lead, rather than
continuing to investigate solo — the decision point where evidence-gathering ends and
containment begins. She stated it plainly in the handoff: one account compromised via a
conditional-access grace-period gap, one active OAuth consent grant with an `offline_access`
scope still live, source infrastructure with a credential-stuffing abuse history, no inbox rule
and no confirmed on-prem lateral movement. Okafor's only question before authorizing containment
was whether disabling the account risked losing volatile evidence — the live OAuth token in
particular — before it could be captured for the ticket. Reyes had already pulled and saved the
app registration's full metadata and the consent event's raw JSON, so the answer was no:
nothing about acting immediately would cost them anything they hadn't already preserved.

Containment ran in three steps, in this order and for a specific reason: disable Kowalski's
account sign-in first, revoke all of his active sessions and refresh tokens second, and revoke
the `QuickSync Reports Sync` app's consent grant and service principal third.

> **Analyst's Gut Check**
> Disabling a compromised account's password and killing its sessions does not touch anything
> that account consented to while it was live. An `offline_access` OAuth grant hands the
> attacker their own refresh token, completely independent of the user's password — check the
> app registration and service principal list separately, every single time, or the takeover
> outlives the "fix."

By 03:14, all three actions were confirmed complete — 36 minutes after the consent grant itself,
and 43 minutes after the successful sign-in that started it.

## 9. Closed as True Positive, with one loose end

**[ESCALATION]** Closed as True Positive: account takeover via a conditional-access grace-period
gap, followed by an illicit OAuth consent grant, contained before confirmed exfiltration.
Confidence at close: High, settled — two independent log sources confirm the same account, the
same window, and the same scope grant, with no contradicting evidence anywhere in the chain.

> **Blind Spot**
> Nothing in this case's evidence set can fully rule out message content access during the
> 36-minute window the `QuickSync Reports Sync` grant was live. The `MailItemsAccessed` audit
> events that would confirm or rule out actual content reads were still catching up on their
> ingestion lag at the time of closure. Closing this as contained assumes the grant was revoked
> before use; it is not yet proven that no API call used it in that window.

> **What Would Change My Mind**
> If the `MailItemsAccessed` events for the 02:38–03:14 window, once fully ingested, show zero
> Graph API calls against Kowalski's mailbox using the `QuickSync Reports Sync` token, this
> stays closed as clean containment with no data access. If even one access event appears
> inside that window, this reopens as a confirmed mail-content exposure, which carries a
> different severity and a different notification obligation than account-takeover containment
> alone.

The grace-period exclusion group itself was referred to Halyard's identity team the same
morning as a policy-scoping gap, separate from this incident's own closure — the same category
of finding `DET-18-03` calls out for legacy-auth exceptions: a scoping hole nobody had reason to
notice until something walked through it.

## 10. What this shift leaves for the next one

**[LESSON LEARNED]** A spray alert's own summary answers "did the shape match a spray."
It does not answer "did it work," and the two questions have different timelines — this
tenant's alert fired 16 minutes after the one successful sign-in inside its own detection
window, which is a detection-lag gap worth naming rather than assuming away on every future
spray alert, not just this one. The broader lesson generalizes past this specific onboarding
exclusion: any conditional access policy exception, whatever its original legitimate purpose,
is a standing scoping gap an attacker doesn't need to know about — they only need to spray
widely enough to land on it by chance, which is exactly what happened to one account out of 47.

The permanent fix belongs to Part 12 and Part 18's detection logic and to IAM-003's containment
checklist, not to this case: tightening `DET-12-01`'s source-IP grouping to subnet or ASN level
so a rotating-address spray from one allocation doesn't require a manual widen mid-investigation,
and extending the standing containment runbook in `password-spraying.md` to explicitly include
an OAuth service-principal and consent-grant sweep for any account confirmed compromised — not
just a password reset and session revoke — so the next analyst on shift doesn't have to
remember it under time pressure the way Reyes did here. The three other accounts still sitting
inside the same onboarding exclusion group at closure are a standing exposure this case's own
containment did nothing to fix; that referral to the identity team, not this incident ticket, is
where that gap actually gets closed.

**Cross-references:** SOC Playbook Handbook, `10-identity-ad-account/password-spraying.md`
(IAM-003); SOC Playbook Handbook, `suspicious-inbox-rule-creation.md`; SOC Playbook Handbook,
`oauth-app-abuse-consent-phishing.md`; Detection Engineering Handbook V2, Part 12
(`part12-identity-access-and-authentication-detection.md` — `DET-12-01`, `DET-12-02`,
`DET-12-03`, `DET-12-04`); Part 17 (`part17-email-detection-engineering.md` — `DET-17-03`,
`DET-17-04`); Part 18 (`part18-cloud-identity-and-saas-detection-engineering.md` — `DET-18-01`,
`DET-18-03`).
