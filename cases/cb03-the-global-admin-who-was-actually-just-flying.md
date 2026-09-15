---
title: "CB-03 — The Global Admin Who Was Actually Just Flying"
case_id: "CB03"
category: "Identity"
disposition: "Insufficient Evidence"
outcome_flavor: "Inconclusive"
confidence_at_close: "Low-Medium"
entry_point: "standing-impossible-travel-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook playbooks/17-cloud/impossible-travel-cloud-sign-in.md (CLD-007)", "SOC Playbook Handbook playbooks/16-email/impossible-travel-mailbox-access.md (EML-012)", "DEH V2 Part 12"]
---

# CB-03 — The Global Admin Who Was Actually Just Flying

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Aldergate Mutual Insurance," its staff, and every host, account, and IP address named below
are invented; no real organization, employee, incident, or breach is depicted or implied.*

---

## Why this case exists

The SOC Playbook Handbook's own `25-false-positive-engineering-case-studies.md`, Case Study
4 — "Impossible Travel on a Cloud Admin Account" — already shows the clean version of this
alert: a Global Admin's two "impossible" sign-ins turn out to share one enrolled device and
one clean MFA push chain, and the case closes Benign Positive in a single review cycle. This
case deliberately does not re-narrate that resolution. It asks a harder question the FP
playbook case study doesn't have to answer: what happens when the same account, the same
alert type, and almost the same reassuring device-match signal show up, but one piece of the
timeline doesn't quite line up, one account-security change in the days before can't be
cleanly attributed to the person it's logged against, and the one human being who could
resolve it by phone gives an answer that's honest, plausible, and not quite complete? This
case also does not re-derive `CLD-007`'s or `EML-012`'s investigation checklists, or
Detection Engineering Handbook V2 Part 12's `DET-12-04` geovelocity query — it cites all
three and shows what the investigation looks like when following them faithfully still
doesn't produce a clean verdict. It closes Insufficient Evidence, on purpose, because that is
also a real, common outcome this book needs represented honestly rather than smoothed over.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-03` |
| Category | Identity |
| Disposition | Insufficient Evidence |
| Outcome flavor | Inconclusive |
| Confidence at close | Low-Medium, unresolved |
| Entry point | Standing impossible-travel correlation alert |
| Primary log sources | Entra ID sign-in logs, Entra ID Identity Protection risk detections, Entra ID audit log (MFA/security-info registration), Exchange Online Unified Audit Log, corporate travel-booking system, ITSM ticket queue, public flight-tracking data (OSINT) |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `CLD-007` (`impossible-travel-cloud-sign-in.md`), `EML-012` (`impossible-travel-mailbox-access.md`); DEH V2 Part 12 (`part12-identity-access-and-authentication-detection.md`, `DET-12-04`) |
| All times | UTC |

---

## 1. Alert: a Critical-severity impossible-travel correlation, on a Global Admin

**[CONCEPT]** Impossible travel is a derived detection, not a raw log signature: it compares
two successful sign-ins for one identity and flags the pair when distance divided by elapsed
time exceeds any plausible travel speed, using the commercial-flight ceiling — roughly
900-1,000 km/h — as the outer bound. `DET-12-04` (Detection Engineering Handbook V2 Part 12,
§6.1) walks each account's sign-in log in order and flags a country change inside a rolling
window; `CLD-007` layers a severity escalation on top: **High/P2** for a standard user,
**Critical/P1** if the account holds any administrative role. This case's account holds one.

At 04:45 UTC on 2026-09-14, Aldergate Mutual Insurance's standing correlation rule fired
Critical/P1 for `dvoss@aldergatemutual.example` — Dana Voss, VP of Cloud Platform Engineering,
and one of four accounts in the tenant carrying standing (not PIM-eligible, not time-boxed)
Global Administrator rights. The rule doesn't care why an account is a Global Admin; it just
raises the floor on how carefully every anomaly on that account gets reviewed. The overnight
SOC analyst — solo on shift, no Tier 2 backup until 07:00 UTC — picked up the ticket at
04:52 UTC.

```text
Alert: Impossible Travel — Concurrent Sign-Ins (Critical/P1)
Account: dvoss@aldergatemutual.example
Escalation reason: Account holds Global Administrator role
Sign-in 1: 2026-09-14T04:02:11Z  IP 198.51.100.23  Location: Denver, CO, US
Sign-in 2: 2026-09-14T04:41:47Z  IP 203.0.113.87   Location: Reykjavik, IS
Delta: 39m36s
```

## 2. First observation: the pattern that usually clears itself

**[ANALYST]** The first question wasn't "is this real," it was "is this the pattern the FP
playbook already has a name for" — the VPN-egress-plus-mobile-carrier-NAT pattern from
`CLD-007`'s own case notes, where two geo-buckets disagree but the authentication factors
tell one consistent story. The analyst pulled both sign-in events in full.

```text
SigninLogs
| where TimeGenerated between (datetime(2026-09-14T03:30:00Z) .. datetime(2026-09-14T05:00:00Z))
| where UserPrincipalName == "dvoss@aldergatemutual.example"
| project TimeGenerated, IPAddress, LocationDetails, DeviceDetail, AuthenticationRequirement,
          ResultType, AppDisplayName, IsInteractive
```

| Field | Sign-in 1 (04:02:11Z) | Sign-in 2 (04:41:47Z) |
|---|---|---|
| IP | `198.51.100.23` | `203.0.113.87` |
| Location | Denver, CO, US | Reykjavik, IS |
| App | Teams (mobile) | Outlook (mobile) |
| Interactive | true | true |
| MFA result | Push approved | Push approved |
| Device ID | `PHN-DV-2291` | `PHN-DV-2291` |
| `isCompliant` | true | false — compliance check unresolved |

Same enrolled device ID on both legs, same push-approval MFA on both legs — the exact
combination that closed the FP playbook's own Case Study 4 as Benign Positive inside one
review. But `isCompliant` flips to `false` on the second leg, meaning Intune couldn't confirm
compliance state over whatever network that sign-in actually traveled — not proof of
anything by itself, just the first place this case's evidence set doesn't match the clean
version of the story as neatly as it first looked like it would.

> **False Lead**
> A quick ASN lookup on `203.0.113.87` came back tagged "Hosting / Satellite Provider" in the
> analyst's threat-intel enrichment tool, a category that overlaps heavily with anonymizing
> VPN infrastructure in that tool's taxonomy — a real red flag on its own, per `CLD-007`'s True
> Positive indicator for infrastructure resolving to "known malicious infrastructure, an
> anonymizing VPN/proxy service." A second lookup against the ASN owner's own public site
> resolved it: Atlantic SatCom Partners, a commercial in-flight and maritime connectivity
> vendor, listed as a connectivity partner on Vantage Air's own website. The category tag was
> a generic bucket, not a threat signal.

## 3. Pivot: from the sign-in pair to the travel record

**[PIVOT]** Same device, clean MFA, and now an explained ASN — three checks that would have
closed this case by 05:10 UTC if the account weren't a Global Admin. Given the severity
escalation, the analyst kept going: was there an actual trip on record, not just a plausible
story the sign-in data could be bent to fit?

### 3.1 Calendar and the travel-booking system

**[PIVOT]** Dana Voss's calendar showed a multi-day out-of-office block, "Busy: Travel — CloudNext
Assurance Summit, Berlin," 2026-09-13 through 2026-09-19. Aldergate's corporate travel-booking
platform confirmed a matching itinerary: Vantage Air flight VA-1187, Denver to Reykjavik,
scheduled departure 03:10 UTC on 2026-09-14, connecting through to Berlin later the same day.

**Confidence: Medium, rising.** A real, calendared, booked trip to a real conference,
departing from the right city at roughly the right time, on an account that travels
internationally several times a year per its own 90-day sign-in baseline. This is starting to
look exactly like the FP playbook's benign pattern, just with worse geo-IP luck on the second
leg.

### 3.2 The arithmetic the analyst didn't skip

**[ANALYST]** `CLD-007`'s investigation steps say do the distance/time math yourself rather than trust the
platform's label. Denver to Reykjavik is roughly 5,800 km great-circle. At a 39-minute
36-second delta, that's approximately 8,800 km/h — about nine times the ~900-1,000 km/h
flight-ceiling threshold the detection uses, and nowhere close to the "under ~1,200 km/h,
treat as candidate false positive" line `CLD-007` gives as its own tuning guidance. The
booked flight explains why Dana Voss might plausibly be near Reykjavik *eventually* on
2026-09-14. It does not, on its own, explain how a sign-in geo-resolved to Reykjavik thirty-
nine minutes after a Denver-resolved sign-in, on a flight that hadn't taken off yet when the
itinerary alone is checked against a wall clock.

## 4. Pivot: from the itinerary to the account's own MFA history

**[PIVOT]** The itinerary explained the destination. It didn't explain the timing. The next
question was whether anything had changed on the account itself in the days before travel —
`CLD-007`'s and `EML-012`'s shared True Positive indicator list both flag a newly registered
MFA method in the hours or days prior to a flagged sign-in as one of the more specific tells
available, precisely because it's a common attacker persistence step
(**T1098.001** — Account Manipulation: Additional Cloud Credentials).

### 4.1 A query that was too broad

**[PIVOT]** The audit trail for MFA/security-info changes lives in Entra ID's directory
audit log, not the sign-in log this investigation had been living in up to this point.

```text
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Register security info"
// too broad — see next query. This returned 380+ rows across the whole tenant;
// self-service MFA method changes happen constantly and most are routine.
```

Narrowed to the one account:

```text
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Register security info"
| where InitiatedBy.user.userPrincipalName == "dvoss@aldergatemutual.example"
| project TimeGenerated, TargetResources, InitiatedBy, Result, AdditionalDetails
```

One row: 2026-09-11T14:22:03Z, a new SMS-based authentication phone number added,
source IP `192.0.2.54` — Aldergate's own corporate office range, not the airport, not
Reykjavik. Initiated-by field: `dvoss@aldergatemutual.example`. Self-service.

### 4.2 What "self-service" does and doesn't prove

**[ANALYST]** The question was no longer just what changed, but whether the log could say who
actually changed it.

> **Evidence Note**
> Entra ID's `Register security info` audit event records the *account* as the initiator on
> any self-service security-info change — there is no separate field for "performed by a
> delegate holding the user's unlocked device," "performed over the phone with the user
> reading a code aloud to an assistant," or any of the ordinary ways a busy executive
> actually gets pre-travel account hygiene done. The log cannot distinguish Dana Voss typing
> this herself from Dana Voss handing her phone to someone else for five minutes. Both look
> identical: the account's own name, a legitimate-looking corporate IP, no anomaly flag at
> all.

That gap matters here because Dana Voss's executive assistant, Priya Nakamura, had opened
ITSM ticket #48217 the day before — 2026-09-10 16:40 UTC — titled "MFA / device check ahead
of international travel — D. Voss." The ticket's body: *"Dana travels internationally next
week and push notifications have been unreliable for her on hotel/airport wifi before. Can
we make sure she has a backup method that'll work?"* No specific action named. No confirmation
of who ultimately made the change. A backup SMS method is, on its face, exactly the kind of
sensible pre-trip step that ticket describes — and also exactly the persistence step
`CLD-007` lists as a True Positive tell. Both readings fit the same three facts.

> **Hypothesis Board — after the MFA registration pivot**
> 1. **Legitimate travel, ordinary pre-trip account hygiene** — still live. Calendar and
>    booking confirm a real trip; the SMS method matches a plausible, ticketed request; the
>    device ID matches on both flagged sign-ins.
> 2. **Credential compromise, timed to a known travel window** — still live. A new MFA method
>    appeared days before travel with no log field capable of confirming who physically
>    performed it, and the flagged sign-in's timing doesn't yet reconcile with the actual
>    flight.
> **Current confidence:** Medium, falling from the prior checkpoint. The device-match and
> itinerary-match evidence that looked reassuring in Section 3 doesn't fully survive contact
> with the MFA-registration gap.

## 5. Additional evidence: what public flight-tracking data adds

**[ANALYST]** The travel-booking system gave a *scheduled* departure. It doesn't log actual
wheels-up time, and Vantage Air's own ops systems weren't something the SOC had access to on
a Sunday overnight shift. The analyst pulled the flight's public tracking history instead —
the same OSINT source security teams routinely check for executive-travel corroboration when
nothing internal has real-time granularity.

VA-1187's public track showed an actual off-block time of 03:47 UTC (a 37-minute gate delay
against the 03:10 UTC schedule) and wheels-up at 04:05 UTC. Scheduled arrival into Reykjavik:
approximately 10:05 UTC.

Laid against the sign-in timeline: sign-in 1 (04:02 UTC, Denver) landed almost exactly at
wheels-up — consistent with a last-connectivity check from the gate or taxiway before
takeoff. Sign-in 2 (04:41 UTC, Reykjavik-resolved) landed 36 minutes *after* wheels-up and
roughly five hours and twenty minutes *before* the flight's actual arrival in Reykjavik. If
Dana Voss was on that aircraft, at 04:41 UTC she was somewhere over the Canadian Arctic or the
North Atlantic, not in Iceland.

**Confidence: Medium, still falling.** This doesn't kill the travel explanation outright —
`CLD-007`'s and `EML-012`'s own False Positive indicator lists both name satellite internet
by name: connectivity that "routes egress through a different country than the user's
physical location, by design." An in-flight satellite gateway resolving to its own ground
station in Reykjavik regardless of the aircraft's real position is a completely ordinary
explanation for exactly this pattern. What it does mean is that the analyst can no longer
treat "the flight landed, so the destination sign-in makes sense" as settled — nobody has
independently confirmed that the gateway resolves this way, and thirty-six minutes after
wheels-up is early enough in a long-haul climb that in-flight wifi being live at all is
plausible but tight, not a given.

## 6. Dead end: chasing the satellite provider's own routing logs

> **Dead End**
> Twenty-five minutes went into trying to get a direct answer from Atlantic SatCom Partners
> on how their gateway attributes geolocation for aircraft mid-flight — specifically, whether
> a passenger connecting thirty-six minutes after a Denver departure would plausibly resolve
> to Reykjavik regardless of the aircraft's real position, or whether that resolution implies
> the gateway session originated from equipment already on the ground in Iceland. The vendor's
> published support channel returned an automated acknowledgment citing a five-business-day
> SLA for any request outside a live outage. That answer was not coming inside this
> investigation's window, and there was no faster path to it available to a solo overnight
> analyst with no existing vendor relationship on file. This specific line of inquiry is
> closed for this case; the gateway-attribution question stays open.

## 7. Pivot: reaching Dana Voss

**[PIVOT]** With the timing question unresolved and the account privileged, the next
required step per both `CLD-007` and `EML-012` was direct, out-of-band contact — not email,
which could itself be the compromised channel. The analyst used Aldergate's travel-security
after-hours line, which had Dana Voss's personal mobile number on file, and reached her at
10:40 UTC, shortly after landing in Reykjavik with a two-hour layover before the Berlin leg.

She confirmed the trip, confirmed VA-1187, and confirmed she recalled approving an
Authenticator push "at the gate, right before we finally boarded after the delay" — matching
sign-in 1. Asked specifically about a second push roughly forty minutes into the flight, her
answer was less certain: *"Maybe? I remember my phone buzzing a couple of times early on
while I was getting settled and just tapping approve without really looking — I assumed it
was the same login re-checking itself. I wasn't trying to ignore anything, I just wasn't
paying attention."* She had no memory of specifically requesting or setting up a new SMS
backup method, and thought Priya "might have looked into something like that" before the
trip, but wasn't sure of the details.

**[HYPOTHESIS]** This is where a purer version of one theory can be ruled out on a specific
technical fact, even though the broader question stays open. Detection Engineering Handbook
V2 Part 12 §7 names a Blind Spot that applies to exactly this kind of account: an
adversary-in-the-middle phishing kit that proxies a real login page lets the actual account
owner complete her own password and MFA step while the attacker steals the resulting session
token, producing a replayed session with **zero** MFA prompt and no new-device flag at all —
because nothing about the credential itself changed. That specific mechanism doesn't fit this
case: sign-in 2 was a fresh, independent, interactive authentication with its own MFA
challenge, not a silent token reuse. Pure session-token replay is ruled out by that one fact.

**Confidence: Medium, rising again.** Ruling out a clean session-token replay, on top of the
confirmed itinerary, the matching device ID on both flagged sign-ins, and Dana Voss's own
memory of approving sign-in 1 at the gate, closes off the single cleanest compromise story
available. That's real ground regained since the fall in Sections 4 and 5, even though it
isn't the whole answer.

What isn't ruled out is a narrower, more mundane version of the same underlying theory: an
attacker who already held Dana Voss's password, timed to a travel window that was visible on
her shared calendar, initiating a sign-in that generated a push she approved without
scrutiny while distracted and mid-flight — a form of **T1078.004** (Valid Accounts: Cloud
Accounts) enabled by **T1621** (Multi-Factor Authentication Request Generation) rather than
a stolen session. Her own account of "tapping approve without really looking" is honest,
plausible, and does not distinguish between those two possibilities from her side of the
phone call any better than the log does from the SOC's side.

## 8. The ticket that almost explains it

**[ANALYST]** Before closing anything out, the analyst checked for the one thing that would
resolve this cleanly toward compromise regardless of the travel-timing ambiguity: any
follow-on tenant activity consistent with an attacker actually doing something with access,
per `EML-012`'s own investigation steps.

```text
// Unified Audit Log — mailbox and directory actions in the 12 hours following sign-in 2
Search-UnifiedAuditLog -StartDate 2026-09-14T04:41:00Z -EndDate 2026-09-14T16:41:00Z
  -UserIds dvoss@aldergatemutual.example
  -Operations New-InboxRule,Set-InboxRule,Add-MailboxPermission,MailItemsAccessed
```

Nothing. No new inbox rule, no delegate grant, no mass mailbox enumeration, no new OAuth app
consent, and — checked separately given the account's own role — no directory-role or
Conditional Access policy changes made from either flagged sign-in's session. Whoever or
whatever was behind sign-in 2, it did not use that session to do anything with the Global
Administrator role it had access to.

Ticket #48217 itself, re-read closely, named no specific technician and closed with a generic
"confirmed MFA methods reviewed" note three days before travel — timed consistently with the
SMS registration, but not written specifically enough to confirm that ticket *caused* that
exact change rather than merely preceding it by coincidence.

**Confidence: Medium, falling again.** The clean follow-on-activity check is reassuring on
its own terms, but it only rules out what a session was *used for*, not whether sign-in 2
belonged to Dana Voss in the first place — and the one piece of evidence that could have
settled that, a named confirmation behind ticket #48217, isn't there. The rise in Section 7
doesn't survive the ticket being read this closely.

> **Hypothesis Board — at closure**
> 1. **Legitimate travel; the Reykjavik resolution is a satellite-gateway artifact, and the
>    second push was Dana Voss's own, distracted approval of her own real login** — favored,
>    but resting on inference: a plausible mechanism (satellite geo-mismatch) that nothing in
>    this investigation independently confirmed, and a memory that is honest but not certain.
> 2. **Credential compromise via a password the attacker already held, timed to a
>    calendar-visible travel window, riding on a push Dana Voss approved without scrutinizing
>    it** — not ruled out: the MFA-registration log cannot confirm who performed that change,
>    and "tapping approve without looking" is equally consistent with an attacker's session as
>    her own.
> **Current confidence:** Low-Medium. Neither hypothesis has a piece of evidence the other
> can't also explain.

## 9. Escalation, decision, and closure

**[ESCALATION]** `CLD-007`'s containment guidance doesn't wait for a settled disposition on
a privileged account: session revocation is low-cost even against a false positive, and the
analyst executed it under standing authority at 05:05 UTC, well before any of Sections 5-8
happened — Dana Voss re-authenticated from the airport without incident, which is itself
uninformative either way, since both a legitimate traveler and an attacker who'd lost the
session would re-authenticate cleanly.

> **Manager's Call**
> Whether to also suspend Dana Voss's Global Administrator role outright, mid-trip, pending
> full resolution, is a decision for the on-call IAM manager, not the analyst — it directly
> trades investigation thoroughness against disrupting a VP who is about to present at the
> conference she's traveling to. The on-call manager chose not to strip the role outright,
> instead disabling the newly added SMS method pending review and requiring a fresh MFA
> registration once Dana Voss reached Berlin. The SOC Manager's Operating Handbook, Part 25 —
> Risk Acceptance & Manager Decision-Making Under Uncertainty covers this tradeoff class in
> full; this case does not re-derive that doctrine, only shows the point where it applied.

**[ESCALATION]** Closed as **Insufficient Evidence**, confidence **Low-Medium, unresolved**.
The account was contained (sessions revoked, the unverified MFA method disabled, re-
registration required) regardless of disposition, because containment cost was low and the
account was privileged. No confirmed malicious action was ever found on the tenant side. No
independent confirmation of the travel explanation's key mechanism — the satellite-gateway
geo-mismatch — was obtained either. The case did not resolve toward either hypothesis; it was
contained toward the safer assumption without ever confirming which story was true.

> **What Would Change My Mind**
> Three specific things, any one of which would move this: (1) direct confirmation from
> Atlantic SatCom Partners that their Reykjavik gateway attributes geolocation independent of
> aircraft position this early after takeoff — would strengthen the travel explanation
> materially; a denial would weaken it just as sharply. (2) A specific, named confirmation
> from Priya Nakamura or IT support that ticket #48217 resulted directly in that exact SMS
> registration, performed by a named person on a named device — currently the ticket is
> consistent with, but doesn't confirm, that causal link. (3) Thirty days of clean activity
> on the account with no recurrence would raise confidence toward benign without fully
> confirming it; any anomalous sign-in or privilege use on this account inside that window
> would move confidence sharply toward compromise instead.

> **Blind Spot**
> This investigation can distinguish "a fresh interactive sign-in with its own MFA challenge"
> from "a replayed session token" — it cannot distinguish "Dana Voss approved her own login"
> from "Dana Voss approved someone else's login for her account without realizing it." No log
> source available to this case captures user *attention* at the moment of an MFA approval,
> only the approval event itself. That gap is why this case can name a specific mechanism for
> each hypothesis and still not be able to choose between them.

## 10. Lesson learned

**[LESSON LEARNED]** Two things generalize past this one account. First: a standing
(non-time-boxed) Global Administrator role turns every routine impossible-travel alert on
that account into a Critical/P1 full investigation, at a cost this case's ten sections
illustrate directly — narrowing that account to PIM-eligible, time-boxed Global Admin access
would not have prevented this alert, but it would have shrunk the blast radius the analyst
had to reason about, since a time-boxed elevation request leaves its own corroborating audit
trail that a standing role never generates. Second, and more broadly applicable across any
identity investigation, not just travel-flagged ones: a self-service security-info change log
that records only the account name as "initiator" is a real, permanent blind spot for any
organization where executives routinely delegate account-hygiene tasks to assistants or IT
support during busy weeks — Detection Engineering Handbook V2 Part 12 owns the identity
telemetry model this gap belongs to, and a detection-engineering fix worth raising there is
correlating *any* new MFA-method registration on a privileged account against a calendared
international trip inside the following seven days as its own composite signal, rather than
leaving the registration event and the travel event to be found independently, by hand, at
04:52 UTC on an otherwise clean Sunday.

---

**Cross-references:** SOC Playbook Handbook `CLD-007` — Impossible Travel (Cloud Sign-In)
(`playbooks/17-cloud/impossible-travel-cloud-sign-in.md`); SOC Playbook Handbook `EML-012` —
Impossible Travel (Mailbox Access) (`playbooks/16-email/impossible-travel-mailbox-access.md`);
SOC Playbook Handbook `25-false-positive-engineering-case-studies.md`, Case Study 4 (the
clean-resolution version this case deliberately does not repeat); Detection Engineering
Handbook V2, Part 12 — Identity Access and Authentication Detection, §6.1 `DET-12-04` and §7's
AiTM Blind Spot; SOC Manager's Operating Handbook, Part 25 — Risk Acceptance & Manager
Decision-Making Under Uncertainty.
