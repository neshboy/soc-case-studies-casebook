---
title: "CB-12 — The QR Code in the Parking Garage Flyer"
case_id: "CB-12"
category: "Web / Email"
disposition: "True Positive"
outcome_flavor: "Subtle"
confidence_at_close: "High"
entry_point: "employee-self-report"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook 16-email/qr-code-phishing.md (EML-006)", "SOC Playbook Handbook 15-web/session-hijacking.md (WEB-016)", "DEH V2 Part 17", "DEH V2 Part 18"]
---

# CB-12 — The QR Code in the Parking Garage Flyer

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Bellhaven Mutual Insurance," its staff, and every host, account, and IP address named below
are invented; no real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

Every other case in this book that touches phishing starts with a message: an inbound email, a decoded link, a mailbox that shows the damage. This one starts with nothing electronic at all — a piece of paper taped to a parking-garage pillar — and for most of its first day, the identity telemetry backs up the "nothing happened" read almost perfectly: no failed logon, no credential-harvesting page, no new device flagged, no password typed anywhere. This case exists to show what an investigation looks like when the standard tells a phishing case usually leans on are all genuinely absent, not just hidden, because the attack was built specifically to avoid generating them. It does not re-narrate how to decode a QR code, walk a redirect chain, or run the standard session-hijack investigation steps — the SOC Playbook Handbook's `qr-code-phishing.md` (EML-006) and `session-hijacking.md` (WEB-016) already own that mechanic in full, and this case cites both rather than rebuilding them. What this case does narrate is the one pivot neither of those two playbooks' default indicator lists quite anticipates: a token minted through a legitimate, pre-consented first-party application, approved by a fully compliant device, that ends up being used by a device that was never enrolled at all.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-12` |
| Category | Web / Email |
| Disposition | True Positive |
| Outcome flavor | Subtle |
| Confidence at close | High, settled |
| Entry point | Employee self-report (not a system alert) |
| Primary log sources | Entra ID sign-in logs (interactive and non-interactive), Microsoft Purview Unified Audit Log (`MailItemsAccessed`), Entra device compliance records, tenant-wide sign-in sweep |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `16-email/qr-code-phishing.md` (EML-006); SOC Playbook Handbook `15-web/session-hijacking.md` (WEB-016); DEH V2 Part 17 — Email Detection Engineering; DEH V2 Part 18 — Cloud Identity & SaaS Detection Engineering |
| All times | UTC |

## 1. A ticket that doesn't look like a security ticket

**[ANALYST]** The ticket that opened this case did not come from the SIEM queue. It came from the general IT helpdesk inbox, filed by Renata Okafor, a claims operations coordinator at Bellhaven Mutual Insurance, two days after the thing she was describing actually happened. Her message, forwarded into the SOC's queue by a helpdesk technician who wasn't sure it was even security-relevant, read: "Might be nothing — there was a flyer in the parking garage Tuesday morning with a QR code, something about a wellness survey and a gift card. I scanned it on my phone, it took me to a Microsoft page where I typed in a short code, and then it just said I could close the window. I didn't type a password or anything, so I don't think it did anything, but a coworker said I should flag it." The ticket sat in the general queue, untriaged, for most of a day before it was routed to the SOC, and then sat again until a slow Friday afternoon shift picked it up.

There was no alert attached to this ticket, because nothing about what Renata described trips a standing rule. No failed sign-in occurred — she never got a password wrong, because she never entered one. No new-device alert fired, because the device that completed the sign-in was her own, already-compliant phone. No suspicious-inbox-rule or OAuth-consent-abuse detection fired either, for reasons that only become clear several pivots later. The only reason this case exists at all is that Renata mentioned it to a coworker at lunch, and the coworker's instinct — "that sounds like something you should report" — turned out to be the single most consequential decision anyone made in this entire investigation.

**Confidence on intake: Low, flat.** Not "probably nothing" as a feeling — as a stated fact, there was exactly one piece of evidence in either direction: a self-report with no corroborating telemetry yet pulled. That is enough to open a ticket and not enough to call it anything.

## 2. Getting the one detail the ticket didn't have

**[ANALYST]** The ticket's own language was too vague to act on: "a Microsoft page" and "a short code" describe half the legitimate sign-in flows Bellhaven's staff go through in a normal week. Before pulling a single log, the analyst needed to know exactly what Renata saw, because "Microsoft page" could mean a normal Authenticator number-matching prompt (routine, no incident) or something else entirely. The analyst called her directly rather than working from the ticket text.

Renata's answer, on the call, was specific: the address bar read `microsoft.com/devicelogin`, and the code she typed was nine characters, all capital letters and numbers, no spaces — she remembered because she'd had to read it back off the flyer twice to get it right. She hadn't seen a fake login form, hadn't seen anything asking for her password, and hadn't noticed what app name, if any, the confirmation screen mentioned before she tapped through it. She'd thrown the flyer away before anyone asked her to keep it, and she had no photo of it.

> **Analyst's Gut Check**
> If a self-report says "I entered a code, not a password," don't file it under generic phishing and move on. That single sentence is the entire tell for device-code-flow abuse — get the exact URL and the exact shape of the code before doing anything else in the identity logs, because it tells you which query to run.

That detail — a real Microsoft domain, a short alphanumeric code, no password field anywhere in the flow — ruled out a fake-login-page credential harvest before the analyst ever opened a log source. It also meant the case wasn't going to look anything like EML-006's own worked example, where the decoded QR lands on a cloned M365 sign-in page on a domain registered days earlier. Here, the domain was completely legitimate, because it was Microsoft's own.

## 3. What the sign-in logs said — and almost didn't

### 3.1 First pass, too broad

**[PIVOT]** The obvious first move was Entra ID sign-in logs for Renata's account, scoped to the day she described.

```kql
// too broad — see next query
SigninLogs
| where UserPrincipalName == "renata.okafor@bellhavenmutual.example"
| where TimeGenerated between (datetime(2026-09-08 00:00:00) .. datetime(2026-09-08 23:59:59))
| project TimeGenerated, AppDisplayName, ClientAppUsed, IPAddress, ResultType, ConditionalAccessStatus
```

This returned 142 rows — Outlook mobile, Teams, SharePoint, the claims platform's SSO integration, a dozen background token refreshes for apps she uses constantly. Nothing about a single busy Tuesday for an active mobile user stands out from a query this wide; the useful signal was buried in ordinary noise, exactly the kind of false start the ticket's own vagueness had set up.

### 3.2 Narrowing to the device-code window

**[CONCEPT]** Renata's description — a real Microsoft domain, a short code, no password — matches a technique this book hasn't covered elsewhere: OAuth 2.0 device authorization grant abuse, sometimes called device-code phishing. An attacker's own client (a script, a CLI tool, anything that can speak to Microsoft's identity platform) requests a device code and a short user code, then talks a victim into visiting the real `microsoft.com/devicelogin` page and typing that code in. If the victim is already signed in on the browser or app they use to approve it, no password prompt appears at all — the approval just inherits whatever session the victim already has, MFA included. The resulting access and refresh tokens are issued to the *attacker's* client, not to the browser that approved the code. DEH V2 Part 18, §4 covers this exact mechanic as one of three ways conditional access gets bypassed without anyone breaking the policy engine itself; this case narrates one specific occurrence of it rather than re-deriving the concept.

With that in mind, the analyst re-ran the query scoped to the 20 minutes around Renata's reported time and dropped the wide app filter in favor of authentication protocol:

```kql
// closer to the raw shape of DET-18-04 than the tuned version —
// improvised mid-investigation against authenticationProtocol, not a standing rule
SigninLogs
| where UserPrincipalName == "renata.okafor@bellhavenmutual.example"
| where TimeGenerated between (datetime(2026-09-08 12:00:00) .. datetime(2026-09-08 12:30:00))
| extend AuthProtocol = tostring(AuthenticationProtocol)
| project TimeGenerated, AppDisplayName, AppId, AuthProtocol, IsInteractive, IPAddress,
          DeviceDetail.isCompliant, ConditionalAccessStatus, ResultType
```

One row came back: 12:14, `AppDisplayName = "Microsoft Azure CLI"`, `AppId = 04b07795-8ddb-461a-bbee-02f9e1bf7b46`, `AuthProtocol = deviceCode`, `IsInteractive = true`, source IP `203.0.113.19` (a Meridian Mobile Wireless carrier range — Renata's own phone), `DeviceDetail.isCompliant = true`, `ConditionalAccessStatus = success`, `ResultType = 0`.

Read on its own, this event is almost aggressively unremarkable: a successful sign-in, MFA-satisfied policy, from a device Entra already trusts. That's the whole problem with this class of attack, and it's why nothing auto-fired. Renata has never run the Azure CLI, has no reason to, and doesn't know what it is — that single field, `AppDisplayName`, was the first real anomaly the entire investigation had produced.

> **Hypothesis Board — after the sign-in log pivot**
> 1. **Nothing happened; the flyer was a dead lure or unrelated marketing** — weakened. A real, successful device-code sign-in under a client Renata has never used exists at almost exactly the time she described, which her own account history doesn't explain.
> 2. **A standard QR credential phish, per EML-006** — weakened. There's no failed logon, no separate credential-harvesting page, and the decoded destination is Microsoft's own legitimate domain, not a lookalike — none of EML-006's true-positive indicators apply here.
> 3. **Device-code-flow abuse (T1204, conditional-access bypass per DEH Part 18, §4)** — supported. The `AppDisplayName`/`AppId` mismatch against Renata's normal baseline is direct, specific evidence; nothing yet rules it out.
> **Current confidence:** Low-Medium, rising.

## 4. Ruling out the boring explanation

**[HYPOTHESIS]** Before treating an unfamiliar client ID as hostile, the analyst had to rule out the boring explanation: Bellhaven's own platform engineering team occasionally runs Azure CLI-based automation for license provisioning and mailbox migrations, and it was plausible that some script had authenticated using Renata's account for an unrelated, legitimate reason — a stale service credential, a misconfigured pipeline, anything with an innocent paper trail.

> **Dead End**
> Twenty minutes went into confirming this with Bellhaven's platform engineering lead: no scheduled job, pipeline, or provisioning script runs under Renata's personal identity, and nothing in the automation team's own change log touches Claims Operations accounts at all. The lead had never heard of a reason Renata's UPN would appear in an Azure CLI sign-in. This wasn't an artifact of internal tooling. Whatever generated that sign-in, it wasn't Bellhaven's own automation.

With the internal-tooling explanation closed off, hypothesis 1 (nothing happened) and the boring corollary to hypothesis 3 (an internal explanation for the odd client) were both gone. Confidence moved to Medium: one favored hypothesis, one piece of direct evidence, and the alternative explanation the analyst could think of had just failed to hold up. That still wasn't enough to escalate — a Medium call resting on one anomalous sign-in event and a user's memory of a flyer is thin, and the analyst hadn't yet shown the token was actually *used* by anyone other than Renata.

## 5. Pivot: from "who approved it" to "who's actually using it"

### 5.1 The non-interactive sign-ins

**[PIVOT]** The interactive sign-in event only captures the approval step — the moment Renata's own compliant phone said yes. Whoever requested that device code in the first place still needed to redeem it, and every subsequent use of the resulting access and refresh tokens shows up in Entra as separate, non-interactive sign-in events under the same application ID. The analyst pulled those next, widening the window to the 48 hours following the approval.

```kql
SigninLogs
| where UserPrincipalName == "renata.okafor@bellhavenmutual.example"
| where AppId == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
| where TimeGenerated between (datetime(2026-09-08 12:00:00) .. datetime(2026-09-10 12:00:00))
| where IsInteractive == false
| project TimeGenerated, IPAddress, DeviceDetail.deviceId, DeviceDetail.isCompliant, ConditionalAccessStatus, ResultType
| order by TimeGenerated asc
```

The result was 34 rows, spaced roughly every 55 to 70 minutes — a refresh-token lifetime pattern, not a one-off. Every single one originated from `198.51.100.230`, an IP in a commercial hosting-provider range with no prior history anywhere in Bellhaven's tenant. None of them carried a populated `deviceId`. `ConditionalAccessStatus` read `success` on every row, because the policy engine had no independent way to know the token was no longer with the device that earned it.

### 5.2 The device field that couldn't be true

**[HYPOTHESIS]** This is the specific gap DEH V2 Part 18, §4.2 (`DET-18-04`) is built to catch — a session or token used from a device and network fingerprint inconsistent with the one that issued it — narrated here in its raw, occurrence-specific form rather than the tuned join logic that section documents. A single account legitimately switching devices mid-session is common and not by itself suspicious. What isn't plausible is a token that Entra recorded as issued to a fully compliant, enrolled phone later being redeemed by a client presenting no device identity at all, over and over, from a hosting-provider IP the account has never touched. A compliant device doesn't stop reporting a device ID between one token use and the next; it either is the device that holds the token, or it isn't.

> **Evidence Note**
> None of Bellhaven's standing OAuth-consent-abuse or new-app-consent detections ever fired on this. Microsoft Azure CLI is a first-party Microsoft application, pre-consented tenant-wide — device-code redemption through it doesn't create a new app registration or a new consent grant for any rule to catch, because from the tenant's point of view, nothing new was ever added. The gap isn't in what the log source captured; it's in the assumption, built into an entire category of standing detections, that a first-party client ID is inherently benign.

At this point the analyst also weighed whether the WEB-016 playbook's own MITRE mapping — centered on T1550.004 (Use Alternate Authentication Material: Web Session Cookie) — actually fit. It doesn't cleanly. There's no stolen browser cookie here; there's a fraudulently completed OAuth device-authorization grant, which maps more precisely to **T1528 (Steal Application Access Token)**. **T1204 (User Execution)** covers the scan-and-approve action itself. Notably, **T1566.002 (Phishing: Spearphishing Link)** — the mapping both EML-006 and DEH V2 Part 17, §5 use for quishing generally — doesn't cleanly apply either, because there was no email, no message platform, and no electronic delivery channel anywhere in this chain; the lure was printed paper. WEB-016's *investigative steps* — pull the session/token identifier, build the device and IP timeline, check for a discontinuity point — transferred to this case exactly as written. Its default MITRE table and its default true-positive indicators, both built around cookie replay, didn't. DET-18-04's own coverage-summary entry carries that same T1550.004 tag by default, for the same reason — cookie replay is its common trigger — which is worth naming rather than leaving implicit: this case tags the rule for the pattern it structurally detects (a token used from a mismatched device/network fingerprint) and tags the incident separately for what actually produced that pattern here, the same rule-versus-incident split Part 17 §6.1 and §7 apply to DET-17-01 and DET-17-02.

> **Hypothesis Board — after the token-use pivot**
> 1. **Nothing happened / boring internal explanation** — ruled out. Platform engineering confirmed no legitimate automation, and the token is actively being redeemed from external infrastructure 55 to 70 minutes apart for two days straight.
> 2. **Standard QR credential phish (EML-006 pattern)** — ruled out. No credential page, no password entry, no lookalike domain exists anywhere in this chain.
> 3. **Device-code-flow token theft (T1528, DEH Part 18 §4)** — confirmed. Two independent sources agree: the interactive sign-in's anomalous `AppId`, and 34 non-interactive redemptions from a hosting IP with a null device ID.
> **Current confidence:** High, and still rising as the blast radius comes into view.

## 6. What the token had already touched

**[ANALYST]** With a confirmed live token in someone else's hands, the next question was what it had actually been used for. The analyst pulled Purview Unified Audit Log entries for `MailItemsAccessed` against Renata's mailbox across the same 48-hour window.

The first pass looked alarming on its face: 61 `MailItemsAccessed` operations in two days. Cross-referencing each entry's client and session identifiers against the mobile-app session Renata's own phone maintains, however, showed that 58 of the 61 matched her own normal Outlook mobile sync pattern — routine background mail fetches, nothing to do with the stolen token.

> **False Lead**
> A spike of 61 `MailItemsAccessed` events read at first like clear evidence of a mailbox raid. Almost all of it turned out to be Renata's own phone doing what phones do — syncing mail in the background all day. Only three of the 61 events tied back to the anomalous session associated with the `198.51.100.230` token redemptions; the other 58 needed to be explained away before the real scope of the access was visible.

The three that did tie back showed folder-level access to Inbox and Sent Items, with no attachment downloads and no forwarding or delegate-permission changes anywhere in the Unified Audit Log for the account. No `New-InboxRule` operation appeared either. Whoever held the token had looked, but as of the point of discovery had not yet set up any persistence that would survive a token revocation.

> **Blind Spot**
> `MailItemsAccessed` confirms that mail was opened; it does not say which messages, or whether any content was copied out through a channel this log doesn't cover. This investigation can distinguish "the attacker looked at Renata's mailbox" from "the attacker looked and took nothing" no better than any other mailbox-audit-only case can. Separately, nobody has any way to identify who physically posted the flyer — Bellhaven's garage-camera coverage of that specific pillar had already rolled past its retention window by the time Facilities was asked to pull it, and Renata discarded the physical flyer before anyone knew to ask her to keep it.

## 7. How far the flyer actually reached

**[PIVOT]** A flyer taped to a pillar in a shared garage isn't a targeted lure aimed at one person — anyone parking that week could have scanned it. The analyst swept the tenant for the same pattern: any account with an interactive `deviceCode` sign-in under an unfamiliar first-party `AppId`, in the several days around Renata's reported date, followed by non-interactive redemptions from an IP the account had no prior history with.

The sweep found two more accounts matching the exact shape — a facilities coordinator and a first-year underwriting analyst, both of whom park in the same garage and had no memory, when asked, of anything unusual until the pattern was described back to them. Both showed the identical signature: a compliant-device approval, followed by redemptions from `198.51.100.230`, the same hosting IP already tied to Renata's account. That shared IP across three unrelated accounts, rather than three coincidental separate campaigns, is what turned this from "one employee's odd afternoon" into a scoped incident with a known number of confirmed victims: three, out of an unknown number of people who scanned the same flyer and didn't think it was worth mentioning to anyone.

## 8. Escalation, containment, and closure

**[ESCALATION]** All three confirmed accounts were escalated to Tier 2/IR under WEB-016's criteria — a live, actively redeemed token qualifies regardless of the account's privilege level, and the multi-account pattern independently meets the volume threshold EML-006 sets for moving fast on takedown and comms. Per WEB-016's containment table, the SOC/IR on-call revoked the specific refresh tokens tied to each of the three accounts immediately, without waiting for further sign-off — the standard first move, and the one that actually matters here, since a password reset alone does not invalidate a refresh token that's already been issued and is actively in use elsewhere. All three accounts also went through a forced password reset and MFA re-registration as a secondary measure, and the IAM team reviewed conditional access policy scope to confirm device-code flow itself couldn't be disabled tenant-wide without breaking other legitimate first-party-app scenarios Bellhaven's engineering team still relies on — that policy conversation was opened as a follow-up ticket, not resolved same-shift.

> **Manager's Call**
> Whether to involve Facilities and Physical Security — sweeping the garage for any remaining copies of the flyer, requesting whatever camera retention still exists, and deciding whether to send a building-wide notice about a physical social-engineering lure — is a cross-team coordination call, not a technical one, and it sits with the incident commander rather than the investigating analyst. The SOC Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment covers how to bring a non-SOC team like Facilities into an incident without the request landing as an accusation; this case does not re-derive that doctrine, only shows the point where the analyst's job ends and that conversation begins.

**[ESCALATION]** All three cases closed as **True Positive**, confidence **High, settled**. The favored hypothesis — device-code-flow token theft delivered through a printed QR lure — is confirmed by two independent, specific pieces of evidence for each account: an interactive sign-in under a first-party `AppId` the account has no history of using, and repeated non-interactive redemptions from a shared external hosting IP with no device identity, continuing across two days until revoked. No plausible alternative survived: the internal-tooling explanation was checked and ruled out, and the classic credential-phish pattern never fit the facts in the first place.

> **What Would Change My Mind**
> This case rests partly on the assumption that Bellhaven's platform engineering team gave a complete and accurate answer when asked whether any legitimate automation touches these three accounts. If a fourth account later turned up with the identical signature and a documented, dated change ticket showing a real internal script behind it — one the automation team had simply forgotten when first asked — that would specifically weaken, though not necessarily overturn, the confidence attached to this case's conclusion for that account, and would be reason to re-ask the same question of the other three with more precise timestamps in hand.

The scope question — how many people scanned the flyer without ever mentioning it to anyone — was closed as genuinely unresolvable with the evidence available. Three confirmed victims is a floor, not a count. The decoded destination, `microsoft.com/devicelogin`, can't be blocked or taken down the way EML-006's containment options assume a phishing-kit domain can, because it's Microsoft's own legitimate infrastructure; the only usable containment lever here was revoking the specific tokens and hardening the response for next time, not disrupting the lure's delivery domain itself.

## 9. Lesson learned

**[LESSON LEARNED]** A phishing detection program built entirely around message-layer signals — sender reputation, decoded-URL scoring, lookalike-domain checks — has no visibility at all into a lure that never touches a message platform and never asks for a password. The identity-layer signal that actually mattered here wasn't a credential; it was an application identity a user has no business ever authenticating through, redeemed afterward by a device identity that couldn't possibly be the one that approved it. Any organization running device-code-flow-capable first-party apps (Azure CLI and several other Microsoft first-party clients chief among them) should treat an unfamiliar `AppId` combined with a `deviceCode` protocol as a standing thing to baseline per user, independent of whether the approving sign-in itself looks clean — because by design, it always will. The permanent fix belongs to DEH V2 Part 18, §4's detection-engineering treatment of conditional-access bypass (`DET-18-04`) and to whatever policy conversation Bellhaven's IAM team has about restricting device-code flow to a named, approved set of applications; this case only shows what it looks like to find one occurrence of the gap by hand, two days after an employee decided a flyer was odd enough to mention at lunch.

---

**Cross-references:** SOC Playbook Handbook `16-email/qr-code-phishing.md` (EML-006); SOC Playbook Handbook `15-web/session-hijacking.md` (WEB-016); Detection Engineering Handbook V2, Part 17 — Email Detection Engineering, §5 (QR-code phishing); Detection Engineering Handbook V2, Part 18 — Cloud Identity & SaaS Detection Engineering, §4 and §4.2 (`DET-18-04`); SOC Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment.
