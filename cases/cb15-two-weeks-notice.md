---
title: "CB-15 — Two Weeks' Notice"
case_id: "CB15"
category: "Insider"
disposition: "True Positive"
outcome_flavor: "Obvious"
confidence_at_close: "High"
entry_point: "hr-triggered-review"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook departing-employee-activity.md", "SOC Playbook large-download.md", "SOC Playbook personal-email-transfer-of-company-data.md", "SOC Playbook cloud-storage-upload-of-sensitive-data.md", "SOC Playbook 20-data-exfiltration-master-playbook.md", "SOC Manager's Operating Handbook Part 27"]
---

# CB-15 — Two Weeks' Notice

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Solvane Technologies," "Ferro Analytics," their staff, and every host, account, and IP
address named below are invented; no real organization, employee, incident, or breach is
depicted or implied.*

## Why this case exists

This case teaches what an investigation looks like when the hardest question — is this
malicious? — resolves almost immediately, and the real work is proving how far it went, not
whether it happened. It closes as an **Obvious** True Positive with confidence that reaches
High on the first substantive pivot and never moves again for the rest of the case: a
deliberate contrast with CB-16, this book's other Insider case, which confirms a genuine
policy violation and then deliberately stays at Medium because the underlying intent never
stops being ambiguous. Two departures, two different shapes of certainty. This case does not
re-derive the threshold logic behind flagging a resignation for security review (SOC
Playbook Handbook, `departing-employee-activity.md`), what counts as an anomalous download
volume for a given role (`large-download.md`), or the detection mechanics behind a
personal-cloud-storage upload or a personal-email transfer
(`cloud-storage-upload-of-sensitive-data.md`, `personal-email-transfer-of-company-data.md`)
— those thresholds and signatures are owned there, cited here, not rebuilt. It also does not
adjudicate the HR and Legal question of exactly when to cut a departing employee's access
relative to a resignation's notice period; that tradeoff belongs to the SOC Manager's
Operating Handbook, Part 27 — Legal, HR & Compliance Interfaces, and this case only shows
where the analyst's job hands off to it.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-15` |
| Category | Insider |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | HR-triggered offboarding review tied to a resignation to a restricted-destination employer, not a technical alert |
| Primary log sources | Entra ID sign-in log, SharePoint Online audit log, CASB cloud-app log, Exchange Online mail-flow DLP log, endpoint DLP (removable media), facilities badge-linked printer audit trail |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `departing-employee-activity.md`, `large-download.md`, `personal-email-transfer-of-company-data.md`, `cloud-storage-upload-of-sensitive-data.md`, `20-data-exfiltration-master-playbook.md`; SOC Manager's Operating Handbook Part 27 — Legal, HR & Compliance Interfaces |
| All times | UTC |

## 1. Entry point: a resignation, not an alert

**[CONCEPT]** Nothing in the SIEM fired here. Solvane's HRIS offboarding workflow checks
every resignation's disclosed next employer against a Restricted Destination List — a
short, quarterly-reviewed roster of named competitors and litigation-adjacent
counterparties maintained jointly by Legal and the SOC. A match auto-routes a copy of the
exit paperwork to the SOC's insider-risk queue as a review ticket, not a detection alert.
SOC Playbook Handbook `departing-employee-activity.md` owns the full trigger criteria and
the default lookback window this routing kicks off; this case only needs the reader to know
that the ticket exists because of what the employee disclosed, not because any tool decided
her activity looked wrong.

**[ANALYST]** Priya Anand, a Senior Enterprise Account Executive, submitted her resignation
on Monday, August 31, effective two weeks later. Her exit form named her next employer as
Ferro Analytics — one of six names on the Restricted Destination List, flagged there
because Ferro competes directly against Solvane's flagship underwriting-workflow product in
enterprise deals. Ticket EXIT-4471 landed in the SOC queue at 14:02 UTC the same day. This
was a business-hours case from the start: a Tier 2 analyst picked it up the next morning
working alongside the HR business partner assigned to the exit, on a scheduled thirty-minute
call before either of them had looked at a single log.

## 2. The download total, and the questions it doesn't answer

**[ANALYST]** The standing procedure for a restricted-destination exit pulls a 30-day CASB
and DLP activity summary for the employee, ending on the resignation date. For Priya, that
meant August 2 through August 31.

| Metric | Priya Anand, Aug 2–31 | Her own 90-day baseline, per 30 days | Enterprise AE peer group, P95 |
|---|---|---|---|
| Files downloaded | 468 | 118 | 240 |
| Total volume | 14.6 GB | 0.9 GB | 2.1 GB |
| Distinct source systems touched | 3 | 2 | 2 |

**[ANALYST]** Fourteen-point-six gigabytes is a real number, but it is not, on its own, a
finding. The last two weeks of August were also the last two weeks of Solvane's fiscal Q3,
and Priya was a strong performer closing pipeline. An account executive who spends the
final stretch of a quarter exporting proposal drafts, pricing worksheets, and CRM reports
for a dozen live deals can post a download total that looks alarming next to her own
quiet-month baseline and still be doing nothing but her job under deadline pressure. The
peer-group comparison narrowed that a little — even the ninetieth-fifth percentile of her
own team didn't reach a third of what she downloaded — but a peer comparison describes an
outlier, not an intent.

> **Analyst's Gut Check**
> A raw volume number on a departing-employee ticket will almost always look bad, because
> volume alone can't tell "closing the quarter" apart from "packing a bag." Don't triage
> the number; triage the file list. The number tells you where to look, not what you'll
> find.

**[ANALYST]** Four questions sat between that table and a second data source: were the
flagged downloads things Priya actually needed for her own open deals, or material outside
her working set? Was this session actually run by Priya, from her own device, or could this
be someone else using her credentials in a notice-period window when account hygiene tends
to slip? Did anything downloaded subsequently leave the company's own systems, and by what
path? And had Priya ever done anything like this before, on a normal week, for an ordinary
reason? None of those four questions can be answered from a 30-day summary table.

## 3. Pivot: from the CASB summary to the file-level audit trail

**[PIVOT]** A 30-day summary answers "how much," never "what" or "when, specifically." That
required the SharePoint Online audit log directly, filtered down from the whole Enterprise
AE team to Priya's own account and cross-referenced against the Salesforce opportunity IDs
she actually owned.

### 3.1 The too-broad first query

```text
// too broad — see next query
SharePointAuditLog
| where TimeGenerated between (datetime(2026-08-02) .. datetime(2026-08-31))
| where Operation == "FileDownloaded"
| where SiteUrl has "sales-enablement"
→ 6,214 matching rows, entire Enterprise AE team
```

Six thousand rows covering every account executive's ordinary quarter-end activity told the
analyst nothing about Priya specifically. Narrowed to her user principal name:

```text
SharePointAuditLog
| where TimeGenerated between (datetime(2026-08-02) .. datetime(2026-08-31))
| where Operation == "FileDownloaded"
| where UserId == "panand@solvane.example"
→ 468 matching rows
```

### 3.2 What the flagged subset actually was

**[ANALYST]** Cross-referencing all 468 filenames against the twelve open Salesforce
opportunities Priya owned sorted them into two very different piles. Four hundred
thirty-one files were exactly what a quarter-end push looks like: proposal drafts, signed
order forms, deal-specific pricing worksheets, all tagged to opportunity IDs on her own
book. The remaining 37 were not tied to any opportunity she owned, and several were not
tied to any opportunity at all:

| Flagged file | Category | Tied to one of her deals? |
|---|---|---|
| `Master_Pricing_Sheet_AllRegions.xlsx` | Company-wide pricing | No — her region-specific sheet exists separately |
| `Renewal_Risk_Model_FY27.xlsx` | Company-wide churn/BI model | No |
| `FY27_Enterprise_Pipeline_AllReps.xlsx` | Every enterprise rep's pipeline | No — includes 40+ accounts she does not own |
| `Enterprise_MSA_Template_v9.docx` | Contract template | No |
| `Enterprise_NDA_Template_v9.docx` | Contract template | No |
| Competitive battlecards (14 files, all verticals) | Sales enablement | 1 of 14 |

All 37 downloads clustered inside a single 48-minute window on Saturday, August 22, between
22:03 and 22:51 UTC — nine days before Priya gave notice, and a day and a time with no
precedent anywhere in her prior three months of activity.

> **False Lead**
> The single most alarming-looking file in the set, at a glance, was the Ferro Analytics
> battlecard — a departing employee downloading competitive intelligence about the company
> she was about to join. It turned out to have an ordinary explanation: Salesforce's own
> opportunity notes showed Ferro listed as the competing bidder on two of Priya's active
> deals that same week, and account executives routinely pull the relevant battlecard when
> a competitor's name comes up in a live sales conversation. That explained one battlecard.
> It did not explain the other 13 — for verticals and regions she had never sold into — which
> is what actually mattered here.

**[HYPOTHESIS]** The "just closing the quarter" theory made a specific prediction: if this
were ordinary pipeline hustle, the flagged files should look like the other 431 —
deal-specific, tied to her own accounts, spread across her normal working hours. Instead,
the 37 outliers were company-wide artifacts she had no individual deal-need for, downloaded
in one unbroken weekend session, more than a week before anyone besides Priya knew she was
leaving. That prediction failed. This was no longer a volume question.

> **Hypothesis Board — after the file-level pivot**
> 1. **Ordinary quarter-end pipeline activity** — ruled out. The 431 routine files fit that
>    theory perfectly; the 37 flagged files fit it not at all — wrong content, wrong
>    timing, wrong day of week, and unprecedented against her own three-month baseline.
> 2. **Someone other than Priya used her account during this window** — still live, not yet
>    checked.
> 3. **Deliberate collection of company-wide material ahead of a move to a named
>    competitor** — supported, pending confirmation the session was genuinely hers.
> **Current confidence:** High that this is deliberate, malicious collection — the CASB/DLP
> volume anomaly and the SharePoint content/timing anomaly are two independent sources
> agreeing on the same conclusion. Not yet settled on who was behind the keyboard.

## 4. Hypothesis check: is this her account, or someone else's session?

**[PIVOT]** A notice period is exactly the kind of window where credential hygiene can
slip — a shared password, a phished session, a departing employee's own account used by
someone else entirely. Before attributing the August 22 session to Priya herself, the
analyst pulled the Entra ID sign-in log for the same window.

```text
// Entra ID sign-in log, panand@solvane.example, 2026-08-22
2026-08-22T22:01:47Z result=success app="SharePoint Online" deviceId=LT-PANAND-04
  authMethod=push-MFA(device •7743) ip=198.51.100.23 location="Columbus, OH, US"
2026-08-22T22:03:12Z result=success app="SharePoint Online" deviceId=LT-PANAND-04
  authMethod=token-refresh ip=198.51.100.23 location="Columbus, OH, US"
2026-08-22T22:50:58Z result=success app="SharePoint Online" deviceId=LT-PANAND-04
  authMethod=token-refresh ip=198.51.100.23 location="Columbus, OH, US"
```

**[HYPOTHESIS]** Every sign-in in the window used Priya's own enrolled device ID, an MFA
push approved on the phone already registered to her, and a residential IP address matching
the home ISP range on file from her prior work-from-home requests — the same device, the
same MFA endpoint, and the same location her ordinary remote sessions used, just on a
Saturday night instead of her usual Wednesday. The facilities badge log showed no badge-in
that day, which is consistent with a from-home session but doesn't independently prove
anything on its own; it's the device and MFA fields in the sign-in log that actually close
this, not the badge log's silence. Nothing in the identity evidence supports a second person
behind this session.

> **Hypothesis Board — updated, after the identity pivot**
> 1. **Ordinary quarter-end pipeline activity** — ruled out (§3).
> 2. **Someone other than Priya used her account** — ruled out. Device ID, MFA endpoint, and
>    source location all match her own established pattern with no deviation.
> 3. **Deliberate collection ahead of a move to a named competitor** — supported, and now
>    the only theory left standing on who did this.
> **Current confidence:** High, settled on attribution and intent. Open on scope.

## 5. Chasing the scope: two channels that moved data, two that didn't

**[PIVOT]** Attribution was settled; scope wasn't. A download confirms collection. It doesn't
confirm the material went anywhere, or by what path — physical or digital. Four channels
were on the checklist before the scope question could close: the office printers, the CASB's
cloud-application log, the mail gateway's DLP log, and the endpoint DLP agent's removable-
media events. Two came back with nothing. Two didn't.

### 5.1 Dead end: the printer audit trail

**[ANALYST]** Digital collection doesn't rule out a parallel physical channel, and Solvane's
badge-linked office printers keep an audit trail of every print job by employee. On the
theory that Priya might have printed anything from the flagged set as a supplementary,
harder-to-monitor channel, the analyst requested the full print log for her badge ID across
the same 30-day window from facilities.

> **Dead End**
> The request took most of an afternoon to come back, routed through a facilities ticketing
> system the SOC doesn't have direct access to. The result: one print job in the entire
> window, three pages, an expense report submitted on August 19. Whatever Priya did with the
> files from August 22, she didn't print them at the office. This channel is closed; nothing
> here changes the scope question, and the afternoon spent waiting on it didn't move the
> case forward.

### 5.2 The personal cloud upload

**[PIVOT]** The next question needed the CASB's cloud-application log and the mail gateway's
DLP log — the two channels `cloud-storage-upload-of-sensitive-data.md` and
`personal-email-transfer-of-company-data.md` are each built to watch.

```text
// CASB cloud-app log, personal-storage category, 2026-08-22
2026-08-22T23:10:04Z user=panand@solvane.example device=LT-PANAND-04
  app="Google Drive (consumer)" action=upload object=Sales_Docs_Backup.zip
  size=612MB destination_account=p.anand.87@gmail.example policy=monitor-only
```

Nineteen minutes after the last of the 37 flagged downloads, a 612 MB zip archive went up
to a personal Google account from the same device, over the same session. The size is
consistent with the flagged set compressed together; the CASB doesn't unpack archive
contents to confirm that directly, but the timing leaves little room for coincidence. This
is T1567.002 (Exfiltration to Cloud Storage).

> **Evidence Note**
> The CASB's cloud-application policy for this category is monitor-only, not blocking, and
> that's a real architectural constraint, not an oversight someone forgot to fix. Solvane's
> own Google Workspace tenant and every employee's personal Google account both resolve
> through the same `drive.google.com` service; the CASB can tell which *account* a session
> authenticated as, but blocking the destination outright would also block legitimate
> access to the company's own tenant unless a separate tenant-restriction control is
> deployed specifically to keep the two apart. Solvane hadn't deployed one. That gap is why
> this upload was logged in detail but never stopped in real time — and why it surfaced only
> because this review went looking, not because anything alerted on its own.

### 5.3 The email two days later

```text
// Exchange Online mail-flow DLP log, 2026-08-24
2026-08-24T15:47:29Z sender=panand@solvane.example recipient=p.anand.87@gmail.example
  subject="resources for later" attachments=3 sensitivity_label=Restricted
  policy=block-external-restricted action=quarantined rule=DLP-EXT-RESTRICTED-01
```

**[PIVOT]** Two days after the weekend session, from the office during business hours,
Priya sent herself an email carrying the enterprise MSA and NDA templates as direct
attachments, plus a share link back to the same Google Drive folder in the body. Unlike the
cloud-app policy, the mail gateway's DLP rule for externally addressed messages carrying a
Restricted sensitivity label runs in blocking mode — the label had cascaded onto the
attachments automatically when they were exported from their source library, and the rule
caught it immediately. The message never left Solvane's mail system; it sat quarantined,
unnoticed by anyone until this review pulled the log. This is T1567.004 (Exfiltration Over
Webmail), attempted, not completed.

### 5.4 Ruling out removable media

**[ANALYST]** One vector remained on the checklist: removable storage. Solvane's endpoint DLP
agent logs every mass-storage device attach event on managed laptops.

```text
// Endpoint DLP, removable-media events, LT-PANAND-04, 2026-08-02–2026-08-31
→ 0 matching events
```

**[HYPOTHESIS]** No removable-media events at all across the full window rules out a USB
copy as a third channel. Combined with the printer dead end in §5.1, the exfiltration
attempt's scope is now bounded to exactly two channels: a successful upload to a personal
cloud account, and an attempted email transfer that Exchange Online's own DLP rule stopped.

## 6. Scope, settled

**[HYPOTHESIS]** Nothing left in evidence points anywhere but one direction: a Solvane
employee, using her own credentials from her own device, collected company-wide sales,
pricing, and contract material she had no individual deal-need for, in a single off-hours
session more than a week before disclosing a move to a named competitor, and moved a
compressed copy of it to a personal account nine days before giving notice. A second attempt
two days later was blocked by an unrelated control that wasn't built with this scenario in
mind — it exists to stop accidental data leaks, not resignations — but stopped it anyway.

> **Blind Spot**
> Everything in this evidence set describes what left Solvane's own systems and by what
> path. Nothing in it can say what happened to the archive after it landed in a personal
> Google account outside Solvane's tenant — whether Priya deleted it, kept it, or forwarded
> it to anyone at Ferro Analytics before her last day. That question sits entirely outside
> any log source Solvane controls. Closing this case as confirmed collection-and-attempted-
> transfer is not the same claim as confirmed disclosure to a third party, and only the
> first of those two claims has direct evidence behind it.

## 7. Escalation and the access-timing question

**[ESCALATION]** The analyst escalated to the incident commander the same afternoon as a
confirmed True Positive, severity High: unauthorized collection and attempted exfiltration
of company-wide sales and contract material by a departing employee moving to a named
competitor, attribution settled, scope bounded to two channels, one successful and one
blocked. Per `departing-employee-activity.md` and the `20-data-exfiltration-master-
playbook.md` containment sequence, the SOC's own actions were mechanical from this point:
preserve a forensic image of `LT-PANAND-04` before it could be wiped or returned, place a
legal hold on Priya's mailbox and SharePoint activity, and prepare — but not yet execute —
immediate suspension of her SSO and VPN access, which would normally still be two weeks from
expiring on its own.

> **Manager's Call**
> Whether to suspend Priya's access immediately, days before her scheduled last day, or let
> the notice period run under close monitoring while HR and Legal decide how to handle the
> exit interview, is the incident commander's decision, not the analyst's. Cutting access
> now stops any further collection instantly but tips her off before HR has had the exit
> conversation; letting it run preserves the appearance of normalcy for that conversation
> but accepts the risk of a third attempt through a channel this review hasn't found. The
> SOC Manager's Operating Handbook, Part 27 — Legal, HR & Compliance Interfaces covers this
> exact evidence-preservation-versus-tipping-off tradeoff in full; this case does not
> re-derive it, only marks the point where the analyst's job — confirm what happened and how
> far it went — ends and the manager's begins.

## 8. Decision and closure

**Disposition: True Positive.** **Outcome flavor: Obvious.** Attribution, intent, and scope
each rest on direct evidence from at least two independent log sources with no unresolved
contradiction between them: the file-audit trail and the CASB upload log agree on timing and
approximate volume; the Entra sign-in log and the CASB session both point to the same
device, account, and location; the mail-flow DLP log independently confirms a second,
separate attempt along a different channel. **Confidence at close: High, settled.** Unlike
CB-16, nothing about this case's confidence trajectory ever dipped or oscillated once the
file-level pivot in §3 landed — the only thing that grew after that point was the scope, not
the doubt.

> **What Would Change My Mind**
> This closes at High confidence on collection and attempted transfer specifically — both
> claims, direct evidence, no gaps. It would take a new fact to revise the one claim this
> case does not make at High confidence: whether the material reached anyone at Ferro
> Analytics. A forensic finding on the returned laptop showing the archive was deleted
> within minutes of upload, with no further access afterward, would weigh toward "collected
> but not disclosed." Any evidence of a second upload attempt, or of the archive being
> shared onward from the personal account, would be the fact that turns the Blind Spot in
> §6 into a confirmed disclosure finding instead of an open one — but that evidence, if it
> exists, sits outside every log source this case had access to.

## 9. Lesson learned

**[LESSON LEARNED]** The 30-day default lookback in `departing-employee-activity.md` caught
this case, but only by margin: the collection happened nine days before Priya gave notice,
inside a 30-day window measured backward from the resignation date, but not by much. If she
had started the same collection five or six weeks ahead of disclosing her move instead of
nine days, the standing procedure as currently tuned would have missed it entirely, because
nothing else about her account behavior in the weeks after would have looked any different
from an ordinary employee. This generalizes past this one case: a fixed lookback window
tuned to the length of a typical notice period assumes departure-adjacent collection starts
inside that notice period, and there is no reason to believe it usually does. The specific,
checkable fix — extending the default lookback well beyond the notice period itself and
re-running it retroactively whenever a restricted-destination match fires — belongs to
`departing-employee-activity.md`, and this case's job is to hand that finding off, not
implement it. Second, separately: the gap that let the cloud upload succeed in real time
wasn't a forgotten exception, it was a genuine tooling limitation — no tenant-restriction
control separating the company's own SaaS tenant from employees' personal accounts on the
same consumer service. That is a specific, closeable gap, and it belongs to
`cloud-storage-upload-of-sensitive-data.md` as a control-coverage finding, not a detection
one; no query tuning fixes a control that was never deployed.

---

**Cross-references:** SOC Playbook Handbook `departing-employee-activity.md`,
`large-download.md`, `personal-email-transfer-of-company-data.md`,
`cloud-storage-upload-of-sensitive-data.md`, `20-data-exfiltration-master-playbook.md`; SOC
Manager's Operating Handbook Part 27 — Legal, HR & Compliance Interfaces.
