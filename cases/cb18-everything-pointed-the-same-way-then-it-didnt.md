---
title: "CB-18 — Everything Pointed the Same Way, Then It Didn't"
case_id: "CB-18"
category: "Ambiguous"
disposition: "Insufficient Evidence"
outcome_flavor: "Inconclusive"
confidence_at_close: "Medium"
entry_point: "standing-alert-plus-volunteered-hr-context"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook large-download.md", "SOC Playbook Handbook large-outbound-data-transfer.md", "SOC Playbook Handbook 20-data-exfiltration-master-playbook.md", "SOC Manager's Operating Handbook Part 27"]
---

# CB-18 — Everything Pointed the Same Way, Then It Didn't

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Averlyne Actuarial Partners," its staff, and every host, account, and IP address named
below are invented; no real organization, employee, incident, or breach is depicted or
implied.*

## Why this case exists

This case exists to show what happens when the two threads this book usually keeps separate — a technical alert and a human-context tip — arrive out of order and neither one finishes the job the other started. `large-outbound-data-transfer.md` and `large-download.md` already document the detection logic for this pattern well: threshold-based, content-aware, tuned to catch bulk movement toward destinations that aren't sanctioned. `20-data-exfiltration-master-playbook.md`'s own worked example, SUG-2026-0904-PELLETIER, already walks through the clean version of this case — a documented HR flag landing on top of a bulk transfer, weighed alongside the rest of the corroborating chain rather than counted on its own. This case deliberately does not restage that clean example. It stages the version that actually shows up more often: a manager's own worried, off-script comment on a phone call that was only supposed to confirm business justification, arriving mid-investigation with no paperwork behind it yet, and a self-filed IT ticket that surfaces afterward looking like either an alibi or a coincidence — and stays looking like both, all the way to closure. Where CB-15 ("Two Weeks' Notice") is built to be unambiguous on purpose, entry point HR-triggered and confidence high throughout, this case starts as a pure technical alert, gets an HR fact volunteered into it uninvited, and never gets the second confirming fact it needed to settle. That's the specific gap in the collection this case fills, and the reason its second half spends as much time weighing what one manager said and one ticket proves as it does reading proxy logs.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-18` |
| Category | Ambiguous |
| Disposition | Insufficient Evidence |
| Outcome flavor | Inconclusive |
| Confidence at close | Medium, unresolved |
| Entry point | Standing CASB/proxy large-outbound-transfer alert, compounded mid-investigation by HR context volunteered on an unrelated call |
| Primary log sources | CASB/secure web gateway proxy logs, endpoint DLP content-inspection logs, EDR file-access and process telemetry, Windows Security event log, badge/physical-access system, internal IT self-service ticketing system, asset-refresh calendar |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `large-download.md`, `large-outbound-data-transfer.md`, `20-data-exfiltration-master-playbook.md` |
| All times | UTC |

## 1. The alert: an upload that outran its own threshold

**[CONCEPT]** `large-outbound-data-transfer.md` scopes its detection the way most exfiltration rules have to: not on any single upload, which is ordinary traffic thousands of times a day, but on cumulative volume from one user to one destination category crossing a threshold inside a rolling window. The technique this specific rule is built to catch is `T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)` — moving data out through a sanctioned-looking web service rather than a bespoke C2 channel, which is exactly why volume and destination category, not payload signature, have to carry the detection. Averlyne Actuarial Partners' CASB runs a rule modeled directly on that playbook's example — `EXFIL-OUT-01`, cumulative bytes to any destination tagged "Personal Cloud Storage" exceeding 3 GB inside a four-hour window, scoped to exclude the company's own Google Workspace tenant so that ordinary corporate Drive use never counts against the threshold.

### 1.1 The rule that fired

At 14:47 on 2026-09-09, it fired.

```json
{
  "alert_id": "EXFIL-OUT-01-88210",
  "rule": "Large Outbound Transfer to Unsanctioned Cloud Storage",
  "first_seen": "2026-09-09T12:58:11Z",
  "last_seen": "2026-09-09T14:47:03Z",
  "user": "pchandrasekhar@averlyne.example",
  "src_ip": "192.0.2.44",
  "dst_host": "upload.googleusercontent.com",
  "dst_ip": "203.0.113.18",
  "dst_category": "Personal Cloud Storage (Google Drive, consumer)",
  "dst_account_id": "not-corp-tenant",
  "bytes_out_cumulative": 3648102400,
  "threshold_bytes": 3221225472,
  "window_hours": 4
}
```

**[ANALYST]** The user was Priya Chandrasekhar, a senior actuarial analyst on the casualty-reserving team. Reyna Okafor, the Tier 2 analyst working Averlyne's DLP/CASB queue that afternoon, pulled the ticket five minutes after it paged. The alert itself answers almost nothing on its own — 3.4 GB to a personal Google account is exactly the shape `large-outbound-data-transfer.md` is built to flag, and exactly the shape a hundred harmless personal-backup habits also produce.

### 1.2 The first, too-broad pull

**[ANALYST]** Reyna's first query pulled every event touching anything Google-shaped for the day, to get oriented:

```sql
-- too broad — see next query
SELECT ts, user, dst_host, bytes_out
FROM proxy_logs
WHERE dst_host LIKE '%google%'
  AND ts BETWEEN '2026-09-09T00:00:00Z' AND '2026-09-10T00:00:00Z'
ORDER BY ts;
```

That returned 6,842 rows. Averlyne runs its email and internal file collaboration on Google Workspace, so nearly every employee's browser talks to something under `google.com` constantly, all day, for entirely sanctioned reasons. This confirmed nothing except that "Google" was the wrong filter.

### 1.3 The narrowed pull

Narrowing to the one user, the one non-corporate destination tenant, and the alert's own window cut it to something readable:

```sql
SELECT ts, user, dst_host, dst_account_id, bytes_out, http_method, uri_path
FROM proxy_logs
WHERE user = 'pchandrasekhar@averlyne.example'
  AND dst_account_id != 'averlyne-corp-tenant'
  AND ts BETWEEN '2026-09-09T10:00:00Z' AND '2026-09-09T15:00:00Z'
ORDER BY ts;
```

**[PIVOT]** 61 rows, nearly all of them resumable-upload `POST` requests to `drive.google.com`'s upload API, running in a steady stream from 12:58 to 14:47 — two browser tabs, one destination account, one continuous session. This wasn't a sync client quietly mirroring a folder in the background; the user agent string was a desktop Chrome browser, meaning someone was sitting at the drag-and-drop upload page in `drive.google.com`, watching files go up.

**Confidence: Low.** One fact worth acting on — this is a real, sustained, browser-driven transfer to an account Averlyne doesn't own — and nothing yet about what was in it or why.

## 2. Pivot: from the CASB log to the DLP content-inspection log

**[ANALYST]** The proxy log carries byte counts and URIs, not filenames — `large-download.md` makes the same point about its own internal-transfer detections: volume tells you something happened, not what. Three things needed answers before a third log source got touched: what, specifically, went up in those 61 requests, and whether any of it carried a confidentiality classification belonging to a client rather than to Priya personally; how those files got onto her laptop in the first place, pulled from a network share or already local; and whether this was actually Priya, at her own machine, or a compromised account acting on her behalf.

**[PIVOT]** Averlyne's endpoint DLP agent inspects file content before it leaves the machine over an unsanctioned channel, tagging matches against a standing classification ruleset — `DLP-CLASSIFY-CLIENT-MODEL` among them. Because `EXFIL-OUT-01` is a detect-and-log rule, not a block rule (blocking outbound Drive uploads outright breaks too many legitimate personal-account edge cases to run in enforce mode company-wide), the transfer itself wasn't stopped, but every file it touched left a content-inspection record.

### 2.1 The manifest

The pull returned 47 distinct files across the session. A summary by classification:

| Classification tag | File count | Example filename |
|---|---|---|
| Confidential — Client Data | 31 | `ClientModel_Meridian_Casualty_v7.xlsx` |
| Internal — Unclassified | 7 | `Reserve_Notes_Draft.docx` |
| No tag match (personal-looking) | 9 | `taxes_2025.pdf`, `resume_draft3.docx` |

**[ANALYST]** 31 of 47 files tagged Confidential — Client Data was the number that moved this off "probably a personal backup" and onto the SOC's active board. `large-outbound-data-transfer.md`'s own escalation criteria treat any confirmed classified-data match to an unsanctioned personal destination as sufficient on its own to open a case, independent of volume — the volume threshold is what got the SOC's attention, but the classification tags are what justified keeping it.

### 2.2 A false lead inside the manifest itself

**[ANALYST]** The classification tags alone made this look worse than it was; opening the actual files ahead of the next pivot changed the count.

> **False Lead**
> Nine of the 31 "Confidential — Client Data" files looked, on the classification tag alone, like the
> worst nine files in the whole set — until Reyna actually opened three of them in a sandboxed
> viewer. They were blank workpaper cover sheets: a standard template every actuarial deliverable
> at Averlyne gets stamped with before any real content is added, carrying the confidentiality
> footer in the template itself rather than in anything that got typed into it later. The DLP
> engine matches on the footer text, not on whether the sheet behind it has data in it yet. Nine of
> the 31 were empty. 22 weren't.

**Confidence: Medium.** 22 files of real client casualty-reserve modeling data, moved by a browser session to a personal account, is enough to justify the next two pivots regardless of how this resolves.

## 3. Pivot: from DLP to endpoint EDR, and ruling out a stolen session

**[PIVOT]** Two things still needed answers before anyone talked to a human: how the 22 real files got onto Priya's laptop, and whether "Priya" was actually Priya.

### 3.1 How the files got onto the laptop

EDR file-access telemetry for workstation `AVL-LT-2291` showed a tight, contiguous window: `explorer.exe` opening files directly from `\\AVL-FS02\Actuarial$\ClientModels\`, a mapped network share, between 12:19 and 12:57 — 38 minutes, ending one minute before the first upload request hit the proxy. The count from the share matched the manifest's classified side exactly: the 31 Confidential — Client Data files plus the 7 Internal — Unclassified files, all pulled from `ClientModels\`. The remaining 9 personal-looking files never touched that share at all — they came from Priya's own local Desktop and Documents folders, outside this particular EDR query's scope. No PowerShell process ran in the 12:19–12:57 window. No archiving utility beyond Windows' own built-in "Send to → Compressed folder" ran twice, against two specific subfolders, not the whole share. That detail mattered: a scripted, automated exfiltration tool typically pulls a share wholesale; this session touched 38 specific files across two folders and left the rest of a much larger share — several hundred other files — untouched.

**[HYPOTHESIS]** A human, choosing specific files by eye, fits this pattern better than a scripted collector would. `T1074.001 (Data Staged: Local Data Staging)` covers the local-copy step; the selective, folder-by-folder pattern is the detail that argues for deliberate human curation over blind automated scraping, whatever that curation turns out to mean about intent.

### 3.2 Ruling out compromise

**[PIVOT]** The Windows Security log for `AVL-LT-2291` showed a single interactive logon spanning the whole window.

```text
Event ID 4624 — An account was successfully logged on
  Subject: N/A
  New Logon:
    Account Name: pchandrasekhar
    Logon Type: 2 (Interactive)
    Workstation Name: AVL-LT-2291
    Logon Time: 2026-09-09T08:54:02Z
```

Logon Type 2 — a console logon, not 10 (RemoteInteractive/RDP) and not 3 (Network) — meant whoever this was sat down at the physical machine. Averlyne's badge system corroborated it: Priya swiped into the office at 08:52, with no matching out-swipe logged until 17:41 that day. No VPN session for her account appeared anywhere in the window. No second concurrent identity session showed up on any other host.

> **Hypothesis Board — after ruling out a stolen session**
> 1. **Compromised account / malware-driven automated collection** — ruled out. A single, badge-
>    corroborated interactive logon (`4624`, Logon Type 2) at the physical workstation covers the
>    entire staging-and-upload window; no scripting host, no second session, no remote-access
>    protocol appears anywhere in it.
> 2. **Approved business use — a sanctioned client hand-off migration** — still live, unconfirmed.
> 3. **Personal-file backup ahead of a known laptop refresh, with confidential files swept up
>    incidentally** — still live.
> 4. **Deliberate exfiltration of client models by the account holder herself** — still live, no
>    motive evidence yet either way.
> **Current confidence:** Medium, rising. This is confirmed to be Priya, at her own machine,
> deliberately selecting files. What remains open is entirely about why.

## 4. Dead end: the client hand-off that wasn't on the books

**[HYPOTHESIS]** Before touching Owen at all, Reyna checked whether this could be sanctioned business use no one had told the SOC about — the theory that would close this fastest and cleanest.

> **Dead End**
> 20 minutes went into checking Hypothesis 2 — that this was an approved, if informally
> executed, hand-off of modeling files to a client engagement that legitimately needed them
> outside Averlyne's own systems. A search of the practice's project-tracking system for any
> active engagement involving the `Meridian Casualty` client, and for any change ticket
> authorizing external file transfer for that account, turned up nothing. Meridian's engagement
> record showed no scheduled deliverable due that week, and no communication thread mentioning an
> external transfer of any kind. If this is business use, nobody wrote it down anywhere Reyna could
> find it.

**Confidence: Medium, rising** — narrowing which theory is plausible, even by elimination, still counts as forward motion.

## 5. The phone call that was supposed to be routine

**[PIVOT]** `large-outbound-data-transfer.md` requires a manager-notification step before a case involving classified client data goes further — not to ask permission to investigate, but to confirm whether the manager independently knows of a business reason for the transfer. Reyna called Owen Faraday, the casualty-reserving practice lead and Priya's direct manager, with a narrow, deliberately neutral question: is there a project reason Priya would need to move client modeling files to a personal account this week?

Owen said no — and then, unprompted, said considerably more than the question asked for. Priya had been placed on a documented performance improvement plan two weeks earlier, over communication and timeliness issues on client deliverables. More than that: the practice was in the middle of a headcount reduction that hadn't been announced yet, expected to be finalized in about three weeks, and Priya's role was one of the ones under discussion. Owen's specific words, paraphrased in Reyna's case notes: "Please don't let this get back to her before we've had that conversation properly — this is going to look exactly like what it probably is."

**[ANALYST]** Owen's statement is not documentation. It's one manager's own worried read of a situation he's also inside of, delivered on a call that was supposed to be about something else entirely. `20-data-exfiltration-master-playbook.md`'s Validation step calls for corroborating an informal signal against an independent source before it counts for anything — the right next step wasn't to take Owen's word as fact, but to ask HR whether any of it was actually on record. Averlyne's HR business partner for the practice, Denise Okoye, would confirm only the fact of a documented conversation, not its contents or status, citing personnel-privacy policy: "There is an active, documented performance conversation on file for this employee." No mention of the reduction, which HR treated as a separate, unconfirmed matter Denise wasn't willing to speak to at all.

> **Evidence Note**
> The HR corroboration here is real but deliberately thin: a documented-PIP confirmation from HR
> is a stronger fact than Owen's own recollection alone, but it is not the reduction-in-force
> confirmation, and HR would not confirm or deny that second, larger claim at all. The investigation
> has one HR-verified fact (a PIP exists) and one HR-unverified claim (a layoff is coming) sitting
> next to each other, and the case cannot treat them as equally solid.

> **Hypothesis Board — after the manager call**
> 1. **Approved business use** — ruled out. No matching engagement or transfer authorization
>    exists anywhere in the project-tracking system.
> 2. **Compromised account** — ruled out. One badge-corroborated interactive logon covers the
>    whole window; no remote session, no second identity, anywhere in it.
> 3. **Personal-file backup, confidential files swept up incidentally** — weakened, but not ruled
>    out. It doesn't explain why 22 real client-model files specifically, rather than the 9 obviously
>    personal ones, made up most of the transfer's substance.
> 4. **Deliberate exfiltration ahead of an anticipated, not-yet-announced termination** — supported.
>    A documented performance action is now confirmed independently of Owen's own account, and it
>    lands in the same two-week window as this transfer.
> **Current confidence:** Medium-High, rising.

## 6. Additional evidence: not a one-off

**[PIVOT]** With a live motive-context hypothesis on the board, Reyna went back to the CASB log for Priya's full 90-day history against personal-cloud destinations — a query nothing before this point had justified running.

```sql
SELECT ts, dst_account_id, bytes_out
FROM proxy_logs
WHERE user = 'pchandrasekhar@averlyne.example'
  AND dst_category = 'Personal Cloud Storage'
  AND ts BETWEEN '2026-06-12T00:00:00Z' AND '2026-09-09T15:00:00Z'
ORDER BY ts;
```

One prior event: 2026-08-19, 640 MB to the same personal Google account, entirely under `EXFIL-OUT-01`'s 3 GB threshold and never flagged. Content-inspection records for that date, pulled separately, showed 4 files, all tagged Internal — Unclassified, no Confidential matches. A smaller, cleaner transfer, three weeks before this one, to the same destination — either a habit that had already started before anything else in this case began, or the first, smaller test of exactly the same channel.

**Confidence: Medium-High.** Two independent facts now point the same direction: a documented HR action inside the same window, and a prior, smaller instance of the identical exfil channel that predates it. Neither one alone would justify this confidence level; together they do.

## 7. The ticket that beat the alert to the punch

**[PIVOT]** Closing this out meant checking Averlyne's IT self-service ticketing system for anything Priya herself might have filed — the last log source in the case, and the one that changed its shape.

```text
Ticket AVL-IT-88213
Submitted: 2026-09-09T11:58:00Z
Submitted by: pchandrasekhar@averlyne.example
Category: Access request — Web filtering exception
Status: Pending Approval
Summary: "Requesting temporary allow-list for personal Google Drive access.
My laptop (AVL-LT-2291) is scheduled for refresh next Monday (9/14) per the
asset calendar and I need to back up personal files — photos, tax stuff, an
old resume draft — before it gets wiped. Will ask for the exception to be
removed once the new laptop is set up."
```

**[ANALYST]** That ticket was filed at 11:58 — 21 minutes before the file-staging window began on the share, and nearly three hours before the CASB alert fired. It wasn't a response to being caught; nobody at Averlyne had contacted Priya about anything yet when she submitted it. A check of the asset-management system confirmed the one independently verifiable claim in it: workstation `AVL-LT-2291` genuinely was on the refresh calendar for 2026-09-14, five days out, scheduled well before this week.

The ticket was still sitting in Pending Approval status when the transfer happened — nobody at IT had granted the exception yet, which meant Priya either found the upload page still reachable through some other gap in the web-filtering policy, or the block that ticket was meant to bypass wasn't actually enforced for her role in the first place. Either way, she didn't wait for approval.

> **Blind Spot**
> Nothing in Averlyne's available logs can establish why the upload succeeded before the ticket
> she filed for it was approved — whether that's a policy gap the SOC didn't know about, or a
> deliberate workaround. Fixing that gap is a real action item; it isn't evidence about intent
> either way, and this case does not treat it as either.

**[HYPOTHESIS]** The ticket's stated justification — personal photos, tax documents, an old resume — matches the 9 untagged files in the manifest almost exactly. It does not explain the other 22. If Priya's account of her own intent is "I was backing up my personal stuff before a scheduled wipe," the manifest doesn't fully agree with her: most of what actually went up wasn't personal at all. That mismatch is the fact this case can't resolve. A genuine, ordinary personal backup that carelessly swept a mapped drive's folder contents along with a desktop full of personal files is a completely plausible way to end up with this exact manifest, filed under a completely true refresh date. A premeditated exfiltration using an honest, independently-verifiable errand as cover is also a completely plausible way to end up with the same manifest, filed under the same true refresh date. Nothing available discriminates between those two readings.

**Confidence: Medium, falling** — down from Medium-High. The self-filed ticket, corroborated by an independent asset record, is real, and it materially weakens the clean "premeditated theft with a fabricated pretext" reading the manager's call had been pushing this case toward. It does not clear her. The classification mismatch between what she said she needed and what she actually took keeps the exfiltration hypothesis alive at the same time.

> **Analyst's Gut Check**
> A self-filed ticket that predates your alert is a stronger fact than almost anything you'll hear
> on a phone call, precisely because the person filing it had no idea you'd ever see it. Treat it
> that way — weigh it as independent evidence, not as a suspect's cover story you're obligated to
> disbelieve just because the timing is inconvenient for the theory you were building.

## 8. Escalation, decision, and closure

### 8.1 Containment without confrontation

**[ESCALATION]** By late afternoon, Reyna had enough to act on the exposure without needing to resolve intent first — `20-data-exfiltration-master-playbook.md`'s own containment guidance treats those as separable questions. Steps taken:

- The classified-data exposure was scoped and documented: 22 real client casualty-reserve files, one external personal account, no evidence yet of further redistribution from that account.
- Priya's account was not suspended, and she was not confronted or informed that a review was underway — per the practice lead's own request and standard guidance for cases that intersect an active, undisclosed HR process, confrontation before HR and Legal align on timing risks tipping off an employee mid-process for no investigative gain.
- The web-filtering gap that let the upload through before her own ticket was even approved was flagged to IT as a policy defect, independent of this case's outcome.
- Legal and HR were looped in jointly, given confirmed movement of classified client data to a destination outside Averlyne's control, to assess client-notification obligations under the Meridian engagement's own data-handling terms.

> **Manager's Call**
> Owen's off-script comment about the pending reduction is the kind of thing a manager should
> not have said yet, and now that it's on record in a case file, someone above Reyna has to decide
> what obligation that creates — toward Priya, toward Owen, and toward whatever HR process is
> still three weeks from finalized. Reyna's own note of it stands regardless; what happens to that
> note, and whether Legal needs to preserve the personal Google account before any of this
> reaches Priya, is a call for Legal and the security manager, not the analyst who happened to be
> on the phone when it was said. The SOC Manager's Operating Handbook, Part 27 — Legal, HR &
> Compliance Interfaces is the doctrine for sequencing that against an unresolved HR process.

### 8.2 Disposition

**[ESCALATION]** Closed as **Insufficient Evidence**. The technical facts are settled and not in dispute: a real, human-driven, selective transfer of 22 classified client files to a personal cloud account, by the account's legitimate owner, at her own machine, following a smaller instance of the same channel three weeks earlier. What those facts add up to is not settled. A documented HR action inside the same window, and a self-filed, independently-verified, mundane justification predating any SOC contact, point in opposite directions on the one question that actually determines disposition — was this negligent carelessness during an honest personal errand, or premeditated theft using that errand as cover — and no available log source breaks that tie.

**Confidence at close: Medium, unresolved.**

> **What Would Change My Mind**
> A second transfer from this account to any personal destination after this date — especially one
> that recurs once the reduction discussion Owen described is actually finalized — would tip this
> firmly toward deliberate exfiltration. A completed asset-refresh event on 2026-09-14 with the
> exception request formally approved beforehand, and no further personal-cloud activity after
> that date, would tip it the other way, toward an honest, if careless, personal backup. Neither
> has happened yet as of this case's close; both are checkable, dated, and specific, which is why
> this closes as Insufficient Evidence rather than a guess dressed up as a finding.

## 9. Lesson learned

**[LESSON LEARNED]** The failure mode this case teaches isn't a detection gap — `large-outbound-data-transfer.md`'s threshold rule worked exactly as designed, and the DLP content-inspection tagging did its job. The failure mode is procedural: an informal, off-the-record HR signal volunteered mid-call carries real investigative weight, and it is genuinely hard, in the moment, not to let it do more work than it's earned. `20-data-exfiltration-master-playbook.md`'s own Validation step exists precisely to stop a case from crossing that line, by requiring at least two independent corroborating data points before committing to a verdict — and this case shows that even followed correctly, that discipline doesn't guarantee resolution. It guarantees the case is honest about what it doesn't know instead of quietly rounding an unverified manager comment up to a confirmed motive. The generalizable fix isn't a new query or a new alert threshold; it's a standing discipline for exactly this shape of case — when a self-reported, independently verifiable justification surfaces after a hypothesis has already gained ground, re-run the manifest against that justification specifically, rather than filing it as either "cleared" or "cover story" on instinct. This one didn't fully match either way, and saying so plainly is the actual finding.

---

**Cross-references:** SOC Playbook Handbook `playbooks/19-insider/large-download.md`, `playbooks/14-network/large-outbound-data-transfer.md`, `playbooks/20-data-exfiltration-master-playbook.md`; SOC Manager's Operating Handbook, Part 27 — Legal, HR & Compliance Interfaces.
