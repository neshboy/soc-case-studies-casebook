---
title: "CB-05 — The Ransomware Precursor That Looked Like a Failed Backup"
case_id: "CB-05"
category: "Endpoint"
disposition: "True Positive"
outcome_flavor: "Subtle"
confidence_at_close: "High"
entry_point: "helpdesk-ticket"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook shadow-copy-vss-deletion.md", "SOC Playbook mass-file-modification-ransomware-adjacent.md", "SOC Playbook 21-ransomware-master-playbook.md", "DEH Part 45", "DEH Part 11", "SOC Manager's Operating Handbook Part 25"]
---

# CB-05 — The Ransomware Precursor That Looked Like a Failed Backup

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Thornfield Logistics," its staff, and every host, account, and IP address named below are
invented; no real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

Most ransomware case studies start at the moment encryption is discovered, because that's the moment that produces a dramatic artifact — a ransom note, a locked desktop, a help desk phone line lighting up. This case starts six days earlier, at a routine backup failure ticket that nobody thought to treat as a security question, because that is where the actual containment window lives. Detection Engineering Handbook V2 Part 45 — Ransomware Detection Model already builds the kill-chain model and the shadow-copy detection logic this case leans on (`DET-45-01`, `DET-45-02`); this case does not re-derive any of that. What it narrates instead is the specific, mundane failure mode that lets a real precursor sit unexamined for most of a week: a helpdesk ticket that pattern-matches to "routine backup housekeeping" closes on sight, and nothing in the SOC's workflow forces a second look until an unrelated ticket happens to land on the same analyst's desk.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-05` |
| Category | Endpoint |
| Disposition | True Positive |
| Outcome flavor | Subtle |
| Confidence at close | High, settled |
| Entry point | Helpdesk ticket, not flagged security-relevant at intake |
| Primary log sources | EDR/Sysmon process-creation telemetry, Veeam backup job history, Windows Security event log (logons, service state changes), VPN/Entra sign-in log, EDR file-modification telemetry, SMB admin-share connection log |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `shadow-copy-vss-deletion.md`, `mass-file-modification-ransomware-adjacent.md`, `21-ransomware-master-playbook.md`; DEH V2 Part 45 (cross-referenced, not re-derived), Part 11 |
| All times | UTC |

## 1. The ticket nobody flagged

**[ANALYST]** On the morning of 11 August, Thornfield Logistics' backup administrator opened helpdesk ticket HD-88214: FS02's nightly Veeam job had failed overnight with a Volume Shadow Copy Service error instead of completing its usual full backup. The Veeam console's own error text named the failure plainly:

```text
Job: "FS02 - Nightly File Server Backup"
Start time: 2026-08-11 03:00:14 UTC
Status: Failed
Error: VSS snapshot creation failed for volume D:\ - no shadow copy present
Details: Unable to create a shadow copy of one or more volumes.
```

Thornfield's backup-agent alerting is wired to forward a copy of every failed-job notice to the SOC queue, which is why this ticket ever crossed a security analyst's screen at all — not because anything about it looked like an attack. The on-call Tier 1 analyst who triaged it that morning read "VSS snapshot creation failed," recognized the shape immediately, and closed the SOC-side copy of the ticket as Expected Activity within four minutes of opening it, with a one-line note: "Known VSS contention issue, backup team already engaged." No process-creation query ran. No parent-process check happened. The disposition was a pattern match against a familiar noise category — Veeam's own snapshot housekeeping trips `vssadmin.exe` constantly on a normal night — not an evidenced conclusion.

> **False Lead**
> The evidence that looked routine was the error message itself. A failed VSS snapshot is Veeam's single most common self-inflicted failure mode — a locked file, a low-disk-space condition, contention with another snapshot-based tool — and Thornfield's SOC had closed dozens of tickets with that exact error text over the prior year, all of them benign. That base rate is real. It is also exactly why nobody checked whether *this* failure had the same cause as the others, rather than just the same symptom.

Confidence at this point was never actually assessed, because the ticket was never treated as a security question in the first place. If it had been, the honest label would have been Low — one host, one failed job, one error string that fits a known benign pattern almost perfectly.

## 2. A second ticket, six days later

**[ANALYST]** On 17 August, an unrelated-looking ticket landed in the general IT queue: HD-88301, filed by a warehouse operations supervisor, reporting that a handful of files on the shared drive "won't open" and show "a weird ending" in the filename that wasn't there before. The ticket named the share path — `\\FS02\Shared\WarehouseOps\` — and nothing else; no mention of backups, no mention of security, filed as a routine file-access problem.

The analyst working the evening shift that day had a standing habit, not a formal rule: at shift handoff, skim any ticket tagged with a file-server hostname against the prior week's closed tickets for the same host, on the theory that file servers rarely generate two unrelated problems in the same week. HD-88214 and HD-88301 both named FS02, six days apart. That was the entire basis for reopening a case that a colleague had already closed as benign — not a new alert, not a new detection firing, just one analyst's own pattern recognition connecting two tickets that had individually triaged as low priority.

**[ANALYST]** The questions worth asking before touching a second log source: did the VSS failure on 11 August and the odd file extensions reported on 17 August happen to the same volume, and is a six-day gap between "backup failed" and "files look wrong" consistent with one continuous incident, or is that just coincidence dressed up by shared hostname? Neither question could be answered from the ticket text alone. Confidence at this point: Low. Two tickets sharing a host and a calendar week is a thin thread, not evidence of anything specific yet.

## 3. Pivot: from two helpdesk tickets to process-creation telemetry

**[PIVOT]** The natural next log source, given a VSS failure at a specific timestamp, is process-creation telemetry for FS02 around 03:00 UTC on 11 August — the exact mechanic Part 45 §6 documents: there is no dedicated Windows event for "a shadow copy was deleted." VSS deletion is a side effect of a command execution, not a first-class logged event in its own right.

> **Evidence Note**
> Detection for this entire category depends on process-creation logging — Sysmon Event ID 1 (Process Create), or Event ID 4688 (A new process has been created) if command-line auditing is enabled via Group Policy, which it was on Thornfield's server tier — capturing the literal command line of `vssadmin.exe`, `wmic.exe`, or `Diskshadow.exe`. Confirmed in this case; DEH Part 45 §6 flags this as a fleet-wide gap where it isn't, and this investigation would have produced nothing at all if FS02's command-line auditing had been off, the same as any other host in that condition.

### 3.1 The too-broad query

**[ANALYST]** The analyst's first pull, run against the EDR console before narrowing anything, was every `vssadmin.exe` invocation fleet-wide over the prior 30 days:

```kql
// too broad — see next query
DeviceProcessEvents
| where FileName =~ "vssadmin.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

That returned 2,214 rows across the file-server and backup tiers — Veeam's own housekeeping, exactly as the Tier 1 analyst had assumed six days earlier, drowning out anything specific to FS02 in a sea of legitimate snapshot creation and pruning.

### 3.2 Narrowing to FS02's destructive verb

**[HYPOTHESIS]** The narrower question: on FS02 specifically, in a window around the 03:00 UTC failure, was there a *destructive* VSS command — `delete`, not `create` or `resize` — and if so, what process actually issued it. This is closer to the raw shape of `DET-45-01` than its tuned production form; the analyst was improvising the idea, not running the maintained rule, which requires an allowlist of backup-agent parent processes the analyst built by hand for this one host rather than pulling from the standing exception list.

```kql
DeviceProcessEvents
| where DeviceName == "FS02"
| where Timestamp between (datetime(2026-08-11T02:45:00Z) .. datetime(2026-08-11T03:15:00Z))
| where FileName in~ ("vssadmin.exe", "wmic.exe", "diskshadow.exe")
| where ProcessCommandLine has_any ("delete", "resize")
| project Timestamp, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine
```

One row came back:

```text
Timestamp: 2026-08-11 03:02:41 UTC
InitiatingProcessFileName: cmd.exe
InitiatingProcessAccountName: THORNFIELD\j.abara
ProcessCommandLine: vssadmin.exe delete shadows /all /quiet
```

**[ANALYST]** The Veeam job's own timestamp for its snapshot-creation step was 03:04:02 UTC — one minute and twenty-one seconds *after* this command ran. The backup didn't fail because of ordinary VSS contention. It failed because every shadow copy on the volume had already been deleted, on purpose, two minutes before Veeam ever tried to make one. And the parent process was `cmd.exe` under an interactive account session, not the Veeam agent's own service process — nowhere near the allowlisted parent identities Part 11 §2.2's four-tier lineage model would treat as Expected for this host.

## 4. Hypothesis check: backup housekeeping, an undocumented script, or something else

> **Hypothesis Board — after the process-creation pivot**
> 1. **Veeam's own retention-pruning job, mistaken for something else** — ruled out. The destructive command ran under `cmd.exe`, spawned by an interactive account session, not the Veeam agent process, and it preceded Veeam's own snapshot attempt rather than being part of it.
> 2. **An undocumented IT maintenance or cleanup script, run by a real admin doing real work** — still live. `j.abara` is a Thornfield service-desk engineer with local admin rights on the file-server tier through a nested AD group; running a script here wouldn't be unusual on its face.
> 3. **Malicious shadow-copy deletion staged ahead of encryption** — still live. No direct evidence of file encryption yet at this point in the investigation; this hypothesis rests entirely on the command's shape and timing so far.
> **Current confidence:** Low-Medium. One specific piece of evidence favors "not routine," but nothing yet distinguishes a careless admin from an attacker.

> **Dead End**
> Twenty minutes went into searching Thornfield's change-management system and internal script repository for any scheduled or ad hoc storage-cleanup task touching FS02 around 11 August, on the theory that hypothesis 2 might resolve cleanly with a ticket number. Nothing turned up — no change record, no script in the repository that issues `vssadmin delete shadows`, and the IT scripting team confirmed by direct message that no such script exists in their inventory. Hypothesis 2, at least in its "documented housekeeping nobody logged properly" form, is done.

Confidence: Medium. The routine-cleanup theory is dead in its most likely form, which narrows the live field to two: a careless or malicious insider action on `j.abara`'s own account, or that account being used by someone else.

## 5. Pivot: from the command line to the account behind it

**[PIVOT]** With the destructive command tied to a specific account, the next log source is the sign-in trail for `j.abara` — where that RDP session into FS02 actually originated, and whether it matches how that account normally connects.

```text
Event ID 4624 (An account was successfully logged on)
LogonType: 10 (RemoteInteractive)
Account Name: j.abara
Source Network Address: 198.51.100.118
Workstation Name: WKS-2209
Logon Time: 2026-08-11 02:44:12 UTC
```

`j.abara`'s documented workstation is WKS-1187 (198.51.100.42), which the badge and asset-management records confirm was checked out to that employee and, per building access logs, unoccupied at 02:44 UTC — the employee's badge last scanned out of the building the previous evening. WKS-2209 belonged to a warehouse shift lead's machine on a different subnet, one `j.abara` had no documented reason to be logged into remotely at all, let alone at that hour on a weeknight.

> **Analyst's Gut Check**
> A LogonType 10 (RemoteInteractive) hit from an account's own credentials doesn't mean that account's owner was at the keyboard. Before treating any "the user did this" theory as settled, check whether the source workstation is one that account normally touches — an asset inventory lookup is a thirty-second check that either closes the "insider mistake" hypothesis or keeps it alive for a real reason, not a guess.

**[PIVOT]** A second pull, this time against the VPN/Entra sign-in log for the same account over the prior two weeks, surfaced one more anomaly: a successful VPN authentication for `j.abara` on 8 August — three days before the FS02 incident — from 203.0.113.77, an IP address with no history against that account and no match to any Thornfield-issued remote-access range. The new-device notification email that logon generated had gone out and sat unread in the account owner's inbox; nobody had flagged it, and nothing in Thornfield's VPN policy required a step-up challenge for a first-time device on an already-valid credential.

Confidence: Medium, rising. An unfamiliar RDP source workstation and an unfamiliar external VPN logon three days earlier, on the same account, don't fit "the account owner ran an undocumented script." They fit a compromised credential better — though neither piece of evidence says how the credential was obtained.

> **Blind Spot**
> Nothing in this case's evidence set explains how `j.abara`'s credential ended up usable from 203.0.113.77 in the first place — no phishing-page hit, no prior failed-logon burst, no credential-dumping alert on any host that account had ever touched. DEH Part 45 §4 names exactly this gap: an operator who obtains valid domain credentials from an infostealer log or a criminal marketplace, entirely outside the organization's own telemetry, produces none of the credential-access signals a SOC would otherwise expect to see first. This case cannot resolve initial access, and closing it as contained does not depend on ever resolving it.

## 6. Additional evidence: the file server's "weird extensions"

**[PIVOT]** The warehouse team's original complaint — files that "won't open" and show "a weird ending" — was still unexplained. Pulling EDR file-modification telemetry for `\\FS02\Shared\WarehouseOps\` around the same 03:00 UTC window answered it directly:

```text
Timestamp range: 2026-08-11 03:03:12 - 03:05:49 UTC
Files renamed with .crptx0 extension: 64
Original file types: .xlsx (31), .pdf (18), .docx (9), .csv (6)
Initiating process: (terminated — PID not resolvable in retained telemetry)
```

Sixty-four files, out of roughly 40,000 on that share, had been rewritten and renamed inside a two-minute-and-thirty-seven-second window — starting thirty-one seconds after the shadow-copy deletion, well before the Veeam job's own failed snapshot attempt at 03:04:02 UTC, and still running for another minute and forty-seven seconds after that attempt failed. The process that did it had already terminated by the time anyone looked, and the EDR console's own record of the event carried no parent-process or command-line detail for it, only the file-level consequence.

**[HYPOTHESIS]** This is where the "ransomware precursor" hypothesis stopped resting on timing alone and gained direct, specific supporting evidence: shadow-copy deletion immediately followed by a burst of file rewrites matching an encryption-stage signature — Part 45's §7 framing of the encryption stage as the point past which detection only affects containment speed, not outcome. The open question the evidence couldn't answer was why the run stopped at 64 files instead of the full share. Whether an endpoint-protection heuristic killed the process, the operator paused deliberately after a small test batch, or something else interrupted it, the retained telemetry doesn't say — the process record shows a termination with no cause code attached.

> **Evidence Note**
> Sixty-four files out of roughly 40,000 is a fraction well under one percent of the share. Whatever this specific ransomware tooling's throughput actually was, it did not have time — or was not permitted — to reach the rest of the share in the window this evidence covers. That gap between "encryption started" and "encryption finished" is the entire reason this case is titled a precursor rather than an incident of completed encryption.

Confidence: Medium-High. Two independent sources — process-creation telemetry and file-modification telemetry — now agree on the same host, the same two-minute window, and a sequence (delete shadows, then rewrite files) that matches the ransomware kill chain's documented order rather than either event happening on its own.

## 7. Pivot: backup infrastructure across the fleet

**[PIVOT]** Part 45 §5 names a specific lateral-movement pattern worth checking for in a ransomware context: movement that disproportionately targets backup and hypervisor management infrastructure rather than spreading evenly. FS02 wasn't Thornfield's only backup-relevant host, so the next pivot was SMB admin-share connection logs for `j.abara`'s session across the rest of the file-server and backup tier.

```text
Source: FS02 — same j.abara RDP session identified in §5 (originating from WKS-2209, 198.51.100.118)
02:47:03 UTC — SMB admin-share connect: DC01 (192.0.2.10) — \\DC01\ADMIN$
02:51:36 UTC — process: cmd.exe → nltest.exe /domain_trusts
02:52:14 UTC — process: cmd.exe → net.exe group "Domain Admins" /domain
03:07:55 UTC — SMB admin-share connect: BKP01 (192.0.2.22) — \\BKP01\ADMIN$
03:11:20 UTC — SMB admin-share connect: FS01 (192.0.2.13) — \\FS01\ADMIN$
```

The discovery commands against `DC01` — domain-trust enumeration and a Domain Admins group listing — ran about eleven minutes before the shadow-copy deletion on FS02, and the admin-share connections to `BKP01` (Thornfield's own Veeam server) and `FS01` (a second file server) followed within nine minutes after it. Both of those hosts' own service-state logs showed the same pattern once pulled:

```text
Event ID 7036 (The service entered the running/stopped state)
Host: BKP01
Service: Veeam Backup Service
State change: Stopped
Timestamp: 2026-08-11 03:09:44 UTC
(no corresponding "Running" state change in the following 96 hours)

Host: FS01
Service: Veeam Agent
State change: Stopped
Timestamp: 2026-08-11 03:13:02 UTC
(no corresponding "Running" state change in the following 96 hours)
```

**[HYPOTHESIS]** This is the shape Part 45's `DET-45-02` and its fleet-wide hunt companion, `HUNT-45-02`, are built to catch: a backup-agent service stopping with no matching restart, and — specifically valuable here — the same pattern clustering across more than one host in the same short window rather than appearing as an isolated, explainable maintenance action. A single stopped agent might be a patch cycle; two agents stopped within four minutes of each other, on the two hosts that between them hold Thornfield's entire backup infrastructure, immediately following domain-trust and privileged-group enumeration, is not that.

## 8. Hypothesis board, updated

> **Hypothesis Board — after the backup-infrastructure pivot**
> 1. **Undocumented IT cleanup script** — ruled out (see the Dead End in §4). No record exists anywhere in change management or the script repository.
> 2. **Compromised admin account, but a human doing something unrelated to ransomware** — weakened. This theory has no account for the domain-trust and Domain Admins enumeration, the SMB admin-share connections to both backup hosts, or the two backup-agent services stopping within minutes of each other on hosts `j.abara`'s ordinary job function never touches.
> 3. **Ransomware precursor via a compromised valid account** — supported. Credential access (unexplained, per the Blind Spot in §5), discovery (domain-trust and privileged-group enumeration), backup/shadow-copy tampering, a partial encryption-stage file-rewrite burst, and lateral movement onto the backup infrastructure specifically all appear in this investigation, in the general shape of Part 45's kill-chain model, inside a single 26-minute window.
> **Current confidence:** Medium-High, rising.

**[HYPOTHESIS]** What would still move this to High: direct evidence that the same account or session touched a third host, or confirmation from the account owner that the credential wasn't in their own possession during the window — closing the gap the Blind Spot in §5 leaves open. Both arrived within the hour: `j.abara`, contacted directly, confirmed they had never seen the 8 August new-device VPN notification and had been asleep, per a phone location consistent with that, at 03:00 UTC on 11 August. No third host turned up in the SMB connection log — the confirmed footprint stayed at three: FS02, BKP01, and FS01.

## 9. Containment, sweep, and closure inside one hour

**[ESCALATION]** At Medium-High and rising, with direct multi-source evidence across three hosts and no unresolved contradiction, the analyst escalated to the incident commander as a confirmed ransomware precursor rather than a suspected one, invoking SOC Playbook Handbook's `21-ransomware-master-playbook.md` for the containment sequence: network-isolate FS02, BKP01, and FS01 immediately; disable `j.abara`'s account and force a credential reset for every account in the nested admin group that grants file-server-tier access; preserve forensic images of all three hosts before any remediation touches them; and open a fleet-wide sweep using Part 45's `DET-45-03` composite kill-chain score plus its `HUNT-45-01` (shadow-copy/snapshot enumeration without a following deletion) and `HUNT-45-02` (fleet-wide backup-agent stop clustering) hunt queries to check whether any other host showed early-stage tampering that hadn't reached the deletion or encryption stage yet.

> **Manager's Call**
> Whether to isolate only the three confirmed hosts or preemptively take the entire file-server tier offline pending the fleet-wide sweep's results is the incident commander's call, not the analyst's — a broader shutdown contains risk faster but stops legitimate warehouse and finance operations that depend on shares this investigation hadn't implicated. The SOC Manager's Operating Handbook, Part 25 — Risk Acceptance & Manager Decision-Making Under Uncertainty covers that tradeoff in full; this case does not re-derive it, only shows the point at which the analyst's evidence-gathering job ends and the manager's risk decision begins. Thornfield's incident commander chose targeted isolation, pending the sweep, and held the broader shutdown in reserve.

The `HUNT-45-01`/`HUNT-45-02` sweep, run against the remaining 40-some hosts in the file-server and backup tier over the following six hours, returned clean: no other host showed shadow-copy enumeration, no other backup-agent service stopped without a matching restart, and no other account showed the same VPN/RDP anomaly pattern. The confirmed blast radius held at three hosts and one compromised account — the same result that closed the case.

Closed as True Positive. Confidence: High, settled. The evidence chain — a destructive VSS command from a non-baseline parent process, an account authenticating from workstations and networks it had never used before, domain-trust and privileged-group enumeration immediately preceding the deletion, backup-agent services stopped in a tight cluster across the two hosts that mattered most for that goal, and a file-rewrite burst matching an encryption-stage signature — spans five independent log sources with no point of contradiction between any of them.

> **What Would Change My Mind**
> A `HUNT-45-01`-style sweep surfacing a fourth host with shadow-copy enumeration and no following deletion, or any host showing shadow copies gone with zero corresponding process-creation event at all — the WMI-method-only deletion path DET-45-01 cannot see, per Part 45 §6.1 — would mean this operator's tooling wasn't limited to what got caught here, and the confirmed three-host blast radius would need to widen. The fleet-wide sweep above found neither. That result is what makes High, settled, defensible rather than a guess dressed up as confidence.

## 10. Lesson learned

**[LESSON LEARNED]** The failure this case actually teaches isn't "the SOC ignored a ransomware indicator" — it's that a single symptom (a VSS error) legitimately maps to both a benign, high-frequency cause and a rare, severe one, and the four minutes it takes to close a ticket on pattern match alone doesn't distinguish between them. `DET-45-01`'s tuned form exists precisely so that distinction doesn't depend on an analyst's gut: destructive verb plus parent process not on the backup-agent allowlist, checked automatically, would have flagged this ticket on 11 August, not 17 August. The generalizable fix isn't "be more suspicious of backup tickets" — suspicion doesn't scale, and most of those tickets really are benign. It's routing every backup-agent failure notice through the actual parent-process check before a human ever reads the error text, the same lineage-classification discipline Part 11 §2.2 builds for every other process pair this book's cases touch.

The second, quieter lesson: nothing in Thornfield's tooling connected HD-88214 and HD-88301. They shared a hostname and a calendar week, and the only reason that connection got made was one analyst's personal habit of skimming file-server-tagged tickets at shift handoff — a real practice, but an institutionally fragile one, since it depends entirely on that specific person working that specific shift. A ticketing system that surfaces "second ticket referencing a host with an open or recently closed security-relevant ticket in the past N days" as its own low-effort correlation would have made this case's entry point a system prompt instead of a habit.

**Cross-references:** SOC Playbook Handbook `shadow-copy-vss-deletion.md`, `mass-file-modification-ransomware-adjacent.md`, `21-ransomware-master-playbook.md`; Detection Engineering Handbook V2 Part 45 — Ransomware Detection Model (`DET-45-01`, `DET-45-02`, `DET-45-03`, `HUNT-45-01`, `HUNT-45-02`, cross-referenced, not re-derived), Part 11 — Endpoint Detection Engineering (§2.2 lineage classification); SOC Manager's Operating Handbook Part 25 — Risk Acceptance & Manager Decision-Making Under Uncertainty.
