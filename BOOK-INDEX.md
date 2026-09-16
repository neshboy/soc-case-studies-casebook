# The SOC Case Studies Casebook

**BOOK-INDEX.md — canonical case list for the architecture pass.**
**Status:** Proposed architecture, not yet drafted. Part of the NESHBOY SOC Professional Library, sitting alongside the SOC Playbook Handbook, the Detection Engineering Handbook V2, and the SOC Manager's Operating Handbook.

## What this book is

A dedicated collection of full, end-to-end synthetic SOC investigation narratives — nothing else. Every other volume in the series either dissects one alert at a time (SOC Playbook Handbook's `*-case-studies.md` companions: one alert, one evidence table, one disposition, roughly 600–900 words) or compresses a multi-stage attack chain into a technical model written in the detection engineer's voice (Detection Engineering Handbook V2 Parts 44–48: cross-plane correlation logic with a worked example folded into one subsection). Neither reads like an actual investigation notebook: alert, first look, the questions an analyst asks before touching a second data source, the pivot that pays off, the one that doesn't, a stated hypothesis that loses, a confidence level that moves as evidence comes in, and a decision. This book is that notebook, nineteen times, each case substantial enough (3,000–6,000 words) to earn its own file and its own place in the series' cross-reference graph.

**What this book does not do:** it does not re-derive detection logic, log-field semantics, MITRE mappings, or query syntax already owned by the SOC Playbook Handbook or the Detection Engineering Handbook V2 — every technical mechanic a case leans on is cross-referenced by ID and title, never rebuilt from scratch. It does not make people-and-process decisions the way the SOC Manager's Operating Handbook's Management Autopsy boxes do — where a case reaches a staffing, legal, or risk-acceptance decision point, it hands off to that book's doctrine via the Manager's Call callout (`STYLE-GUIDE.md` §6.7) rather than adjudicating the decision itself.

## Content model

Six content tags (`STYLE-GUIDE.md` §11), built around **stage of investigation** rather than reader role, since this book has one narrative voice throughout:

`[CONCEPT]` — grounding note, cross-referenced not re-derived · `[ANALYST]` — reasoning at a triage step · `[PIVOT]` — the jump from one log source/entity to another, with the reason stated · `[HYPOTHESIS]` — a single named, falsifiable theory · `[ESCALATION]` — a decision actually made, with severity and authority · `[LESSON LEARNED]` — the closing retrospective, generalized beyond the one case.

Eight callout boxes (`STYLE-GUIDE.md` §6): **Hypothesis Board** (periodic scoreboard of every live theory and its status — the structural fix for "cases must consider multiple hypotheses"), **Dead End** (a pivot that consumed time and paid off nothing), **Analyst's Gut Check** (a tactical aside), **Evidence Note** (how a real log source actually behaves here — lag, retention, timezone), **Blind Spot** (a named, specific gap the investigation could not see even at closure), **False Lead** (one specific piece of evidence that looked bad and wasn't), **Manager's Call** (the decision point that hands off to the SOC Manager's Operating Handbook), and **What Would Change My Mind** (the falsifiability statement, mandatory below High confidence).

Three case-construction classes (`STYLE-GUIDE.md` §8), disclosed in the mandatory first line of every case: `SYNTHETIC — INVENTED`, `SYNTHETIC — RECONSTRUCTED FROM PUBLIC TTP PATTERNS`, `SYNTHETIC — COMPOSITE ACROSS SERIES`. No case depicts a real organization, breach, or person; the disclosure line is non-negotiable and comes before any other prose.

## Production model

Every case carries the same YAML front matter mechanic as both companion volumes (`author`, `reviewer` — mandatory, different person/agent — `status`, `last_validated`, `depends_on`), plus this book's own fields: `case_id`, `category`, `disposition`, `outcome_flavor`, `confidence_at_close`, `entry_point`, `construction_class`. Case IDs (`CB-##`) are permanent and position-independent, assigned once at creation, in this book's own namespace — distinct from the SOC Manager's Operating Handbook's `CASE-####` ledger and the Detection Engineering Handbook V2's `DET-####`/`HUNT-####` ledgers, so no cross-volume ID collision is possible. `status` for this book's "tested" gate specifically means: every cited playbook/detection/part ID has been checked against the *current* `BOOK-INDEX.md` of its home volume, not cited from memory.

## The hardest design call: keeping nineteen cases from being one template with the nouns changed

`STYLE-GUIDE.md` §2 states the mechanism; this index is where it's enforced with a number, per case, so drift is visible without reading all nineteen files back to back. Fixing the natural investigative flow — alert, observation, pivots, hypotheses, decision — as a literal fixed section list was the single biggest risk to this book reading as one formula wearing different technical costumes. The fix adopted: every case is required to vary independently on **entry point**, **hypothesis count**, and **confidence trajectory** (tracked below), and the beat vocabulary in `STYLE-GUIDE.md` §3 is explicitly a menu, not a checklist — no case is required to use every beat, in the same order, at the same length as its neighbor. The table below is the audit surface for that requirement: if two adjacent rows show the same entry point, the same trajectory shape, and the same category, that's a flag for the architecture pass, not something to discover after nineteen full drafts exist.

---

## Outcome distribution (deliberate, not incidental)

| Outcome flavor | Count | Cases |
|---|---|---|
| Obvious / confirmed True Positive | 7 | CB-01, CB-04, CB-07, CB-11, CB-13, CB-14, CB-15 |
| Subtle True Positive (individually low-signal; the combination is what matters) | 6 | CB-02, CB-05, CB-08, CB-10, CB-12, CB-16 |
| Benign True Positive (the alert was technically correct; it isn't a security incident) | 2 | CB-06, CB-19 |
| Confirmed False Positive | 2 | CB-09, CB-17 |
| Genuinely Inconclusive | 2 | CB-03, CB-18 |

Obvious-TP is deliberately the largest bucket — that's the realistic distribution of what a SOC actually closes once an investigation runs to completion — while the other four flavors are each guaranteed at least two representatives spread across different categories, so no single flavor reads as "the one section's gimmick." The two Inconclusive cases (CB-03, CB-18) close with an explicit **What Would Change My Mind** and a stated Low or Low-Medium confidence, never a manufactured clean resolution.

## Non-duplication check against existing series material

Read before drafting, specifically to avoid re-narrating: SOC Playbook Handbook `25-false-positive-engineering-case-studies.md` (six single-alert FP dispositions: backup-account lockout storm, legacy-RC4 Kerberoasting, SCCM-driven encoded PowerShell, VPN/carrier-NAT impossible travel, RMM mass service install, backup-dedup DNS volume) and `10-identity-ad-account/password-spraying.md`; Detection Engineering Handbook V2 Part 46 — Identity Compromise Model (the DET-46-01 through DET-46-06 hybrid-identity chain and its compressed six-step worked case study, §8 of that part). Where this book's cases touch the same *topic* as one of those (CB-01/password spraying, CB-03/impossible travel on a privileged account, CB-02/the DET-46 hybrid chain), each is deliberately built to a **different outcome or a different evidentiary path** than the source material — CB-03 closes Inconclusive where the Playbook's impossible-travel case closes clean Benign Positive; CB-02 narrates the DET-46 chain from the analyst's chair as a multi-hour investigation with dead ends, where Part 46 §8 compresses it into six sentences. No case reproduces a source case study's specific evidence set, account names, or resolution.

---

## Case Table

*File path pattern:* `C:\Users\User\projects\soc-case-studies-casebook\cases\cbNN-slug.md`

### Section A — Identity

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-01 | The Spray That Almost Worked | `cases\cb01-the-spray-that-almost-worked.md` | True Positive (Obvious) | Low → High, steady climb | Standing SIEM correlation alert (spray threshold) | SOC Playbook IAM-003 (`password-spraying.md`), email inbox-rule and OAuth-consent playbooks; DEH Part 12, Part 17, Part 18 |
| CB-02 | Two Alerts, One Identity | `cases\cb02-two-alerts-one-identity.md` | True Positive (Subtle) | Low/Low → High once joined | Two independently low-priority tickets, connected by one analyst's own pattern recognition, not a rule | DEH Part 46 (`DET-46-01`, `DET-46-02`, `DET-46-03`) — narrated, not re-derived; SOC Playbook IAM-020 (`dcsync.md`) |
| CB-03 | The Global Admin Who Was Actually Just Flying | `cases\cb03-the-global-admin-who-was-actually-just-flying.md` | **Inconclusive** | Medium, oscillating → Low-Medium, unresolved | Standing impossible-travel correlation alert | SOC Playbook impossible-travel (email/cloud) playbooks; DEH Part 12 |

### Section B — Endpoint

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-04 | Encoded, But Not by SCCM | `cases\cb04-encoded-but-not-by-sccm.md` | True Positive (Obvious) | Medium → High, fast | EDR alert on encoded PowerShell | SOC Playbook EP-003/EP-004, `scheduled-task-persistence.md`, `credential-dumping-lsass-access-mimikatz-indicators.md`; DEH Part 10, Part 11 |
| CB-05 | The Ransomware Precursor That Looked Like a Failed Backup | `cases\cb05-the-ransomware-precursor-that-looked-like-a-failed-backup.md` | True Positive (Subtle) | Low (dismissed by Tier 1 as a backup issue) → High | Helpdesk ticket, not flagged security-relevant at intake | SOC Playbook `shadow-copy-vss-deletion.md`, `mass-file-modification-ransomware-adjacent.md`, `21-ransomware-master-playbook.md`; DEH Part 45 (cross-referenced, not re-derived), Part 11 |
| CB-06 | The Miner That Wasn't a Miner | `cases\cb06-the-miner-that-wasnt-a-miner.md` | **Benign True Positive** | High throughout (the *shape* of the finding changes, not the confidence) | Standing alert (unsigned binary + high CPU + outbound beacon-shaped traffic) | SOC Playbook `unsigned-binary-execution.md`, `beaconing.md`; hands off to Insider/HR boundary (Manager's Call → SOC Manager's Operating Handbook Part 27) |

### Section C — Network

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-07 | Slow Beacon, Fast Conclusion | `cases\cb07-slow-beacon-fast-conclusion.md` | True Positive (Obvious) | Medium → High | Standing DNS/beaconing detection | SOC Playbook `beaconing.md`, `c2-communication.md`, `dns-tunnelling.md`; DEH Part 14, Part 15 |
| CB-08 | The VPN Login From a Country We Don't Do Business In | `cases\cb08-the-vpn-login-from-a-country-we-dont-do-business-in.md` | True Positive (Subtle) | Low (looks like a routine geo-anomaly FP) → High once network + identity + endpoint join | Standing alert, deliberately shaped to read like it will resolve benign | SOC Playbook `lateral-movement-network-view.md`, `internal-network-reconnaissance.md`, `rdp-scanning.md`; DEH Part 14, Part 44 |
| CB-09 | The Port Scan That Was Us | `cases\cb09-the-port-scan-that-was-us.md` | **False Positive** | High trigger → drops to zero once traced | Standing scan-detection alert | SOC Playbook `port-scanning.md`, `smb-scanning.md`; SOC Manager's Operating Handbook Part 26 — Cross-Team Politics & Stakeholder Alignment |

### Section D — Web / Email

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-10 | Two Rules, One Wire Transfer | `cases\cb10-two-rules-one-wire-transfer.md` | True Positive (Subtle) | Low (routine automated "new inbox rule" notice) → High (BEC/wire-fraud attempt) | Low-priority automated notice, not treated as a "real" alert at first glance | SOC Playbook `suspicious-inbox-rule-creation.md`, `oauth-app-abuse-consent-phishing.md`, `bec.md`, `vendor-impersonation.md`; DEH Part 17, Part 18 |
| CB-11 | The Web Shell Behind the Marketing Site | `cases\cb11-the-web-shell-behind-the-marketing-site.md` | True Positive (Obvious) | Medium → High | WAF alert (SQLi pattern) | SOC Playbook `sql-injection.md`, `web-shell-detection.md`, `rce.md`; DEH Part 16, Part 47 (cross-referenced) |
| CB-12 | The QR Code in the Parking Garage Flyer | `cases\cb12-the-qr-code-in-the-parking-garage-flyer.md` | True Positive (Subtle) | Near-zero (no failed logon, no password entered) → High via device-compliance mismatch | Employee self-report, not a system alert | SOC Playbook `qr-code-phishing.md`, `session-hijacking.md`; DEH Part 17, Part 18 |

### Section E — Cloud

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-13 | New Access Key, Old Habits | `cases\cb13-new-access-key-old-habits.md` | True Positive (Obvious) | Medium → High, fast | CloudTrail anomaly alert (new access-key creation) | SOC Playbook `credential-leakage-keys-in-code-logs.md`, `new-access-key-creation.md`, `privilege-escalation-via-role-policy-chaining.md`, `mass-object-download-from-storage.md`; DEH Part 19 |
| CB-14 | The Agent That Read the Wrong File | `cases\cb14-the-agent-that-read-the-wrong-file.md` | True Positive (Obvious, but explicitly flagged as an immature-telemetry domain) | Medium → High, with an explicit Evidence Note on telemetry completeness | AI platform's own audit-trail alert (unusual tool-call pattern) | SOC Playbook `00-malicious-file-uploaded-into-ai-system.md` (AI master playbook), `indirect-prompt-injection.md`, `agent-tool-abuse.md`, `knowledge-base-poisoning.md`; DEH Part 20, Part 21, Part 48 (cross-referenced) |

### Section F — Insider

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-15 | Two Weeks' Notice | `cases\cb15-two-weeks-notice.md` | True Positive (Obvious) | High throughout — deliberately unambiguous, to contrast with CB-16 | HR-triggered review tied to a resignation, not a technical alert | SOC Playbook `departing-employee-activity.md`, `large-download.md`, `personal-email-transfer-of-company-data.md`, `cloud-storage-upload-of-sensitive-data.md`, `20-data-exfiltration-master-playbook.md`; SOC Manager's Operating Handbook Part 27 |
| CB-16 | The Record That Wasn't Theirs to Look At | `cases\cb16-the-record-that-wasnt-theirs-to-look-at.md` | True Positive (Subtle) | Medium, stays Medium — deliberately non-escalating even once confirmed | Routine proactive quarterly access-review hunt, no alert at all | SOC Playbook `access-outside-job-role-need-to-know.md`, `privileged-access-misuse.md`, `unusual-database-access.md`; SOC Manager's Operating Handbook Part 27, Part 19 |

### Section G — Ambiguous / False-Positive

| ID | Title | File Path | Disposition (flavor) | Confidence trajectory | Entry point | Primary cross-references |
|---|---|---|---|---|---|---|
| CB-17 | The Critical Alert That Was Actually Nothing | `cases\cb17-the-critical-alert-that-was-actually-nothing.md` | **False Positive** | High trigger → zero within the hour | Critical-severity standing alert (privileged group change outside the approved-change window) | SOC Playbook `domain-admin-group-modification.md`; SOC Manager's Operating Handbook Part 25 — Risk Acceptance & Manager Decision-Making Under Uncertainty |
| CB-18 | Everything Pointed the Same Way, Then It Didn't | `cases\cb18-everything-pointed-the-same-way-then-it-didnt.md` | **Inconclusive (flagship)** | Rises to Medium-High → a late piece of evidence knocks it back to Medium, unresolved | Standing large-outbound-transfer alert, compounded by HR context volunteered mid-investigation | SOC Playbook `large-download.md`, `large-outbound-data-transfer.md`, `20-data-exfiltration-master-playbook.md` |
| CB-19 | Suspicious, Legitimate, and Still Worth a Policy Change | `cases\cb19-suspicious-legitimate-and-still-worth-a-policy-change.md` | **Benign True Positive** | High from the first pivot → drops to Benign only at the very last one | Standing high-severity alert (replication-rights activity from an unexpected host) | SOC Playbook `dcsync.md`; SOC Manager's Operating Handbook Part 26 (explicitly echoes `CASE-2602`, "The GuardDuty Slack bot," as the same shadow-tooling failure mode in a different technical guise) |

**Total: 19 cases across 7 categories.**

---

## Appendix Table (proposed, not yet drafted)

| Appendix | Title | Contents |
|---|---|---|
| A1 | Case Construction Class Register | Every case's construction class (§8 of `STYLE-GUIDE.md`), tracked the way `CASE-INVENTORY.md` tracks the SOC Manager's Operating Handbook's cases — created once the first cases move from draft to reviewed. |
| A2 | Cross-Series Citation Index | Every SOC Playbook Handbook playbook ID and Detection Engineering Handbook V2 part/detection ID cited anywhere in this book, reverse-indexed so a maintainer of either source book can see which of this book's cases would break if a cited ID moves. |
| A3 | Confidence-Trajectory Atlas | A one-line trajectory summary for all 19 cases, side by side, as the running audit surface for `STYLE-GUIDE.md` §2 — supersedes the per-section tables above once the book is far enough along that reviewing 19 rows in one place becomes more useful than reviewing them by category. |

**Total: 3 proposed appendix bundles.**
