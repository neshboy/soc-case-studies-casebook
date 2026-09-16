# The SOC Case Studies Casebook — STYLE-GUIDE.md

**Status:** Adopted for the NESHBOY SOC Professional Library, adapted from the Detection Engineering Handbook V2 `STYLE-GUIDE.md` and the SOC Manager's Operating Handbook `STYLE-GUIDE.md` for series consistency.
**Applies to:** every case file, appendix, and figure in this book.
**Audience:** every writer, technical reviewer, and editor working on this book.

## Why this document exists

This is a cross-series brand standard, not a from-scratch style guide. The voice rules, the banned-filler list, and the general mechanic of "six content tags, one fixed callout-box system, a labeled construction-evidence class on every case" are carried over from the two companion volumes' style guides, which themselves exist because V1 of the Detection Engineering Handbook shipped with diagnosed drift — the same callout rendering five different ways across parts, tags appearing bare in one part and bolded in the next. This book adopts the same fixed contract before a single case is drafted, so a reader moving between all three prior NESHBOY volumes and this one recognizes the same mechanics even though the *unit of content* is different: this book's unit is not a part covering a topic, and not a playbook covering one alert — it is one continuous, multi-source investigation narrative, told once, start to finish.

That difference matters enough to state plainly. The SOC Playbook Handbook's `*-case-studies.md` companions each dispose of six single alerts in a page apiece — one alert, one evidence table, one disposition. The Detection Engineering Handbook V2's Part 46–48 "applied compromise models" walk a multi-stage attack chain but stay in the *detection engineer's* voice, cross-referencing detection IDs and compressing the case study itself into a numbered list of six steps. This book does neither. It is written from the analyst's chair, in real time, with the false starts, the wrong hypothesis chased for twenty minutes, the pivot that pays off and the one that doesn't, and a stated confidence level that moves as the evidence comes in — the way an actual investigation notebook reads, not the way a finished incident report summarizes it after the fact. Every technical mechanic a case leans on — what a 4769 means, why RC4 tickets are a Kerberoasting tell, how the DET-46 hybrid-identity join works — is cross-referenced to the playbook or detection-engineering part that owns it, never re-derived. This book owns the *investigation*, not the mechanism.

**"Must"** means a PR gets rejected if it doesn't comply. **"Should"** means deviate only with a reason recorded in the PR description. **"Avoid"** is a strong default a reviewer can override with justification, and a documented override is a guide change, not silent drift.

---

## 1. Voice and Tone

### 1.1 The core rule

Write like the analyst's own notebook, kept honestly, by someone who will have to defend every disposition in a shift handoff. The reader already knows what a SOC is and does not need scene-setting. Every sentence should survive the question: **what did the analyst actually see, ask, check, or decide here?** If a sentence doesn't advance the investigation or the reader's understanding of it, cut it.

Concretely:

- **Show the evidence before the conclusion.** State what the query returned, then what it means — never the reverse.
- **Name the question the analyst is actually asking themselves at each step**, not just the action taken. "Is this one identity or two identities that happen to share a login window?" beats "the analyst investigated further."
- **State confidence as a level, not a feeling.** Use the controlled vocabulary in §7 — "Medium, rising" or "Low, and not moving" — never "pretty sure" or "seems suspicious."
- **Let a hypothesis lose.** A case that only ever considers one theory and confirms it isn't an investigation, it's a press release. Every case must show at least one hypothesis seriously entertained and then weakened or ruled out by a specific piece of evidence (see §3 and the Hypothesis Board callout, §6.1).
- **Prefer active voice with a named actor** — "the analyst," "the on-call engineer," "the SIEM," "the attacker" — over passive constructions that hide who did what or who decided what.
- **Commit to a claim, including an uncomfortable one.** If a case closes with real ambiguity, say so in exactly those terms — "closed as Insufficient Evidence, confidence Low, and here specifically is what would resolve it" — rather than manufacturing false closure for narrative neatness.
- Second person is rare in this book (there's no reader being instructed mid-narrative); first person plural is fine for the book's own framing text (`## Why this case exists` sections). The case body itself is close third person, past tense, from the analyst's point of view.
- It's fine for an investigation to be boring, or for a promising lead to just be nothing. Not every case needs a dramatic reveal.

### 1.2 Banned filler

Identical list and identical test to the Detection Engineering Handbook V2 `STYLE-GUIDE.md` §1.2 and the SOC Manager's Operating Handbook `STYLE-GUIDE.md` §1.2 — not reproduced here to avoid a third copy silently drifting from the other two. **The reviewer's test:** does the phrase carry information, or does it just sound like it does? If it can be deleted with no loss of meaning, cut it. Two additions specific to this book's narrative register:

| Banned pattern (as filler) | Why it's banned here specifically |
|---|---|
| "little did they know" / "what happened next would change everything" | True-crime-podcast framing. This book is a technical notebook, not a thriller. The evidence should carry the tension; the prose should not manufacture it. |
| "the analyst had a bad feeling about this one" | Confidence is a stated level (§7), not a mood. If the analyst is uneasy, name the specific thing driving that — an unexplained field, a source that hasn't reported in, a timeline gap. |

### 1.3 Worked GOOD vs. BAD examples

**Example 1 — narrating a pivot**

> BAD: "The analyst decided to dig deeper and found something concerning in the logs."

> GOOD: "The 4625 events were all `0xC000006A` — bad password, not `0xC0000064` — so this was a validated username list, not a guessed one. That ruled out the 'random internet noise' hypothesis; whoever built this list already knew which accounts existed."

**Example 2 — stating confidence**

> BAD: "This looked pretty bad at this point."

> GOOD: "Confidence: Medium, rising. Two independent sources now agreed on the same account and the same ten-minute window; nothing yet explained *why* that account and not one of the other 40 in the same OU."

**Example 3 — a hypothesis that loses**

> BAD: "It turned out to be nothing after all."

> GOOD: "The 4662 timestamp preceded the OAuth consent grant by eleven minutes, not the ninety seconds DET-46-03's join window assumes for a live, human-driven pivot. That gap was the tell: eleven minutes is long enough for a scheduled task to run, short enough to still fall inside the join. The 'same attacker, same session' hypothesis didn't survive that arithmetic — two automated jobs sharing a service account looked more likely than a human pivoting live."

**Example 4 — honest inconclusion**

> BAD: "Ultimately, more monitoring would be needed to fully resolve this situation."

> GOOD: "Closed as Insufficient Evidence, confidence Low. What would change that: a DLP content-inspection hit on the transferred files (the one log source that never reported), or a second transfer to the same personal endpoint after the account owner was told the account was being reviewed."

### 1.4 Sentence and paragraph mechanics

- Default to active voice; passive only when the actor genuinely doesn't matter (log delivery, background system behavior).
- One claim per sentence where possible. Prefer sentences under ~30 words.
- One beat of the investigation per paragraph — a query, a result, a question, a decision. A paragraph that runs a query, states the result, and draws two conclusions from it should be three short paragraphs.
- Numbers: digits for event IDs, port numbers, timestamps, and any count ≥ 10; spell out one through nine in prose, except inside tables and except counts paired with a unit or identifier (Event ID 4625, a 15-minute window, T1110.003), which always use digits. Same rule as the two companion volumes.
- Contractions are fine and preferred — this book has a spoken, first-person-notebook register, the most informal of the four volumes.
- Timestamps in case bodies always carry an explicit time zone or an explicit statement that all times in the case are normalized to one zone ("all times UTC unless noted") — stated once, in the case metadata block, never re-stated per timestamp.

---

## 2. What Makes a Case Different From the Next One — the Actual Design Problem

This is the section every other convention in this guide exists to protect. Fixing "alert → observation → questions → log sources → query → result → pivot → evidence → decision → escalation → closure" as a literal, fixed prose scaffold and running nineteen cases through it produces nineteen stories that differ only in the nouns — swap "PowerShell" for "OAuth grant" and the shape underneath is identical. That flow is how a *good analyst thinks*, not a table of contents every case must expose in the same order, at the same length, with the same number of stops.

**Every case must vary independently on at least these four axes**, tracked per case in `BOOK-INDEX.md` so drift is visible at a glance rather than discovered on a read-through:

1. **Entry point.** Not every case starts with a SIEM alert firing. A case may open on a helpdesk ticket that wasn't flagged as security-relevant, a resignation-triggered HR review, a routine proactive access-review hunt with no alert at all, an employee's own report ("I scanned something weird"), or a second analyst noticing a pattern across two tickets that individually triaged as low priority. State the entry point explicitly in the case metadata block (§9).
2. **Hypothesis count and outcome.** Some cases genuinely only need two competing theories before one is confirmed; others need four, with two ruled out before the real one surfaces. Do not pad a simple case with manufactured extra hypotheses to hit a quota, and do not compress a genuinely ambiguous case down to one theory for tidiness. The Hypothesis Board callout (§6.1) is where this is made visible structurally.
3. **Confidence trajectory.** Confidence is not always a monotonic climb to High. It can start high and fall (a damning-looking signature that resolves benign only at the very last pivot), stay flat through most of the case and jump once at the end, oscillate before settling, or never settle at all. §7 gives the controlled vocabulary; the *shape* of the trajectory across a case's length is itself a variable to design deliberately, stated in the metadata block so a reader (or an editor auditing the collection for drift) can see the distribution across all cases at once.
4. **Pacing and emphasis.** Not every case distributes its word count evenly across its beats. A case can spend forty percent of its length on one gnarly pivot that took the analyst most of a shift, and two sentences on three other checks that came back clean fast. Let the actual investigation's difficulty shape the prose's shape.

A fifth, softer axis worth varying deliberately: **analyst context** — solo overnight analyst under time pressure, a two-person day-shift review, a threat-hunting team working without any alert at all, a Tier 2 analyst picking up a Tier 1 escalation mid-chain. This is not tracked as a mandatory metadata field, but a reviewer should flag a manuscript where every case reads as the same unnamed analyst in the same unstated shift.

> **What Would Change My Mind**
> The working assumption behind this section is that varying entry point, hypothesis count, confidence trajectory, and pacing is *sufficient* to keep nineteen investigation narratives from reading as one template with the nouns swapped. If an independent editor reads the finished collection back to back and still reports that cases feel interchangeable once the technical domain is abstracted away, that's a signal this section's remedy was necessary but not sufficient, and the fix is a fifth structural axis (most likely varying narrative person/distance, or deliberately breaking the numbered-beat structure entirely for one or two cases) — not more domain variety, which this collection already has in surplus.

---

## 3. The Investigation Beats — a Vocabulary, Not a Template

Case bodies use `##`-numbered sections per §4's heading rules, but the **labels and the count of those sections are chosen per case**, not fixed. The list below is a vocabulary to draw from, not a checklist every case must complete in order:

- Alert / trigger / entry point
- First observation
- Questions the analyst asks before touching a second data source
- Pivot N (numbered, one per distinct log-source jump — a case might have two, might have six)
- Hypothesis check
- Dead end (see the callout, §6.2 — an explicit, named beat when a pivot consumed real time and paid off nothing)
- Additional evidence
- Escalation / handoff
- Decision and closure
- Lesson learned

A case that uses every single one of these, in this order, every time, has failed §2's mandate regardless of how well any individual section is written. A short, sharp case might have five sections total. A sprawling one might have eleven, several of them named things not on this list, because the actual investigation called for a section this list didn't anticipate.

---

## 4. Heading Level Conventions

Locked down for series consistency, identical mechanic to both companion volumes:

| Level | Use for | Example |
|---|---|---|
| `#` (H1) | Case title only, with its permanent case ID. One per file, first line. | `# CB-01 — The Spray That Almost Worked` |
| `##` (H2) | Major beats within the case (see §3). Number sequentially: `## 1. Title`, `## 2. Title`. `## Why this case exists` and `## Case metadata` (§9) are the two mandatory unnumbered exceptions and always come first, in that order, before `## 1.` begins. | `## 4. Pivot: from mailbox audit log to OAuth consent log` |
| `###` (H3) | Subsections within a beat — a specific query and its result, a specific piece of evidence examined in detail. Numbered `### 4.2` under `## 4`, never restarted as an independent `### 1`. | `### 4.2 The consent-grant timestamp` |
| `####` (H4) | Rare; only for a structured sub-breakdown inside a long H3 (e.g., "Fields checked," "What this ruled out"). Do not nest deeper. | `#### What this ruled out` |

Rules:

- Callout boxes are never headings (§6) — blockquotes opened with a bold label, at the same nesting level as the paragraph they annotate.
- Never skip a level.
- `## Why this case exists` is mandatory and comes first (after the H1 and the mandatory opening disclosure line, §8) — it states, in one paragraph, what distinct investigative pattern this case teaches and which specific existing playbook/detection-part treatment it deliberately does not re-narrate. This is this book's version of the series-wide "no silent duplication" defense, made an explicit, checkable field rather than an assumption.
- Section titles are sentence case: "Pivot: from mailbox audit log to OAuth consent log," not "Pivot: From Mailbox Audit Log To OAuth Consent Log."
- Every H2/H3 unique within its file.

---

## 5. Log, Query, and Evidence Block Conventions

This book inherits the Detection Engineering Handbook V2 `STYLE-GUIDE.md` §3 (code block language tags), §4 (Windows Event ID notation — "Event ID 4624" on true first use per case, bare `4624` after), and §5 (MITRE ATT&CK ID formatting — `T1110.003 (Kerberoasting)` on first use per section, bare after) **exactly, without modification.** A case narrating a 4769 or citing T1078.004 follows those rules to the letter; this guide does not restate them to avoid a second copy drifting from the source.

Two additions specific to a narrative-notebook format:

- **Query/result pairs are shown as the analyst actually ran them**, not cleaned up into a final tuned form. If the analyst's first query was too broad and returned 4,000 rows before a second, narrower query returned the useful 40, show both, briefly — the false start is part of the investigation, not noise to edit out. Label the discarded first attempt `// too broad — see next query` inline rather than silently deleting it.
- **A query that reproduces a detection or hunt already published in the SOC Playbook Handbook or the Detection Engineering Handbook V2 must cite that detection/playbook ID instead of re-deriving the query from scratch.** Where the analyst's actual query in the narrative differs from the standing one (because they're improvising mid-investigation, not running the tuned production rule), say so explicitly: "This is closer to the raw shape of `DET-13-04` than the tuned version — the analyst hadn't pulled up the production query yet, just the idea behind it."

---

## 6. Callout Boxes — Exact Templates

All eight use the same base shape as the companion volumes: a **blockquote** opened with a bold label line, visually and structurally consistent, distinguished only by label text. They sit inline in the flow of a beat — never a separate jump-target, never nested inside another callout.

```
> **[Label — optional short qualifier]**
> Body text, 1–5 sentences.
```

If a box needs more than ~5 sentences, promote it to real prose in the beat itself.

### 6.1 Hypothesis Board

The structural mechanism for §1's "let a hypothesis lose" rule. Used at least once per case, typically after the first two or three pivots, whenever more than one theory is genuinely live. Lists every hypothesis still in play with a one-line status.

```
> **Hypothesis Board — after [pivot/beat reference]**
> 1. **[Hypothesis A]** — [supported / weakened / ruled out], because [specific evidence].
> 2. **[Hypothesis B]** — [supported / weakened / ruled out], because [specific evidence].
> **Current confidence:** [level from §7], [direction].
```

Worked example:

```
> **Hypothesis Board — after the HybridIdentityMap join**
> 1. **Two unrelated low-priority tickets, no real connection** — weakened. The mapped
>    identity is the same on both sides, and the six-minute gap matches the documented
>    hash-sync lag almost exactly.
> 2. **A help-desk password reset, not an attack** — still live. No ticket in the ITSM
>    system yet found, but the search hasn't covered the on-call queue.
> 3. **DCSync-driven account takeover** — supported. The 4662 immediately preceding the
>    reset used replication-rights GUIDs, not a standard admin reset path.
> **Current confidence:** Medium, rising.
```

### 6.2 Dead End

Names a pivot or hypothesis that consumed real investigation time and led nowhere. Not every case needs one, but a case with zero Dead Ends is either very short or suspiciously tidy.

```
> **Dead End**
> What was checked, why it seemed promising, and the specific piece of evidence that closed
> it off. No hedge — say plainly that this line of inquiry is done.
```

Worked example:

```
> **Dead End**
> Twenty minutes went into pulling every 4768 for the target account across the prior
> thirty days, on the theory that the RC4 ticket request was part of an ongoing pattern.
> It wasn't — the account had exactly one RC4 request in the entire window, the one already
> flagged. Whatever this is, it isn't a slow-burn campaign against this specific account.
```

### 6.3 Analyst's Gut Check

A tactical, practitioner-voice aside — the tip or pivot you'd actually say out loud to the analyst sitting next to you. Informal, short, no filler.

```
> **Analyst's Gut Check**
> The tip, stated as something you'd say out loud to the person sitting next to you.
```

Worked example:

```
> **Analyst's Gut Check**
> When an inbox-rule alert and an OAuth-consent alert land in the same queue an hour apart
> for two different accounts, check whether they're actually the same identity before
> triaging them as two separate low-priority tickets. The account name in a consent-grant
> audit log and the mailbox owner in a rule-creation alert don't always render the same way
> in two different tools.
```

### 6.4 Evidence Note

A grounded statement about how the actual log source, tool, or timestamp behaves in this specific scenario — gaps, lag, timezone quirks, retention limits — as opposed to what the reader might assume.

```
> **Evidence Note**
> The gap between what this log source is assumed to capture and what it actually captured
> in this case, stated as a fact, plus the consequence for the investigation.
```

Worked example:

```
> **Evidence Note**
> The proxy's retention window is 21 days. The transfer the analyst wanted to compare this
> one against — the account's last confirmed use of the same personal-backup client, from
> "about a month ago" per the account owner's own statement — had already rolled off by the
> time this ticket was opened. The comparison the case needed most wasn't available; this
> is why the case leans on the client's locally cached history instead of proxy logs for
> that specific claim.
```

### 6.5 Blind Spot

A specific, named gap in what this investigation could see — never a vague disclaimer. Same purpose and name as both companion volumes.

```
> **Blind Spot**
> What this investigation could not see, stated specifically, and what would have been
> needed to see it.
```

Worked example:

```
> **Blind Spot**
> Nothing in this case's evidence set can distinguish "the attacker read the file and left"
> from "the attacker read the file and copied it somewhere this log source doesn't cover."
> The mailbox audit log confirms access; it does not confirm exfiltration one way or the
> other. Closing this as contained assumes the access itself was the objective, which is a
> judgment call, not a proven fact.
```

### 6.6 False Lead

A specific piece of evidence that looked incriminating but had an innocent explanation particular to this case — narrower than the companion volumes' "False Positive Trap," which describes a recurring pattern; this describes one specific misleading fact inside one specific investigation.

```
> **False Lead**
> The evidence that looked bad, and the specific fact that explained it away.
```

Worked example:

```
> **False Lead**
> The source IP resolved to a hosting-provider ASN with no business relationship to the
> company — a strong hostile-infrastructure signal on its own. It turned out to be the
> company's own SaaS vendor's outbound webhook relay, which legitimately runs on the same
> hosting provider's shared IP ranges. The vendor's own documentation, found on the second
> search, named the exact ASN.
```

### 6.7 Manager's Call

The decision a manager, not the investigating analyst, has to make at this point — staffing, escalation, legal/HR involvement, risk acceptance, or external communication. Cross-references the SOC Manager's Operating Handbook rather than re-deriving management doctrine.

```
> **Manager's Call**
> The decision, who has to make it, and the tradeoff — cross-referencing the SOC Manager's
> Operating Handbook for the doctrine behind the call, not re-deriving it here.
```

Worked example:

```
> **Manager's Call**
> Whether to loop in HR before or after confirming intent is the incident commander's call,
> not the analyst's, the moment a resignation-linked download pattern is confirmed as real.
> The SOC Manager's Operating Handbook, Part 27 — Legal, HR & Compliance Interfaces covers
> the timing tradeoff (evidence preservation vs. tipping off the employee) in full; this
> case does not re-derive it, only shows the point at which the analyst's job ends and the
> manager's begins.
```

### 6.8 What Would Change My Mind

An explicit falsifiability statement — what evidence would overturn or materially revise the case's stated conclusion or confidence level. Mandatory in every case that closes with confidence below High, and strongly encouraged even in High-confidence closures. Same name and purpose as the Detection Engineering Handbook V2.

```
> **What Would Change My Mind**
> The specific, checkable observation that would overturn or materially revise this case's
> conclusion — not a vague "more monitoring needed."
```

(Worked example under §1.3, Example 4.)

### 6.9 Callout usage density

A typical case carries one Hypothesis Board, one-to-two Dead Ends, one Evidence Note, and one What Would Change My Mind; the other four are used opportunistically. A case stacking all eight in a single beat is over-boxed.

---

## 7. Confidence and Hypothesis Conventions

Every case states confidence using this controlled five-point vocabulary, always paired with a direction where the narrative continues past that point:

| Level | Meaning |
|---|---|
| `Low` | More than one hypothesis remains plausible; no single piece of evidence yet outweighs the others. |
| `Low-Medium` | One hypothesis is favored but rests on inference, not direct confirming evidence. |
| `Medium` | One hypothesis is favored and has at least one piece of direct, specific supporting evidence, but a plausible alternative hasn't been ruled out. |
| `Medium-High` | The favored hypothesis has multiple independent corroborating sources; the remaining alternative would require an additional, specific coincidence to be true instead. |
| `High` | The favored hypothesis is confirmed by direct evidence from at least two independent log sources with no unresolved contradiction. |

Direction is stated alongside the level: **rising**, **falling**, **flat**, or **unresolved/oscillating**. "Confidence: Medium, rising" and "Confidence: Medium-High, falling" are both valid and both meaningfully different from "Confidence: Medium" alone. A case's closure section always states a final confidence level and direction (a settled case's direction is simply omitted or stated as "settled").

A case closes using the same disposition taxonomy as the SOC Playbook Handbook, not an invented alternative: **True Positive**, **Benign Positive**, **Expected Activity**, or **Insufficient Evidence**. This book adds one qualifier, used only in the case metadata block (§9) and this guide, never as a fifth disposition value in the case's own closure line: cases are additionally tagged **Obvious**, **Subtle**, **Benign**, **False Positive**, or **Inconclusive** for the purpose of `BOOK-INDEX.md`'s outcome-distribution tracking — this qualifier describes how the investigation *felt to run*, not a disposition the analyst would ever write in a real closure note.

---

## 8. Case Construction Classes — the Mandatory Opening Disclosure

Every case in this book is synthetic. None depicts a real organization, a real breach, or a real person, and no case may be written or read in a way that implies otherwise — this is the book's honesty policy, adapted from the "evidence classification" discipline both companion volumes apply to figures, applied instead to the case narrative itself, since a full investigation notebook carries far more risk of being mistaken for a real incident write-up than a single Mermaid diagram does.

**Every case file's very first line, immediately after the H1 title, before any other prose, is an italicized disclosure using one of these three exact construction-class labels:**

| Class | Meaning |
|---|---|
| `SYNTHETIC — INVENTED` | Built from plausible technical mechanics with no specific public incident or report behind it. |
| `SYNTHETIC — RECONSTRUCTED FROM PUBLIC TTP PATTERNS` | Built from attacker techniques and investigative patterns documented in public sources (MITRE ATT&CK, vendor/CISA advisories, published DFIR write-ups), recombined into a new fictional organization, timeline, and outcome. Never a retelling of one specific named incident — if a detail is close enough to a real, identifiable breach that a reader could reasonably guess which one, generalize it further before publishing. |
| `SYNTHETIC — COMPOSITE ACROSS SERIES` | Built primarily by threading together technical mechanics already published across this series' own playbooks and detections (cited by ID) into one continuous multi-source narrative. The primary construction method for this book. |

Exact template for the mandatory opening line:

```
*This is a [construction class in plain words] investigation. [Organization/person names]
are invented; no real organization, employee, incident, or breach is depicted or implied.*
```

Worked example:

```
*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Northwind Fixtures," its staff, and every host, account, and IP address named below are
invented; no real organization, employee, incident, or breach is depicted or implied.*
```

A case may name a real, published attacker technique, tool, or CVE (Mimikatz, Rubeus, a named ransomware family's documented TTPs) — that is public technical fact, not an incident claim — but must never attach that technique to an invented company in a way that reads as "this happened to a real, identifiable target." When in doubt, generalize the fictional organization further (industry, size, and name) rather than the technique.

This construction class is recorded in the case's front-matter YAML (`construction_class`, §10) in addition to the mandatory prose disclosure — the prose line protects the reader encountering the case in isolation; the front-matter field protects the build/audit tooling that scans for compliance across the whole book.

---

## 9. Case Metadata Block

Immediately after `## Why this case exists` and before `## 1.` begins, every case carries a `## Case metadata` table:

```
## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-01` |
| Category | Identity |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | Standing SIEM correlation alert |
| Primary log sources | DC Security log, Entra sign-in log, mailbox audit log, Entra AuditLogs (OAuth consent) |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook IAM-003; SOC Playbook Handbook, Email & Collaboration Threats (mailbox forwarding, OAuth consent phishing); DEH V2 Part 12, Part 17, Part 18 |
| All times | UTC |
```

This table is this book's equivalent of the companion volumes' YAML front matter rendered human-readable inline; the actual machine-readable front matter (§10) duplicates these fields for tooling.

---

## 10. Front Matter (YAML)

Every case file carries mandatory YAML front matter, same production-model mechanic as both companion volumes:

```yaml
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
status: "draft"
last_validated: "2026-09-15"
depends_on: ["SOC Playbook IAM-003", "DEH Part 12", "DEH Part 17", "DEH Part 18"]
---
```

`status` follows the same draft → reviewed → tested → released lifecycle as the Detection Engineering Handbook V2. "Tested" for this book means: every cited playbook/detection ID actually exists in the cited book at the cited location (a stale cross-reference is a lint failure, per the SOC Manager's Operating Handbook `STYLE-GUIDE.md` §4), and every Event ID / MITRE ID used follows §5 of this guide.

---

## 11. Content-Level Tags

Format locked to `**[TAG]**` — bold, brackets, all caps, at the start of the paragraph or subsection it governs. Never a heading, never doubled on one paragraph. These six tags are this book's adaptation of the series mechanic, redesigned around the *stage of the investigation* rather than the *role of the reader* (the axis both companion volumes use) — appropriate for a book with one narrative voice (the investigating analyst) rather than five different professional readers sharing one page.

| Tag | Use for | Do not use for |
|---|---|---|
| `[CONCEPT]` | A brief grounding note explaining a mechanism the investigation depends on, cross-referenced to the playbook/detection-part that owns it in full — enough for the reader to follow the next pivot, not a re-derivation. | Anything with a specific query, threshold, or command — that belongs in the narrative itself or a callout, not a `[CONCEPT]` aside. |
| `[ANALYST]` | The analyst's own reasoning at a triage step — the question being asked, what's being checked first and why, in first-person-adjacent notebook voice. | A completed decision or disposition — that's `[ESCALATION]` territory once a call is actually made. |
| `[PIVOT]` | The explicit move from one log source or entity to another, stated with the specific reason for making that jump. | A query result with no stated reason for why this particular next source was chosen — that's incomplete, not a `[PIVOT]`. |
| `[HYPOTHESIS]` | A single named, falsifiable theory under consideration, stated plainly enough that a reader could say what evidence would confirm or kill it. | A vague suspicion with no falsifiable content ("something felt off") — sharpen it into a real hypothesis or cut it. |
| `[ESCALATION]` | The decision point — escalate, contain, hand off, or close — stated with severity, audience, and who holds the authority to act. | Routine evidence-gathering that hasn't reached a decision yet. |
| `[LESSON LEARNED]` | The closing retrospective note: what this case teaches, what would have caught it faster or slower, and the cross-reference to the playbook/detection part that owns the permanent fix (a new rule, a tuning change, a process fix). | Restating the case's own plot — a `[LESSON LEARNED]` paragraph should generalize beyond this one case, not just summarize it. |

Tagging guidance:

- A case's beats typically carry several tags across their subsections — a single pivot section plausibly opens with `[ANALYST]` (the question), moves through `[PIVOT]` (the jump) and `[HYPOTHESIS]` (what's being tested), and may close with a Hypothesis Board callout rather than a tag. That layering is expected.
- `[CONCEPT]` is the only tag allowed to open a case's first numbered beat before any other tag appears, and only when the reader genuinely needs a grounding fact before the alert makes sense (e.g., a one-sentence reminder of what a 4769 is, before diving into why fourteen of them in a row matters).
- The pair most often confused: `[ANALYST]` (the reasoning while still gathering evidence) vs. `[ESCALATION]` (a decision actually made). If the sentence is still asking a question, it's `[ANALYST]`; if it's stating what happens next and why, it's `[ESCALATION]`.

---

## 12. Table Conventions

Identical to both companion volumes: lead-in sentence stating what decision the table supports; short noun-phrase headers, title case; left-aligned text columns; fragments not sentences in cells; inline code for field names/event IDs/hostnames used as literal values; never a blank cell (use "—"); MITRE IDs and Event IDs inside table cells follow §5's inherited rules exactly.

---

## 13. Figures and Diagrams: Evidence Classification

Case narratives are text-first; a case that needs a timeline or sequence diagram (attack-chain sketch, entity-relationship diagram of the accounts involved) uses the same four evidence-class tags as the Detection Engineering Handbook V2 §9 (`CONTROLLED LAB EXAMPLE`, `REAL LAB EXAMPLE`, `OFFICIAL REFERENCE`, `CONCEPTUAL`) for the figure itself — almost always `CONCEPTUAL`, since a case's diagram illustrates an invented scenario's structure, not a captured real artifact. **Do not conflate this figure-level tag with the case-level construction class in §8** — a case tagged `SYNTHETIC — COMPOSITE ACROSS SERIES` at the case level still labels its own diagrams `CONCEPTUAL` individually, per the companion volume's existing convention; the two tagging systems answer different questions (what is this case built from vs. what is this specific picture evidence of) and both are required where applicable.

Mermaid source stays in the file alongside its rendered image reference, per the Detection Engineering Handbook V2 §10, never deleted once rendered.

---

## 14. Review Checklist

1. **Opening disclosure:** Is the mandatory italicized construction-class line present, first, exactly per §8's template? Does it avoid implying a real organization or incident?
2. **Voice:** Any banned filler? Any sentence that doesn't advance the investigation?
3. **Structure:** Is `## Why this case exists` present and does it name what this case does not re-narrate? Is `## Case metadata` present and complete (§9)? Do the numbered beats avoid mechanically repeating the same fixed template as the previous case reviewed (§2)?
4. **Headings:** Correct level nesting, no heading used as a bold-line substitute.
5. **Event IDs / MITRE IDs:** Follow the inherited DEH V2 §4/§5 rules exactly, no exceptions.
6. **Cross-references:** Every playbook/part citation checked against the current `BOOK-INDEX.md` of the target book, not cited from memory; full form on first use per section, reason stated in the same sentence.
7. **Callouts:** Correct label string, correct blockquote structure, density not excessive (§6.9), at least one Hypothesis Board and one What Would Change My Mind present unless the case closes at High confidence with genuinely no live alternative (rare, and the reviewer should ask why).
8. **Tags:** Every `##`/`###` subsection carries at least one `[TAG]`, no paragraph carries two.
9. **Confidence:** Uses the §7 controlled vocabulary throughout, states a level and direction at every major checkpoint, final closure states a settled level.
10. **Variance check (this book's own version of the Detection Engineering Handbook V2's "depth check"):** Compare this case's entry point, hypothesis count, and confidence trajectory against its immediate neighbors in `BOOK-INDEX.md`. Flag — don't silently wave through — a case that reproduces the prior case's shape with different nouns.

Match this guide over inventing local precedent. Any deviation a reviewer approves gets recorded as a documented change to this file.
