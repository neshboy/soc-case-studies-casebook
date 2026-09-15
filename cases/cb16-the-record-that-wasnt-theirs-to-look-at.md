---
title: "CB-16 — The Record That Wasn't Theirs to Look At"
case_id: "CB-16"
category: "Insider"
disposition: "True Positive"
outcome_flavor: "Subtle"
confidence_at_close: "Medium"
entry_point: "proactive-access-review-hunt"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook access-outside-job-role-need-to-know.md", "SOC Playbook privileged-access-misuse.md", "SOC Playbook unusual-database-access.md", "SOC Manager's Operating Handbook Part 27", "SOC Manager's Operating Handbook Part 19"]
---

# CB-16 — The Record That Wasn't Theirs to Look At

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks into one continuous narrative. "Castlebridge
Financial," its staff, and every host, account, and record ID named below are invented; no
real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

This case teaches that "confirmed as a real policy violation" and "confident about what it
actually was" are two different claims, and that a case can close True Positive without the
analyst's confidence ever climbing past Medium — because the one fact that would move it
sits outside every log source the SOC has. It deliberately does not re-derive what makes a
database access count as "outside job role" in the first place, or how a legitimate
privileged-override function becomes the way around the rule it was built to support —
SOC Playbook `access-outside-job-role-need-to-know.md`, `privileged-access-misuse.md`, and
`unusual-database-access.md` own those mechanics in full, cited here and never rebuilt.
What this case owns is the shape of an investigation that starts from no alert at all,
confirms a real violation through a pattern rather than one damning event, and then
deliberately stops reaching for more certainty than the evidence honestly supports. That's a
direct contrast to this book's own CB-15, a departing-employee case built to be unambiguous
from the first pivot: where CB-15 hands the reader a clean, high-confidence story on
purpose, this case hands the reader a confirmed-but-bounded one. The access violation is
real and the SOC's job on it is done; the human question underneath it belongs to the SOC
Manager's Operating Handbook, Part 27 and Part 19 — not to a query the analyst hasn't
thought to run yet.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-16` |
| Category | Insider |
| Disposition | True Positive |
| Outcome flavor | Subtle |
| Confidence at close | Medium, settled |
| Entry point | Routine proactive quarterly access-review hunt, no alert at all |
| Primary log sources | Anchor CRM record-view audit log (override-search reason codes), CaseTrack case-management export, contact-center phone system call detail records (CDR), Anchor SSO/session-authentication log, quarterly QA sampling roster, Employee Relations relationship-confirmation memo |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook `access-outside-job-role-need-to-know.md`, `privileged-access-misuse.md`, `unusual-database-access.md`; SOC Manager's Operating Handbook Part 27 — Legal, HR & Compliance Interfaces, Part 19 — Team Culture & Psychological Safety |
| All times | UTC |

## 1. The hunt: a quarter with no alert in it at all

**[CONCEPT]** Castlebridge Financial's contact-center servicing platform, Anchor, enforces a
hard technical rule for its roughly 140 customer service associates: no account's
transaction history, balance, or contact details open past a locked summary card without an
active, assigned case tied to that account. A rep can search a customer by name or account
number, but the full record won't expand until a case exists. The one deliberate exception
is Override Search, built for the moment a customer calls in and the platform's automated
identity check fails or hasn't run yet, so the rep can locate the right account before a
case can be created. Every override view requires a reason code from a fixed list —
`NEW_INBOUND_CONTACT`, `VERIFICATION_EXCEPTION`, `SUPERVISOR_QA_SAMPLE`, `FRAUD_REFERRAL`,
`BRANCH_WALKIN` — and every one is logged. `access-outside-job-role-need-to-know.md` owns
the design logic behind that lock-and-exception model in full; `privileged-access-misuse.md`
owns what it looks like when the exception itself becomes the way around the rule it exists
to support. This case uses both and re-derives neither.

**[ANALYST]** Kendra Voss picked up Castlebridge's Q2 entitlement-review hunt the first week
of July 2026 — a standing quarterly item on the SOC's own calendar, run whether or not
anything upstream has ever flagged a problem. No alert had fired. No ticket had been opened.
Kendra ran it on the calendar, not on a threshold breach — the standing complement to the
anomaly-triggered checks `unusual-database-access.md` owns, for exactly the reason that
playbook's own trigger logic can't cover: a rep using a working exception the way it's meant
to be used, every time, produces no anomaly to fire on. The hunt exists because a regulator
expects it, and because, as Kendra's team likes to put it, the interesting ones never alert
on themselves — an override function built to let a rep in without a case is, by design,
invisible to any control that only watches for cases.

## 2. First observation: eleven pairs out of two thousand

**[ANALYST]** The hunt's standard first query joins every `OVERRIDE_SEARCH` event in
Anchor's audit log against CaseTrack, looking for a case opened on the same account within a
day of the view — a same-day match is the normal shape of a real inbound-contact override,
since the whole point of the reason code is that a case gets created moments later.

```sql
-- too broad — see next query
SELECT v.rep_id, v.account_id, v.view_ts, v.reason_code
FROM anchor_record_view v
LEFT JOIN casetrack c
  ON v.account_id = c.account_id
 AND c.opened BETWEEN v.view_ts AND v.view_ts + INTERVAL '24' HOUR
WHERE v.view_type = 'OVERRIDE_SEARCH'
  AND v.view_ts BETWEEN '2026-04-01' AND '2026-06-30'
  AND c.case_id IS NULL;
```

2,116 rows. That's not a finding, it's the reason the hunt runs a second query. A quarter's
worth of override use across 140 reps produces plenty of same-day misses that mean nothing —
a rep starts the wrong search and corrects it, a case lands under a different account ID a
minute later, a customer hangs up before the rep finishes. Kendra narrowed for the pattern
that actually matters: the same rep, the same account, more than once across the quarter,
with no case *ever* opened against it by that rep — not a same-day miss, a standing gap.

```sql
SELECT v.rep_id, v.account_id, COUNT(*) AS override_views,
       MIN(v.view_ts) AS first_seen, MAX(v.view_ts) AS last_seen
FROM anchor_record_view v
WHERE v.view_type = 'OVERRIDE_SEARCH'
  AND v.view_ts BETWEEN '2026-04-01' AND '2026-06-30'
  AND NOT EXISTS (
        SELECT 1 FROM casetrack c
        WHERE c.account_id = v.account_id
          AND c.assigned_rep = v.rep_id
          AND c.opened BETWEEN '2026-04-01' AND '2026-06-30')
GROUP BY v.rep_id, v.account_id
HAVING COUNT(*) >= 2
ORDER BY override_views DESC;
```

11 rows: 11 rep/account pairs, each with at least two override views of the same
customer's record across the whole quarter and not one case to show for it.

## 3. Ten explained fast, one that wasn't

**[ANALYST]** Ten of the eleven closed within an hour of routine checking. Two were the same
customer under two account IDs after a card-product conversion re-issued a new number
mid-quarter — the cases existed, just filed against the old ID the join never matched.
Three more were reps on Castlebridge's fraud-referral desk, where a `FRAUD_REFERRAL`-coded
override legitimately opens a case in a separate fraud-case system the quarterly join
doesn't reach. Four more were data-quality noise not worth narrating individually. That left
one pair worth real time before the last one on the list.

> **Dead End**
> Marcus Elden, a rep on Castlebridge's Wealth Relationship Desk, had 14 override views of
> the same account across the quarter with zero matches in CaseTrack — the highest count on
> the whole list, and the one that looked worst on paper. Thirty minutes went into it: the
> Wealth desk services a small book of high-net-worth clients through a separate legacy
> system, the Relationship Manager Console, that predates CaseTrack and was never integrated
> into it. Pulling that console's own case log directly showed a matching case entry for
> every one of the 14 views, each opened within minutes. This wasn't a gap in policy. It was
> a gap in the join. The account is done.

**[ANALYST]** One row was left standing: rep_id `CSR-4417`, Renata Solis, a Tier 1 customer
service associate, six override views of account `ACCT-7734912` across the quarter, reason
code `NEW_INBOUND_CONTACT` every time, and no case anywhere Kendra could find.

## 4. Pivot: does the reason code's own story hold up

**[PIVOT]** `NEW_INBOUND_CONTACT` makes a specific, checkable claim: a customer called in,
the automated check didn't clear them, and the rep searched to find the right account before
a case existed. That claim lives in a different system than Anchor — the contact center's
own phone platform, which keeps call detail records independently of anything Anchor logs.

```text
SELECT ts, direction, extension, ani, duration
FROM cdr
WHERE extension = '4417'
  AND ts BETWEEN '2026-04-14T15:15:00Z' AND '2026-04-14T15:30:00Z';
```

Zero rows — for that timestamp, and for the same five-minute window around each of the other
five. Not one of the six override views had an inbound call anywhere near it on Renata's
extension. That's a specific, falsifiable claim failing a specific, checkable test, not "this
looks unusual."

> **Evidence Note**
> The phone platform's CDR retention at Castlebridge is 120 days. All six of Renata's flagged
> views fell inside that window when Kendra ran this check in the first week of July, with
> some room to spare — the earliest, from mid-April, was still nearly 40 days from rolling
> off. A hunt run even two months later against this same quarter would have lost that
> comparison for the earliest two views entirely, and the case would have opened with four
> confirmed mismatches instead of six.

**[ANALYST]** Before treating six missing calls as proof of anything, Kendra checked whether
Renata's override use looked like this normally. It didn't.

```text
SELECT reason_code, COUNT(*) AS total,
       SUM(CASE WHEN has_matching_case THEN 1 ELSE 0 END) AS cased
FROM anchor_record_view
WHERE rep_id = 'CSR-4417' AND view_type = 'OVERRIDE_SEARCH'
  AND view_ts BETWEEN '2026-04-01' AND '2026-06-30'
GROUP BY reason_code;
```

```text
reason_code            total  cased
NEW_INBOUND_CONTACT      41      35
VERIFICATION_EXCEPTION    9       9
```

Thirty-five of 41 `NEW_INBOUND_CONTACT` overrides that quarter led to a case, most within
minutes — a normal, busy Tier 1 pattern. The other six, all on the same account, were the
only overrides in her entire quarter that never became a case and the only ones with no
matching call. This was not how she normally worked.

> **Analyst's Gut Check**
> A reason code is a claim a person makes about their own actions, not a fact. Treat it
> exactly that skeptically — the moment something reads `NEW_INBOUND_CONTACT`, go find the
> inbound contact in a system the person filling in the reason code doesn't control, before
> deciding whether to believe it.

## 5. Was it even her: the shared-workstation question

**[ANALYST]** One loose end sat ahead of any hypothesis about *why*: whether these six events
were even attributable to Renata specifically, or to whichever rep happened to be logged in
at a shared terminal.

> **False Lead**
> All six views logged from `src_ip=198.51.100.44`, an address inside the contact center's
> floating VDI pool (`198.51.100.32/27`), reassigned to whichever rep's session claims it at
> login — the kind of shared-address pattern that would normally make attributing a specific
> action to a specific person a real problem. It wasn't one here. Anchor's SSO session log
> showed Renata's own authenticated session covering every one of the six timestamps exactly,
> with no other login on that address overlapping any of them. The address is shared across
> shifts; the sessions on it, checked one at a time, aren't.

## 6. Hypothesis check: what's actually still live

**[HYPOTHESIS]** With the reason code disproven and the attribution confirmed, three
theories were on the table, and only one of them was in trouble.

> **Hypothesis Board — after the reason-code and attribution checks**
> 1. **Undocumented but legitimate use** — a supervisor asked her to check something
>    informally, or a QA sample that never got tagged right — weakened. Castlebridge's
>    monthly QA sampling roster for Q2 doesn't list `ACCT-7734912` under any rep, and none of
>    Renata's supervisors have an open exception on file for informal look-ups.
> 2. **Personal curiosity** — she recognized the name and looked, for reasons that have
>    nothing to do with work — live and favored on the pattern alone: one account, repeated,
>    never cased, never matched to a call, against an otherwise clean 2.5-year history.
> 3. **Something more concerning** — active monitoring of this specific person's finances
>    for a reason that isn't idle curiosity — live, unweakened by anything checked so far.
>    Nothing yet distinguishes it from hypothesis 2.
> **Current confidence:** Medium overall, and not moving from there — the access-violation
> finding itself is nearly certain on its own, but the number that matters is capped by
> hypotheses 2 and 3, and nothing yet distinguishes between them.

## 7. Pivot: a name Kendra already knew

**[PIVOT]** Kendra opened Renata's HR directory entry to confirm role and tenure before
writing the finding up, and paused at the photo. She and Renata had gone through new-hire
orientation together in the spring of 2025, sat two tables apart at the same cohort lunch for
a week, and still say hello passing through the third-floor break room.

**[ANALYST]** Nothing about the technical finding changed in that moment. But Kendra flagged
the connection to her SOC lead before writing another line, rather than either quietly
stepping back without saying why or continuing as if she hadn't noticed.

> **Manager's Call**
> Whether Kendra should keep working the case, and how, once she recognized the flagged
> employee, wasn't hers to decide alone, and it isn't really a technical question at all.
> The SOC Manager's Operating Handbook, Part 19 — Team Culture & Psychological Safety covers
> the standing norm this decision follows: an analyst who recognizes a name is expected to
> say so immediately, and doing so is treated as good judgment, not as a conflict that
> reflects badly on them or a reason to doubt their objectivity going forward. Castlebridge's
> SOC lead kept Kendra on the log-based work — the queries, the CDR check, and the baseline
> comparison were already documented independent of anyone's personal read of Renata — and
> walled her off from any conversation about Employee Relations' eventual findings or
> outcome. This case does not re-derive that doctrine, only shows the moment it applied.

## 8. Pivot: testing the one hypothesis the SOC's own data can't settle

**[PIVOT]** The remaining live question, personal curiosity versus something worse, turns on
a fact no system log at Castlebridge records: whether Renata and the account holder know each
other outside work. That fact lives in HR's data, not the SOC's, and pulling it wasn't a
decision Kendra could make just because she happened to have directory access.

> **Manager's Call**
> Testing the personal-connection hypothesis meant comparing an employee's own personal
> information — an address, an emergency contact, a maiden name — against a customer's
> account record, and deciding who does that comparison, and how much of the result the SOC
> actually needs to see, isn't the analyst's call. The SOC Manager's Operating Handbook,
> Part 27 — Legal, HR & Compliance Interfaces covers the timing and ownership of exactly this
> kind of request; this case does not re-derive it, only shows where the analyst's job stops.
> Castlebridge's SOC lead routed the request to Employee Relations rather than having Kendra
> query HR data directly, asking a single yes-or-no question: does a personal relationship
> appear to exist between employee `CSR-4417` and the account holder on `ACCT-7734912`.
> Employee Relations ran its own comparison and answered within three business days.

> **Evidence Note**
> Employee Relations' reply confirmed that a personal relationship exists between Renata and
> the account holder, based on emergency-contact information Renata provided at hire. It did
> not name the relationship, describe its nature, or share anything else about either person,
> and Kendra's team didn't ask for more than the yes-or-no the case needed. That's
> need-to-know applied to the SOC's own side of this investigation, not just Renata's — the
> same principle `access-outside-job-role-need-to-know.md` names for Anchor governs what the
> SOC gets handed back here. This case closes without Kendra, or this write-up, ever learning
> who the account holder is to Renata beyond "someone she has a real, confirmed connection to
> outside work."

## 9. Additional evidence: how far this actually reached

**[PIVOT]** One question remained answerable from logs alone: whether this was a
single-target lapse or a broader pattern the quarter's window happened to catch only part of.

```text
SELECT account_id, COUNT(*) AS override_views,
       MIN(view_ts) AS first_seen, has_ever_had_case
FROM anchor_record_view
WHERE rep_id = 'CSR-4417' AND view_type = 'OVERRIDE_SEARCH'
GROUP BY account_id, has_ever_had_case
ORDER BY override_views DESC;
```

Across Renata's full 2.5-year tenure at Castlebridge, not just Q2, `ACCT-7734912` was the
only account she had ever viewed more than once through override search without a case
eventually attached. Every other account on the list, including several viewed three or four
times across different quarters, had a case opened the same shift each time.

> **Hypothesis Board — after Employee Relations' reply**
> 1. **Undocumented but legitimate use** — ruled out. No QA sample, no supervisor exception,
>    and now a confirmed personal relationship that a routine work reason wouldn't need.
> 2. **Personal curiosity, contained to this one relationship** — supported. A confirmed
>    personal connection, an isolated single-account pattern across two and a half years of
>    otherwise clean override use, and nothing found showing the information went anywhere.
> 3. **Something more concerning than curiosity** — still live, and nothing checked has moved
>    it either direction. The SOC's evidence set has nothing that can distinguish "looked, out
>    of habit, and stopped" from "looked, repeatedly, for a reason that matters."
> **Current confidence:** Medium. It was Medium after the reason-code mismatch, and it stays
> Medium here — the access violation itself is as solid as this evidence gets; what it means
> underneath that is exactly as open now as it was after Section 6, because the fact that
> would move it isn't a fact SOC telemetry can supply.

> **Blind Spot**
> Nothing in Castlebridge's evidence set can show whether Renata told the account holder, or
> anyone else, anything about what she saw — a balance, a recent transaction, an address on
> file. No DLP tooling, no screenshot detection, and no monitoring on the Anchor terminal
> covers that gap; the platform logs that a screen was opened, not what happened after
> someone read it. Closing this as a contained, single-target access violation assumes the
> looking was the extent of it. That is Employee Relations' judgment to make in an actual
> conversation, not a fact this log evidence can supply either way.

## 10. Escalation: what the SOC can decide and what it can't

**[ESCALATION]** By the second week of July, Kendra's package was three things: a confirmed,
isolated pattern of override-search use against one account with no matching case or call
across an otherwise clean tenure; a confirmed personal relationship between the employee and
the account holder, reported back at exactly the level of detail the case needed and no
more; and a confirmed absence of any broader pattern across her other accounts, or across the
other ten rep/account pairs the hunt had flagged. That was enough to act on the access
question directly. Castlebridge's identity team suspended Renata's `OVERRIDE_SEARCH`
privilege pending review — a control action squarely inside the SOC and IAM team's own
authority, no different from disabling any other credential tied to a confirmed policy
violation — while leaving her standard, case-linked access untouched so she could keep
working her queue.

What the SOC could not decide, and did not try to: whether this was a coaching conversation,
a formal disciplinary finding, or something that required notifying the account holder. That
referral went to Employee Relations under the same doctrine already invoked in Section 8,
this time for the disposition itself rather than the evidence-gathering step — Part 27's
territory, not this case's to resolve.

## 11. Decision and closure

**Disposition: True Positive.** Renata Solis accessed a specific customer's account outside
her job role and outside Castlebridge's need-to-know model, six times across one quarter,
using a privileged override function whose own logged justification did not match any event
in an independent system. That access-outside-need-to-know finding is confirmed by three
independent sources agreeing with each other and with no unresolved contradiction: the
Anchor audit log, the absent call record, and her own baseline pattern across 2.5 years of
otherwise normal override use. Nothing about that conclusion is in question.

**Confidence at close: Medium, settled.** The access violation itself would support a far
higher confidence rating on its own. What keeps the overall case at Medium is the second
question this investigation was always actually about — personal curiosity, contained,
versus something the evidence can't rule out — which never moved past where it stood after
Section 6. Every source the SOC has has already been checked, and none of them speaks to
motive. Calling this High would mean claiming certainty about a question this evidence set
was never built to answer.

> **What Would Change My Mind**
> Two things would move this, in opposite directions. If Employee Relations' review turns up
> a statement, a shared account, or a documented arrangement showing the account holder
> knowingly permitted Renata's involvement, this shifts back toward hypothesis 1 — still a
> process violation, but a materially smaller one. If it turns up any indication the
> information was acted on outside the bank — contact with the account holder referencing
> what was seen, timing that lines up with a dispute or legal proceeding, or a third party who
> knew something they shouldn't have — this moves immediately to a safety and
> fraud-enablement concern requiring account-holder notification, independent of anything
> else in this write-up. Neither has surfaced yet, and this case closes before Employee
> Relations' own review does.

## 12. Lesson learned

**[LESSON LEARNED]** The technique that actually cracked this — checking whether a
privileged tool's own logged justification is independently true, not just present —
generalizes well past Anchor's override function. Any system that lets a user self-select a
reason for bypassing a control produces exactly this kind of artifact: a field that looks
like evidence but is really just a claim, checkable against a second system the person
filling it in doesn't control. `privileged-access-misuse.md`'s guidance to treat a
self-attested justification as a hypothesis rather than a fact is the general form of the
specific check Section 4 ran here, and it's worth running as a standing pass across every
override-style control in the environment, not just the one this hunt happened to be pointed
at. The narrower lesson is about the write-up itself: this case had every opportunity to
manufacture a tidier ending, treating the confirmed relationship as proof of intent or
treating the isolated pattern as proof of innocence, and either move would have overstated
what six log sources and one three-word answer from Employee Relations actually support. A
confirmed True Positive that stays at Medium confidence on the question underneath it isn't
an unfinished investigation; closing it honestly at Medium, with a specific, named question
still open, is the finished state this evidence was always going to produce. Finally, the
Section 7 moment is worth keeping as a standing team practice, not a one-off judgment call:
an analyst who says "I know this person" partway through a proactive hunt should never have
reason to expect that disclosure counts against them.

---

**Cross-references:** SOC Playbook `access-outside-job-role-need-to-know.md`,
`privileged-access-misuse.md`, `unusual-database-access.md`; SOC Manager's Operating
Handbook Part 27 — Legal, HR & Compliance Interfaces, Part 19 — Team Culture &
Psychological Safety.
