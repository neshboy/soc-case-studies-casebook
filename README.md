# The SOC Case Studies Casebook

**Nineteen Full, End-to-End Synthetic SOC Investigation Narratives — Alert to Closure, Told Once, Start to Finish**

📄 **[Download the full PDF](./SOC_Case_Studies_Casebook.pdf)** — 196 pages, ~73,000 words across 19 cases in 7 categories.

Volume 4 of the **NESHBOY SOC Professional Library**, alongside [SIGNAL TO ACTION: The Complete SOC Playbook Handbook](https://github.com/neshboy/soc-playbook-handbook), [The Detection Engineering Handbook V2](https://github.com/neshboy/detection-engineering-handbook), and [The SOC Manager's Operating Handbook](https://github.com/neshboy/soc-manager-handbook).

Every other volume in this series either dissects one alert at a time (the SOC Playbook Handbook's case-study companions: one alert, one evidence table, one disposition, roughly 600–900 words) or compresses a multi-stage attack chain into a technical model written in the detection engineer's voice (Detection Engineering Handbook V2 Parts 44–48: cross-plane correlation logic with a worked example folded into one subsection). Neither reads like an actual investigation notebook: alert, first look, the questions an analyst asks before touching a second data source, the pivot that pays off, the one that doesn't, a stated hypothesis that loses, a confidence level that moves as evidence comes in, and a decision. This book is that notebook, nineteen times, each case substantial enough (3,000–6,000 words) to earn its own file and its own place in the series' cross-reference graph.

It does not re-derive detection logic, log-field semantics, MITRE mappings, or query syntax already owned by the SOC Playbook Handbook or the Detection Engineering Handbook V2 — every technical mechanic a case leans on is cross-referenced by ID and title, never rebuilt from scratch. It does not make people-and-process decisions the way the SOC Manager's Operating Handbook's Management Autopsy boxes do — where a case reaches a staffing, legal, or risk-acceptance decision point, it hands off to that book's doctrine via the Manager's Call callout rather than adjudicating the decision itself.

## What's synthetic vs. real

**Every one of the nineteen cases in this book is synthetic** — invented, reconstructed from public TTP patterns, or a composite threading together mechanics already published across this series' own playbooks and detections. None depicts a real organization, a real breach, or a real person. Each case's very first line, before any other prose, is a mandatory italicized disclosure stating its construction class (`SYNTHETIC — INVENTED`, `SYNTHETIC — RECONSTRUCTED FROM PUBLIC TTP PATTERNS`, or `SYNTHETIC — COMPOSITE ACROSS SERIES`) and naming the invented organization — this is a non-negotiable, checkable field, not a footnote.

## The outcome distribution is a design feature, not an accident

Nineteen cases that all close as a clean confirmed compromise would be a false picture of what a SOC actually does. This collection deliberately spreads its endings across five outcome flavors:

| Outcome flavor | Count | What it means |
|---|---|---|
| Obvious / confirmed True Positive | 7 | The realistic largest bucket — what a SOC actually closes once an investigation runs to completion |
| Subtle True Positive | 6 | Individually low-signal; the combination across sources is what confirms it |
| Benign True Positive | 2 | The alert was technically correct; it just isn't a security incident |
| Confirmed False Positive | 2 | High-severity trigger that traces cleanly to nothing |
| Genuinely Inconclusive | 2 | Closes with a stated Low or Low-Medium confidence and an explicit "What Would Change My Mind," never a manufactured clean resolution |

Obvious-TP is the largest bucket on purpose, while the other four flavors are each guaranteed at least two representatives spread across different categories, so no single flavor reads as "the one section's gimmick." Full mapping of case to flavor is in `BOOK-INDEX.md`'s outcome-distribution table.

## Reading the book

- **[SOC_Case_Studies_Casebook.pdf](./SOC_Case_Studies_Casebook.pdf)** — the assembled, print-ready book. Start here.
- **[BOOK-INDEX.md](./BOOK-INDEX.md)** — the full Case Table, grouped into seven lettered categories (Identity, Endpoint, Network, Web/Email, Cloud, Insider, Ambiguous/False-Positive), with per-case disposition, confidence trajectory, entry point, and cross-references — plus the outcome-distribution and non-duplication-check sections this README summarizes.
- **[STYLE-GUIDE.md](./STYLE-GUIDE.md)** — the voice, formatting, and callout-box contract every case follows: six content tags (`[CONCEPT]`, `[ANALYST]`, `[PIVOT]`, `[HYPOTHESIS]`, `[ESCALATION]`, `[LESSON LEARNED]`) built around stage of investigation rather than reader role, and eight recurring callouts (Hypothesis Board, Dead End, Analyst's Gut Check, Evidence Note, Blind Spot, False Lead, Manager's Call, What Would Change My Mind), adapted from the companion volumes' style contracts for series-wide consistency.

## How it was built

- `build/build_book.js` — parses `BOOK-INDEX.md`'s Case Table (a different shape from the companion volumes' Part/Appendix tables: `CB-##` case IDs, a `cases/` file-path column, and lettered category sections instead of numbered parts), assembles all 19 case files into one HTML document, and prints it to PDF via headless Chrome.
- `build/add_watermark.py` — applies the diagonal `neshboy` watermark to every page.

No case in this book currently contains a Mermaid diagram, so this build has no diagram-rendering step; `render_mermaid.py` from the companion volumes was evaluated and is not needed here yet. If a future case adds one, adapt that script the same way the Detection Engineering Handbook did, pointed at `cases/*.md` instead of `chapters/*.md`.

## Rebuilding it yourself

```
cd build
npm install
node build_book.js
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer ^
  --print-to-pdf="..\_build\SOC_Case_Studies_Casebook.pdf" "..\_build\book.html"
python add_watermark.py
```

## Repository layout

- `cases/` — the 19 cases (`cb01-...md` through `cb19-...md`), Markdown source of record, each carrying YAML front matter (`case_id`, `category`, `disposition`, `outcome_flavor`, `confidence_at_close`, `entry_point`, `construction_class`, plus the standard `author`/`reviewer`/`status`/`last_validated`/`depends_on` fields shared with the companion volumes).
- `appendices/` — reserved for the three appendix bundles proposed in `BOOK-INDEX.md` (Case Construction Class Register, Cross-Series Citation Index, Confidence-Trajectory Atlas); none are drafted yet, so this directory is currently empty.
- `assets/diagrams/` — reserved for rendered Mermaid diagrams; empty, since no case currently has one.
- `build/` — the build/watermark tooling above.
- `BOOK-INDEX.md`, `STYLE-GUIDE.md` — cross-cutting project documentation.
