---
title: "CB-11 — The Web Shell Behind the Marketing Site"
case_id: "CB11"
category: "Web / Email"
disposition: "True Positive"
outcome_flavor: "Obvious"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-15"
depends_on: ["SOC Playbook sql-injection.md", "SOC Playbook web-shell-detection.md", "SOC Playbook rce.md", "DEH Part 16", "DEH Part 47"]
---

# CB-11 — The Web Shell Behind the Marketing Site

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Cascadia Outdoor Gear," its staff, and every host, account, domain, and IP address named
below are invented; no real organization, employee, incident, or breach is depicted or
implied.*

## Why this case exists

This case teaches the ordinary, unglamorous shape of a web-facing compromise: a
signature-based WAF alert on a well-known attack class, a legacy plugin nobody remembers
approving, and a chain from injection to file write to command execution that plays out
almost exactly the way the textbook describes it — except for the two hours the analyst
spent chasing the wrong IP address because of how the CDN logs client traffic. It
deliberately closes as an **Obvious** True Positive, not because the investigation was
trivial, but because every hypothesis genuinely worth entertaining collapses in the same
direction once the host-level evidence comes in. Because the chain itself is the textbook
case, this write-up spends most of its length on the two things that weren't textbook — the
CDN attribution dead end and the per-vhost WAF exception that made the exploit possible in
the first place — and moves quickly through the confirmatory steps once each one lands, rather
than giving every step in the chain equal space. This case does not re-derive what a
successful SQL injection signature looks like at the WAF layer (SOC Playbook Handbook,
`sql-injection.md`), what separates a web shell from a legitimate CMS artifact
(`web-shell-detection.md`), or how a web-server worker process spawning a shell gets flagged
as remote code execution (`rce.md`) — those mechanics are owned there and only cited here.
It also does not re-narrate the compressed exploit-to-shell chain that DEH V2 Part 47's web
compromise model already documents step by step; this case shows what running that chain
live, on a real shift, with one analyst and an incomplete first log source, actually feels
like.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-11` |
| Category | Web / Email |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | Standing WAF correlation alert (SQL injection signature) |
| Primary log sources | CDN/WAF edge log, origin web server access log, host file integrity monitoring (FIM), host EDR process-creation telemetry, DMZ perimeter firewall log |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `sql-injection.md`, `web-shell-detection.md`, `rce.md`; DEH V2 Part 16 (web-layer detection mechanics), Part 47 (web compromise model, cross-referenced, not re-narrated) |
| All times | UTC |

## 1. Alert: a WAF signature fires on the marketing site

**[CONCEPT]** A web application firewall (WAF) sitting in front of a public site inspects
request parameters for known attack patterns — a `UNION SELECT`, a stacked semicolon
followed by a second statement, a comment sequence used to truncate a query — and either
blocks the request or logs it, depending on how the rule is deployed for that specific
path. SOC Playbook Handbook `sql-injection.md` owns the full signature catalog and the
block-versus-log distinction in detail; this case only needs the reader to know that a WAF
rule firing does not, by itself, mean the request was stopped.

At 03:14 UTC on a Saturday, the on-call analyst's queue picked up a WAF correlation alert:
five requests in ninety seconds against `trailrewards.cascadiaoutdoorgear.example`, each
carrying a `UNION SELECT` pattern in the `zip` parameter of a POST to
`/wp-admin/admin-ajax.php`. The site was a seasonal trade-in-quote microsite the marketing
team ran on its own WordPress install, using a plugin called QuoteRequest Pro to look up
shipping rates by ZIP code. It sat behind the same corporate CDN and WAF as the main
e-commerce domain, but on a separate, older WordPress core version that IT didn't manage
day to day.

**[ANALYST]** The alert's severity was Medium — high enough to page the on-call analyst,
not high enough to auto-page a second responder. The first thing worth checking on any WAF
alert is whether the WAF actually stopped anything. Five `UNION SELECT` attempts in ninety
seconds is unremarkable background noise on its own; the internet sprays that pattern at
every public form constantly. What matters is what happened to the requests that carried it.

```
// WAF edge log, filtered to the alert's correlation ID
2026-07-18T03:14:02Z host=trailrewards.cascadiaoutdoorgear.example rule=SQLI-UNION-002
action=log-only status=200 src=203.0.113.10 path=/wp-admin/admin-ajax.php
2026-07-18T03:14:19Z host=trailrewards.cascadiaoutdoorgear.example rule=SQLI-UNION-002
action=log-only status=200 src=203.0.113.10 path=/wp-admin/admin-ajax.php
2026-07-18T03:14:41Z host=trailrewards.cascadiaoutdoorgear.example rule=SQLI-UNION-002
action=log-only status=200 src=203.0.113.10 path=/wp-admin/admin-ajax.php
2026-07-18T03:15:07Z host=trailrewards.cascadiaoutdoorgear.example rule=SQLI-UNION-002
action=log-only status=200 src=203.0.113.10 path=/wp-admin/admin-ajax.php
2026-07-18T03:15:29Z host=trailrewards.cascadiaoutdoorgear.example rule=SQLI-UNION-002
action=log-only status=200 src=203.0.113.10 path=/wp-admin/admin-ajax.php
```

Every entry read `action=log-only`. Someone had put the SQLI-UNION-002 rule into detection
mode for this specific vhost eight months earlier, per the WAF's own change history, with a
ticket comment reading "marketing site false-positiving on legit ZIP lookups, log only until
they fix the plugin." Nobody had followed up. Every one of those five requests had gone
straight through to the origin server, and every one of them got a 200.

> **Analyst's Gut Check**
> Before triaging any WAF SQLi alert as "just scanner noise," check the rule's action for
> that specific path, not the rule's default. Per-vhost exceptions like this one are exactly
> the kind of thing that gets created under deadline pressure and never gets revisited —
> and they turn a routine alert into a live exploitation path without anyone changing the
> alert's own severity label.

**[HYPOTHESIS]** Two theories were live at this point, and they made different predictions
about what the origin server's own logs would show. If this was ordinary background
scanning that happened to land on an unusually permissive rule, the origin log should show
the same shape of noise it always shows: a wide spread of source IPs, mixed paths, no
sustained interest in one endpoint. If this was a scan that had actually found something,
the origin log should show a narrower pattern — one source, repeated interest in the same
parameter, and, if it had worked, requests to something new.

## 2. Pivot: from the WAF edge log to the origin access log

**[ANALYST]** Four questions needed answering before the next move: Did any of these five
requests actually return different content, not just the same 200 boilerplate every request
to this endpoint returns? Were there other requests from the same source outside the five
the WAF flagged — before or after? Does the plugin's own backing database user have any
privilege that would let a stacked query do more than read data? And is there anything new
on disk on the origin server that wasn't there yesterday? The WAF log alone couldn't answer
any of them — it logs the request line and a few headers, not response bodies, and it says
nothing about what a plugin's database user can do.

**[PIVOT]** The WAF sits at the CDN edge; the origin web server keeps its own access log
independent of it, and that log records every request the origin actually received —
including ones the CDN never flagged. That gap between "what the WAF decided to alert on"
and "what the origin server actually processed" is the reason this pivot has to happen on
every SQLi alert where the rule wasn't blocking, not just the flagged five.

### 2.1 The too-broad first query

The analyst's first pull filtered the origin access log to the last twenty-four hours for
the `admin-ajax.php` path generally:

```
// too broad — see next query
grep "admin-ajax.php" access.log | grep "2026-07-1[78]"
→ 3,842 matching lines
```

`admin-ajax.php` is WordPress's general-purpose AJAX router; QuoteRequest Pro used it, but
so did four other plugins, a page-view counter, and a comment-spam filter that fired on
every page load. Thirty-eight hundred lines told the analyst nothing.

### 2.2 The narrowed query

Narrowing to the source IP the WAF had logged, `203.0.113.10`, and the specific `qrp_`
action prefix QuoteRequest Pro used:

```
grep "src=203.0.113.10" access.log | grep "action=qrp_" 
→ 41 matching lines, 2026-07-18T02:47:11Z through 2026-07-18T03:22:56Z
```

Forty-one requests, not five — the WAF's correlation window had only caught a slice of a
longer session that started twenty-seven minutes earlier and continued eight minutes after
the alert fired. The early requests were plain rate lookups. Starting at 02:58:34Z, the
`zip` parameter carried increasingly deliberate SQL syntax — first a single quote to test
for an error, then a `UNION SELECT NULL,NULL,NULL` to find the column count, then, at
03:14:02Z, the payload the WAF finally flagged: a stacked query appending
`INTO OUTFILE '/var/www/trailrewards/wp-content/uploads/2026/07/rate-cache.php'`.

**[HYPOTHESIS]** That is not a data-exfiltration payload. `INTO OUTFILE` writes the result
of a query to a file on the database server's own filesystem — useful for reading data out
one way, but here the file being written was a `.php` file inside the web server's own
document root, not an export destination. Confidence moved to **Medium** at this point:
this was no longer scanner noise finding a permissive rule; this was a specific, working
technique to get a file written where the web server would execute it.

## 3. Dead end: chasing the CDN's own IP address

**[PIVOT]** Before going any further with `203.0.113.10`, the analyst tried to attribute it
— WHOIS, passive DNS, abuse-contact lookups — to build a picture of who was doing this.

> **Dead End**
> Forty minutes went into profiling `203.0.113.10`: WHOIS said it belonged to a large,
> reputable CDN provider, not a hosting-abuse ASN, which briefly looked like a point in
> favor of "this is legitimate traffic somehow." It wasn't a point in favor of anything —
> `203.0.113.10` was the CDN's own shared edge node IP, the address every visitor to the
> site shows up as in the origin's access log because the vhost's logging configuration
> never enabled `mod_remoteip`/`X-Forwarded-For` capture for this specific site. The
> profiling effort was attributing infrastructure the site's own logging gap made look like
> a single actor's IP. Whatever this told the analyst, it wasn't who.

> **Evidence Note**
> The origin access log for `trailrewards.cascadiaoutdoorgear.example` had never been
> configured to log the CDN's `X-Forwarded-For` header, unlike the main e-commerce vhost on
> the same box, which had it enabled from day one. Every visitor to the marketing site,
> legitimate or not, was recorded as the CDN edge IP. The true client IP existed — the CDN's
> own edge log carried it in a field the origin's access log simply didn't capture. Fixing
> the vhost config, not re-running the same WHOIS lookup a different way, was what actually
> resolved this.

Pulling the CDN's raw edge log (a separate system from the WAF alert feed, retained
independently) for the same forty-one requests surfaced the `X-Forwarded-For` value the
origin never recorded: `198.51.100.77` on every one of them. That was the actual source.
Reputation lookup on `198.51.100.77` returned no prior abuse history — it came back clean,
which meant nothing more than "not previously reported," not "not the attacker."

## 4. Pivot: from the access log to the host — confirming the shell and what it did

**[PIVOT]** A request that writes a file is a claim, not a fact, until something on the
host confirms the file exists, when it was created, and what it contains. That meant file
integrity monitoring (FIM) on the web server's document root, and the host's own EDR
process-creation telemetry, covering the same window as the 03:14:02Z request.

```
// FIM alert queue, trailrewards-web-01, 2026-07-18
2026-07-18T03:14:03Z FILE_CREATED path=/var/www/trailrewards/wp-content/uploads/2026/07/rate-cache.php
  owner=www-data mode=0644 size=1847
```

One second after the SQLi payload, a file matching the exact path from the injection
appeared. That much was not ambiguous.

### 4.1 The false lead

**[ANALYST]** Before treating `rate-cache.php` as confirmed malicious, the analyst checked
whether this was actually new — QuoteRequest Pro's own rate-caching feature wrote files with
similar names into the same `uploads/2026/07/` directory on a legitimate hourly cron job, and
one of those, `rate-cache-2026-07-18.php.bak`, already existed from that morning's run.

> **False Lead**
> The filename `rate-cache.php` looked, at a glance, like it belonged to the plugin's own
> legitimate hourly cache job, which writes similarly named files to the same directory —
> enough of a naming coincidence that the analyst almost logged this as "plugin's own
> cache artifact, not related" and moved on. The plugin's real cache files all carry a
> `.bak` extension and a date-stamped filename by design, confirmed against the plugin's own
> published changelog; this file had neither, and its creation timestamp — 03:14:03Z — fell
> one second after the injection request, not on the plugin's hourly cron boundary. The
> naming similarity was coincidence, not cover; the timestamp and the missing `.bak`
> extension were what actually separated the two.

Pulling the file's content (read-only, off a snapshot, per the containment procedure in
`web-shell-detection.md`) confirmed it: a single `<?php` block wrapping a base64-encoded
payload that decoded to a generic command-execution shell — read a parameter from the
request, pass it to `shell_exec()`, echo the result. This is the file-write half of
T1505.003 (Server Software Component: Web Shell); the injection itself is T1190 (Exploit
Public-Facing Application).

> **Hypothesis Board — after the host-level pivot**
> 1. **Background scanner noise that happened to hit a permissive rule** — ruled out. A
>    scanner doesn't escalate from a quote-count probe to a targeted `INTO OUTFILE` payload
>    against a path it just enumerated, and nothing about `rate-cache.php`'s content or
>    creation timing is explained by automated background noise.
> 2. **The file is a legitimate plugin cache artifact, misnamed by coincidence** — ruled
>    out. Confirmed against the plugin's own naming convention and the file's decoded
>    content, which is a web shell, not a cache payload.
> 3. **A working web shell was placed via SQL injection, and the attacker has code
>    execution on the host** — supported. Direct evidence: the injection payload, the FIM
>    file-creation event one second later, and the decoded shell content, from three
>    independent sources agreeing on the same file, the same timestamp, and the same intent.
> **Current confidence:** Medium-High, rising.

### 4.2 What the shell actually did

**[PIVOT]** A dropped shell that was never used is a different, smaller problem than one
that was. The access log for requests to `/wp-content/uploads/2026/07/rate-cache.php`
itself, and the host's EDR process tree for `trailrewards-web-01` in the same window,
answered whether it had been used.

```
// origin access log, filtered to the shell's own path
2026-07-18T03:16:44Z src=203.0.113.10 method=GET path=/wp-content/uploads/2026/07/rate-cache.php?c=whoami status=200
2026-07-18T03:16:58Z src=203.0.113.10 method=GET path=/wp-content/uploads/2026/07/rate-cache.php?c=id status=200
2026-07-18T03:17:41Z src=203.0.113.10 method=GET path=/wp-content/uploads/2026/07/rate-cache.php?c=uname+-a status=200
2026-07-18T03:19:12Z src=203.0.113.10 method=GET path=/wp-content/uploads/2026/07/rate-cache.php?c=cat+/etc/passwd status=200
```

```
// EDR process-creation telemetry, trailrewards-web-01
2026-07-18T03:16:44Z parent=apache2 child=/bin/sh -c whoami
2026-07-18T03:16:58Z parent=apache2 child=/bin/sh -c id
2026-07-18T03:17:41Z parent=apache2 child=/bin/sh -c "uname -a"
2026-07-18T03:19:12Z parent=apache2 child=/bin/sh -c "cat /etc/passwd"
```

This is the pattern SOC Playbook Handbook `rce.md` names explicitly: a web server worker
process (`apache2`) spawning a shell is never expected behavior, regardless of what command
runs. The commands themselves were low-value reconnaissance — `whoami`, `id`, `uname -a`, a
read of `/etc/passwd` — the kind of first-minute orientation any operator runs right after
gaining a foothold, not evidence of a specific further objective yet. This maps to T1082
(System Information Discovery) layered on top of the T1505.003 foothold. Two independent
sources, the access log and the EDR process tree, agreed on the same four timestamps and the
same four commands. **Confidence: High, settled on the foothold; still open on scope.**

This is close to the raw shape of `DET-16-04` in DEH V2 Part 16's web detection engineering
chapter — the web-server-process-spawns-a-shell correlation — but the analyst was working
from the access log and the EDR feed directly, not the tuned production correlation rule;
Part 16 is where that rule lives in its finished form, and this case doesn't re-derive it.

## 5. Did this stay in the DMZ?

**[PIVOT]** Four reconnaissance commands confirm a foothold. They don't confirm scope. The
web server sat in a segmented DMZ subnet with a firewall policy that should only permit it
to reach its own application database, nothing else internal. Whether that policy actually
held was the next question, and it needed the perimeter firewall log, not another host
artifact.

**[HYPOTHESIS]** Two competing pictures at this point: the compromise stayed contained to
one DMZ host talking only to its own database, the blast radius this architecture was
designed to permit even in a worst case — or the attacker had already used the shell to
probe or reach further into the internal network, which would turn a single-host cleanup
into a much larger incident.

```
// DMZ perimeter firewall log, trailrewards-web-01 (192.0.2.15), 2026-07-18 02:30–04:00Z
2026-07-18T02:31:07Z src=192.0.2.15 dst=192.0.2.20 dport=3306 action=allow  // app DB, expected
2026-07-18T02:30:00Z–04:00:00Z src=203.0.113.10 dst=192.0.2.15 dport=443 action=allow  // CDN edge traffic, expected
2026-07-18T03:14:00Z–04:00:00Z src=192.0.2.15 dst=192.0.2.0/24 action=deny  // 0 matches
```

No denied or allowed connections from `192.0.2.15` to any other internal host in the
`192.0.2.0/24` range showed up across the ninety-minute window — not even a denied attempt.
Nor did the full log pull for the window surface any other outbound connection from the host
at all, beyond the one expected database call and the CDN's own inbound edge traffic. A
`shell_exec()`-based shell like this one takes its commands and returns its output entirely
inside the same inbound HTTP request/response cycle the CDN already proxies; it never needed
a second, outbound channel for this firewall to catch. The segmentation policy the network
team had designed for exactly this scenario had held.

> **Hypothesis Board — after the firewall pivot**
> 1. **Compromise contained to the one DMZ host** — supported. Zero internal connection
>    attempts, allowed or denied, from the compromised host across the full window; no
>    outbound connection of any kind beyond the one expected database call, consistent with
>    a shell whose entire command-and-response cycle rides inside inbound HTTP traffic the
>    CDN already proxies.
> 2. **Attacker already pivoted into the internal network** — ruled out, on current
>    evidence. No firewall log entry of any kind supports it, and this policy logs denies as
>    well as allows, so a blocked attempt would still have appeared.
> **Current confidence:** High, settled.

> **Blind Spot**
> The firewall log confirms the compromise didn't spread past this one host over the
> network. It cannot confirm what the attacker read from the application database over the
> *legitimate*, allowed connection on port 3306 that this host was always permitted to make.
> Query-level auditing wasn't enabled on that database, only connection-level logging. If
> the attacker ran a `SELECT` against the quote-request table — which stores names, email
> addresses, and ZIP codes submitted through the form — over that already-permitted
> connection sometime in the ninety-minute window, this evidence set cannot see it and never
> will. Closing this as contained-to-one-host does not mean closing it as no-data-exposure;
> those are two different claims, and only the first one is proven here.

## 6. Escalation, containment, and closure

**[ESCALATION]** At 05:40 UTC, with the foothold confirmed by three independent sources
(WAF/CDN log, origin access log plus FIM, and EDR process telemetry) and scope confirmed
contained by a fourth (firewall log), the analyst escalated to the on-call incident
commander as a confirmed True Positive, severity High: active remote code execution on a
public-facing host via a web shell, contained to that host, unresolved question on database
read scope.

Containment actions taken immediately: the web server was isolated at the network layer
(outbound and inbound traffic blocked except to the SOC's own forensic collection subnet),
the shell file was preserved via snapshot before removal, the plugin's database user had its
`FILE` privilege revoked — the specific privilege that made `INTO OUTFILE` possible in the
first place — and the SQLI-UNION-002 rule's per-vhost exception was reverted to blocking
mode across the board, not just for this site.

> **Manager's Call**
> Whether the quote-request table's contents count as a reportable exposure — and whether
> affected customers need direct notification — is not a call the investigating analyst
> makes. It depends on what the database's own query logs (retroactively enabled, but only
> from this point forward) and a legal assessment of the data categories involved determine
> once forensics on the database itself completes. The SOC Manager's Operating Handbook,
> Part 27 — Legal, HR & Compliance Interfaces covers the timing tradeoff (evidence
> preservation vs. tipping off the employee) in full; this case does not re-derive it, only
> marks the point where the analyst's job — confirm the technical scope — ends and the
> incident commander's and legal's begins.

**Disposition: True Positive.** **Outcome flavor: Obvious.** The foothold, the mechanism,
and the contained scope were each confirmed by at least two independent log sources with no
unresolved contradiction between them — the WAF/CDN log and the origin access log agreed on
the injection; the FIM feed and the shell's decoded content agreed on what was dropped; the
access log and the EDR process tree agreed on what ran; the firewall log independently
confirmed no lateral spread. **Confidence at close: High, settled.**

> **What Would Change My Mind**
> This closes at High confidence on the foothold and the contained scope specifically —
> those two claims have direct, multi-source evidence with no gaps. It would take a specific
> new fact to revise either: evidence that `198.51.100.77` was itself a compromised
> third-party relay rather than the attacker's own infrastructure would reopen the
> attribution question (though not the technical scope, which the firewall log settles on
> its own). On the one claim this case does not close at High — what was read from the
> database over the legitimate connection — the retroactively enabled query log picking up a
> second, similar access pattern from the same session window would be the fact that turns
> the Blind Spot in §5 into a confirmed data-access finding instead of an open question.

## 7. Lesson learned

**[LESSON LEARNED]** The technical chain here — SQL injection to file write to shell to
discovery — is the textbook version DEH V2 Part 47's web compromise model already
documents, and it played out with almost no deviation from that model. What made this case
worth writing was not the chain; it was the two infrastructure gaps that shaped how long it
took to confirm, both of which generalize far past this one marketing microsite. First: a
per-vhost WAF exception created under deadline pressure eight months earlier, with no
expiration and no follow-up ticket, is a standing control gap masquerading as a closed
incident — any organization running a shared WAF across multiple properties should audit
per-path rule exceptions on a schedule, not wait for the exception itself to be the reason an
exploit succeeds. Second: a vhost that doesn't capture the real client IP behind a CDN turns
every investigation on that vhost into an attribution problem before it's a technical one;
this is a logging-configuration checklist item, not a detection-engineering one, and it
belongs in onboarding for any new public-facing site, not just the ones IT already knows
about. The permanent fixes — restoring SQLI-UNION-002 to blocking mode fleet-wide and adding
`X-Forwarded-For` capture to every vhost's logging config as a build standard — are process
changes, not new detections; DEH V2 Part 16 owns the detection-side tuning this case's
findings feed into, and this case's job ends at handing that finding off, not implementing
it.

---

**Cross-references:** SOC Playbook Handbook `sql-injection.md`, `web-shell-detection.md`, `rce.md`; DEH V2 Part 16 (web-layer detection mechanics, `DET-16-04` cross-referenced) and Part 47 (web compromise model, cross-referenced, not re-narrated); SOC Manager's Operating Handbook Part 27 — Legal, HR & Compliance Interfaces.
