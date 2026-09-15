---
title: "CB-07 — Slow Beacon, Fast Conclusion"
case_id: "CB-07"
category: "Network"
disposition: "True Positive"
outcome_flavor: "Obvious"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook beaconing.md", "SOC Playbook Handbook c2-communication.md", "SOC Playbook Handbook dns-tunnelling.md", "DEH V2 Part 14 (DET-14-03)", "DEH V2 Part 15 (DET-15-01, HUNT-15-01)", "SOC Manager's Operating Handbook Part 25"]
---

# CB-07 — Slow Beacon, Fast Conclusion

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative. "Halcyon Freight
Systems," its staff, and every host, account, domain, and IP address named below are
invented; no real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

Most beaconing writeups make the interval short and the tell obvious — a five-minute
check-in is easy to flag and easy to write up. This case teaches the opposite shape: a
beacon deliberately built to sit inside the exact window a standing detection's own
documentation admits is its weakest spot — an interval long enough, and a jitter tight
enough, to look for hours like the kind of legitimate scheduled infrastructure that
detection is *supposed* to ignore. It does not re-narrate the coefficient-of-variation
beaconing logic itself, which belongs to Detection Engineering Handbook V2 Part 14 §2.1
(`DET-14-03`) and is cited here, not rebuilt. It also does not cross into DNS-tunnelling
territory — the SOC Playbook Handbook's `dns-tunnelling.md` and Part 15 §9 own that
channel-encoded-in-the-query-name pattern; this beacon's DNS lookup is a single ordinary
resolution feeding a first-seen-domain enrichment signal (`DET-15-01`), not the covert
channel itself. What this case does narrate: how long it took, and how many separate
non-C2 explanations had to fail, before a single process-level pivot ended the argument
in one query.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-07` |
| Category | Network |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | Standing correlation alert — connection-interval beaconing (`DET-14-03` logic) joined to a first-seen-apex-domain signal (`DET-15-01` logic) |
| Primary log sources | Proxy/netflow connection logs, DNS resolver logs, CMDB and change-management records, passive DNS and WHOIS, Sysmon Event ID 1 and Event ID 3, Security Event ID 4698, TLS certificate metadata |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `beaconing.md`, `c2-communication.md`, `dns-tunnelling.md`; Detection Engineering Handbook V2 Part 14 — Network Detection Engineering (`DET-14-03`), Part 15 — DNS Detection Engineering (`DET-15-01`) |
| All times | UTC |

## 1. A rule that had been right for a day and a half before anyone read it

**[CONCEPT]** Halcyon's SIEM runs a correlation rule built from two separate signals that
neither one, alone, is trusted to alert on: connection-interval regularity between a
source and destination (the coefficient-of-variation logic in `DET-14-03`) and a
first-seen apex domain outside the environment's rolling baseline (`DET-15-01`). Neither
signal is a verdict by itself — `DET-14-03`'s own documentation names scheduled internal
automation as its single biggest false-positive source, and `DET-15-01` flags hundreds of
new domains a day on unrestricted web traffic. Joined together, though, a destination that
is both brand-new to the environment *and* being talked to on a tight, regular schedule is
a much narrower set. That's the rule that fired.

**[ANALYST]** The ticket landed at 14:22 UTC on 2026-09-14, on the sole SOC analyst
covering Halcyon's day shift — the overnight and weekend queue is watched by a managed
detection vendor, and this was the first thing waiting in the handoff when the vendor's
shift ended. Host `APP-DISPATCH-02` (192.0.2.45), a Windows Server 2019 box running
Halcyon's route-dispatch application, had made more than twenty connections to
`api.merqroute-metrics.io` (203.0.113.77) over the prior day and a half, with a
coefficient of variation under 0.15 on the inter-connection interval and no prior history
of that apex domain anywhere in the thirty-day baseline. The rule had been watching this
pair since the very first connection. At an average interval of 54 minutes — close enough
to `DET-14-03`'s one-hour ceiling that each connection barely counted toward the
statistic — crossing the `connections > 20` floor alone took most of a day on its own; the
rule doesn't re-score a pair continuously, so the ticket didn't actually land in the queue
until the next scheduled evaluation pass caught it, a full day and a half after that very
first connection.

## 2. The shape this detection is built to wave through

**[ANALYST]** The first question wasn't "is this bad" — it was "is this even unusual for
this host." `APP-DISPATCH-02` runs Halcyon's dispatch and route-optimization application,
and that application has a documented, sanctioned integration with a routing-data vendor
called MerqRoute. A server that talks to one external vendor on a fixed schedule is not,
on its own, strange. A 54-minute interval with light jitter is also exactly the shape
`DET-14-03`'s documentation warns will look like "cron-driven syncs, monitoring-agent
heartbeats, license-check phone-homes" — the analyst's own production rule had, in effect,
pre-flagged its own most likely false-positive shape before the analyst even opened the
ticket.

**[HYPOTHESIS]** Two questions needed answers before either explanation was worth
committing to: does Halcyon's actual, sanctioned MerqRoute integration talk to
`api.merqroute-metrics.io`, or to something else — and is `api.merqroute-metrics.io` a
domain that has existed, doing this, for longer than thirty days, just outside whatever
window fed the baseline. A third, smaller question got checked first and closed fast: NOC
maintains its own allowlist of destinations used by internal scheduled automation
(license checks, monitoring heartbeats, backup jobs) specifically because `DET-14-03`'s
documentation calls that the expected noise source. Neither the hostname nor the
destination IP appeared on it. That ruled out "this is our own automation hitting an
unlisted destination" in under five minutes — the two questions that remained were the
ones worth real time.

**[ANALYST]** Those two remaining questions mattered because they pointed at different
next steps entirely. If the real MerqRoute integration was somehow behind this traffic,
the fix was a five-minute call to the app owner confirming a vendor-side change, and the
case closed as Expected Activity by lunch. If it wasn't, everything downstream — the
domain's age, who registered it, what process on the host was actually making the
connection — needed to be pulled before anyone could say which. Nothing about the proxy
log alone could tell the difference, which made it the wrong log source to try to answer
either question from directly.

## 3. Confirming the pattern before trusting the rule's own summary

**[PIVOT]** The correlation rule's own output gave a count and a coefficient of variation,
not the raw connection list. Pulling that list directly from proxy logs was the first
move, and — closer to the raw shape of `DET-14-03` than the tuned production version, since
the analyst wanted the actual rows, not a re-run of the aggregate statistic — the first
query was too broad.

### 3.1 The too-broad first pull

```spl
// too broad — see next query
index=proxy src_ip="192.0.2.45" earliest=-7d
| stats count by dest_host
| sort - count
```

**[ANALYST]** That returned 1,847 distinct destination hostnames over seven days —
ordinary background noise from Windows Update, telemetry endpoints, and the browser most
admins leave open on a server they shouldn't be browsing from at all (a separate, smaller
finding logged for IT hygiene and not pursued further here). Nothing in that list
narrowed anything down.

### 3.2 Narrowing to the one destination

```spl
index=proxy src_ip="192.0.2.45" dest_host="api.merqroute-metrics.io" earliest=-2d
| table _time, src_ip, dest_host, dest_ip, dest_port, bytes_out, bytes_in
| sort _time
```

```text
2026-09-13 02:18:04  192.0.2.45  api.merqroute-metrics.io  203.0.113.77  443   612  1904
2026-09-13 03:12:47  192.0.2.45  api.merqroute-metrics.io  203.0.113.77  443   598  1877
2026-09-13 04:07:19  192.0.2.45  api.merqroute-metrics.io  203.0.113.77  443   604  1921
2026-09-13 05:01:58  192.0.2.45  api.merqroute-metrics.io  203.0.113.77  443   611  1889
...
2026-09-14 13:18:26  192.0.2.45  api.merqroute-metrics.io  203.0.113.77  443   609  1902
2026-09-14 14:12:03  192.0.2.45  api.merqroute-metrics.io  203.0.113.77  443   611  1898
```

**[HYPOTHESIS]** Forty connections, every one to the same IP, every one on port 443,
intervals clustered tightly around 54 minutes with a handful of minutes of jitter —
enough to defeat a naive fixed-interval check, not enough to clear `DET-14-03`'s
coefficient-of-variation floor. This was the pattern, confirmed from the raw log rather
than trusted from the rule's summary alone.

> **Evidence Note**
> Halcyon's proxy does not perform TLS inspection on this traffic category, so the log
> above is metadata only — server name indication, timing, and encrypted byte counts.
> Nothing in this log source can say what's actually inside these sessions, only that
> something is being exchanged on a tight, repeating schedule. Confirming content, not
> just shape, was always going to require a pivot off this log source entirely.

## 4. Testing the vendor explanation against the change ticket

**[HYPOTHESIS]** Hypothesis one: this is Halcyon's real MerqRoute integration, and
`api.merqroute-metrics.io` is a new or rotated endpoint the vendor stood up that nobody
told the SOC about. That's a mundane, common failure mode — vendors change infrastructure
without always routing the change through the customer's change-management process — and
it deserved a real check before being set aside.

**[PIVOT]** The change-management system held the answer. Halcyon's firewall rule
permitting `APP-DISPATCH-02` to reach MerqRoute was approved under a change ticket from
November 2025, ten months old at the time of this alert.

```text
CHG-2025-1142 — Approved 2025-11-06
Requested by: Dispatch Systems (App Owner: R. Iyer)
Change: Permit outbound HTTPS from APP-DISPATCH-02 to api.merqroute.io (MerqRoute
Technologies Inc. routing-data API). Sanctioned vendor integration per contract
MRQ-4471. Service account: svc-dispatch-merqroute.
```

`api.merqroute.io` — not `api.merqroute-metrics.io`. Close enough to read past at a glance,
different enough to matter. This didn't rule out Hypothesis One on its own; vendors do
occasionally add a second, metrics-specific subdomain. It did mean the sanctioned
integration and the alerting traffic were, on paper, two different destinations, and the
burden of proof had shifted.

> **Hypothesis Board — after the change-ticket pivot**
> 1. **Legitimate MerqRoute integration, new or rotated endpoint** — weakened. The
>    documented, sanctioned destination is a different hostname (`api.merqroute.io`), not
>    the one alerting. Possible the vendor added a second endpoint and never told anyone;
>    not yet ruled out.
> 2. **Lookalike domain, attacker-controlled infrastructure** — supported, not confirmed.
>    The name is close enough to the real vendor's domain to pass a casual review, which
>    is a stronger signal for T1036.005 (Masquerading: Match Legitimate Name or Location)
>    than for coincidence, but naming similarity alone isn't proof of malice.
> **Current confidence:** Medium, rising.

## 5. A domain with three weeks of history, not three years

**[PIVOT]** If `api.merqroute-metrics.io` were a legitimate second endpoint the vendor
quietly stood up, its registration and resolution history should look like ordinary
vendor infrastructure — registered years ago, resolving to a stable range, showing up in
passive DNS well before this week. If it were built for this specific beacon, the history
should be short and thin.

### 5.1 WHOIS on the lookalike domain

```text
Domain Name: MERQROUTE-METRICS.IO
Creation Date: 2026-08-27T09:14:00Z
Registrar: <redacted registrar>
Registrant Organization: REDACTED FOR PRIVACY
Name Server: ns1.bulkdns-example.net
Name Server: ns2.bulkdns-example.net
```

**[ANALYST]** Eighteen days old at the time of the alert, registered through a privacy
proxy, on bulk nameservers unconnected to any infrastructure MerqRoute's real domain uses.

### 5.2 Passive DNS on both domains

```text
api.merqroute-metrics.io
  first_seen: 2026-08-27   last_seen: 2026-09-14   distinct_ips: 1 (203.0.113.77)

api.merqroute.io
  first_seen: 2023-04-02   last_seen: 2026-09-14   distinct_ips: 3
    (198.51.100.20, 198.51.100.21, 198.51.100.22 — stable CDN-style rotation)
```

**[HYPOTHESIS]** The real vendor domain has three years of passive DNS history and
rotates across a small, stable set of addresses — ordinary CDN behavior. The lookalike
domain has eighteen days of history, one IP, ever. That's not what a quietly-added
second vendor endpoint looks like.

> **False Lead**
> The proxy's own URL-category feed listed `api.merqroute-metrics.io` as
> "Uncategorized — Business/Technology," not flagged, not blocked. For a few minutes that
> read as mildly reassuring — if this were known-bad infrastructure, wouldn't a reputation
> feed have caught it by now? It hadn't, because category feeds crawl and classify
> domains over time, and this one was eighteen days old. "Uncategorized" here meant "not
> yet crawled," not "checked and found clean." Absence of a bad reputation is not evidence
> of a good one on a domain this young.

## 6. The hosting angle that led nowhere

**[PIVOT]** With the domain's own history pointing away from Hypothesis One, the next
obvious move was the destination IP's hosting context — infrastructure reputation can
sometimes settle a case on its own, in either direction.

> **Dead End**
> ASN and hosting-reputation data for 203.0.113.77 went into the queue next, on the theory
> that a listed C2-associated ASN would confirm Hypothesis Two outright, or a known CDN or
> SaaS range shared with a vendor Halcyon actually uses would clear it the way a
> shared-hosting explanation sometimes does. Neither happened. The address belongs to a
> low-cost VPS reseller with no reputation listing on either side and no association with
> any vendor in Halcyon's own SaaS inventory. This line of inquiry closed with nothing added
> to either hypothesis — it simply wasn't going to be the source of the deciding evidence.

## 7. What was actually running on the host

**[PIVOT]** Everything so far described the network's view of the pattern and the
domain's own paper trail. Neither one could say what process on `APP-DISPATCH-02` was
actually making these connections, and that was the one fact that could settle the case
outright — the real MerqRoute integration runs as a specific, known service; anything
else making this connection has no legitimate explanation on this host at all.

### 7.1 The process-creation record

```text
Event ID 1 (Process Creation) — APP-DISPATCH-02, 2026-09-13 02:16:41 UTC
  ParentImage: C:\Windows\System32\svchost.exe
  ParentCommandLine: svchost.exe -k netsvcs -p
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  CommandLine: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBl...
  User: NT AUTHORITY\SYSTEM
  ProcessGuid: {b1e28f3a-6a12-4a99-9e77-2f0c114d55aa}
```

```text
Event ID 4698 (A scheduled task was created) — APP-DISPATCH-02, 2026-09-13 02:16:38 UTC
  Task Name: \MerqRouteSync
  Task Content: <Exec><Command>powershell.exe</Command>
    <Arguments>-NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBl...</Arguments></Exec>
  Creator: NT AUTHORITY\SYSTEM
```

**[HYPOTHESIS]** A scheduled task named `MerqRouteSync` — deliberately close to the real
integration's own naming, T1036.005 (Masquerading: Match Legitimate Name or Location)
again — created sixteen days after the lookalike domain's registration and just two
minutes before the first beacon connection, running an encoded PowerShell command via
T1053.005 (Scheduled Task/Job: Scheduled Task), not the vendor's actual integration
service.

### 7.2 The network-connection join

```text
Event ID 3 (Network Connection) — APP-DISPATCH-02, 2026-09-13 02:18:04 UTC
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  ProcessGuid: {b1e28f3a-6a12-4a99-9e77-2f0c114d55aa}
  DestinationIp: 203.0.113.77
  DestinationPort: 443
```

**[ANALYST]** Same `ProcessGuid`, same server, first connection two seconds after the
timestamp the proxy log already showed. This was the process making every one of the
forty connections in Section 3.2 — not `DispatchSync.exe`, the real MerqRoute
integration binary, which was still running normally under its own service account the
entire time and had never once touched `api.merqroute-metrics.io`.

> **Hypothesis Board — after the process-correlation pivot**
> 1. **Legitimate MerqRoute integration, new or rotated endpoint** — ruled out. The real
>    integration's own process never made these connections; a separate, disguised
>    scheduled task did, running under `SYSTEM`, not the vendor's service account.
> 2. **Lookalike domain, attacker-controlled infrastructure** — confirmed. A task named to
>    resemble the vendor integration, created two minutes before the beacon started,
>    running encoded PowerShell against an eighteen-day-old domain one letter-group away
>    from the real vendor's own.
> **Current confidence:** High, settled.

> **Analyst's Gut Check**
> A hostname that's almost your vendor's real one is worth a change-ticket check before
> anything else — not a WHOIS lookup, not a reputation feed. The fastest way to catch a
> lookalike is to compare it against the one document that says what the sanctioned
> destination is actually supposed to be, because a human reading both names side by side
> in a ticket will catch a one-word difference faster than most automated similarity
> scoring will.

### 7.3 One more thing, logged for the record

**[CONCEPT]** By the time this pivot ran, the disposition was already settled — this was
corroboration, logged for the incident record rather than to move confidence further.

```text
api.merqroute-metrics.io
  Issuer: Let's Encrypt (R11)
  Not Before: 2026-08-28 03:02:11 UTC
  Not After:  2026-11-26 03:02:10 UTC
  SAN: api.merqroute-metrics.io only

api.merqroute.io (Halcyon's real vendor integration)
  Issuer: DigiCert Global CA
  Subject: CN=*.merqroute.io, O=MerqRoute Technologies Inc., L=Denver, ST=Colorado, C=US
  Not Before: 2026-01-15   Not After: 2027-01-14
```

A single-hostname, domain-validated certificate issued the day after the lookalike domain
was registered, against an organization-validated wildcard certificate the real vendor has
renewed on the same subdomain for years — the current cert is only months old, but the CDN
rotation above and three years of passive DNS history are what actually establish the
vendor's tenure, not this one artifact's own dates. Nothing about the certificate
contradicted anything already established; it simply matched the shape everything else had
already shown.

## 8. Closing the loop, then closing the ticket

### 8.1 Checking for spread before closing the loop

**[PIVOT]** Before writing up a disposition, the analyst ran one more query — fleet-wide,
this time, rather than against `APP-DISPATCH-02` alone — pulling every host with a
scheduled task named `MerqRouteSync` or any process history touching
`api.merqroute-metrics.io` or 203.0.113.77.

```spl
index=proxy dest_host="api.merqroute-metrics.io" OR dest_ip="203.0.113.77" earliest=-30d
| stats values(src_ip) as sources
```

```text
sources: 192.0.2.45
```

One host, one destination, thirty days back. That's evidence this specific beacon didn't
spread — it is not evidence that whatever created the scheduled task in the first place
didn't touch anything else using a different destination or a different name, a
distinction the closing Blind Spot and What Would Change My Mind sections both come back
to.

**[ESCALATION]** This closed as **True Positive** — a beacon riding attacker-controlled
infrastructure disguised as a vendor integration, T1071.001 (Application Layer Protocol:
Web Protocols) and T1573 (Encrypted Channel) for the channel itself, T1008 (Fallback
Channels) per `DET-14-03`'s own mapping, T1584.001 (Compromise Infrastructure: Domains)
for the lookalike domain's acquisition, and T1053.005 (Scheduled Task/Job: Scheduled Task)
for the persistence mechanism. The analyst blocked `api.merqroute-metrics.io` and
203.0.113.77 at the proxy and perimeter
firewall, disabled the `MerqRouteSync` scheduled task, and opened an incident ticket for
forensic imaging of `APP-DISPATCH-02` and rotation of the `svc-dispatch-merqroute` service
account credentials — standard containment steps for a confirmed beacon per the SOC
Playbook Handbook's `beaconing.md` and `c2-communication.md`.

> **Manager's Call**
> Full containment meant taking `APP-DISPATCH-02` off the network during the middle of a
> weekday dispatch shift, which stops live route assignments for Halcyon's fleet. Whether
> to isolate immediately or hold the host live-but-blocked until the evening maintenance
> window, accepting the risk that a still-running implant might have a fallback channel
> the block doesn't cover, is a business-impact call for the incident commander, not the
> analyst. The SOC Manager's Operating Handbook Part 25 — Risk Acceptance &
> Manager Decision-Making Under Uncertainty covers that tradeoff in full; this case shows where
> the analyst's evidence ends and that decision begins, not how the decision was made.

> **Blind Spot**
> Nothing gathered here explains how `MerqRouteSync` got created in the first place —
> whether through a vulnerability specific to `APP-DISPATCH-02`, a compromised admin
> credential, or something further upstream. Every log source in this case starts at
> 02:16:38 UTC on 2026-09-13, the moment the task appeared, and none of them can see
> earlier than that. That question belongs to the forensic imaging already opened, not to
> this case.

## 9. What this beacon actually cost, and what would catch it sooner next time

**[LESSON LEARNED]** `DET-14-03`'s own falsifiability note warns that modern C2 jitter in
the thirty-to-fifty-percent range would defeat coefficient-of-variation beaconing
detection entirely. This beacon's jitter was much tighter than that, which is exactly why
the rule still caught it — but the design choice that actually cost the most analyst time
wasn't the interval, it was the domain name. A destination one letter-group away from a
real, sanctioned vendor is a cheap way to buy hours of a legitimate-integration hypothesis
before anyone checks it directly. The fix that generalizes past this one case: any
allowlist or change-ticket entry for a vendor integration should record the exact,
literal FQDN, and any alert on a *similar-but-different* hostname to an allowlisted entry
should route to analyst review with that similarity called out explicitly, rather than
relying on an analyst to notice a one-word difference on a tired read-through. The other
generalizable gap: `DET-14-03`'s interval ceiling of one hour means a beacon tuned to
check in every ninety minutes or longer sits outside this standing rule's coverage
entirely, not just inside its noisier edge — the same low-and-slow logic `HUNT-15-01`
already applies to DNS subdomain fan-out below its own alerting threshold is worth
building as an equivalent hunt for connection intervals above `DET-14-03`'s ceiling,
before the next version of this beacon is tuned to sit just past it.

A smaller, more mundane lesson closes the case: the fleet-wide destination check in
Section 8.1 took under a minute to run and materially changed the confidence attached to
"this is contained." Running that check is cheap enough that it belongs in the standard
`beaconing.md` disposition workflow as a required step before closing any confirmed
beacon, not an optional extra a busy analyst skips when the primary hypothesis already
feels settled.

> **What Would Change My Mind**
> The disposition itself is settled — the process-level evidence in Section 7 isn't
> going to be overturned by anything found later. What's still open is scope: whether
> `MerqRouteSync` was created through something specific to `APP-DISPATCH-02` (an
> unpatched local vulnerability, one stolen credential) or through a broader compromise
> that reaches other hosts. If forensic imaging finds evidence of lateral movement
> predating the task's creation, or a second host with its own version of this same
> lookalike-domain pattern, this stops being a single-host containment and becomes a
> wider incident.

---

**Cross-references:** SOC Playbook Handbook `beaconing.md`, `c2-communication.md`,
`dns-tunnelling.md`; Detection Engineering Handbook V2 Part 14 — Network Detection
Engineering (`DET-14-03`), Part 15 — DNS Detection Engineering (`DET-15-01`,
`HUNT-15-01`); SOC Manager's Operating Handbook Part 25 — Risk Acceptance & Manager
Decision-Making Under Uncertainty.
