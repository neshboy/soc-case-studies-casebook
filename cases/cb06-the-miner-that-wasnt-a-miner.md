---
title: "CB-06 — The Miner That Wasn't a Miner"
case_id: "CB-06"
category: "Endpoint"
disposition: "Benign Positive"
outcome_flavor: "Benign"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook unsigned-binary-execution.md", "SOC Playbook Handbook beaconing.md", "SOC Manager's Operating Handbook Part 27"]
---

# CB-06 — The Miner That Wasn't a Miner

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks into one continuous narrative. "Corvane
Underwriting," its staff, and every host, account, domain, and IP address named below are
invented; no real organization, employee, incident, or breach is depicted or implied.*

## Why this case exists

This case teaches that "confirmed, with a clean technical signature" and "confirmed as a
security incident" are two different claims, answered by two different evidence chains, and
that a case can hold the first at full confidence for its entire length while the second one
flips underneath it. It deliberately does not re-derive what makes an unsigned binary
suspicious or what makes outbound traffic "beacon-shaped" — SOC Playbook Handbook
`unsigned-binary-execution.md` and `beaconing.md` own that mechanic in full, cited here and
never rebuilt. What this case owns instead is the moment a textbook-clean finding — an
unsigned process, sustained CPU, a beacon-regular outbound connection, everything a
correlation rule was built to catch, caught correctly — still forks into two entirely
different response paths depending on one fact those playbooks' detection logic cannot
supply on its own: who started it, and why. This case does not adjudicate what happens to
that "why" once it turns out to be a person, not an attacker; it hands that decision to the
SOC Manager's Operating Handbook, Part 27, at the exact point the SOC's own job ends.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-06` |
| Category | Endpoint |
| Disposition | Benign Positive |
| Outcome flavor | Benign |
| Confidence at close | High, settled |
| Entry point | Standing EDR/SIEM correlation alert (unsigned binary + sustained high CPU + regular outbound beacon) |
| Primary log sources | EDR process-creation and file-creation telemetry, host firewall/proxy egress log, DNS query log, Windows Security log (logon/lock events), physical badge-access log, VPN concentrator log |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `unsigned-binary-execution.md`, `beaconing.md`; SOC Manager's Operating Handbook, Part 27 — Legal, HR & Compliance Interfaces |
| All times | UTC |

## 1. A threshold trips at 03:14, and the easy half of the question closes in ten minutes

**[CONCEPT]** A correlation rule built around "unsigned binary, sustained CPU, regular
outbound connection" is designed to catch a specific technique, not a specific actor: T1496
(Resource Hijacking), most commonly cryptocurrency mining running on hardware its owner
never budgeted for. SOC Playbook Handbook `unsigned-binary-execution.md` owns the
signing-and-provenance checks that flag the binary; `beaconing.md` owns the interval and
jitter math that flags the traffic as regular rather than incidental. Both playbooks are
explicit that they detect the *shape* of the behavior. Neither one asks, or can ask, who is
sitting behind the keyboard that started it.

At 03:14 UTC on Tuesday, September 8, 2026, the overnight analyst — solo on shift, the
second-shift handoff still six hours out — picked up `ALERT-EP-0442`, a correlation alert on
host `CU-WKSTN-2231`. The host belonged to Priya Chandran, a senior underwriting analyst in
Corvane Underwriting's commercial-lines group, a specialty managing general underwriter with
a few hundred desk staff split across two office floors. The alert's own summary line read:
`xmrig.exe — unsigned — 96h+ sustained CPU >90% — 1 persistent outbound session`.

**[ANALYST]** The alert card gave more than enough to start with: a process named
`xmrig.exe`, unsigned, running from `C:\Users\pchandran\AppData\Roaming\rig\xmrig.exe`,
consuming 92–97% CPU across seven of eight logical cores, continuously, for more than 96
hours — long enough to cross the rule's 72-hour sustained-load threshold and finally fire.
One persistent outbound TCP session had stayed open the entire time.

None of that took long to place. XMRig is real, public, open-source cryptomining software —
legitimately used by individuals who mine on their own hardware, and just as commonly
dropped by attackers monetizing a foothold they already have. Leaving one core free while
pinning the rest is a standard mining-thread configuration, tuned so the host stays
responsive enough that nobody notices. The analyst pulled the binary's hash and the on-disk
config file in the same first ten minutes and confirmed both: this was not a resource-heavy
legitimate business tool being misclassified, it was actually XMRig, actually configured
with a live pool address, not a test file or leftover build artifact.

**Confidence: High — and that was going to hold for the rest of the shift.** Not because the
case turned out simple, but because the thing in question was never ambiguous from the first
pull. What the analyst wrote in the ticket at 03:26 UTC: *"Confirmed real, currently running
cryptominer, not a suspicious-looking false alarm. Still completely open: attacker-deployed
or self-installed."* That sentence is the shape of this entire case — one question closes in
minutes and never reopens; a second, different question takes the rest of the shift.

> **Evidence Note**
> The outbound traffic pattern a stratum-protocol miner produces — one long-lived TCP
> session, small regular bursts, no new connections — is identical whether an attacker's
> dropper started the process or the machine's own logged-in user did. Nothing in the network
> or process telemetry itself carries an intent signal. `beaconing.md`'s interval-and-jitter
> math correctly flags this traffic either way; it was never designed to answer who is on the
> other end of the keyboard, and this case is a clean illustration of why that's a separate
> evidence chain, not a missing feature.

## 2. What the wire is actually doing

**[ANALYST]** Four questions shaped where to look next, in order of how fast each one could
be answered: Was `xmrig.exe` launched moments ago by something else on the host — a dropper,
a macro, a scheduled task under a service account — or has it simply been running
undisturbed for a while? Is the destination pool a known-hostile address, or a dual-use one
that tells us nothing about intent on its own? Was anyone logged on at the console when this
started, and is that the same account the host is assigned to? And is there anything *else*
on this host — lateral movement, credential access, a second implant — that would only make
sense if this were part of a larger compromise rather than one isolated process? The alert
card couldn't answer any of them; it only confirmed the process existed and had been running
long enough to cross a duration threshold.

**[PIVOT]** The EDR agent's own network module logs new socket events, but a threshold-based
alert like this one fires on a process that has already been running for days — the original
connection event had long since scrolled out of the module's short local buffer. Confirming
what the live session was actually doing meant the firewall's egress log and the DNS
resolver log, both of which retain independently of the endpoint agent.

### 2.1 The too-broad first query

```text
// firewall egress log, too broad — see next query
grep "192.0.2.87" firewall.log | grep "2026-09-08"
→ 4,106 matching lines
```

`192.0.2.87` was `CU-WKSTN-2231`'s internal address. Everything the host had touched that
day — Windows Update, the mail client, three internal line-of-business apps, this connection
— came back in one pull. Not useful on its own.

### 2.2 The narrowed query

```text
grep "192.0.2.87" firewall.log | grep "dport=3333"
```

```text
2026-09-08T03:14:02Z action=allow proto=tcp src=192.0.2.87 sport=51774 dst=203.0.113.44 dport=3333 bytes_out=182 bytes_in=964 duration=61s
2026-09-08T03:15:03Z action=allow proto=tcp src=192.0.2.87 sport=51774 dst=203.0.113.44 dport=3333 bytes_out=178 bytes_in=951 duration=61s
2026-09-08T03:16:04Z action=allow proto=tcp src=192.0.2.87 sport=51774 dst=203.0.113.44 dport=3333 bytes_out=180 bytes_in=958 duration=61s
```

One destination, one source port, held open across the entire window, with a new
small-burst entry roughly every 60 seconds — share submissions on a stratum mining
connection, not repeated reconnects. Port 3333 is a common stratum-protocol default. The DNS
log showed the same story further back:

```text
2026-08-19T14:08:22Z client=192.0.2.87 query=pool.oreblock.example qtype=A answer=203.0.113.44 ttl=300
```

The domain resolved to `203.0.113.44` as far back as August 19 — three weeks before the
alert fired. **[HYPOTHESIS]** If this connection had been running, unremarked, for three
weeks, the correlation rule catching it on September 8 said more about the rule than about
the miner. That turned out to be exactly right: `ALERT-EP-0442` had only entered full
enforcement on September 4, during a phased rollout across the endpoint fleet. The miner
predated the detection by weeks.

### 2.3 The pool IP's secondhand reputation

**[PIVOT]** Before trusting `203.0.113.44` as merely a mining pool and moving on, the analyst
ran it against the threat-intel platform — a five-minute check that is standard on any
unfamiliar external IP, and one that briefly reopened the case in the wrong direction.

```text
IOC: 203.0.113.44
Tag: Cobalt Strike C2 — third-party feed, campaign "GRAYRIVER," confidence: medium
First seen: 2025-02-11   Last seen: 2025-03-04
Feed last refreshed: 2025-03
```

For a few minutes, that looked like it changed everything: a documented C2 IP would put the
external-compromise hypothesis back at the top of the list, hard.

> **Dead End**
> Twenty minutes went into re-checking whether `203.0.113.44` was live C2 infrastructure
> reused for a second purpose. It wasn't, and the feed's own dates were the tell: the
> Cobalt Strike tag was last refreshed in March 2025, eighteen months before this alert.
> Current passive DNS and the pool's own published stratum endpoint list showed the same
> address now serving `pool.oreblock.example`'s mining relay — consistent with ordinary IP
> churn on cheap, shared hosting, where an address gets reassigned to an unrelated tenant
> long after a stale feed entry stops being updated. Whatever this IP was doing in 2025, it
> wasn't doing that in September 2026.

> **False Lead**
> A medium-confidence C2 tag on the destination IP looked like strong evidence for the
> "attacker-deployed" hypothesis. It explained a stale threat-intel snapshot, not this
> connection — the address had changed hands on the hosting side in the eighteen months
> since that tag was written, and the pool's own current documentation named the exact IP
> range this fell inside. Reputation data has a shelf life network infrastructure doesn't
> respect; checking the refresh date, not just the tag, was what actually closed this off.

## 3. Ruling out a live operator

**[PIVOT]** A live mining connection running at 03:14 UTC doesn't need anyone at the
keyboard right then — that's the point of running it unattended. Confirming who was logged
on *at the moment of the alert* couldn't settle attacker-versus-insider on its own, but it
was the fastest next check, and it ruled out one thing cleanly: whether someone was
remotely operating the host live when the rule fired.

```text
Event ID 4800
2026-09-05T18:41:07Z  Account: pchandran  Workstation: CU-WKSTN-2231  Session locked
```

No Event ID 4624 interactive logon and no VPN session existed anywhere near 03:14 on
September 8. The workstation had been locked, not logged off, since the evening of
September 5 — a standard desktop left running over a long weekend, exactly the condition under which a
background process nobody is watching keeps running undisturbed. That fact ruled out a live
remote operator at the time of the alert. It did not rule out either remaining hypothesis:
an attacker's autonomous payload runs unattended just as easily as a self-installed one
does.

> **Hypothesis Board — after the identity pivot**
> 1. **External attacker deployed the miner after some other compromise of this host** —
>    weakened. No other alert has ever fired on `CU-WKSTN-2231`; no credential-access or
>    lateral-movement indicator exists anywhere in its EDR history; `xmrig.exe`'s own
>    persistence is a plain user-writable registry Run key, not the kind of loader chain a
>    real intrusion on this host would be expected to leave behind.
> 2. **The account's own user installed and runs the miner personally, for their own
>    benefit** — live and favored, but not yet directly evidenced. The persistence mechanism
>    and lack of any other compromise indicator both point this way; nothing yet confirms who
>    was at the keyboard when the file first landed on disk.
> 3. **A third party used Priya Chandran's credentials or console access without her
>    knowledge** — live, unchecked. Requires confirming whether any other account has ever
>    authenticated to this host.
> **Current confidence:** High that this is an active, unauthorized resource-hijacking
> process with no compromise indicators anywhere else on the host or the fleet; still open
> which of the three above explains it.

> **Analyst's Gut Check**
> Don't let "nobody was logged on when the alert fired" read as "nobody was involved." A
> miner is built to run unattended — that's the entire economic point of it. The moment that
> actually tells you something is the moment the persistence mechanism was first created, not
> the moment a duration threshold happened to cross.

## 4. The paper trail from the first afternoon

**[PIVOT]** Nothing about the September 8 alert window could distinguish the three live
hypotheses. The disambiguating evidence, if it existed anywhere, was at the *origin* event —
the first time `xmrig.exe` ever ran on this host — which meant pivoting backward across the
EDR's longer retention window instead of sideways to a new log source.

```text
DeviceProcessEvents
| where DeviceName == "CU-WKSTN-2231"
| where FileName =~ "xmrig.exe" or ProcessCommandLine has "xmrig"
| where Timestamp < datetime(2026-09-08T00:00:00Z)
| order by Timestamp asc
| take 5
```

```text
2026-08-19T14:03:47Z FileCreated    Path=C:\Users\pchandran\Downloads\xmrig-6.21.3-msvc-win64.zip
  InitiatingProcess=msedge.exe
  URL=https://github.com/xmrig/xmrig/releases/download/v6.21.3/xmrig-6.21.3-msvc-win64.zip
2026-08-19T14:07:52Z ProcessCreated FileName=start.bat        InitiatingProcessFileName=explorer.exe
  FolderPath=C:\Users\pchandran\AppData\Roaming\rig\
2026-08-19T14:07:53Z ProcessCreated FileName=xmrig.exe        InitiatingProcessFileName=cmd.exe
  FolderPath=C:\Users\pchandran\AppData\Roaming\rig\  Signed=false
2026-08-19T14:08:01Z RegistryValueSet Key=HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  Value=RigMonitor  Data="C:\Users\pchandran\AppData\Roaming\rig\xmrig.exe --config=config.json"
```

The chain was a plain interactive download-and-run: a browser fetch straight from the
project's own public release page, extraction to a user-writable folder, a batch file
double-clicked from Explorer, and a Run key added in the same minute. No loader, no
obfuscation, no second-stage payload — the shape of someone setting up software for their
own use, not the shape of a dropper hiding a foothold.

That still left the identity question. The Security log for the same window:

```text
2026-08-19T13:47:22Z Badge: P.CHANDRAN (EMP-30142)  Reader: HQ-2F-EAST-TURNSTILE  Result: GRANTED
2026-08-19T13:52:04Z Event ID 4624  Account: pchandran  Logon Type: 2 (Interactive)
  Workstation: CU-WKSTN-2231  Source Network Address: 127.0.0.1
```

A badge grant to the account's own physical access card five minutes before an interactive
console logon under the account's own name, roughly twelve minutes before the download,
matched at the console the entire way through. No VPN session, no remote-access tool, and
no second account had ever authenticated to `CU-WKSTN-2231` in its full logon history — which closed
the third hypothesis on the board. Whoever set this up did it in person, at that desk, on
that badge.

## 5. The detail that signs its own name

**[ANALYST]** One artifact remained unread: the miner's own config file, pulled read-only
off a snapshot rather than the live host.

```json
{
  "pools": [
    {
      "url": "pool.oreblock.example:3333",
      "user": "4Ab9kXq2ZP7mWn6...redacted-by-analyst...tW3f.pchandran-office-rig",
      "pass": "x",
      "keepalive": true,
      "tls": false
    }
  ]
}
```

XMRig's pool `user` field commonly carries a wallet address and an optional worker label,
separated by a period, so an individual running several machines can tell them apart on the
pool's own dashboard. The worker label here was `pchandran-office-rig` — not a generic
default, not an attacker's throwaway identifier, but a name someone chose specifically to
mean "this is my rig, at the office." That single field did more to settle the question than
every log source pulled before it combined.

The firewall log added one more consistent detail: across the three weeks of DNS and egress
history, the persistent connection showed brief, repeated gaps of eight to twelve minutes,
several of which lined up with badge-in events on the account over that period. An
attacker's unattended payload has no reason to pause when the legitimate user happens to walk
back to their desk. Someone checking on their own mining software, on their own schedule,
does exactly that.

**Confidence, restated at this point: High — the same level it has been since the tenth
minute of the shift, now attached to a settled answer instead of an open question.** The
finding never got more or less certain; what it *was* a finding of changed completely.

> **Blind Spot**
> This evidence set proves the software was downloaded, run, and labeled by a session
> authenticated as Priya Chandran's own account, from her own badge-matched physical
> presence, with no other account ever touching the host. It does not, and cannot, prove
> intent beyond that — whether she understood this violated policy, whether she was aware of
> the electricity or hardware-wear cost to the company, or whether she'd stop if asked. Those
> are questions for a conversation, not a log query, and this investigation's evidence ends
> exactly at the boundary of what telemetry can show.

## 6. Two decisions, and only one of them belongs to the analyst

**[ESCALATION]** By 05:50 UTC, the technical picture was settled from three independent
sources agreeing on the same account, the same physical presence, and the same three-week
timeline: the download log, the badge-and-logon pair, and the config file's own worker label.
Severity for IR purposes dropped from the alert's original "possible active compromise" to
"confirmed unauthorized software, no compromise indicators" — but the process was still, at
that moment, actively running and actively costing the company compute and power.

Two decisions did not belong to the analyst. Whether to kill the process and remove the
software immediately, or leave it running long enough for someone else to independently
observe it before the account holder is confronted, changes what evidence exists at the
moment of that conversation — and that tradeoff is exactly the kind of call this book leaves
to management, not the investigating analyst.

> **Manager's Call**
> Removing `xmrig.exe` immediately stops the resource cost right away but tips off the
> account holder the moment she next unlocks the machine and finds it gone. Leaving it running
> a while longer preserves the option for HR or a manager to observe it directly, or to raise
> it in conversation before any technical action occurs — at the cost of continued,
> now-confirmed unauthorized use. Deciding which tradeoff to take, and looping in HR before or
> after that decision, is the incident commander's call. The SOC Manager's Operating
> Handbook, Part 27 — Legal, HR & Compliance Interfaces covers this exact
> evidence-preservation-versus-tipping-off tension in full; this case does not re-derive it,
> only marks the point where the analyst's job — confirm what's running and who put it there
> — ends and the manager's begins.

## 7. Closing the ticket at the confidence it opened with

**Disposition: Benign Positive.** The alert fired correctly on real, unambiguous technical
evidence — an unsigned binary, a genuine sustained cryptomining workload, a genuine
beacon-regular outbound session to a real mining pool — and every part of that reading held
up under every pivot. It closes Benign Positive rather than True Positive in the sense this
book's Section G cases use False Positive, because there was never anything wrong with the
detection: the wrong assumption was only ever the reader's, not the rule's, and it was the
assumption that "matches this signature" means "security incident." Here it meant "policy
violation by the assigned user of the asset," confirmed by identity and provenance evidence,
not by the network or process telemetry that triggered the alert in the first place.

**Confidence at close: High, settled.** It had been High since the tenth minute of the shift
and stayed there through every pivot; only the referent changed, from "this is a functioning
miner" to "this miner belongs to the person who was assigned this laptop, and she put it
there herself."

> **What Would Change My Mind**
> This closes at High confidence on both the technical finding and the attribution, on direct
> evidence from independent sources with no unresolved contradiction between them. What would
> reopen the external-compromise hypothesis specifically: the same binary hash or the same
> pool address appearing on a second host under a service account or a scheduled task rather
> than an interactive user session, or any credential-access or lateral-movement indicator
> surfacing on `CU-WKSTN-2231` in the same window. Neither has shown up in a fleet-wide sweep
> run alongside this case, and that sweep is the specific check that would need to change for
> this disposition to move.

## 8. What carries forward

**[LESSON LEARNED]** A detection built around a technique — T1496, resource hijacking — will
correctly and repeatedly fire on that technique regardless of who's running it, because
dual-use tools produce identical telemetry whether an external attacker or the asset's own
assigned user put them there. `unsigned-binary-execution.md` and `beaconing.md` do exactly
what they're built to do here; neither one is the log source that resolves attacker-versus-
insider, and no amount of tuning either one will make it so. That evidence lives in identity,
logon, and process-lineage history, every time, and a case built only on network and process
telemetry — however clean the signature — will stall exactly where this one would have
stalled without the pivot back to badge and logon data. The second, narrower lesson: this
miner predated its own detection rule by three weeks, because the rule was mid-rollout when
it started. Any team turning on a new correlation rule should run one retroactive sweep
across existing endpoint history for matches that predate the rule going live, rather than
assuming day one of enforcement is day one of the behavior. Both fixes are process changes on
the detection-engineering side, not new findings this case needs to re-argue; this case's job
ends at handing them off, not implementing them.

---

**Cross-references:** SOC Playbook Handbook `unsigned-binary-execution.md`; SOC Playbook
Handbook `beaconing.md`; SOC Manager's Operating Handbook, Part 27 — Legal, HR & Compliance
Interfaces.
