---
title: "CB-08 — The VPN Login From a Country We Don't Do Business In"
case_id: "CB-08"
category: "Network"
disposition: "True Positive"
outcome_flavor: "Subtle"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook Handbook lateral-movement-network-view.md", "SOC Playbook Handbook internal-network-reconnaissance.md", "SOC Playbook Handbook rdp-scanning.md", "DEH Part 14", "DEH Part 44", "SOC Manager's Operating Handbook Part 27"]
---

# CB-08 — The VPN Login From a Country We Don't Do Business In

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Halstead Regional Health," "Meridian Clinical Systems," their staff, and every host,
account, and IP address named below are invented; no real organization, employee,
incident, or breach is depicted or implied.*

## Why this case exists

This case teaches the specific discipline of not letting an alert's own boring base rate
become the reason to under-invest in it: a VPN-country alert that closes benign
thirty-some times in a row is exactly the alert an overnight analyst learns to move
through fast, and this case shows what the next one costs to catch anyway — not through
one dramatic piece of evidence, but through three individually unremarkable observations
(a residential ASN, a clean single-attempt one-time code, a firewall log almost nobody
reads until asked) that only add up once joined. It deliberately does not re-narrate the
SOC Playbook Handbook's own VPN/carrier-NAT impossible-travel false-positive case study —
that case study is a *different* standing control (impossible-travel correlation between
two sign-ins) resolving benign; this case's control is a country allow-list, and it
resolves as a genuine account compromise, so the two should not be read as the same alert
type with a different ending. It also does not re-derive the scan-detection or RDP-abuse
mechanics themselves — DEH Part 14 and the `rdp-scanning.md` / `internal-network-
reconnaissance.md` / `lateral-movement-network-view.md` playbooks own that logic in full;
this case only shows an analyst applying it mid-investigation.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-08` |
| Category | Network |
| Disposition | True Positive |
| Outcome flavor | Subtle |
| Confidence at close | High, settled |
| Entry point | Standing SIEM correlation alert (VPN unapproved-country control), deliberately the kind of alert that usually closes benign |
| Primary log sources | VPN concentrator (GlobalProtect) auth log, GeoIP/ASN enrichment, RADIUS one-time-code auth log, perimeter firewall/NetFlow, Windows Security log (target hosts) |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook `lateral-movement-network-view.md`, `internal-network-reconnaissance.md`, `rdp-scanning.md`; DEH Part 14 — Network Detection Engineering; DEH Part 44 — Adversary Behaviour for Defenders |
| All times | UTC |

## 1. The alert that's supposed to be boring

**[CONCEPT]** Halstead Regional Health runs a three-hospital regional network in the
American Midwest and maintains a remote-access VPN (Palo Alto GlobalProtect) for staff,
home-health nursing coordinators, and a short list of third-party support contractors.
One of the standing correlation rules riding on top of the VPN concentrator's auth log
isn't really a security detection at all — it's a data-residency control, written to
satisfy a vendor contract clause promising a handful of partners that Halstead's clinical
data would never be accessed from outside an approved list of countries. The rule,
`VPN-GEO-002`, opens a low-severity ticket every time a successful VPN authentication's
source IP resolves, via GeoIP enrichment, to a country outside that list. It was never
tuned as an attacker-detection control, and it shows: in the 90 days up to and including
this case, `VPN-GEO-002` has fired 38 times; the 37 firings before this one all closed
Benign Positive or Expected Activity — hotel Wi-Fi routing through a foreign proxy, a
stale GeoIP database entry, a nurse coordinator on a cruise who forgot to file a travel
exception.

**[ANALYST]** At 03:14, `VPN-GEO-002` fires again, this time for the account `dvargas` —
a support contractor from Meridian Clinical Systems, the vendor that maintains Halstead's
electronic health record integration layer. The on-call analyst, working alone on the
overnight shift, pulls the ticket and does what 37-out-of-38 tells you to do: assume it's
noise until something specific says otherwise, and go find out fast rather than slow.

### 1.1 What the VPN log actually shows

```text
2026-09-15T03:14:02Z hrh-vpn-gw01 GlobalProtect: type=auth-success
  user=dvargas srcip=203.0.113.44 srcip-country=Uruguay
  authmethod=LDAP+RADIUS-OTP client-os=Windows client=GlobalProtect-6.2.0
  assigned-ip=198.51.100.22 gateway=hrh-vpn-gw01
```

**[ANALYST]** Source IP 203.0.113.44, GeoIP-resolved to Uruguay. Halstead has no clinics,
no vendors, and no clinical-trial sites in Uruguay — the approved-country list backing
`VPN-GEO-002` covers the United States, Canada, and one Meridian office in Ireland where
a handful of their engineers work remotely. Nothing else in the log is unusual for a
support-contractor login: the authentication-method field reads `LDAP+RADIUS-OTP`, a
password plus a one-time code from a hardware token — Meridian's contractor accounts
predate Halstead's newer SSO-and-push-MFA rollout and still ride the older RADIUS path.
That gap is a known, accepted risk on four legacy vendor accounts, `dvargas` among them,
tracked on a risk-acceptance register rather than remediated; nobody has re-issued
Meridian's contractors into the newer identity stack yet.

## 2. Two boring explanations to kill before anything else

**[ANALYST]** Two questions, in order, before pulling anything else. First: is this
source IP actually in Uruguay, or is the GeoIP enrichment wrong — a stale database entry,
or a commercial VPN/hosting exit node misattributed to a residential geography, which is
the single most common explanation behind `VPN-GEO-002`'s 37-out-of-38 closure rate.
Second, if the geography holds up: is there a mundane reason a Meridian contractor would
be physically in Uruguay tonight, the kind of thing a 5-minute records check would settle
— a business trip, a personal vacation on file with a travel exception, a device his
employer already knows about.

**[HYPOTHESIS]** Two theories are live at this point, and both are the boring kind:
**GeoIP misattribution** (the alert is technically firing correctly on bad enrichment
data, and the real source is domestic or a known VPN exit range), and **legitimate but
unlogged travel** (the geography is correct, and the explanation is a person, not an
attacker). Neither has been checked yet.

## 3. Pivot: GeoIP, ASN, and the residential-proxy problem

**[PIVOT]** The analyst pivots from the VPN log to a WHOIS/ASN lookup on 203.0.113.44,
because that's the fastest way to kill or confirm the misattribution theory — a
commercial VPN or hosting-provider ASN behind the IP would explain the whole alert in one
line.

```text
IP: 203.0.113.44
ASN: fixed-line residential allocation, Montevideo, Uruguay
Type: Residential broadband -- not listed on any commercial VPN, proxy,
      or hosting-provider reputation feed checked
```

**[ANALYST]** That result cuts the wrong way for the "this is just noise" read. The IP
isn't a data-center range, isn't on a Tor-exit or commercial-VPN reputation list, and
isn't the kind of ASN that shows up behind GlobalProtect logins that later turn out to be
GeoIP drift. It looks like a real residential internet connection in Uruguay, which on
its face is more consistent with a real person's home network than with obviously hostile
infrastructure.

> **False Lead**
> The residential ASN read, at first, as exculpatory — "not a known-bad hosting range" is
> the exact fact that closes most of this alert's siblings as GeoIP noise. It isn't
> exculpatory here. DEH Part 14 — Network Detection Engineering, §7 (Tor and proxy abuse)
> names this pattern directly: a residential-consumer ASN suddenly producing access
> patterns consistent with automated tooling is a *stronger* proxy-abuse signal than a
> known-bad hosting range, precisely because compromised home routers and IoT devices
> resold as residential-proxy exit points were never on any watchlist to begin with. A
> clean ASN reputation ruled out one specific benign explanation; it did not rule out an
> attacker.

**[CONCEPT]** Residential-proxy networks — the infrastructure layer behind a lot of
credential-stuffing and account-takeover tooling, T1090 (Proxy) — exist specifically to
defeat the "known-bad ASN" check the analyst just ran. Part 14 §7 covers the detection
angle for this pattern in full; this case doesn't re-derive it, only applies the
conclusion: a clean ASN check narrows the field, it doesn't clear the account.

## 4. Dead End: the scan-window theory

**[ANALYST]** Before going any further with the residential-IP result, the analyst checks
the one benign explanation that wouldn't require any of this to be malicious at all.

> **Dead End**
> Fifteen minutes went into checking whether Halstead's own vulnerability-management team
> had a scan window open against the VPN gateway or the contractor VLAN overnight —
> GlobalProtect gateways occasionally get flagged by an organization's own external
> scanner, and if Meridian's contractor tooling had somehow proxied through a scan
> appliance, that would explain an odd source with no compromise at all. The change
> calendar showed no scheduled scan that night, the vulnerability-management lead
> confirmed by text that nothing was running, and Halstead's scanner doesn't route through
> residential ISPs in South America under any configuration that exists. This wasn't
> Halstead scanning itself. Whatever `203.0.113.44` is, it isn't an internal control the
> analyst just didn't know about.

## 5. Where the two easy explanations stood

**[HYPOTHESIS]** Both starting theories are now weaker than they were at 03:14, and a
third has to be named to keep the board honest.

> **Hypothesis Board — after the ASN check**
> 1. **GeoIP misattribution (this is really a domestic or VPN-exit login)** — ruled out.
>    The ASN is a residential allocation with no VPN/hosting/Tor reputation hits; the
>    enrichment is very likely correct about the country.
> 2. **Legitimate, unlogged contractor travel** — weakened, not ruled out. No travel
>    exception on file for `dvargas`, and Meridian's own after-hours support roster
>    (checked via the vendor's shared on-call calendar) lists a different engineer covering
>    tonight's shift.
> 3. **Compromised credential, used from a residential-proxy or genuinely
>    attacker-controlled host in Uruguay** — newly live. Nothing yet confirms it, but
>    nothing has ruled it out either, and it's the only theory that explains both the ASN
>    result and the missing travel record.
> **Current confidence:** Low-Medium, rising.

## 6. Pivot: the one-time-code log and the travel-exception queue

**[PIVOT]** The analyst moves from network enrichment to identity, pulling the RADIUS
authentication log for the same session — specifically, how many one-time-code attempts
preceded the success, because a brute-forced or guessed code looks very different from a
correctly entered one on the first try.

```text
2026-09-15T03:13:58Z radius-hrh01 Access-Request user=dvargas otp-attempt=1
2026-09-15T03:14:01Z radius-hrh01 Access-Accept  user=dvargas otp-attempt=1
```

**[ANALYST]** One attempt, accepted. Meridian's contractor tokens are physical
hardware one-time-code fobs, not a soft token synced to a phone app — whoever logged in
either has David Vargas's actual token in hand, has a cloned seed for it, or is David
Vargas. A single first-try success doesn't distinguish those three. It does rule out one
thing cleanly: this was not a credential-stuffing or brute-force attempt against the code
itself. Whoever this is didn't guess their way in.

**[PIVOT]** Next, the vendor side. The analyst emails Meridian's after-hours support line
— a standing arrangement for exactly this kind of question — asking whether David Vargas
is traveling, and whether Meridian's own device inventory shows his laptop active
anywhere unusual. Meridian's reply, at 04:02: David Vargas is off this week, in the
country, his corporate laptop is checked into their office per their own badge log, and
nobody at Meridian authorized any access from Uruguay tonight.

> **Analyst's Gut Check**
> When a vendor's after-hours line answers a "is this your person" question with a badge
> log instead of just a verbal no, take that seriously — it's the difference between "we
> don't think so" and "we can prove where the device actually is." A verbal no from
> someone who hasn't checked anything is worth far less than it sounds like at 4 a.m.

**[HYPOTHESIS]** With the travel-exception theory now closed — not just unconfirmed,
actively contradicted by Meridian's own badge log — only one live theory remains
standing: this is `dvargas`'s credential, T1078 (Valid Accounts) from the moment of
authentication, used by someone who is not David Vargas, from a residential IP address in
Uruguay that shows no sign of being a mislabeled corporate exit point. T1078 is exactly
why the VPN log itself never looked wrong on its own — a stolen, correct credential
produces the same successful sign-in a legitimate one does.

## 7. Pivot: what the VPN-assigned address actually touched inside the network

**[PIVOT]** A successful VPN authentication is not, on its own, evidence of compromise —
plenty of legitimate contractor sessions look exactly like this one up to this point. The
next question is what the session actually *did* once it was inside, which means leaving
the identity stack behind and pulling perimeter firewall and NetFlow logs for everything
sourced from the VPN-assigned address, `198.51.100.22`, across the session window.

```spl
// too broad -- see next query
index=firewall src_ip=198.51.100.22
| stats count by dest_ip, dest_port, action
```

**[ANALYST]** That first query returns over 4,000 rows in under 3 minutes of session
time — far too broad to read, but the shape is visible even at a glance: hundreds of
distinct destination IPs, almost all on port 3389, almost all denied. Meridian's
contractor VPN profile is supposed to be scoped to exactly one destination — a single
jump host used for EHR administration — so "hundreds of destinations" is already wrong on
its face. The analyst narrows the query to the pattern that matters: distinct
destinations per minute, which is the horizontal-scan shape DEH Part 14's `DET-14-02` is
built to catch, adapted here to the analyst's own on-the-fly query rather than the tuned
production rule.

```spl
index=firewall src_ip=198.51.100.22 dest_port=3389
| bucket _time span=1m
| stats dc(dest_ip) as distinct_destinations, count by _time, action
| where distinct_destinations > 20
```

```text
_time                distinct_destinations  count  action
2026-09-15T03:15:00Z  61                    64     denied
2026-09-15T03:16:00Z  89                    93     denied
2026-09-15T03:17:00Z  74                    78     denied (4 allowed)
```

**[ANALYST]** 61 to 89 distinct destination addresses per minute, almost entirely on port
3389 (RDP), across 3 minutes — that's not a person clicking through a remote-desktop
client. This is closer to the raw shape of `DET-14-02` than the tuned version; the
analyst hadn't pulled up the production rule yet, just recognized the pattern from it.
This matches the exact profile the `rdp-scanning.md` and `internal-network-
reconnaissance.md` playbooks describe as automated internal service discovery, T1046
(Network Service Discovery) feeding a T1021.001 (Remote Desktop Protocol)
lateral-movement attempt — every host on the clinical device VLAN, `192.0.2.0/24`, that
answers on 3389 got probed inside a 2-minute window. Most of the segmentation held: the
firewall denied the overwhelming majority of these connections outright, because that
VLAN isn't supposed to be reachable from the VPN pool at all except to the one jump host.
Four connections got an `allowed` verdict in the third minute — 192.0.2.14, 192.0.2.22,
192.0.2.187, and 192.0.2.201 — four hosts that shouldn't have answered and did.

> **Evidence Note**
> The firewall's `action` field only tells you whether the *connection* was permitted, not
> whether an authentication attempt behind it succeeded or failed — that distinction lives
> one layer up, on the destination hosts' own security logs, not in NetFlow. A
> network-only view of this session tells you exactly how far the scan reached and no
> further; closing this out at the network layer alone would leave "did any of the four
> reachable hosts actually get logged into" as an open question, which is exactly the gap
> the next pivot exists to close.

## 8. Additional evidence: four failed logons on the far end

**[PIVOT]** The analyst pulls the Windows Security log — Event ID 4625 (failed logon) —
from the four hosts that returned an `allowed` verdict, scoped to the same 3-minute
window.

```text
2026-09-15T03:17:41Z host=hrh-clin-lab04 (192.0.2.14) Security 4625
  TargetUserName=dvargas LogonType=10 IpAddress=198.51.100.22
  FailureReason=%%2313 (unknown user name or bad password)
2026-09-15T03:17:44Z host=hrh-clin-imaging11 (192.0.2.22) Security 4625
  TargetUserName=dvargas LogonType=10 IpAddress=198.51.100.22
  FailureReason=%%2313
```

**[ANALYST]** Two of the four reachable hosts show a 4625 for the exact same source
address and the exact same account name, `LogonType=10` — a network-originated RDP logon
attempt, not console access. `dvargas` isn't a local account on either of these machines,
so every attempt fails on username lookup, not a wrong password. The other two reachable
hosts, 192.0.2.187 and 192.0.2.201, show nothing in Security log for this window at all —
likely legacy imaging or lab equipment that accepts the TCP handshake on 3389 but doesn't
forward RDP auth events anywhere the SIEM can see.

> **Blind Spot**
> The two hosts with no logon events at all are exactly the two the analyst most wants
> visibility into — legacy clinical devices are the segment most likely to have port 3389
> open by default and least likely to have modern audit-log forwarding configured.
> Whether an authentication attempt against those two hosts succeeded, failed, or was
> never actually completed at the protocol level is invisible from where this
> investigation sits. Closing this case as contained assumes those two devices didn't
> answer with anything more than a TCP handshake; nothing in the evidence gathered here
> proves that either way.

**[ANALYST]** What the two confirmed 4625s do establish: this wasn't blind port-mapping
curiosity. Whoever controls this session tried to *authenticate as David Vargas* against
machines his account has no legitimate reason to touch — the lateral-movement attempt DEH
Part 44 — Adversary Behaviour for Defenders, §9 (Lateral Movement, TA0008) describes as
T1021 (Remote Services) riding a valid, already-compromised credential rather than any
new exploit. The `lateral-movement-network-view.md` playbook's framing applies directly
here: the entity pairing — this account, these hosts, this hour — is the tell, not the
tool, because RDP itself is exactly what a legitimate administrator would also use.

## 9. Three weak signals, one direction

**[HYPOTHESIS]** Three sources now agree independently; it's worth stating the board once
more before moving to containment.

> **Hypothesis Board — after the firewall and Windows Security pivots**
> 1. **Legitimate contractor session, unusual but explainable** — ruled out. Meridian's
>    badge log places David Vargas's device in their own office; the account's actual
>    session ran an internal RDP sweep and tried to authenticate against clinical devices
>    no support contract covers.
> 2. **GeoIP or ASN artifact, not a real Uruguay-sourced session** — ruled out. Confirmed
>    residential ASN, no reputation-feed hits, and the behavior downstream is fully
>    consistent with hands-on-keyboard reconnaissance, not enrichment noise.
> 3. **Compromised `dvargas` credential, used for internal reconnaissance and RDP-based
>    lateral-movement staging** — supported. Three independent sources agree: the VPN log
>    (the session itself), the firewall/NetFlow log (the scan shape), and the Windows
>    Security log on two target hosts (the authentication attempts).
> **Current confidence:** High, settled.

## 10. Scope check: the other three legacy accounts

**[PIVOT]** Before writing this up as a single-account incident, the analyst pivots one
more time — back to the risk-acceptance register mentioned in §1, which lists four
legacy `LDAP+RADIUS-OTP` vendor accounts, `dvargas` among them. If whatever compromised
this token also has a line on the other three, closing this as an isolated account
problem would be premature.

```text
index=vpn (user=jkinsella OR user=rpettibone OR user=achukwu)
| stats count by user, srcip, srcip-country, _time
```

**[ANALYST]** No hits from an unapproved country for any of the other three accounts in
the same 90-day window `VPN-GEO-002`'s own history covers, and no failed-then-succeeded
one-time-code pattern on any of them either. Whatever happened to `dvargas`'s token looks
account-specific rather than a shared weakness in how Meridian issues or stores these
credentials — a phished individual, or a single lost or cloned fob, is more consistent
with this result than a compromise of Meridian's token infrastructure itself. That's
Meridian's determination to make with more visibility than Halstead's logs provide, not
a conclusion this case can reach on its own, but it's enough to scope the immediate
containment to one account rather than pulling all four legacy contractor tokens
overnight.

> **Evidence Note**
> `VPN-GEO-002`'s own 90-day history is the only baseline available for the other three
> accounts, and it only covers unapproved-country logins — it says nothing about whether
> any of the three logged in domestically, at an odd hour, in a way that would look
> anomalous by a different measure entirely. A clean result against this one alert's
> history is not the same claim as "these three accounts show no anomaly of any kind,"
> and the case record should not imply otherwise.

## 11. Escalation and containment

**[ESCALATION]** At 04:41, the analyst escalates to the on-call incident commander as a
confirmed account compromise with attempted lateral movement, not a routine
`VPN-GEO-002` closure. Immediate containment: `dvargas`'s account is disabled, the active
VPN session is killed at the gateway, and the RADIUS one-time-code token tied to that
account is flagged for reissue rather than reactivation — Meridian will need to physically
account for the original fob before any replacement credential goes out. The clinical
VLAN's segmentation held for all but four hosts; those four go on an accelerated
patch/configuration review rather than a full incident-scope isolation, since nothing in
the evidence shows a completed authentication anywhere on that VLAN.

> **Manager's Call**
> Whether this triggers Halstead's HIPAA-adjacent third-party-incident notification clause
> in Meridian's vendor contract — and on what timeline Meridian's own security team gets
> read in versus just told the account is disabled — is the incident commander's call, not
> the analyst's. The SOC Manager's Operating Handbook, Part 27 — Legal, HR & Compliance
> Interfaces covers the evidence-preservation-versus-notification-timing tradeoff this
> decision rests on; this case does not re-derive that doctrine, only shows the point
> where the analyst's evidence-gathering job ends and the manager's decision begins.

**[ESCALATION]** A parallel thread goes to Meridian directly: their contractor's
credential is confirmed compromised, and Halstead needs Meridian to determine how — a
phished token-adjacent workflow, a cloned seed, or something on Meridian's own side the
analyst has no visibility into from Halstead's logs alone. That determination is
Meridian's to make; Halstead's evidence stops at "this credential was used against us from
an address we can locate, by someone who is demonstrably not the person it belongs to."

## 12. Decision and closure

**[ESCALATION]** Closed as True Positive, confidence High, settled. The VPN authentication
itself was never the strongest piece of evidence — on its own, it's indistinguishable from
the 37 benign closures behind it in the same quarter. What moved this case was three
independently weak signals that pointed the same direction once joined: a residential ASN
that ruled out one benign explanation without confirming a hostile one, a vendor badge
log that closed the travel theory outright, and a firewall/NetFlow pattern no legitimate
contractor session produces. No single one of those three would have justified an
escalation by itself.

> **What Would Change My Mind**
> If Meridian's own investigation surfaces a business reason for `dvargas`'s account to
> have run an RDP sweep of Halstead's clinical VLAN — an undocumented, poorly-scoped
> automated inventory tool Meridian runs from contractor accounts without telling
> Halstead's SOC, for instance — that would move this case's disposition from True
> Positive toward Benign Positive, though it would not explain away the missing travel
> record or the residential-Uruguay source on its own. Short of that, nothing currently on
> file supports walking this back from High confidence.

## 13. Lesson learned

**[LESSON LEARNED]** The base rate that makes `VPN-GEO-002` boring — 37 benign closures
out of 38 — is also exactly the condition under which the next one gets a shallower look
than it deserves, not because any analyst is careless, but because the alert has trained
everyone touching it to expect one specific ending. The fix this case argues for isn't a
louder alert; it's a standing habit, applied to *any* alert with a high benign-closure
rate, of pulling the one downstream log source (here, the firewall/NetFlow view of what
the authenticated session actually touched) before writing the disposition, rather than
after a second signal forces the question. DEH Part 14 — Network Detection Engineering
already owns the query mechanics this case leaned on (`DET-14-02`'s horizontal-scan
shape); the gap this case actually closes is procedural, not technical — a checklist item,
not a new detection, is what would have made this join happen by default rather than by
one analyst's judgment call at 03:20 in the morning.

---

**Cross-references:** SOC Playbook `lateral-movement-network-view.md`; SOC Playbook
`internal-network-reconnaissance.md`; SOC Playbook `rdp-scanning.md`; DEH Part 14 —
Network Detection Engineering; DEH Part 44 — Adversary Behaviour for Defenders.
