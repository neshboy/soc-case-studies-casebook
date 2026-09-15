---
title: "CB-13 — New Access Key, Old Habits"
case_id: "CB-13"
category: "Cloud"
disposition: "True Positive"
outcome_flavor: "Obvious"
confidence_at_close: "High"
entry_point: "standing-alert"
construction_class: "SYNTHETIC-COMPOSITE"
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: ["SOC Playbook CLD-002", "SOC Playbook CLD-009", "SOC Playbook CLD-013", "SOC Playbook CLD-018", "DEH Part 19", "SOC Manager Part 26"]
---

# CB-13 — New Access Key, Old Habits

*This is a synthetic, composite investigation, built by threading together mechanics from
several of this series' own playbooks and detections into one continuous narrative.
"Thornbury Analytics," its staff, and every host, account, key ID, and IP address named
below are invented; no real organization, employee, incident, or breach is depicted or
implied.*

## Why this case exists

This case exists to show a privilege-escalation-and-persistence chain from the *middle* outward, the way an on-call analyst actually meets one: the alert that pages the SOC is not the beginning of the story, it's the second-to-last event in it, and the job is to reconstruct both what came before it and what came after from a single CloudTrail principal ID. The Detection Engineering Handbook V2 Part 19, §8 already walks a stolen-access-key chain start to finish, hour by hour, in the threat hunter's voice, from the leak forward — this case deliberately does not re-narrate that chain. It starts where DET-19-06 fires, works backward through a role-policy escalation (a different mechanism than Part 19's direct self-attached `AdministratorAccess`, and the one `privilege-escalation-via-role-policy-chaining.md` actually names in its title), and only then works forward into the data-access impact. It also carries a second thread neither of those sources covers: what it means, institutionally, when the root cause turns out to be a habit the organization already knew about and had already "fixed" once — the reason this case is called what it's called, and the reason its second half spends as much time in the ticketing system as it does in CloudTrail.

## Case metadata

| Field | Value |
|---|---|
| Case ID | `CB-13` |
| Category | Cloud |
| Disposition | True Positive |
| Outcome flavor | Obvious |
| Confidence at close | High, settled |
| Entry point | Standing CloudTrail anomaly correlation alert (new access-key creation) |
| Primary log sources | AWS CloudTrail (management and S3 data events), BuildForge (CI vendor) build-log archive, internal ticketing system |
| Construction class | SYNTHETIC — COMPOSITE ACROSS SERIES |
| Primary cross-references | SOC Playbook Handbook `new-access-key-creation.md` (CLD-002), `privilege-escalation-via-role-policy-chaining.md` (CLD-009), `mass-object-download-from-storage.md` (CLD-013), `credential-leakage-keys-in-code-logs.md` (CLD-018); Detection Engineering Handbook V2 Part 19 — Cloud Infrastructure Detection Engineering (`DET-19-01`, `DET-19-06`) |
| All times | UTC |

## 1. Paged at 00:22: a deploy role minting keys for someone else

**[CONCEPT]** An AWS access key is a long-lived, MFA-free credential, and `CreateAccessKey` is an ordinary, frequent, entirely legal API call — CI/CD pipelines rotate their own keys on a schedule, and nobody wants an alert on every one of them. `new-access-key-creation.md` (CLD-002) scopes this correctly: the call itself is noise; a call made *by* one identity *targeting* a different identity, with no matching rotation record, is not. Thornbury Analytics' cloud SOAR runs a correlation rule modeled on this book's `DET-19-06` — a `CreateAccessKey` event only becomes a candidate when the same principal produced a privilege-escalation-shaped precursor (a policy attach, a policy put, an unfamiliar `AssumeRole`) within the preceding hour. This is closer to the raw shape of `DET-19-06` than a byte-for-byte copy of it; Thornbury's version joins on `userIdentity.arn` the same way, but scores the precursor window at 45 minutes, not 60, because their own tuning history showed the extra 15 minutes bought nothing but noise from an unrelated nightly Lambda.

At 00:22 on 2026-09-15, that rule fired. The event: `CreateAccessKey`, target user `svc-deploy-prod` — Thornbury's Jenkins deploy pipeline's IAM identity, a legacy holdover from before the platform team finished migrating CI/CD onto short-lived OIDC federation — called not by `svc-deploy-prod` acting as itself, but by an assumed-role session.

```json
{
  "eventTime": "2026-09-15T00:17:52Z",
  "eventName": "CreateAccessKey",
  "eventSource": "iam.amazonaws.com",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::111122223333:assumed-role/thornbury-deploy-prod-role/svc-deploy-prod-session",
    "accessKeyId": "AKIA2E7Q**********WXQ2"
  },
  "sourceIPAddress": "203.0.113.77",
  "userAgent": "Boto3/1.34.28 Python/3.11.6 Linux/5.15",
  "requestParameters": { "userName": "svc-deploy-prod" },
  "responseElements": {
    "accessKey": { "accessKeyId": "AKIA2E7Q**********P91K", "status": "Active" }
  }
}
```

**[ANALYST]** The analyst on Thornbury's cloud on-call rotation picked this up five minutes after it fired. The question worth asking before anything else: is the *caller* the same identity as the *target*? Here it plainly isn't — `svc-deploy-prod` didn't create its own key, a session assuming `thornbury-deploy-prod-role` created one on `svc-deploy-prod`'s behalf. CLD-002's own example query flags exactly this shape (`callerIsTarget=0`), and it's the single fact that took this alert from "routine key management" to "somebody used a role to reach into a different identity and hand it a durable credential."

**Confidence: Medium, rising.** One fact — caller and target don't match, and the source ASN has no history with this account — is enough to take this off the "ignore" pile, but not enough yet to say what actually happened.

### 1.1 A deploy role that isn't supposed to touch IAM at all

**[ANALYST]** `thornbury-deploy-prod-role` is `svc-deploy-prod`'s own deploy role — the one the Jenkins pipeline assumes every time it pushes a release, dozens of times a day. An `AssumeRole` into it from `svc-deploy-prod` is, by itself, the least surprising event in the entire account. What's surprising is what that session did *with* the role once inside it: IAM permissions to manage another user's access keys are not part of a deploy role's job description under any normal reading of "deploy."

That gap raised three questions before a second log source was worth touching: does the role actually hold `iam:CreateAccessKey` scoped to `svc-deploy-prod`, and since when; what did `203.0.113.77` do in this account before the call that paged the SOC; and is `svc-deploy-prod`'s original, years-old access key still the one in play, or is there a separate, earlier compromise sitting underneath this one.

A quick check of the role's current inline and attached policies answered the first question, and not in the direction anyone wanted: yes, it holds `iam:CreateAccessKey`, `iam:PutRolePolicy`, and a handful of other IAM-management actions, scoped with a resource condition to `svc-deploy-prod`'s own ARN. Nothing in the role's *original*, documented permission set included IAM actions at all — this was added. The other two questions needed a direct CloudTrail pull.

## 2. Pivot: from the alerting event to the full session

**[PIVOT]** The SOAR ticket only carried the single `CreateAccessKey` event. Everything else needed a direct CloudTrail pull, scoped to the same principal across a wider window.

### 2.1 The first query — too broad

```sql
-- too broad — see next query
SELECT eventtime, eventname, useridentity.arn, sourceipaddress
FROM cloudtrail_logs
WHERE eventtime BETWEEN '2026-09-14T00:00:00Z' AND '2026-09-15T01:00:00Z'
  AND eventname IN ('CreateAccessKey','PutRolePolicy','AttachRolePolicy','AssumeRole')
ORDER BY eventtime;
```

This returned 214 rows — every Terraform apply, every scheduled Lambda role assumption, every legitimate CI deploy across the whole account for a full day. Not useless, but not a shape the analyst could read at a glance.

### 2.2 The narrowed query

```sql
SELECT eventtime, eventname, useridentity.type, useridentity.arn,
       sourceipaddress, useragent, requestparameters
FROM cloudtrail_logs
WHERE eventtime BETWEEN '2026-09-14T23:30:00Z' AND '2026-09-15T00:35:00Z'
  AND (useridentity.arn LIKE '%svc-deploy-prod%'
       OR sourceipaddress = '203.0.113.77')
ORDER BY eventtime;
```

**[PIVOT]** Narrowing to the one hour bracketing the alert, and to either the principal name or the specific source IP, cut the result to 19 rows — and those 19 rows read as a single continuous session, not scattered noise:

| Time (UTC) | Event | Notes |
|---|---|---|
| 23:41:07 | `ListUsers` | source `203.0.113.77` |
| 23:41:19 | `ListAccessKeys` | target `svc-deploy-prod` |
| 23:44:02 | `ListAttachedUserPolicies` | target `svc-deploy-prod` |
| 23:44:37 | `ListRolePolicies` | target `thornbury-deploy-prod-role` |
| 23:52:18 | `PutRolePolicy` | policy name `deploy-ops-extend`, target `thornbury-deploy-prod-role` |
| 23:53:40 | `AssumeRole` | caller `svc-deploy-prod`, role `thornbury-deploy-prod-role` |
| 00:17:52 | `CreateAccessKey` | target `svc-deploy-prod` — the alerting event |
| 00:19:04–00:31:26 | `ListObjectsV2` / `GetObject` × 2,341 | bucket `thornbury-customer-exports` |

**[HYPOTHESIS]** Before chasing the escalation call itself, the analyst pulled the actual `deploy-ops-extend` policy document `PutRolePolicy` had written, rather than trusting the event name. It granted `iam:CreateAccessKey`, `iam:PutUserPolicy`, and `iam:PassRole` on resource `arn:aws:iam::111122223333:user/svc-deploy-prod` — not a bare wildcard, but broad enough, and scoped precisely to reach the one identity that mattered. `privilege-escalation-via-role-policy-chaining.md` (CLD-009) calls this pattern out directly: discovery, then a modify call, then privileged use, by the same principal, inside a tight window — under 30 minutes for scripted chains. This one ran discovery-to-modify in eleven minutes, modify-to-assume in barely over a minute, and assume-to-use — the moment the newly assumed session actually called `CreateAccessKey` — twenty-four minutes after that. `T1098.003 (Account Manipulation: Additional Cloud Roles)` covers the `PutRolePolicy` step; `T1098.001 (Account Manipulation: Additional Cloud Credentials)` covers the `CreateAccessKey` step that followed it.

> **Hypothesis Board — after the full-session pull**
> 1. **Scheduled key rotation, off by a few hours** — ruled out. Thornbury's actual key-rotation
>    automation runs under a dedicated `svc-secrets-rotator` role on a documented monthly cadence,
>    last run 11 days earlier with a matching change ticket. Nothing in this window traces to
>    that role at all.
> 2. **An on-call engineer manually unblocking a broken deploy at 3 AM** — weakened. The calling
>    session used `svc-deploy-prod`'s own existing access key, not a human's federated console
>    login; no MFA challenge, no Entra sign-in event, precedes any step in this chain. The
>    on-call schedule shows no active page for this service before 00:22.
> 3. **Credential compromise: the leaked key used to escalate, then persist** — supported. Discovery,
>    then a scoped policy grant, then an `AssumeRole`, then `CreateAccessKey` targeting a different
>    identity than the caller, all inside 37 minutes, from an ASN with no prior history on this
>    account.
> **Current confidence:** Medium-High, rising.

## 3. Dead end: ruling out a stolen instance role before trusting a leaked static key

> **Dead End**
> Twenty-five minutes went into checking whether `203.0.113.77` was actually the public-facing
> address of one of Thornbury's own EC2 instances calling home through a NAT gateway — the theory
> being that this was Instance Metadata Service credential theft (T1552.005) via an SSRF-vulnerable
> web app, not a stolen static key at all, which would point containment at rebuilding a workload
> rather than rotating a key. VPC Flow Logs for every instance in the production VPC showed no
> outbound traffic to `203.0.113.77` in the prior 24 hours, and no instance's local IMDS access
> logs showed an anomalous credential-fetch burst in the window. The credential in play here is a
> static, long-lived `AKIA`-format key, not a stolen session token — this is `credential-leakage-keys-in-code-logs.md` territory (CLD-018), not an SSRF case, and the twenty-five minutes confirmed that cleanly enough to stop looking for a compromised instance.

**Confidence: Medium-High, rising** — narrowing to "which log source" rather than "which theory" is itself forward progress, even when the specific check comes back empty.

## 4. Pivot: from IAM to S3 — what the new key actually touched

**[PIVOT]** With the escalation chain reconstructed, the next question was impact: what did the attacker do with the durable key they'd just minted for themselves?

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       requestparameters.bucketName, count(*) as call_count
FROM cloudtrail_logs
WHERE eventname IN ('ListObjectsV2','GetObject')
  AND eventtime BETWEEN '2026-09-15T00:17:00Z' AND '2026-09-15T01:00:00Z'
GROUP BY eventtime, eventname, sourceipaddress, useragent, requestparameters.bucketName
ORDER BY eventtime;
```

The result: a `ListObjectsV2` burst against `thornbury-customer-exports` at 00:19:04, followed by 2,341 sequential `GetObject` calls ending at 00:31:26 — 12 minutes for the full pull, roughly 1.9 GB, using the *new* access key rather than the original leaked one. Source IP had shifted one address over, to `203.0.113.81`, still inside the same hosting-provider range. User agent: `rclone/1.66.0` — `mass-object-download-from-storage.md` (CLD-013) names this exact client string as a tell in its own worked example, precisely because Thornbury's own applications never touch this bucket with anything but the platform's internal SDK wrapper.

**[ANALYST]** `thornbury-customer-exports` holds the CSV files Thornbury's own customers generate when they export contact lists and engagement reports out of the analytics platform — business names, work emails, job titles, campaign-engagement history. No health or payment data, but real, third-party personal data belonging to Thornbury's customers' customers, which matters for what happens at closure.

> **False Lead**
> The user agent on the *discovery* calls — `Boto3/1.34.28` — briefly looked like it might just be
> `svc-deploy-prod`'s own deploy tooling misfiring, since the pipeline's containers also run on
> Boto3. It wasn't: the deploy image's pinned `requirements.txt` locks Boto3 at `1.28.11`, three
> minor versions behind, and the deploy script's source contains no call to `ListUsers` or
> `ListAccessKeys` anywhere in its history. A matching SDK family was a coincidence of popularity,
> not a shared origin.

**Confidence: High.** Two independent log sources — the IAM management-plane chain and the S3 data-plane read burst — now agree on the same principal, the same narrow window, and a bucket holding data with no legitimate reason to be read at this volume by this identity. `T1530 (Data from Cloud Storage)` and `T1048 (Exfiltration Over Alternative Protocol)` both apply to the `rclone`-driven pull.

## 5. Old habits: a name the analyst already recognized

**[ANALYST]** One more question, prompted by nothing more than familiarity with `svc-deploy-prod`'s name from a prior shift: had this account been flagged before? A search of the internal ticketing system for the account name turned up a closed ticket from 2026-04-08 — five months earlier.

That ticket's shape was almost identical to this one's root cause, and almost nothing like its outcome. In April, the platform team's own internal log-hygiene scanner — not an attacker, not a public scanning bot — caught `svc-deploy-prod`'s access key printed into a Jenkins console log during a different troubleshooting session, one where an engineer had also temporarily enabled verbose debug output to chase a failing deploy step. That exposure never left Thornbury's internal log aggregator; there was no evidence of any external reach, and the case closed as **Benign Positive — Exposure Without Use**, per CLD-018's own closure criteria, once the key was rotated. The remediation ticket filed alongside that closure — disable verbose debug logging by default on the deploy job, add a log-scrubbing step for anything matching an AWS key pattern before a build log is persisted anywhere — sat in the platform team's backlog, unstarted, for five months.

That closed ticket didn't just explain a coincidence — it pointed at where to look next. If September's leak shared April's habit, the key probably hadn't surfaced in source control at all; it had probably surfaced the same way it did last time, in a build log nobody scrubbed.

## 6. Additional evidence: tracing the chain back to its source

**[PIVOT]** The April ticket reframed the question. Confirming what happened no longer required more theories about *this* incident in isolation — it required checking whether September's exposure had the same shape as April's, since nothing so far explained how an outside party got a working credential for `svc-deploy-prod` in the first place. `credential-leakage-keys-in-code-logs.md` (CLD-018) frames this exposure search as the very first investigation step for a reason: blast radius is defined by the exposure, not by what's already been observed.

The analyst didn't have standing access to Thornbury's CI vendor's log archive, and looped in the platform engineering lead to pull it. Searching BuildForge's build-log history for the literal (partial, redacted) key string surfaced one hit: build run `#4127` on the `platform-deploy` project, 2026-09-10 at 16:14, a `printenv`-style debug step that dumped the job's full environment — including `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for `svc-deploy-prod` — into the run's console log. That run's log had been reachable via an unlisted BuildForge URL, because the `platform-deploy` project's "public build status" toggle had been switched on eight months earlier for an unrelated open-source demo and never switched back off.

> **Evidence Note**
> `credential-leakage-keys-in-code-logs.md`'s exposure-side detection list leans on GitHub's own
> secret-scanning partner program, GitGuardian, and similar tooling — all of which watch source-control
> hosting, not a CI vendor's own build-log sharing feature. This key never touched a Git commit, so
> none of those exposure-side detections had anything to see. Exposure-side detection here depended
> entirely on whatever generic, internet-wide credential scanner eventually found the unlisted
> BuildForge URL — which took roughly three days, not the "minutes" CLD-018 documents for a
> public GitHub exposure, precisely because this surface isn't the one those scanners are tuned
> to crawl first.

A single light touch on 2026-09-13 at 14:02:31, from `198.51.100.5` — one `GetCallerIdentity` call and nothing else — confirmed the key was live and functional, roughly a day and a half before the attacker who actually used it showed up from `203.0.113.77`. Two different pieces of infrastructure, two different roles in the same exposure: a scanner validating the find, and, a day and a half later, someone acting on it.

**[HYPOTHESIS]** This matters for more than narrative tidiness. It changes what "root cause" means for this case. The proximate cause of September's exposure is the same specific habit as April's: an engineer, under time pressure, re-enabling verbose debug logging to troubleshoot a broken deploy, without anyone re-checking what that logging mode actually prints. April's incident didn't become external exposure because the log stayed inside Thornbury's own aggregator. September's became external exposure because of a second, independent gap — the `platform-deploy` project's public-build-status toggle, left on since an unrelated demo — that April's incident never touched at all. The habit recurred; the outcome this time depended on a second unfixed thing intersecting with it.

> **Blind Spot**
> Nothing in this evidence set can rule out a second, still-undiscovered copy of the leaked key
> in circulation — BuildForge's own access logs for the unlisted URL only retain 30 days, and
> the analyst has no way to confirm whether any other automated scanner or human visited that
> link between 2026-09-10 and the first confirmed touch on 2026-09-13. The investigation can
> account for the actor it found; it cannot certify that actor was the only one who found the key.

**Confidence: High, settled** on the question of whether this is a real compromise with real impact. The old-habits thread doesn't move that number — it explains the case, it doesn't change the disposition.

## 7. Escalation and containment

**[ESCALATION]** By 01:10 the analyst had enough to act without waiting for the root-cause dig to finish. Per CLD-002 and CLD-018's containment guidance, rotation and revocation don't wait on a completed investigation:

- Both access keys for `svc-deploy-prod` — the original leaked key and the attacker-minted backdoor key — deactivated at 01:14.
- The `deploy-ops-extend` inline policy removed from `thornbury-deploy-prod-role`, reverting it to its documented permission set.
- Active STS sessions for the role force-expired via a temporary explicit-deny attached to the role's trust policy, then removed once no new sessions appeared for 30 minutes.
- Platform engineering paged to disable the `platform-deploy` project's public-build-status toggle and purge the exposed build log from BuildForge's cache; a vendor takedown request was filed for the unlisted URL itself.
- `thornbury-customer-exports` access scoped down pending a full review; application owner notified same morning.
- A breach-notification assessment opened with Legal given confirmed external read access to third-party contact data, per `mass-object-download-from-storage.md`'s escalation criteria for regulated or customer-owned data categories.

> **Manager's Call**
> Whether this recurrence gets raised to engineering leadership as an accountability finding —
> not just a second remediation ticket that might age the same way the first one did — is a call
> for the security manager, not the analyst. The SOC Manager's Operating Handbook, Part 26 —
> Cross-Team Politics & Stakeholder Alignment covers the tradeoff between re-filing a quiet fix
> and escalating a known, unfixed gap that just caused a second incident; this case does not
> re-derive that doctrine, it only marks the point where the analyst's job (contain, scope, close)
> ends and the manager's (make sure it doesn't happen a third time) begins.

## 8. Decision and closure

**[ESCALATION]** Closed as **True Positive**, per `new-access-key-creation.md`'s own closure criteria: the key is deactivated, the owning identity's sessions are revoked, and downstream use is fully scoped in the case timeline. The disposition draws on all four cited playbooks at once — a leaked static credential (CLD-018), used to escalate through a role it already had partial reach into (CLD-009), used to mint a durable backdoor credential on the original identity (CLD-002), used to pull 2,341 objects from a customer-data bucket (CLD-013).

**Confidence at close: High, settled.** Two independent log sources — CloudTrail's management-plane chain and its S3 data-plane read burst — corroborate the same principal, window, and outcome, with no unresolved contradiction between them.

> **What Would Change My Mind**
> A confirmed second, unrelated set of API calls using the *original* leaked key — not the
> backdoor key this case tracked — from infrastructure unconnected to `203.0.113.77`/`.81`, would
> mean a second actor found the same exposure independently, and this case's scoping would need
> to reopen rather than close. Nothing in the 24 hours before or after this window shows that; the
> Blind Spot above is the specific reason this can't be stated as fully ruled out, only as
> unobserved.

## 9. Lesson learned

**[LESSON LEARNED]** A closed Benign Positive is not the same claim as "the underlying gap is fixed" — CLD-018's own closure criteria are honest about scoping to *this* exposure, not to the habit that produced it, and that's the right scope for a single ticket. The miss here wasn't the April investigation; it was that nothing in the SOC's own process re-checked, five months later, whether the remediation ticket attached to that closure had actually shipped. A recurring-root-cause check — did the fix from the last time this exact identity or this exact failure mode got flagged actually land, not just get filed — belongs in the closure workflow for any case where the root cause is a process gap rather than a one-time mistake, not left to an analyst's memory of a ticket they happened to have worked five months earlier. The technical fix here is CLD-018's own: push protection, log scrubbing, disabling debug-mode secret printing by default. The process fix is the one this case actually teaches: a remediation ticket tied to a closed case needs its own expiry check, or "fixed" quietly becomes "flagged once."

---

**Cross-references:** SOC Playbook Handbook `playbooks/17-cloud/new-access-key-creation.md` (CLD-002), `playbooks/17-cloud/privilege-escalation-via-role-policy-chaining.md` (CLD-009), `playbooks/17-cloud/mass-object-download-from-storage.md` (CLD-013), `playbooks/17-cloud/credential-leakage-keys-in-code-logs.md` (CLD-018); Detection Engineering Handbook V2, Part 19 — Cloud Infrastructure Detection Engineering (`DET-19-01`, `DET-19-06`, §7, §8); SOC Manager's Operating Handbook, Part 26 — Cross-Team Politics & Stakeholder Alignment.
