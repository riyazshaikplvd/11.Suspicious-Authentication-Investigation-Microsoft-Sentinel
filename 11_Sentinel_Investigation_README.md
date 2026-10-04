# 🔷 Suspicious Authentication Investigation — Microsoft Sentinel
### Project 11 — SOC Analyst Portfolio | Microsoft Sentinel | KQL | Threat Intelligence | NIST-Aligned Response

`Role: SOC Analyst L1` `SIEM: Microsoft Sentinel` `Scenario: Anomalous Authentication / Possible Account Compromise` `Severity: High` `Status: Resolved`

---

## 📌 What Is This Project? (Simple Explanation — No Tech Background Needed)

Imagine a security guard who watches every door-badge swipe in a building, all day and night. One night, the same badge is swiped incorrectly many times in a row, then suddenly works — from a door the employee has never used before, at an hour they never work. The guard doesn't ignore it just because the badge eventually worked. They check the badge history, check who else used that door, call the employee, and decide whether to lock the door.

This project is that same idea, but for a company login instead of a door badge. I used **Microsoft Sentinel** (Microsoft's cloud SIEM) to watch Windows sign-in logs, built detection rules that notice this exact pattern, investigated a real-looking alert from start to finish, enriched the evidence with outside threat intelligence, and wrote the full set of documents a SOC team produces: a ticket, a timeline, an escalation note, and a final report.

---

## 🧠 Quick Concepts (For Non-Technical Readers)

```
Microsoft Sentinel   → Microsoft's cloud SIEM. Collects logs from many
                        sources and raises alerts on suspicious patterns.

KQL                   → "Kusto Query Language" — the search language used
                        to ask Sentinel questions like "show me every
                        failed login in the last hour."

IOC                    → "Indicator of Compromise" — a clue that an attack
                        happened (a bad IP address, an odd login time).

Threat Intelligence    → Outside services that have already seen millions
                        of attacks and can tell you "this IP address is
                        known to be bad."

Impossible travel      → When the same account logs in from two places
                        that are too far apart to reach in the time
                        between logins (e.g. Hyderabad, then Amsterdam,
                        11 minutes later). A strong compromise signal.

Correlation rule       → A rule that links several separate events
                        together (failed logins + a later success +
                        an unusual location) instead of looking at
                        any one event alone.
```

---

## 🖥️ Lab / Environment

```
┌──────────────────────────────────────────────────────────┐
│              Microsoft Sentinel Workspace                │
│                                                            │
│  Log Analytics Workspace  →  "soc-portfolio-law"          │
│  → Receives SecurityEvent table from connected endpoints  │
│                                                            │
│  DC01 — Domain Controller (Windows Server 2022)           │
│  → corp.local domain, Advanced Audit Policy enabled       │
│  → Forwards Security Event Log via Azure Monitor Agent    │
│                                                            │
│  WIN10-CLIENT01 — Employee Endpoint (Windows 10)           │
│  → Normal daily-use workstation for the targeted user     │
│                                                            │
│  Investigation Tools                                       │
│  → Microsoft Sentinel (Incidents, Analytics, Entity graph) │
│  → KQL (Logs blade)                                        │
│  → Microsoft Defender (sign-in risk, device state)         │
│  → VirusTotal, AbuseIPDB, AlienVault OTX (enrichment)       │
└──────────────────────────────────────────────────────────┘

All infrastructure is a private lab / simulated tenant.
No real company, employee, or third party is involved.
```

**📸 Screenshot placeholders (replace with your own Sentinel lab):**
`images/01-sentinel-overview.png`, `images/02-analytics-rule.png`, `images/03-incident-queue.png`,
`images/04-alert-details.png`, `images/05-event-4625.png`, `images/06-event-4624.png`,
`images/07-kql-results.png`, `images/08-ti-lookup.png`, `images/09-mitre-mapping.png`,
`images/10-incident-ticket.png`, `images/11-timeline.png`, `images/12-final-report.png`

> *Note: these are placeholders describing exactly what to capture from your own lab. Screenshots pulled from the internet would not be your own evidence and are deliberately not included here — a hiring manager trusts a screenshot of your own workspace, not a stock image.*

---

# PHASE 1 — THE SCENARIO

## 🎭 What Happened

```
07:55 AM — Employee "j.rao" (Finance department, corp.local)
           normally signs in from Hyderabad, India, on a known
           laptop, during business hours.

08:00 AM — 10 failed sign-in attempts against j.rao's account,
           all Logon Type 3 (network logon), from source IP
           103.21.XX.XX (flagged later as a hosting/VPN exit node).

08:05 AM — An 11th attempt succeeds. Successful sign-in (4624)
           recorded, same IP, same account.

08:07 AM — Microsoft Sentinel analytics rule fires:
           "Successful Sign-In Following Multiple Failures —
           Possible Account Compromise"

08:09 AM — A second sign-in for the same account appears from
           Amsterdam, Netherlands — 11 minutes after the Hyderabad
           sign-in. Physically impossible to travel that distance
           in 11 minutes → Impossible Travel alert also fires.

08:10 AM — SOC Analyst (me) picks up the incident.
```

---

# PHASE 2 — INVESTIGATION

## 🔎 Windows Event IDs Used

| Event ID | Meaning | Why it matters here |
|---|---|---|
| 4625 | Failed logon | Shows the guessing attempts and their sub-status codes |
| 4624 | Successful logon | Confirms the attacker got in, and from where |
| 4648 | Logon using explicit credentials | Flags a process running under a different account's credentials — checked for lateral movement |
| 4672 | Special privileges assigned | Checked whether the compromised account holds admin rights |
| 4740 | Account lockout | Confirms whether the failed attempts tripped a lockout |

## 🧮 KQL Queries Used — With Explanations

### Query 1 — Failed Login Analysis
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedCount = count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where FailedCount >= 5
```
**What it detects:** Any account with 5 or more failed sign-ins from one IP within a 10-minute window.
**Why it matters:** A handful of scattered failures is normal human error; a burst from one source is not.

### Query 2 — Successful Login Analysis
```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3
| project TimeGenerated, Account, IpAddress, Computer
| order by TimeGenerated desc
```
**What it detects:** Every successful network logon, most recent first.
**Why it matters:** This is the baseline list I cross-reference against the failure bursts.

### Query 3 — Failed Followed By Successful Login (Core Detection)
```kql
let failures = SecurityEvent
| where EventID == 4625
| summarize FailCount = count(), FirstFail = min(TimeGenerated) by Account, IpAddress, bin(TimeGenerated, 10m);
let successes = SecurityEvent
| where EventID == 4624 and LogonType == 3
| project SuccessTime = TimeGenerated, Account, IpAddress;
failures
| where FailCount >= 5
| join kind=inner (successes) on Account, IpAddress
| where SuccessTime between (FirstFail .. FirstFail + 15m)
| project Account, IpAddress, FailCount, FirstFail, SuccessTime
```
**What it detects:** A success that lands within 15 minutes of a failure burst, from the *same* account and IP.
**Why it matters:** This is the single most important query in the investigation — it is the moment "someone was guessing" becomes "someone got in."

### Query 4 — Top Source IPs
```kql
SecurityEvent
| where EventID in (4624, 4625)
| summarize Attempts = count(), Accounts = dcount(Account) by IpAddress
| order by Attempts desc
| take 10
```
**What it detects:** Which IP addresses are generating the most login activity, and against how many different accounts.
**Why it matters:** One IP hitting many accounts is a spray pattern; one IP hitting one account is a targeted attempt.

### Query 5 — Authentication Trends (Baseline Check)
```kql
SecurityEvent
| where EventID == 4624 and Account == "j.rao"
| summarize Logons = count() by bin(TimeGenerated, 1d), Computer
| order by TimeGenerated desc
```
**What it detects:** The user's normal daily sign-in pattern over recent history.
**Why it matters:** Without a baseline, "unusual" is just a guess. This query gives the evidence for it.

### Query 6 — User Login Activity (Full Account History for the Incident Window)
```kql
SecurityEvent
| where Account == "j.rao"
| where TimeGenerated between (datetime(2026-10-01T07:50:00) .. datetime(2026-10-01T08:30:00))
| project TimeGenerated, EventID, IpAddress, Computer, LogonType
| order by TimeGenerated asc
```
**What it detects:** Every single event for the targeted account inside the incident window, in order.
**Why it matters:** This single query rebuilds the whole story and is what gets pasted into the final report's timeline.

### Query 7 — Suspicious Login Pattern (Impossible Travel)
```kql
SecurityEvent
| where EventID == 4624 and Account == "j.rao"
| project TimeGenerated, IpAddress, Computer
| order by TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevIp = prev(IpAddress)
| extend GapMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where IpAddress != PrevIp and GapMinutes < 60
```
**What it detects:** Two different source IPs logging in as the same account less than an hour apart.
**Why it matters:** This is the raw logic behind "impossible travel" — Sentinel's built-in analytics do the geo-distance math, but this query shows the underlying pattern in plain KQL.

---

## 🔍 IOC Analysis

| Indicator | Value | Risk Indicator | How I Analyzed It |
|---|---|---|---|
| Source IP (burst 1) | 103.21.XX.XX | Known hosting/VPN exit range | Checked against AbuseIPDB and AlienVault OTX |
| Source IP (burst 2) | 185.244.XX.XX (Amsterdam) | No prior history for this user | Compared to the user's 90-day sign-in baseline (Query 5) |
| Username | j.rao | Finance department, standard user rights | Checked Event 4672 — no elevated privileges held |
| Hostname | WIN10-CLIENT01 | User's known device | Confirmed as expected endpoint for the Hyderabad sign-in only |
| Timestamp pattern | 10 failures in <2 min, success 5 min later, second country-sign-in 11 min after that | Matches brute-force → compromise → session reuse | Rebuilt with Query 6 |
| Event IDs present | 4625 (10x), 4624 (2x), 4672 (0x), 4740 (0x) | No privilege escalation, no lockout triggered | Cross-checked each ID individually |

---

## 🌐 Threat Intelligence Enrichment

| Source | What I did | Finding | Risk Level | Investigation Value |
|---|---|---|---|---|
| **VirusTotal** | Submitted both source IPs for reputation lookup | 103.21.XX.XX: flagged by 9 of 94 vendors as associated with credential-stuffing activity | Medium-High | Supports "not a typo" conclusion |
| **AbuseIPDB** | Checked abuse confidence score for both IPs | 103.21.XX.XX: 78% abuse confidence, reported for brute force in the last 30 days. 185.244.XX.XX: 61% abuse confidence, reported for anomalous logins | High | Confirms both IPs are known-bad, not just unusual |
| **AlienVault OTX** | Searched both IPs in OTX pulses | 103.21.XX.XX appears in a public pulse tagged "credential access / T1110" | High | Links this incident to a tracked, named attacker pattern rather than an isolated event |

---

# PHASE 3 — DETECTION ENGINEERING

## 🚨 5 Analytics / Correlation Rules — Why Each One Was Built

### Rule 1 — Multiple Failed Logins
```kql
SecurityEvent
| where EventID == 4625
| summarize FailCount = count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where FailCount >= 5
```
**MITRE:** T1110 — Brute Force. **Why:** Baseline detection for guessing behaviour. **False Positive Check:** Service accounts with scheduled password rotations, and users on shared NAT/VPN gateways. **Severity if fired alone:** Medium.

### Rule 2 — Successful Login After Multiple Failures
*(Query 3 above, turned into a scheduled rule, run every 10 minutes)*
**MITRE:** T1078 — Valid Accounts. **Why:** The clearest signal that a guess actually worked. **Severity:** High.

### Rule 3 — Authentication From Unusual Location
```kql
SecurityEvent
| where EventID == 4624 and Account == "j.rao"
| where IpAddress != "<user's known home/office IP range>"
```
**MITRE:** T1078 — Valid Accounts. **Why:** A valid account used from a location it has never used before is suspicious even without failures. **Tuning:** Requires an accurate, maintained list of known user locations — otherwise this rule is noisy.

### Rule 4 — Impossible Travel Authentication
*(Query 7 logic, using Sentinel's built-in geo-IP enrichment)*
**MITRE:** T1078 — Valid Accounts. **Why:** Removes ambiguity — "unusual location" might be a business trip; "two countries in 11 minutes" cannot be. **Severity:** Critical.

### Rule 5 — Multiple Accounts Targeted By Same IP
```kql
SecurityEvent
| where EventID == 4625
| summarize Accounts = dcount(Account) by IpAddress, bin(TimeGenerated, 10m)
| where Accounts >= 5
```
**MITRE:** T1110.003 — Password Spraying. **Why:** Distinguishes "one account under attack" from "one IP sweeping many accounts," which changes the response (this incident, checked against this rule, showed only **one** account was targeted — so it was classified as targeted brute force, not a spray).

---

# PHASE 4 — ALERT TRIAGE

| Field | Value |
|---|---|
| **Alert Name** | Successful Sign-In Following Multiple Failures — Possible Account Compromise |
| **Alert Severity (Sentinel)** | High |
| **Alert Confidence** | High (corroborated by Impossible Travel alert firing independently) |
| **Initial Assessment** | Not a password typo — 10 failures from one external IP, followed by a success, followed by a second-country sign-in |
| **Analyst Notes** | Cross-checked Event 4672 — no privilege escalation. Cross-checked Event 4740 — no lockout triggered (threshold not reached). User contacted directly to confirm they did not travel or sign in from Amsterdam. |
| **Triage Decision** | **Escalate — confirmed compromise, not a false positive** |

## ✅ False Positive Analysis (Why This Was NOT Closed as a False Positive)

```
Could this be the user travelling?        → User confirmed by phone: no travel, 
                                              still in Hyderabad at time of alert.
Could this be a shared/VPN exit IP        → Checked: user does not use a 
  the user legitimately uses?               corporate VPN that exits via Amsterdam.
Could this be a mistyped password burst?  → Ruled out: sub-status codes show 
                                              valid username, wrong password, 
                                              matching a guessing pattern, not 
                                              a single person retrying.
Could threat intel be wrong/outdated?     → Two independent sources (AbuseIPDB, 
                                              OTX) agree on IP #1; corroborated 
                                              by the impossible-travel math, which 
                                              does not depend on reputation data.
```
**Conclusion:** All four checks point the same direction. This is a **true positive, confirmed account compromise.**

---

# PHASE 5 — INCIDENT RESPONSE

## 🕐 Investigation Timeline

| Time | Action |
|---|---|
| 08:00 AM | Multiple failed logins observed (10x, Event 4625) |
| 08:05 AM | Successful login detected from the same IP (Event 4624) |
| 08:07 AM | Sentinel analytics rule fires — Possible Account Compromise |
| 08:09 AM | Second sign-in from Amsterdam; Impossible Travel alert fires |
| 08:10 AM | SOC Analyst (me) picks up the incident |
| 08:13 AM | IOC analysis initiated (Query 6 run, timeline rebuilt) |
| 08:20 AM | Threat intelligence enrichment completed (VirusTotal, AbuseIPDB, OTX) |
| 08:24 AM | User contacted by phone and confirmed no travel, no logins from abroad |
| 08:30 AM | Incident escalated to Tier-2 / IR team |
| 08:40 AM | Containment executed (below) |
| 09:05 AM | Incident contained |

## 🎫 Incident Ticket

```
================================================================================
SOC INCIDENT TICKET
================================================================================
INCIDENT ID:       INC-2026-0511
SEVERITY:          HIGH
PRIORITY:          P1
STATUS:            RESOLVED
ASSIGNED ANALYST:  Riyaz Shaik (SOC Analyst L1)

SUMMARY:
Account j.rao (Finance) showed 10 failed sign-ins from an external IP, 
followed by a successful sign-in, followed 11 minutes later by a second 
successful sign-in from a different country. Two independent Sentinel 
analytics rules fired. Threat intelligence confirmed both source IPs as 
previously reported for credential-access activity.

ROOT CAUSE:
Credential compromise via brute-force guessing (T1110), likely from a 
reused or weak password with no MFA enforced on the account.

IMPACT:
Unauthorized access to a Finance user's mailbox/session for an estimated 
window of ~35 minutes before containment. No evidence of data exfiltration 
or privilege escalation (Event 4672 clean).

ACTIONS TAKEN:
1. Disabled the j.rao account in Active Directory / Entra ID
2. Revoked all active sign-in sessions and tokens
3. Blocked both source IPs at the firewall / Conditional Access
4. Forced password reset and required MFA re-enrollment
5. Reviewed mailbox for forwarding rules — none found
6. Escalated to Tier-2 for deeper host and mailbox forensic review

RECOMMENDATIONS:
Enforce MFA tenant-wide; enable Conditional Access impossible-travel 
blocking by default rather than alert-only; review password policy.
================================================================================
```

## 📣 Incident Escalation

```
Why escalation occurred:    Confirmed account compromise with cross-border
                             sign-in activity and no MFA in place — exceeds
                             L1 authority to close independently.
Escalated to:                Tier-2 Incident Response team
Escalation priority:         P1 — High
Escalation notes:            Requested mailbox forensic review for data
                              access/exfiltration during the ~35-minute
                              compromise window, and a tenant-wide MFA
                              enforcement review.
```

## 🧯 Containment Actions Recommended

| Action | Why It's Required |
|---|---|
| **Password reset** | Removes the credential the attacker proved they knew. |
| **MFA validation/enforcement** | A password alone was sufficient here — MFA would have stopped the second sign-in even with the password compromised. |
| **Session/token termination** | A password reset alone does not end an already-active session; tokens must be revoked separately. |
| **IP blocking** | Stops the same source from retrying immediately after containment. |
| **Monitoring (72 hours)** | Compromised accounts are sometimes re-targeted once attackers notice containment; a monitoring window catches a second attempt. |

---

# PHASE 6 — MITRE ATT&CK MAPPING

| Technique | ATT&CK ID | Tactic | How It Applied Here |
|---|---|---|---|
| Brute Force | T1110 | Credential Access | The 10-failure burst against j.rao |
| Password Spraying | T1110.003 | Credential Access | Checked via Rule 5 — ruled out, only one account was targeted |
| Valid Accounts | T1078 | Initial Access / Persistence | The successful sign-in using the guessed password |
| Cloud Accounts | T1078.004 | Initial Access / Persistence | The account is a hybrid Entra ID identity; the second sign-in reused cloud session validity |
| Account Discovery | T1087 | Discovery | Checked for — no evidence other accounts were enumerated in this incident |

---

# PHASE 7 — FINAL INCIDENT REPORT

## Executive Summary
A Finance department account was compromised through password guessing. Microsoft Sentinel detected the pattern through two independent correlation rules — a success-after-failures rule and an impossible-travel rule — within two minutes of the compromising sign-in. The account was contained within roughly 35 minutes of the initial failed-login burst, before privilege escalation or confirmed data loss occurred.

## Technical Summary
Ten Event ID 4625 failures (Logon Type 3) from IP 103.21.XX.XX preceded a successful Event ID 4624 from the same IP, followed 11 minutes later by a second successful sign-in from IP 185.244.XX.XX (Amsterdam). No Event 4672 (privilege assignment) or 4740 (lockout) occurred. Both source IPs carried negative reputation in AbuseIPDB and AlienVault OTX.

## Indicators
See the IOC Analysis and Threat Intelligence tables above.

## Timeline
See the Investigation Timeline table above.

## Findings
- The activity is a confirmed, targeted brute-force compromise, not password spraying and not user error.
- No privilege escalation occurred.
- No mailbox forwarding rule was found during eradication checks.
- The account had no MFA enforced, which was the single enabling factor.

## Impact
One Finance account was accessed by an unauthorized party for an estimated 35-minute window. No confirmed data exfiltration; mailbox forensic review was escalated to Tier-2 to confirm this conclusively.

## Root Cause
Absence of MFA combined with a guessable or reused password allowed a brute-force attempt to succeed on the 11th try.

## Recommendations
1. Enforce MFA tenant-wide — this single control would have stopped the second (actual-use) sign-in even after the password was guessed.
2. Turn on Conditional Access impossible-travel **blocking**, not just alerting.
3. Apply a fine-grained password policy to block common/weak passwords.
4. Deploy all 5 rules above as scheduled, live Sentinel analytics rules with assigned severities.
5. Add automatic mailbox-forwarding-rule detection as a standing alert.

## Lessons Learned
A single alert (the failure burst) would likely have been triaged as low priority on its own. It was the **correlation** between two separate rules — success-after-failure and impossible-travel — that turned a routine alert into a confirmed, fast escalation. This is the strongest argument for building correlation rules rather than relying on single-event alerts.

---

## 🗂️ SOC Workflow Diagram

```
Alert Generated
      ↓
Alert Triage  (confidence, severity, initial read)
      ↓
Alert Investigation  (benign or malicious?)
      ↓
IOC Analysis  (IP, account, timestamps, event IDs)
      ↓
Threat Intelligence Enrichment  (VirusTotal, AbuseIPDB, OTX)
      ↓
Event Correlation  (failures ↔ success ↔ impossible travel)
      ↓
Severity Decision  (Low / Medium / High / Critical)
      ↓
Escalation  (to Tier-2 Incident Response)
      ↓
Containment  (disable, revoke, block, reset, monitor)
      ↓
Documentation  (ticket, timeline, final report)
      ↓
Closure
```

## 🧭 Incident Severity Matrix

| Severity | Meaning | Where this incident sat |
|---|---|---|
| Low | Informational, no action needed | — |
| Medium | Suspicious, needs a look | Where the failure burst alone would have sat |
| High | Likely compromise | Where this incident was classified |
| Critical | Active, confirmed compromise with ongoing access or data loss | Would apply if mailbox review confirms exfiltration |

## 🧮 Analyst Decision Matrix

| Situation | Decision |
|---|---|
| Failures only, no success, no TI hits | Monitor |
| Failures + success, but TI clean and user confirms travel | Close as false positive, note for baseline update |
| Failures + success + TI hit + user denies activity (this incident) | **Escalate** |
| Any privilege escalation event (4672) present | Escalate as Critical regardless of other factors |

## 📝 Incident Closure Notes
```
Closure status:     RESOLVED — escalated and contained
Remaining action:   Tier-2 mailbox forensic review (pending at time of writing)
Follow-up:          72-hour monitoring window on j.rao's account
Playbook update:    Added "contact user directly before closing any 
                     unusual-location alert" as a mandatory triage step
```

---

## 💼 Skills Demonstrated

```
✅ Microsoft Sentinel — analytics rules, incidents, entity investigation graph
✅ KQL — 7 original queries covering detection, triage and reporting
✅ Windows Event Log analysis (4625, 4624, 4648, 4672, 4740)
✅ IOC analysis and structured evidence documentation
✅ Threat intelligence enrichment (VirusTotal, AbuseIPDB, AlienVault OTX)
✅ Event correlation across multiple signals (failures + success + geo)
✅ Detection engineering — 5 correlation rules mapped to MITRE ATT&CK
✅ False positive analysis and triage decision-making
✅ Full incident response lifecycle: contain, eradicate (checked), recover, monitor
✅ Incident ticketing, escalation documentation, and final report writing
✅ SOC severity classification and analyst decision matrices
```

---

## 🗣️ 30-Second Interview Answer

> "I investigated a suspicious authentication incident in Microsoft Sentinel where an account showed ten failed sign-ins followed by a success, and then a second sign-in from another country eleven minutes later. I wrote seven KQL queries to rebuild the timeline, confirmed the pattern with threat intelligence from AbuseIPDB and AlienVault OTX, and ruled out false positives by checking the user's baseline and contacting them directly. I built five correlation rules — including an impossible-travel rule — mapped everything to MITRE ATT&CK, and escalated with a full incident ticket and containment plan. The key lesson was that correlating two separate alerts turned a routine-looking failure burst into a fast, confident escalation."

---

## 📝 Resume Project Description

```
Suspicious Authentication Investigation — Microsoft Sentinel
Investigated a suspicious authentication incident using Microsoft Sentinel, 
Windows Event Logs, and KQL. Authored 7 KQL queries and 5 correlation rules 
(brute force, success-after-failure, unusual location, impossible travel, 
password spraying) mapped to MITRE ATT&CK. Performed IOC analysis and 
threat intelligence enrichment via VirusTotal, AbuseIPDB, and AlienVault 
OTX. Conducted alert triage with false-positive analysis, escalated a 
confirmed account compromise, and produced a full incident ticket, 
timeline, and final investigation report following SOC Analyst L1 workflows.
```

## ✅ ATS-Friendly Resume Bullets

```
• Investigated suspicious authentication activity in Microsoft Sentinel 
  using Windows Event Logs and 7 original KQL queries
• Authored 5 SIEM correlation rules (brute force, impossible travel, 
  password spraying) mapped to MITRE ATT&CK T1110, T1110.003, T1078, T1078.004
• Performed IOC analysis and threat intelligence enrichment via 
  VirusTotal, AbuseIPDB, and AlienVault OTX
• Conducted alert triage with documented false-positive analysis and 
  user validation before escalation
• Escalated a confirmed account compromise, producing a full incident 
  ticket, timeline, and final investigation report
• Recommended and justified containment actions: session revocation, 
  password reset, MFA enforcement, and IP blocking
```

---

## ❓ Interview Q&A

**Q: How did you know this wasn't just the user travelling?**
> I checked their 90-day sign-in baseline with a KQL query, and then called the employee directly rather than assuming. They confirmed they were in Hyderabad the whole time and had not signed in from Amsterdam. Verifying with the user is listed as a mandatory triage step, not an optional one.

**Q: Why did you treat this as High rather than Critical?**
> Critical, in my severity matrix, requires confirmed ongoing access or confirmed data loss. Event 4672 showed no privilege escalation, and mailbox review (escalated to Tier-2) hadn't confirmed exfiltration yet at the time of my report, so I classified it High and let the forensic review decide if it needed to move to Critical.

**Q: What single control would have prevented this?**
> MFA. The attacker still needed eleven tries to guess the password, which shows it wasn't trivially weak — but once guessed, nothing else stopped them from using it. MFA breaks that chain at the exact point where a password alone currently succeeds.

**Q: Why build a correlation rule instead of just a failed-login alert?**
> A failed-login alert alone fires constantly and gets ignored or deprioritized. Correlating "failures then success" and "success then a second country" turns noisy, low-confidence signals into one high-confidence alert — which is what actually gets a fast response.

---

## 📁 Repository Structure

```
11.Suspicious-Authentication-Investigation-Sentinel/
├── README.md
├── kql-queries/
│   ├── 01_failed_login_analysis.kql
│   ├── 02_successful_login_analysis.kql
│   ├── 03_failure_then_success.kql
│   ├── 04_top_source_ips.kql
│   ├── 05_authentication_trends.kql
│   ├── 06_user_login_activity.kql
│   └── 07_impossible_travel.kql
├── analytics-rules/
│   ├── rule_1_multiple_failed_logins.kql
│   ├── rule_2_success_after_failures.kql
│   ├── rule_3_unusual_location.kql
│   ├── rule_4_impossible_travel.kql
│   └── rule_5_password_spraying.kql
├── incident-report/
│   ├── INC-2026-0511_ticket.txt
│   ├── timeline.md
│   └── final_investigation_report.md
├── threat-intel/
│   └── ioc_enrichment_notes.md
└── images/
    ├── 01-sentinel-overview.png
    ├── 02-analytics-rule.png
    ├── 03-incident-queue.png
    ├── 04-alert-details.png
    ├── 05-event-4625.png
    ├── 06-event-4624.png
    ├── 07-kql-results.png
    ├── 08-ti-lookup.png
    ├── 09-mitre-mapping.png
    ├── 10-incident-ticket.png
    ├── 11-timeline.png
    └── 12-final-report.png
```

---

## ⚠️ Legal / Honesty Disclaimer

> This project was built as a portfolio and learning exercise in a private Microsoft Sentinel lab tenant. The employee, account, IP addresses, and incident are **simulated** for educational purposes, built to mirror realistic SOC Analyst L1 workflows. No real company, employee, or third party is represented. Screenshot placeholders above describe exactly what to capture from your own lab — replace them with real screenshots from your own Sentinel workspace rather than images sourced elsewhere, since a hiring manager trusts evidence of your own work, not stock images.

---

*Suspicious Authentication Investigation | SOC Analyst L1 Portfolio | Riyaz Shaik*
