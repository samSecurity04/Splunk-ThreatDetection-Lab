# 🛡️ Splunk Threat Detection Lab

### Three Splunk detections built from raw SPL — including one that failed on real data, and why.

![Splunk](https://img.shields.io/badge/Splunk_Cloud-9.x-000000?style=for-the-badge&logo=splunk&logoColor=white)
![SPL](https://img.shields.io/badge/SPL-Detection_Engineering-FF6F00?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-Data_Generation-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=for-the-badge)

---

## At a Glance

This repository demonstrates three threat detections built in **Splunk Cloud** using raw SPL and live feature engineering.

| Project | Detection | Key Result |
|---------|-----------|------------|
| 🌍 Project 1 | Impossible Travel | Calculated geo-velocity live using the Haversine formula |
| 🔗 Project 2 | Threat Intel Correlation | Matched outbound traffic against the real abuse.ch Feodo Tracker C2 feed |
| 🧬 Project 3 | DNS Tunneling | Worked on synthetic data, then collapsed to **13.4% recall** on a real labeled dataset |

The strongest part of this lab is **Project 3**: a DNS tunneling detector that looked perfect on synthetic data but failed against real-world labeled domains. Instead of hiding that failure, this project documents exactly why it happened.

---

## Why This Project Exists

Building a detection that works on planted synthetic data is easy.

Building one that survives contact with real data is harder.

This lab focuses on the second problem.

Each detection was built from raw fields instead of pre-labeled flags. The goal was to practice real detection engineering: feature extraction, SPL logic, validation, dashboarding, and honest failure analysis.

---

## The Honest Version

| What is real | What is not |
|-------------|-------------|
| ✅ All SPL detections compute features live from raw fields | ⚠️ Authentication, network, and DNS lab traffic are synthetic |
| ✅ The threat-intel feed is the real abuse.ch Feodo Tracker C2 blocklist | ⚠️ Some thresholds are hand-tuned rather than statistically baselined |
| ✅ Project 3 was tested against a real 5,559-domain labeled dataset | ⚠️ Synthetic data results are not treated as proof of real-world performance |
| ✅ Failures, bugs, and dead ends are documented | ⚠️ The lab is educational, not production-ready |

The point of this repository is not to claim perfect detections.

The point is to show the detection engineering process clearly: what worked, what failed, why it failed, and what would need to change in production.

---

## Detection Pipeline

```text
Raw Logs
   ↓
Feature Engineering in SPL
   ↓
Detection Logic
   ↓
Dashboard / Investigation View
   ↓
Validation
   ↓
Failure Analysis
```

---

# 🌍 Project 1 — Impossible Travel Detection

## Scenario

A user logs in from two cities so far apart, and so close together in time, that legitimate travel is physically impossible.

This is a classic indicator of:

- Compromised credentials
- Stolen session tokens
- Account sharing
- Unauthorized access through VPNs or proxies

In this lab, the clearest example was:

> **Sam logged in from Melbourne, then London, 15 minutes later.**

---

## Detection Result

| User | Route | Distance | Time | Speed | Severity |
|------|-------|----------|------|-------|----------|
| **Sam** | Melbourne → London | 16,903 km | 0.25 h | **67,612 km/h** | Critical |
| **Vineet** | New York → Mumbai | 12,538 km | 0.38 h | **32,708 km/h** | Critical |
| **Vineet** | Mumbai → New York | 12,538 km | 0.33 h | **37,614 km/h** | Critical |

A speed of **67,612 km/h** is not a traveler.

It is a strong signal of a hijacked session, proxy abuse, or credential misuse.

> 📸 **Figure 1:** `03_travel_detection.png` — 7 flagged events with computed distance, speed, and severity.

---

## Detection Logic

This detection does not rely on a pre-existing `impossible_travel` field.

Instead, SPL calculates geo-velocity directly:

1. Sort events by user and time.
2. Use `streamstats` to retrieve each user's previous login.
3. Calculate distance between login locations using the Haversine formula.
4. Calculate elapsed time between logins.
5. Compute travel speed.
6. Flag speeds above realistic travel thresholds.

```spl
index=main sourcetype=csv
| sort 0 user _time
| streamstats current=f last(city) as prev_city last(lat) as prev_lat last(lon) as prev_lon last(_time) as prev_time by user
| where city!=prev_city
| eval time_diff_hours=(strptime(_time,"%Y-%m-%dT%H:%M:%S")-strptime(prev_time,"%Y-%m-%dT%H:%M:%S"))/3600
| eval lat1_rad=prev_lat*3.14159/180, lat2_rad=lat*3.14159/180
| eval dlat=lat2_rad-lat1_rad, dlon=(lon-prev_lon)*3.14159/180
| eval a=sin(dlat/2)*sin(dlat/2)+cos(lat1_rad)*cos(lat2_rad)*sin(dlon/2)*sin(dlon/2)
| eval distance_km=round(2*6371*asin(sqrt(a)),0)
| eval speed_kmh=round(distance_km/time_diff_hours,0)
| eval severity=case(speed_kmh>5000,"Critical",speed_kmh>2000,"High",speed_kmh>900,"Medium")
| where speed_kmh>900
| table _time user prev_city city distance_km time_diff_hours speed_kmh severity
```

---

## Dashboard

The dashboard was designed as a SOC triage view.

It includes:

- Global authentication map
- Severity breakdown
- Login timeline
- Investigation queue

> 📸 **Figure 2:** `04_travel_dashboard.png` — 4-panel impossible travel dashboard.

---

## Scope Note

The geo-velocity calculation is a real computed detection.

The dashboard also displays additional authentication anomaly categories such as failed-login bursts, off-hours new-device activity, and MFA failures. These categories are seeded in the synthetic data generator and counted for visualization.

Only the Haversine geo-velocity logic is treated as the live detection in this project.

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|--------|-----------|
| Initial Access / Persistence | T1078 — Valid Accounts |
| Defense Evasion | T1550 — Alternate Authentication Material |

---

## Real-World Limitations

Impossible travel detection is useful, but noisy in production.

Legitimate users can appear to travel impossible distances because of:

- VPNs
- Corporate proxies
- Cloud access gateways
- Mobile carrier routing
- Shared egress IPs

Attackers can also evade this detection by using infrastructure geographically close to the victim.

In production, this detection should be enriched with:

- Known VPN ranges
- Trusted corporate egress IPs
- MFA status
- Device fingerprinting
- User baseline behavior
- Session risk scoring

Impossible travel is best used as one signal in a larger account-compromise detection strategy, not as a standalone verdict.

---

# 🔗 Project 2 — Threat Intelligence Correlation

## Scenario

A compromised endpoint is quietly communicating with external command-and-control (C2) infrastructure.

Rather than looking for behavioral anomalies, this detection identifies known malicious infrastructure by correlating outbound network traffic with a live threat intelligence feed.

This is a classic example of **Indicator of Compromise (IOC) matching**—simple, fast, and effective against known threats.

---

## Detection Result

One internal host repeatedly communicated with four IP addresses present in the **abuse.ch Feodo Tracker** C2 blocklist.

| User | Source IP | Threat Matches | Risk |
|------|-----------|---------------:|------|
| **Andrea** | 10.0.1.52 | **4** | High |

---

### Matched Infrastructure

| Destination IP | Malware Family | Status | Connections |
|---------------|----------------|---------|------------:|
| 162.243.103.246 | Emotet | Offline | 8 |
| 178.62.3.223 | QakBot | Offline | 8 |
| 34.204.119.63 | QakBot | Offline | 8 |
| 50.16.16.211 | QakBot | **🟢 Online** | 5 |

One of the matched servers was still listed as **online** when the detection was performed, demonstrating correlation against an actively maintained threat intelligence feed rather than historical IOC data.

> 📸 **Figure 3:** `project2-07-correlation-4-c2-hits.png`

---

## Detection Logic

This project uses the public **abuse.ch Feodo Tracker** blocklist as a Splunk lookup table.

Every outbound destination IP is checked against the threat intelligence feed during search execution.

If a destination matches a known malicious IP, the event is enriched with malware family, infrastructure status, and additional threat context.

Unlike behavioral detections, this approach does not attempt to infer malicious activity—it simply asks:

> **"Is this host communicating with infrastructure already known to be malicious?"**

---

## SPL Detection

```spl
index=main source="network_traffic.csv"

| lookup threat_intel dst_ip
OUTPUT malware as threat_name
       c2_status
       last_online

| where isnotnull(threat_name)

| stats
    count as connection_count
    sum(bytes_out) as total_bytes
    by user src_ip dst_ip threat_name c2_status

| sort -connection_count
```

---

## Threat Intelligence Preparation

Before the lookup could be used inside Splunk, the Feodo Tracker feed was cleaned and converted into a lookup table.

The preparation process included:

- Removing comments
- Removing inactive records
- Formatting fields for CSV lookup
- Importing into Splunk Cloud
- Configuring automatic lookup enrichment

> 📸 **Figure 4:** `project2-01-feed-prep-grep.png`

---

## Detection Workflow

```text
Network Traffic
        │
        ▼
Extract Destination IP
        │
        ▼
Threat Intelligence Lookup
        │
        ▼
IOC Match?
      ┌───────┐
      │       │
     Yes      No
      │       │
      ▼       ▼
 Enrich Event Continue
      │
      ▼
 SOC Investigation
```

---

## Why IOC Matching Still Matters

IOC matching is sometimes dismissed because it cannot detect novel attacks.

That criticism is true—but incomplete.

Known malicious infrastructure remains responsible for a significant amount of commodity malware, phishing kits, botnets, and command-and-control traffic.

IOC correlation provides:

- Low computational cost
- Easy implementation
- High analyst confidence
- Valuable context during investigations

For mature SOCs, it serves as one layer in a defense-in-depth strategy rather than a complete detection solution.

---

## Dashboard

The accompanying dashboard provides analysts with:

- Top infected hosts
- Malware family distribution
- Connection frequency
- Threat severity
- Timeline of C2 communication

> 📸 **Figure 5:** `project2-dashboard.png`

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|--------|-----------|
| Command and Control | **T1071 — Application Layer Protocol** |
| Exfiltration | **T1041 — Exfiltration Over C2 Channel** |

---

## Real-World Limitations

IOC matching is intentionally simple.

It detects communication only with infrastructure that is already known and published.

It will **not** detect:

- Newly registered attacker infrastructure
- Fast-flux networks
- Domain Generation Algorithms (DGAs)
- Domain fronting
- Cloud redirectors
- Private C2 servers
- Zero-day campaigns

Its effectiveness also depends on the quality and freshness of the underlying threat intelligence feed.

For that reason, IOC matching should be combined with behavioral analytics, anomaly detection, and endpoint telemetry rather than used as the sole detection strategy.

---

## What This Project Demonstrates

- Building Splunk lookups
- Threat intelligence enrichment
- IOC correlation using SPL
- Network traffic analysis
- Investigation-oriented dashboard development
- Understanding both the strengths and limitations of indicator-based detection

---

# 🧬 Project 3 — DNS Tunneling: When the Detection Failed

> **This is the most important project in this repository—not because the detection succeeded, but because it didn't.**

Many portfolio projects end when the dashboard turns green.

This one starts there.

The detection achieved **100% recall** on synthetic data. It then dropped to **13.4% recall** when evaluated against a real, publicly labeled DNS tunneling dataset.

Understanding *why* that happened turned out to be far more valuable than the original detection itself.

---

## Scenario

DNS tunneling abuses the DNS protocol to move data through subdomains that appear to be legitimate DNS queries.

Compared to normal domains, tunneling traffic often exhibits characteristics such as:

- unusually long subdomains
- high character diversity
- encoded payloads
- repeated DNS requests

The goal of this project was to detect those characteristics using only SPL.

---

# Stage 1 — Building the Detection

Rather than searching for known malicious domains, the detector computes two behavioral features directly from each DNS query.

### Feature 1 — Subdomain Length

Long encoded payloads often produce unusually long subdomains.

Example:

```
Normal:
mail.google.com

Tunnel:
aj29djq83jskslq9qk282jdj3299.example.com
```

---

### Feature 2 — Character Diversity

Encoded payloads also tend to contain many unique characters.

Normal DNS names usually contain repeated words:

```
login
mail
api
portal
```

Encoded payloads look much more random:

```
a92js82jd92jx91ks82jjq
```

To measure this, SPL computes

```
unique characters
-----------------
subdomain length
```

A higher ratio indicates greater randomness.

---

## SPL Detection

```spl
index=main source="dns_logs.csv"

| eval sub=mvindex(split(query,"."),0)

| eval sub_len=len(sub)

| eval chars=split(sub,"")

| eval unique_chars=mvcount(mvdedup(chars))

| eval char_diversity=round(unique_chars/sub_len,2)

| eval suspicious=
    if(
        sub_len>20
        AND char_diversity>0.45,
        1,
        0
    )

| where suspicious=1

| stats
    count as suspicious_queries
    avg(sub_len) as avg_len
    avg(char_diversity) as avg_diversity
    by user src_ip

| where suspicious_queries>5
```

---

## Synthetic Evaluation

Using the synthetic DNS dataset generated for this lab:

| Metric | Result |
|--------|-------:|
| Recall | **100%** |
| False Positives | **0%** |

At first glance, the detector appeared excellent.

It caught every simulated tunneling session while producing no false alerts.

But there was a problem.

The synthetic tunneling traffic had been deliberately generated to be:

- long
- random
- highly encoded

The detector was effectively being tested against data that had been designed to satisfy its own assumptions.

A perfect score on synthetic data proves very little.

---

# Stage 2 — Testing Against Real Data

To evaluate the detector under more realistic conditions, it was tested against a **public Zenodo dataset containing 5,559 labeled domains**.

This evaluation was performed without changing the detection logic.

---

## Results

| Class | Total | Flagged | Result |
|-------|-------:|--------:|--------|
| Tunneling | 1,559 | **209** | **13.4% recall** |
| Benign | 3,000 | 67 | **2.2% false positive rate** |

The detection that looked perfect on synthetic data missed **87% of real tunneling domains.**

That collapse became the most valuable result in the project.

> 📸 **Figure 6:** `project3-12-real-confusion-matrix.png`

---

# Why Did It Fail?

The obvious assumption was that the thresholds simply needed adjustment.

They didn't.

Splitting the dataset across both detection features revealed the real problem.

---

## Distribution of Real Tunneling Domains

| | Diversity ≤ 0.45 | Diversity > 0.45 |
|---|---:|---:|
| **Length ≤20** | 4 | **725** |
| **Length >20** | **621** | **209** ✅ |

Only the bottom-right quadrant satisfies both conditions:

```
Length >20
AND
Diversity >0.45
```

Everything else is missed.

That means:

- **725** domains were short but highly diverse
- **621** were long but relatively low diversity

Together, those two groups represent **1,346 missed tunneling domains.**

---

## The Important Lesson

The malicious traffic was **bimodal**.

Instead of forming one neat cluster, it split into two distinct groups.

A detector based on a single rectangular threshold cannot separate both groups simultaneously.

This wasn't a threshold problem.

It was a feature-space problem.

---

# The Tempting "Fix"

The obvious idea was to replace

```
Length >20
AND
Diversity >0.45
```

with

```
Length >20
OR
Diversity >0.45
```

The results changed dramatically.

| Metric | Original | OR Rule |
|--------|---------:|---------:|
| Recall | 13.4% | 99.7% |
| False Positives | Low | Extremely High |

Almost every malicious domain was detected.

So were thousands of legitimate domains.

The detector became practically unusable.

It would have been easy to report the **99.7% recall** and ignore the false positives.

That would also have been misleading.

Detection engineering is about balancing precision and recall—not maximizing one metric at the expense of the other.

---

# Conclusion

This experiment demonstrated that simple Boolean threshold logic cannot reliably distinguish real DNS tunneling traffic from legitimate DNS activity.

Improving performance would require additional features such as:

- entropy
- n-gram frequency
- query frequency
- temporal behavior
- destination reputation
- weighted scoring
- machine learning

The failed detector became a stronger portfolio project than a successful one because it exposed the limitations of simplistic detection logic and highlighted the importance of proper validation.

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|--------|-----------|
| Command and Control | **T1071.004 – DNS** |
| Exfiltration | **T1048.003 – Exfiltration Over Unencrypted Protocol** |
| Command and Control | **T1568 – Dynamic Resolution** |

---

## What This Project Demonstrates

- Feature engineering directly in SPL
- Behavioral detection design
- Validation against public labeled datasets
- Confusion matrix analysis
- Precision vs recall trade-offs
- Root-cause analysis of detector failure
- Honest reporting of experimental results

---

> **The most valuable outcome wasn't the detector. It was discovering why it failed.**


# 🔥 Detection Engineering War Stories

Building the detections was only part of the project. Debugging them—and understanding why they failed—was where most of the learning happened.

---

## 1. The `avg_diversity = 1.0` Bug

The first version of the DNS detector produced an average character diversity of **1.0** for every query.

The bug wasn't random—it was structural.

Using:

```spl
split(sub,"")
```

followed by:

```spl
mvcount(chars)
```

counted **every character**, including duplicates. As a result, the numerator and denominator were always identical.

The fix was to remove duplicate characters before counting them:

```spl
mvdedup(chars)
```

After correcting the calculation, the average diversity dropped to realistic values (~0.62) and the detector began producing meaningful results.

---

## 2. Aggregate First, Detect Never

The initial DNS detector aggregated all DNS traffic per user before applying detection thresholds.

That decision buried malicious traffic inside normal activity.

For example:

- Normal queries: **1,218**
- Malicious queries: **120**

When averaged together, neither feature exceeded the threshold and the search returned:

> **No Results Found**

The solution was simple but important:

> **Detect first. Aggregate second.**

Filtering individual suspicious queries before aggregation immediately recovered the expected detections.

---

## 3. When the Detection Wasn't the Problem

While building the Threat Intelligence correlation project, the SPL search repeatedly returned zero matches.

The query was correct.

The lookup was correct.

The issue turned out to be timing.

The lookup table had not yet finished saving in Splunk Cloud, so the search executed before the lookup became available.

Re-running the search after the lookup propagated immediately produced the expected C2 matches.

It was a useful reminder that sometimes the infrastructure—not the detection—is the source of the bug.

---

## 4. Knowing When to Stop

One goal was to visualize DNS tunneling clusters using a two-dimensional scatter plot.

After multiple attempts with Splunk's classic visualization engine, it became clear that the available chart types could not represent the data cleanly without excessive workarounds.

Instead of forcing a visualization that obscured the results, the project switched to:

- a confusion matrix,
- a 2×2 feature distribution table,
- and a simpler bubble chart.

Those visualizations communicated the underlying problem more effectively.

Sometimes choosing a simpler visualization is the better engineering decision.

---

# 🎯 MITRE ATT&CK Mapping

| Project | Technique | MITRE ID |
|----------|-----------|----------|
| Impossible Travel | Valid Accounts | T1078 |
| Impossible Travel | Alternate Authentication Material | T1550 |
| Threat Intelligence Correlation | Application Layer Protocol | T1071 |
| Threat Intelligence Correlation | Exfiltration Over C2 Channel | T1041 |
| DNS Tunneling | Application Layer Protocol: DNS | T1071.004 |
| DNS Tunneling | Exfiltration Over Unencrypted Protocol | T1048.003 |
| DNS Tunneling | Dynamic Resolution | T1568 |

---

# 💡 Key Takeaways

## Technical

Throughout this project I gained practical experience in:

- Building detections that compute features directly in SPL rather than relying on pre-labeled indicators.
- Implementing geo-velocity calculations using the Haversine formula.
- Enriching events with external threat intelligence through Splunk lookups.
- Designing behavioral detections based on engineered features.
- Validating detection logic using public labeled datasets.
- Evaluating detector performance using confusion matrices and recall/false-positive analysis.

---

## Engineering

This project reinforced several lessons that extend beyond Splunk itself.

- A detector that performs perfectly on synthetic data is not necessarily a good detector.
- Validation against realistic data is just as important as writing the detection.
- Improving one metric (such as recall) often comes at the expense of another (such as precision).
- Understanding *why* a detector fails is often more valuable than demonstrating that it works.
- Detection engineering is an iterative process of hypothesis, testing, debugging, and refinement.

---

# 🛠️ Skills Demonstrated

### Platforms

- Splunk Cloud
- Python

### Detection Engineering

- SPL
- Feature Engineering
- Detection Development
- Geo-Velocity Analysis
- IOC Correlation
- Behavioral Analytics
- DNS Tunneling Detection

### Security Operations

- Threat Hunting
- SOC Dashboard Development
- Investigation Workflows
- Threat Intelligence Integration

### Analysis

- Confusion Matrix Evaluation
- Detection Validation
- Root Cause Analysis
- Data Visualization

### Frameworks

- MITRE ATT&CK

---

# 👤 Author

**Samruddhi (Sam) Patil**

🎓 CompTIA Security+  
🎓 Microsoft SC-900  
🎓 EC-Council CASE (Java)  
🎓 Google Cybersecurity Professional Certificate

**GitHub**  
https://github.com/samSecurity04

**LinkedIn**  
https://www.linkedin.com/in/samruddhi-p-patil/

---

### About This Repository

This project was built as part of a personal cybersecurity portfolio to explore practical detection engineering using Splunk.

Synthetic datasets were used to simulate authentication, network, and DNS activity. Real-world context was incorporated through the **abuse.ch Feodo Tracker** threat intelligence feed and a **public Zenodo DNS dataset** used to evaluate the behavioral DNS detection.

The objective was not to build perfect detections, but to demonstrate the engineering process behind designing, testing, validating, and improving them.
