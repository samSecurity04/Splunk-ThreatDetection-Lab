# 🛡️ Splunk Threat Detection Lab

### *Anyone can write a detection that flags planted data. The real test is whether it survives contact with the real world — mine did, and one of them didn't.*

![Splunk](https://img.shields.io/badge/Splunk_Cloud-9.x-000000?style=for-the-badge&logo=splunk&logoColor=white)
![SPL](https://img.shields.io/badge/SPL-Detection_Engineering-FF6F00?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-Data_Generation-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=for-the-badge)

> **Three detections built from raw SPL — geo-velocity, threat-intel correlation, and behavioral DNS tunneling.** Not pre-labeled data fed through a rule. Real math computed live in the search bar, then stress-tested against a real labeled dataset. Including the one that failed at 13.4% recall — and exactly why.

---

## 📌 Table of Contents

- [The Honest Version](#-the-honest-version)
- [Project 1 — Impossible Travel Detection](#-project-1--impossible-travel-detection)
- [Project 2 — Threat Intel Correlation](#-project-2--threat-intel-correlation)
- [Project 3 — DNS Tunneling: The One That Failed](#-project-3--dns-tunneling-the-one-that-failed)
- [Detection Engineering War Stories](#-detection-engineering-war-stories)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [What I Learned](#-what-i-learned)
- [Skills Demonstrated](#-skills-demonstrated)

---

## 🎯 The Honest Version

Most lab writeups show you the detection that worked and stop there. This one shows the seams — because that's where the actual skill is.

| What's real | What's not |
| --- | --- |
| ✅ All SPL computed **live** from raw fields (Haversine, char-diversity) | ⚠️ All traffic data is **synthetic** (generators included) |
| ✅ Threat-intel feed is the **real** abuse.ch C2 blocklist | ⚠️ Thresholds are **hand-tuned, not baselined** |
| ✅ Project 3 tested against a **real 5,559-domain labeled dataset** | ⚠️ "0 false positives" on synthetic data is **by construction** |
| ✅ Every failure and dead-end documented, not hidden | ⚠️ Project 3's detection **failed on real data — and I show it** |

**The centerpiece is Project 3**, where a detection that scored 100% on synthetic data collapsed to **13.4% recall** on real tunneling domains — and I diagnosed exactly why instead of quietly tuning a number to hide it.

---

## 🌍 Project 1 — Impossible Travel Detection

> **Scenario:** A user logs in from two cities so far apart, so close in time, that the travel speed is physically impossible. The classic fingerprint of a stolen session.

**The catch:** Sam logged in **Melbourne → London in 15 minutes.**

| User | Route | Distance | Time | Speed | Severity |
| --- | --- | --- | --- | --- | --- |
| **Sam** | Melbourne → London | 16,903 km | 0.25 h | **67,612 km/h** 🚨 | Critical |
| **Vineet** | New York → Mumbai | 12,538 km | 0.38 h | **32,708 km/h** | Critical |
| **Vineet** | Mumbai → New York | 12,538 km | 0.33 h | **37,614 km/h** | Critical |

67,612 km/h is ~55× the speed of sound. That's not a traveler — that's a hijacked session.

> 📸 [screenshot: 03_travel_detection.png — 7 flagged events with computed speed and severity]

### The detection — Haversine geo-velocity, computed live in SPL

No pre-labeled "impossible_travel" field. `streamstats` pulls each user's previous login; the Haversine formula computes real great-circle distance; speed flags anything faster than a jet.

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

### The dashboard — 4-panel SOC triage view

> 📸 [screenshot: 04_travel_dashboard.png — dark 4-panel dashboard: global auth map, severity breakdown, login timeline, investigation queue]

<details>
<summary><b>🔎 Scope note — what's detected vs. what's displayed (click to expand)</b></summary>

The **geo-velocity speed calculation is a real, computed detection** (the SPL above). The dashboard *also* surfaces other auth-anomaly categories — failed-login burst, off-hours new-device, MFA failure — via `stats count by event_type`. Those categories are **seeded in the synthetic generator and counted for visualization**, not independently computed detections. Only the Haversine logic is a live detection. Calling it anything else would be dishonest.
</details>

**🎯 MITRE:** T1078 (Valid Accounts) · T1550 (Alternate Authentication Material)

**⚠️ Real-world limitation:** VPNs and proxies are the killer here. A legit user on a VPN looks like 60,000 km/h; an attacker proxying through the victim's own city looks local and evades entirely. In production this rule is noisy without egress-IP allowlisting.

---

## 🔗 Project 2 — Threat Intel Correlation

> **Scenario:** An internal host is quietly beaconing to command-and-control servers. Catch it by correlating outbound traffic against a **live, real-world** C2 blocklist.

**The catch:** One machine — **Andrea, 10.0.1.52** — beaconing to **4 known C2 servers, one still ONLINE.**

| Destination IP | Malware | C2 Status | Connections |
| --- | --- | --- | --- |
| 162.243.103.246 | Emotet | offline | 8 |
| 178.62.3.223 | QakBot | offline | 8 |
| 34.204.119.63 | QakBot | offline | 8 |
| 50.16.16.211 | QakBot | **🔴 ONLINE** | 5 |

One C2 was live at detection time — an active, ongoing compromise, not just historical residue.

> 📸 [screenshot: project2-07-correlation-4-c2-hits.png — Andrea's host matched against 4 C2 IPs]

### The detection — real abuse.ch feed as a Splunk lookup

The threat feed is the **actual [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) C2 blocklist**, loaded as a lookup and correlated against every outbound destination.

```spl
index=main source="network_traffic.csv"
| lookup threat_intel dst_ip OUTPUT malware as threat_name c2_status last_online
| where isnotnull(threat_name)
| stats count as connection_count, sum(bytes_out) as total_bytes by user src_ip dst_ip threat_name c2_status
| sort -connection_count
```

> 📸 [screenshot: project2-01-feed-prep-grep.png — cleaning the abuse.ch blocklist into a Splunk lookup]

**🎯 MITRE:** T1071 (Application Layer C2) · T1041 (Exfiltration Over C2)

<details>
<summary><b>⚠️ Honest limitation — this is IOC matching, NOT C2 detection (click to expand)</b></summary>

This catches traffic to **IPs already known and published** in a public feed. It does **not** detect C2 behaviorally. Fresh infrastructure, domain fronting, fast-flux, or a cloud redirector all evade it completely. It's only as good as the feed's freshness — which is exactly why threat intel is one layer, never the whole stack.
</details>

---

## 🧬 Project 3 — DNS Tunneling: The One That Failed

> **This is the most important project in the repo — because it failed on real data, and I show you the failure instead of hiding it.**

> **Scenario:** DNS tunneling smuggles data inside DNS queries — long, high-entropy subdomains under an attacker-controlled domain, slipping past controls that blindly trust DNS.

### On synthetic data: flawless. And that's the trap.

Two features computed **live** from the raw query string: **subdomain length** and **character diversity** (`unique_chars / length`). On synthetic data: **100% recall, 0% false positives.**

```spl
index=main source="dns_logs.csv"
| eval sub=mvindex(split(query,"."),0)
| eval sub_len=len(sub)
| eval chars=split(sub,"")
| eval unique_chars=mvcount(mvdedup(chars))
| eval char_diversity=round(unique_chars/sub_len,2)
| eval suspicious=if(sub_len>20 AND char_diversity>0.45,1,0)
| where suspicious=1
| stats count as suspicious_queries, avg(sub_len) as avg_len, avg(char_diversity) as avg_diversity by user src_ip
| where suspicious_queries>5
```

> 📸 [screenshot: project3-05-mvdedup-fix.png — Andrea's 120 tunneling queries flagged, diversity 0.62]

**But 0 false positives here means nothing** — the synthetic tunneling was *built* to be long and diverse. Proving a rule works on data designed to make it work proves nothing. So I tested it against reality.

### The real test — 5,559 labeled domains from a public Zenodo corpus

> 📸 [screenshot: project3-12-real-confusion-matrix.png — detector scored against real benign/tunneling/DGA labels]

| Real class | Total | Flagged | Result |
| --- | --- | --- | --- |
| **Tunneling** | 1,559 | **209** | **🔴 13.4% recall — missed 87%** |
| **Benign** | 3,000 | 67 | 2.2% false-positive rate |

On synthetic data it caught everything. On **real** tunneling it caught **13.4%**. That collapse is the whole lesson.

### Why it failed — the diagnosis

The missed domains weren't random. Splitting real tunneling across the two thresholds exposed the problem:

> 📸 [screenshot: project3-14-real-separability-2x2.png — the 2×2 split proving bimodality]

| | diversity ≤ 0.45 | diversity > 0.45 |
| --- | --- | --- |
| **length ≤ 20** | 4 | **725** ← short but diverse |
| **length > 20** | **621** ← long but low-diversity | 209 ✅ *(only cell AND catches)* |

The `AND` rule only catches the bottom-right cell. It **rejected 1,346 real tunneling domains that satisfied just one signal** — 725 short-but-diverse, 621 long-but-low-diversity. The malicious class is **bimodal**: two clusters, each overlapping benign traffic on one axis. **No single axis-aligned threshold box can separate it.**

> **The tempting cheat:** relax `AND` → `OR`. Recall jumped to 99.7%… and so did the false-positive rate. It flagged *everything*. Useless. I could have reported the 99.7% recall and hidden the false positives. I didn't.

**The real conclusion:** simple two-threshold boolean logic **cannot** separate real DNS tunneling. It needs **weighted scoring or ML** — documented as future work, *not* faked with a tuned number to make the synthetic result look like it held.

**🎯 MITRE:** T1071.004 (DNS) · T1048.003 (Exfiltration Over Unencrypted Protocol) · T1568 (Dynamic Resolution)

---

## 🔥 Detection Engineering War Stories

> This is where most lab writeups stop. Mine doesn't.

**🧮 War Story 1 — The `avg_diversity = 1` bug**
`split(sub,"")` returns *every* character including duplicates, so `mvcount` equaled the string length and diversity was **structurally 1.0 for every single row**. Not a coincidence — a systematic error hiding in plain sight. Fixed with `mvdedup` to collapse to distinct characters first. Diversity dropped to a real 0.62.

**🔀 War Story 2 — Aggregate-then-filter returned zero**
First DNS attempt averaged features *per user* then filtered — 120 malicious queries drowned by 1,218 normal ones, cleared no threshold, returned **"No results."** Fix: filter at the per-query level *first*, then aggregate. Filter-then-aggregate, not aggregate-then-filter.

**⏳ War Story 3 — The lookup that "had no results"**
Project 2's correlation returned nothing — not because the logic was wrong, but because the query ran before the lookup table finished saving in Splunk Cloud. Re-ran after the save propagated: 4 C2 hits. Cloud lookups aren't instantaneous.

**📊 War Story 4 — Six rounds with the scatter-chart engine**
Six attempts to render a two-color length-vs-diversity scatter in Splunk's classic viz engine, each failing differently. The classic engine maps columns to axes by rigid rules that don't fit "two overlapping clusters in 2D." Correct call: stop, use the bubble chart's visible cluster gap, and let the 2×2 table carry the separation argument. Knowing when to stop *is* the skill.

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Project |
| --- | --- | --- | --- |
| Initial Access / Persistence | T1078 | Valid Accounts | Impossible Travel |
| Defense Evasion | T1550 | Alternate Authentication Material | Impossible Travel |
| Command and Control | T1071 | Application Layer Protocol | Threat Intel |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Threat Intel |
| Command and Control | T1071.004 | Application Layer Protocol: DNS | DNS Tunneling |
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted Protocol | DNS Tunneling |
| Command and Control | T1568 | Dynamic Resolution | DNS Tunneling |

---

## 💡 What I Learned

**Technical:**
- Writing detections that **compute features live in SPL** (Haversine, character diversity) instead of reading pre-labeled fields — the difference between a real detection and a lookup.
- Correlating live threat intel against traffic with Splunk lookups.
- **Validating a detection against real labeled data** — and reading a confusion matrix honestly when the numbers are bad.
- Why bimodal feature distributions break single-threshold rules, and when a problem actually needs weighted scoring or ML.

**Mindset:**
- A detection that only works on data built to make it work is worthless. **Test against reality.**
- When the honest fix (OR) produces a useless result, report it — don't tune a number to hide the failure.
- Knowing when to *stop* polishing (the scatter chart) is as valuable as knowing how to build.
- The failure is the credential. Anyone can screenshot a green dashboard.

---

## 🎓 Skills Demonstrated

`Splunk Cloud` `SPL` `Detection Engineering` `Threat Hunting` `Geo-Velocity Analysis` `Threat Intel Correlation` `IOC Matching` `DNS Tunneling Detection` `Behavioral Analytics` `Confusion Matrix Analysis` `Feature Engineering` `MITRE ATT&CK` `Python Data Generation` `Dashboard Design` `abuse.ch` `Synthetic Data Modeling`

---

## 👤 Author

**Samruddhi (Sam) Patil**

[![GitHub](https://img.shields.io/badge/GitHub-samSecurity04-181717?style=for-the-badge&logo=github)](https://github.com/samSecurity04)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-samruddhi--p--patil-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/samruddhi-p-patil/)

🎓 CompTIA Security+ | Microsoft SC-900 | EC-Council CASE (Java) | Google Cybersecurity

*Built for educational and cybersecurity skill-development purposes. All data is synthetic except the abuse.ch threat feed and the Zenodo DNS corpus used for real-world validation.*
