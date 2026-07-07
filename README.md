# 🛡️ Splunk Threat Detection Lab

> **Three threat detections built entirely in Splunk SPL using live feature engineering:not pre-computed labels.** This project demonstrates geo-velocity analysis, threat intelligence correlation, and behavioral DNS tunneling detection while evaluating each approach against both synthetic and real-world datasets.

![Splunk](https://img.shields.io/badge/Splunk_Cloud-9.x-000000?style=for-the-badge&logo=splunk&logoColor=white)
![SPL](https://img.shields.io/badge/SPL-Detection_Engineering-FF6F00?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-Data_Generation-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=for-the-badge)

---

# 📖 Project Overview

This repository showcases three independent threat detections built in **Splunk Cloud** using raw SPL.

Rather than relying on pre-labeled indicators or existing detection fields, each project derives its own features directly from log data during search execution. The goal was not simply to build detections that work on synthetic data, but to understand how they perform when exposed to more realistic datasets and document the engineering decisions behind them.

Each project focuses on a different aspect of detection engineering:

- 🌍 Geo-velocity analysis for compromised accounts
- 🔗 Threat intelligence correlation using a live IOC feed
- 🧬 Behavioral DNS tunneling detection using feature engineering

---

# 🚀 Key Results

| Detection | Technique | Outcome |
|-----------|-----------|---------|
| 🌍 Impossible Travel | Live Haversine geo-velocity calculation | Successfully identified impossible authentication events |
| 🔗 Threat Intel Correlation | abuse.ch IOC matching | Detected outbound communication with known command-and-control infrastructure |
| 🧬 DNS Tunneling | Behavioral feature engineering | Achieved **13.4% recall** on a public labeled dataset, demonstrating the limitations of simple threshold-based detection |

---

# ✨ Repository Highlights

- ✅ Feature engineering performed directly in SPL
- ✅ Three independent detection engineering projects
- ✅ Real threat intelligence integration (abuse.ch Feodo Tracker)
- ✅ Validation using a public DNS tunneling dataset
- ✅ MITRE ATT&CK mapping
- ✅ SOC dashboards for investigation workflows
- ✅ Honest documentation of failures, debugging, and limitations

---

# 📊 Data Sources

| Component | Source |
|-----------|--------|
| Authentication logs | Synthetic |
| Network traffic | Synthetic |
| DNS traffic | Synthetic generator |
| Threat Intelligence | Real abuse.ch Feodo Tracker |
| Validation dataset | Public Zenodo DNS corpus |

> **Why synthetic data?**  
> Building realistic attack scenarios in a personal lab allows complete control over attacker behavior while avoiding privacy concerns. Wherever possible, detections were validated using public real-world datasets to measure how well the detection logic generalized beyond synthetic traffic.

---

# 🏗️ Detection Pipeline

```text
Raw Security Logs
        │
        ▼
Feature Engineering (SPL)
        │
        ▼
Detection Logic
        │
        ▼
Alert Generation
        │
        ▼
SOC Dashboard
        │
        ▼
Validation & Analysis
```

---

# 🌍 Project 1 — Impossible Travel Detection

## Objective

Detect authentication events where a user appears to travel between geographically distant locations within an implausibly short period of time.

Impossible travel is commonly associated with:

- Compromised credentials
- Stolen authentication tokens
- Session hijacking
- Unauthorized account access

---

## Detection Method

Instead of relying on a pre-existing `impossible_travel` field, the detection derives travel speed directly from authentication logs.

For each user:

1. Retrieve the previous successful login.
2. Calculate the great-circle distance using the **Haversine formula**.
3. Calculate elapsed time between logins.
4. Compute travel speed.
5. Flag events exceeding realistic travel thresholds.

This demonstrates how SPL can perform feature engineering directly during search execution without requiring preprocessing or external enrichment.

---

## Example Detection Results

| User | Route | Distance | Time | Speed | Severity |
|------|--------|---------:|------:|-------:|----------|
| Sam | Melbourne → London | 16,903 km | 15 min | **67,612 km/h** | Critical |
| Vineet | New York → Mumbai | 12,538 km | 23 min | **32,708 km/h** | Critical |
| Vineet | Mumbai → New York | 12,538 km | 20 min | **37,614 km/h** | Critical |

The calculated speeds are physically impossible for legitimate travel and strongly indicate credential misuse or session compromise.

> 📸 **Figure 1.** Impossible travel detections with calculated speed and assigned severity.

---

## Detection Logic

The detection uses:

- `streamstats` to retrieve the previous login for each user
- Haversine distance calculation using latitude and longitude
- Elapsed time calculation
- Speed computation
- Severity classification

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
| eval severity=case(
    speed_kmh>5000,"Critical",
    speed_kmh>2000,"High",
    speed_kmh>900,"Medium"
)
| where speed_kmh>900
| table _time user prev_city city distance_km time_diff_hours speed_kmh severity
```

---

## Dashboard

The accompanying dashboard provides a SOC-focused investigation workflow including:

- Authentication timeline
- Geographic login map
- Severity distribution
- Investigation queue

> 📸 **Figure 2.** Impossible Travel dashboard.

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Initial Access | T1078 – Valid Accounts |
| Defense Evasion | T1550 – Alternate Authentication Material |

---

## Limitations

This detection has important operational limitations.

VPNs, corporate proxies, cloud gateways, and shared egress infrastructure can generate apparent impossible travel events for legitimate users. Likewise, an attacker operating from infrastructure near the victim may evade geo-velocity detection entirely.

In production environments this detection should be supplemented with contextual signals such as trusted VPN ranges, MFA status, device fingerprints, and historical user behavior rather than operating as a standalone alert.
