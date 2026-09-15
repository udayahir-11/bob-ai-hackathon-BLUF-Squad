# Problem Statement

## Background

Modern defence and security operations centres (SOCs) operate in a high-tempo environment where threat data arrives continuously from dozens of heterogeneous sources — Security Information and Event Management (SIEM) platforms, satellite surveillance feeds, distributed cyber sensors, and human-generated intelligence reports. Each source produces alerts in its own format, at its own rate, with its own confidence calibration.

The convergence of these feeds creates a data volume problem that human analysts alone cannot solve.

---

## The Problem

**Defence analysts are overwhelmed by thousands of daily alerts from disparate sources, making it impossible to manually distinguish genuine threats from false positives while producing timely, structured reports for commanders.**

In a realistic operational day:

- A single SIEM can generate **5,000–50,000 raw alerts** per 24-hour period.
- Up to **95% of those alerts are noise** — false positives caused by misconfigured rules, benign resolver traffic, internal heartbeats, loopback artefacts, and low-severity protocol chatter.
- The remaining genuine threats are buried in that noise and require correlation across multiple source types before their true severity is understood.
- Once a genuine threat is identified, analysts must manually look up MITRE ATT&CK technique mappings, assign priority tiers, write commander-ready summaries, and produce structured reports — all under time pressure.

The result: **mean time to detect (MTTD) is measured in hours rather than minutes**, and commanders receive delayed, inconsistently formatted intelligence that impairs rapid decision-making.

---

## Who Is Affected

**Primary persona — Tier 1 / Tier 2 SOC Analyst** in a defence or government security operations context:

- Manages alert queues from 4–8 simultaneous feed sources (SIEM, satellite, cyber sensors, intel reports).
- Expected to triage, correlate, and escalate genuine threats within a strict SLA (often 15–60 minutes for CRITICAL incidents).
- Spends the majority of their shift manually dismissing false positives rather than investigating real threats.
- Required to produce BLUF (Bottom Line Up Front) summaries for commanding officers who need actionable intelligence, not raw log data.

**Secondary persona — Commanding Officer / Decision-Maker:**

- Receives threat intelligence from analysts but has no direct visibility into the raw alert pipeline.
- Needs concise, prioritised, structured summaries (BLUF format) to make rapid resource and response decisions.
- Currently dependent on manual analyst write-ups that vary in format, completeness, and timeliness.

---

## Why It Matters

| Impact Area | Cost of the Problem |
|---|---|
| **Analyst fatigue** | Manually triaging 95% noise burns cognitive capacity, increasing miss rates on genuine threats |
| **Detection latency** | Hours-long MTTD on critical incidents (C2, exfiltration, lateral movement) directly increases breach impact |
| **Report inconsistency** | Ad-hoc analyst write-ups lack standardisation — commanders cannot compare reports across shifts or analysts |
| **Campaign blindness** | Alerts from the same attacker infrastructure reviewed in isolation are never correlated into a campaign picture |
| **MITRE coverage gaps** | Manual technique tagging is inconsistent and incomplete, degrading threat intelligence quality over time |

In an active incident, a one-hour delay in identifying a **Command & Control beacon** or an **exfiltration channel** can mean the difference between containment and a full data breach.

---

## Why Existing Solutions Fall Short

| Existing Approach | Why It Fails |
|---|---|
| **Raw SIEM dashboards** | Surface all alerts with equal visual weight — no automated false-positive suppression, no priority tiers, no MITRE mapping |
| **Manual analyst triage** | Does not scale beyond ~200 alerts/hour per analyst; subjective and inconsistent across personnel |
| **Commercial TIP platforms** | Expensive, require cloud connectivity, significant configuration overhead, and still output raw IOC lists rather than commander-ready BLUF summaries |
| **Rule-based SOAR playbooks** | Require constant maintenance as TTPs evolve; do not produce narrative intelligence summaries or cross-source campaign correlation |

None of these approaches deliver a **zero-dependency, single-command pipeline** that ingests raw multi-source feeds and produces a fully structured, MITRE-tagged, campaign-correlated BLUF report in milliseconds — ready for a commanding officer to read without translation.
