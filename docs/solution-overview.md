# Solution Overview

## What We Built

The **Threat Intelligence Correlation & Alert Prioritisation Assistant** is a zero-dependency C++17 command-line tool that ingests raw, multi-source threat feeds and transforms them into structured, prioritised, commander-ready intelligence — in a single command, in milliseconds, with no external libraries, cloud accounts, or runtime dependencies required.

It solves the analyst overload problem end-to-end: from noisy raw alerts all the way to a polished HTML commander dashboard and a terminal BLUF (Bottom Line Up Front) report, automatically.

---

## How It Works

The system runs a **7-stage processing pipeline** on every execution:

1. **Ingest** — Reads a CSV threat feed (`threat_feed.txt`) containing alerts from four source types: SIEM, Satellite, Cyber Sensor, and Intel Report. Each record carries an alert ID, source/destination IP, protocol, severity score (0–100), timestamp, source type, and a free-text description.

2. **False Positive Filtering** — Applies rule-based heuristics to suppress noise before any further processing:
   - Loopback addresses (`127.0.0.1`, `::1`) → always filtered
   - RFC-1918 private ranges (`10.x`, `192.168.x`, `172.16–31.x`) → filtered (external threat feed context)
   - Low-severity UDP < 30 and ICMP < 20 → filtered (multicast/ping noise)
   - Known benign DNS resolvers (`8.8.8.8`, `1.1.1.1`) with score < 50 → filtered

3. **MITRE ATT&CK Mapping** — Each genuine alert is matched against keyword and protocol rules to assign a specific ATT&CK technique ID, technique name, and tactic. Covers: C2/Beaconing (T1071), Exfiltration (T1041), Port Scanning (T1046), Brute Force (T1110), Phishing (T1566), Lateral Movement (T1021), DDoS/Impact (T1498), DNS Tunnelling (T1071.004), and Exploit Delivery (T1203).

4. **Threat Category Classification** — Maps the assigned ATT&CK tactic to one of seven internal threat categories: Reconnaissance, Initial Access, Lateral Movement, Exfiltration, Command & Control, Impact, or Denial of Service.

5. **Priority & Confidence Assignment** — Computes a composite confidence score (0.0–1.0) from the raw severity score plus source-type boost (Intel Report: +0.15, SIEM: +0.10, Satellite: +0.05) plus tactic boost for high-value techniques (+0.08–0.10). Assigns a priority tier: **CRITICAL** (score ≥ 85 + confidence ≥ 0.80), **HIGH** (≥ 60), **MEDIUM** (≥ 35), **LOW** (< 35).

6. **Campaign Correlation** — Groups alerts sharing the same source IP or the same /24 subnet into adversary campaign groups. This surfaces coordinated multi-alert attacks from the same infrastructure that would be invisible when reviewing alerts individually.

7. **BLUF Report Generation** — Produces four output artefacts simultaneously:
   - **Terminal BLUF report** — commander-readable situation summary with priority breakdown and per-alert detail lines
   - **JSON feed** — machine-readable enriched alert data for downstream tooling
   - **CSV export** — spreadsheet-ready full alert table (`threat_report.csv`)
   - **HTML commander dashboard** — dark-theme, colour-coded visual dashboard (`index.html`) with stats grid, tactic badges, MITRE IDs, campaign group tags, and confidence scores

---

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed diagram.

```
threat_feed.txt (CSV)
        │
        ▼
┌─────────────────────────────────┐
│  AlertManager::ingestFromFile() │  ← Parse CSV, create ThreatAlert objects
└────────────────┬────────────────┘
                 │
        ┌────────▼────────┐
        │  filterFP()     │  ← IP/protocol/score heuristics → isFalsePositive
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  geoLookup()    │  ← Static /24-prefix GeoIP table → geoCountry
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  mapMITRE()     │  ← Keyword + protocol → techniqueId / tactic
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  classify()     │  ← tactic → ThreatCategory enum
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  assignPrio()   │  ← severity + boosts → confidenceScore + PriorityTier
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  correlate()    │  ← /24 subnet grouping → correlationGroup ID
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  genBLUF()      │  ← Per-alert one-line BLUF string
        └────────┬────────┘
                 │
     ┌───────────┼───────────┬──────────────┐
     ▼           ▼           ▼              ▼
  stdout      stdout    threat_report.csv  index.html
 (BLUF)      (JSON)        (CSV)         (Dashboard)
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **Zero external dependencies (C++17 STL only)** | Deployable on any air-gapped or restricted defence network without package managers, internet access, or runtime installers |
| **Single-file pipeline (`main.cpp` + two headers)** | Minimal attack surface, trivial to audit, compiles in under 2 seconds on any C++17-capable toolchain |
| **Rule-based FP filtering before any enrichment** | Eliminates noise early so all downstream processing (MITRE mapping, confidence scoring) only runs on genuine signal — keeps runtime deterministic |
| **Composite confidence score (severity + source boost + tactic boost)** | A raw severity score from one sensor is not enough; boosting Intel Report and C2/Exfil tactics reflects real-world analyst weighting of source reliability |
| **/24 subnet campaign correlation** | Real adversary campaigns typically use adjacent IPs within the same rented block; subnet-level grouping catches this without requiring a full graph algorithm |
| **Runtime HTML generation (no frontend framework)** | The dashboard is fully produced by `generateDashboard()` at runtime — no build step, no npm, no bundler; the output file is self-contained and browser-ready immediately |
| **BLUF format output** | The primary consumer is a commanding officer, not a technical analyst — BLUF forces the pipeline to produce actionable summaries rather than raw data dumps |

---

## IBM Technologies Used

- **IBM Bob (AI-assisted development & code generation):** IBM Bob was used throughout the development of this project as the primary AI pair-programming assistant. Bob was used to design the 7-stage pipeline architecture, generate the C++ class structure (`ThreatAlert`, `AlertManager`), refine the MITRE ATT&CK keyword-matching logic, produce the runtime HTML dashboard generation code, and iterate on the confidence-scoring formula. The entire project was built within the IBM Bob workspace environment.
