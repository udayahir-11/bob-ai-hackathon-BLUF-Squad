# 🚀 [Threat Intelligence Correlation & Alert Prioritisation Assistant]



---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | [BLUF Squad] |
| **Track** | [AI] |
| **Team Lead** | [Uday] — [25bsit001@charusat.edu.in] |
| **Members** | [Bhavish], [Krish], [Krisha] |
---

## 🎯 Problem Statement

> Defence analysts are overwhelmed by thousands of daily alerts from disparate sources (SIEM, satellite, cyber sensors, intel reports), making it impossible to manually distinguish genuine threats from false positives while producing timely, structured reports for commanders.


---

## 💡 Solution

> An AI-driven assistant that correlates multi-source alerts, filters false positives, maps attacker techniques to MITRE ATT&CK, and auto-generates prioritised BLUF summaries — cutting analyst overload and enabling commanders to act within minutes.


---

## ✨ Key Features

- **Multi-Source Alert Correlation - Ingests and correlates alerts from SIEM, satellite feeds, cyber sensors, and intel reports into unified, de-duplicated incidents.** 
- **AI-Powered False Positive Filtering — Uses ML classification to score and suppress low-confidence noise, surfacing only genuine threats.** 
- **MITRE ATT&CK Technique Mapping — Automatically tags correlated incidents with adversary tactics and techniques for standardized threat context.** 
- **Automated BLUF Report Generation — Produces prioritised, commander-ready summaries (Bottom Line Up Front) enabling rapid decision-making.**


---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | C++17 |
| **Frameworks** | Standard Library (STL) — no external dependencies |
| **IBM Technologies** | IBM Bob (AI-assisted development & code generation) |
| **Threat Intelligence** | MITRE ATT&CK Framework |
| **Output Formats** | HTML Dashboard, CSV Export, JSON Feed, BLUF Terminal Report |
| **Build Tools** | GCC 7+ / Clang 5+ / MSVC 2017+ |

---

## 📁 Repository Structure

```
├── src/                  # All source code
├── docs/                 # Written documentation
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/                 # Demo artifacts
│   ├── screenshots/      # App screenshots
│   └── demo-video-link.txt  # Link to demo video
├── presentation/         # Slide deck
└── submission.yaml       # Structured submission metadata
```

---

## ⚡ How to Run

**Requirements:** C++17 compiler — GCC 7+, Clang 5+, or MSVC 2017+. No external libraries or dependencies required.

```bash
# 1. Clone the repo
git clone https://github.com/udayambaliya04/ibm-bob.git
cd ibm-bob

# 2. Compile
g++ -std=c++17 -O2 -Wall -o main main.cpp

# 3. Run with the bundled threat feed
./main

# 4. (Optional) Run with a custom feed file
./main my_feed.csv
```

**Outputs produced after running:**

| Output | Location | Description |
|---|---|---|
| BLUF Report | `stdout` | Commander-readable prioritised summary |
| JSON Feed | `stdout` | Machine-readable enriched alert data |
| CSV Export | `threat_report.csv` | Spreadsheet-ready full alert table |
| HTML Dashboard | `index.html` | Dark-theme commander visual dashboard — open in any browser |

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/slides.pdf](presentation/) |

---

## ⚠️ Known Limitations

- **Static GeoIP table** — Country tags for source IPs are resolved from a hard-coded lookup map; real-world deployments would need MaxMind GeoLite2 or a live GeoIP API.
- **Keyword-based MITRE mapping** — Technique assignment relies on keyword matching in alert descriptions; a trained NLP classifier would improve accuracy on ambiguous or novel threat language.
- **No live feed ingestion** — The system reads from a static CSV file (`threat_feed.txt`); integration with live SIEM APIs or streaming pipelines is not implemented.
- **Single-threaded pipeline** — All processing steps run sequentially; very large alert volumes (100k+) would benefit from parallelisation.
- **No persistent storage** — Results are written to files on each run; there is no database layer or historical trend analysis.

---

## 🏅 What We're Most Proud Of

The end-to-end pipeline runs as a **zero-dependency, single-file C++ solution** that takes raw, noisy multi-source alerts and produces a polished commander dashboard in one command — no install, no config, no cloud account needed.

The piece we're most proud of is the **7-stage processing pipeline** in `main.cpp`: false-positive filtering → MITRE ATT&CK mapping → threat categorisation → confidence-weighted priority assignment → IP-subnet campaign correlation → per-alert BLUF generation → sorted output. Each stage is independently testable and the whole chain runs in milliseconds even on modest hardware.

We're also proud of the **HTML dashboard** (`index.html`) generated at runtime — a dark-theme, colour-coded commander view with a BLUF summary card, statistics grid, and a fully enriched alert table (MITRE technique IDs, tactic badges, confidence scores, campaign groups, geo tags) — all produced without a single frontend framework or build step.

---
