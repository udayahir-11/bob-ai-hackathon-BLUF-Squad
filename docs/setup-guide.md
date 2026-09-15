# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

This project is a **zero-dependency C++17 command-line tool**. You only need a C++ compiler — no package managers, no runtimes, no cloud accounts.

- [ ] A C++17-capable compiler: **GCC 7+**, **Clang 5+**, or **MSVC 2017+**
- [ ] Standard shell (bash, zsh, PowerShell, or Command Prompt)

To verify your compiler:
```bash
g++ --version        # GCC
clang++ --version    # Clang
```

**No other prerequisites.** There are no Python, Node.js, Docker, or cloud dependencies.

---

## Environment Variables

**None required.** This project has no environment variables, API keys, or `.env` file. The `.env.example` in `src/` is a scaffold template and can be ignored.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/udayambaliya04/ibm-bob.git
cd ibm-bob
```

That's all. No dependency installation step is needed.

---

## Building the Application

Compile from the `src/` directory with a single command:

```bash
# GCC (Linux / macOS)
cd src
g++ -std=c++17 -O2 -Wall -o main main.cpp

# Clang (Linux / macOS)
cd src
clang++ -std=c++17 -O2 -Wall -o main main.cpp

# MSVC (Windows — Developer Command Prompt)
cd src
cl /std:c++17 /O2 /W3 /EHsc /Fe:main.exe main.cpp
```

Expected output: silent (no warnings, no errors). Compilation takes under 2 seconds.

---

## Running the Application

```bash
# Run with the bundled threat feed (from inside src/)
./main

# Run with a custom CSV feed file
./main my_feed.csv
```

**Windows:**
```cmd
main.exe
main.exe my_feed.csv
```

### What Happens When You Run It

The pipeline executes all 7 stages automatically and prints progress to stdout:

```
[INFO] Ingested 20 alerts from threat_feed.txt
[INFO] Starting correlation pipeline...
[INFO] Pipeline complete. 15 genuine threats, 5 false positives, 9 campaign group(s).

======================================================================
  THREAT INTELLIGENCE BLUF REPORT
  Bottom Line Up Front — Commander Summary
======================================================================
...
```

---

## Outputs Produced

After a successful run, four artefacts are produced:

| Output | Location | Description |
|---|---|---|
| **BLUF Terminal Report** | `stdout` | Commander-readable prioritised situation summary |
| **JSON Feed** | `stdout` (after BLUF) | Machine-readable enriched alert data |
| **CSV Export** | `src/threat_report.csv` | Full enriched alert table — open in Excel or any spreadsheet tool |
| **HTML Dashboard** | `src/index.html` | Dark-theme commander visual dashboard — open directly in any browser |

To separate the terminal BLUF report from the JSON output, redirect stdout:
```bash
./main > output.json 2>&1   # capture everything
./main 2>/dev/null          # suppress INFO logs, print report + JSON only
```

---

## Viewing the Dashboard

After running, open the generated HTML dashboard in any browser:

```bash
# Linux
xdg-open src/index.html

# macOS
open src/index.html

# Windows
start src\index.html
```

Alternatively, open `src/soc-triage.html` directly in a browser — this is a static companion analyst triage view that does not require running the binary.

---

## Using a Custom Threat Feed

The tool accepts any CSV file matching this format:

```
# Comment lines (starting with #) are ignored
# Format: id,srcIP,dstIP,protocol,score,timestamp,sourceType,description
ALT-001,185.15.59.222,10.0.0.5,TCP,99,2025-07-15T08:19:41Z,SIEM,C2 beacon detected
```

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique alert identifier |
| `srcIP` | string | Source IP address |
| `dstIP` | string | Destination IP address |
| `protocol` | string | `TCP`, `UDP`, `ICMP`, `DNS`, or other |
| `score` | int (0–100) | Raw severity score from the sensor |
| `timestamp` | string | ISO-8601 datetime string |
| `sourceType` | string | `SIEM`, `SATELLITE`, `CYBER_SENSOR`, or `INTEL_REPORT` |
| `description` | string | Free-text description (drives MITRE keyword matching) |

Run with your file:
```bash
./main /path/to/your_feed.csv
```

---

## Running Tests

This project does not include a formal test suite. To verify the pipeline is working correctly, inspect the output against the known input in `src/threat_feed.txt`:

- **5 alerts should be filtered** (ALT-001 internal RFC-1918, ALT-002 low UDP, ALT-004 loopback, ALT-010 low ICMP, ALT-019 internal UDP)
- **ALT-003, ALT-011, ALT-016, ALT-017** should be `CRITICAL`
- **Campaign groups** should correlate `ALT-003` / `ALT-016` (both `185.15.59.x` subnet) and `ALT-006` / `ALT-017` (both `112.213.89.x` subnet)

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `error: unrecognized command-line option '-std=c++17'` | Upgrade GCC to version 7 or later: `sudo apt install g++` (Ubuntu/Debian) |
| `fatal error: ThreatAlert.h: No such file or directory` | Compile from inside the `src/` directory: `cd src && g++ -std=c++17 -o main main.cpp` |
| `[ERROR] Cannot open feed file: threat_feed.txt` | Run the binary from inside the `src/` directory, or pass the full path: `./main ../src/threat_feed.txt` |
| `[ERROR] Cannot create dashboard: index.html` | Check write permissions on the current directory: `chmod 755 .` |
| Blank `index.html` opened in browser | Ensure you ran the binary first — `index.html` is generated at runtime, not pre-committed |
| MSVC: `C2429` or C++17 feature errors | Use `/std:c++17` flag and ensure Visual Studio 2017 or later is installed |
