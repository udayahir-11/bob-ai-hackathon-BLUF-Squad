// =============================================================================
// Threat Intelligence Correlation & Alert Prioritisation Assistant
// =============================================================================
// Architecture:
//   1. Ingest multi-source threat feed (CSV)
//   2. Filter false positives (IP heuristics + protocol/score rules)
//   3. Map to MITRE ATT&CK framework (technique + tactic)
//   4. Classify threat category (Recon, C2, Exfil, etc.)
//   5. Assign priority tier (CRITICAL / HIGH / MEDIUM / LOW)
//   6. Correlate related alerts into campaign groups
//   7. Generate per-alert BLUF lines + full commander BLUF report
//   8. Export JSON feed + CSV + HTML commander dashboard
// =============================================================================

#include "ThreatAlert.h"
#include "AlertManager.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <iomanip>
#include <ctime>

// =============================================================================
// ThreatAlert — Implementation
// =============================================================================

ThreatAlert::ThreatAlert(std::string alertId,
                         std::string srcIp,
                         std::string dstIp,
                         std::string proto,
                         int score,
                         std::string ts,
                         std::string srcType,
                         std::string desc)
    : id(std::move(alertId)),
      sourceIP(std::move(srcIp)),
      destinationIP(std::move(dstIp)),
      protocol(std::move(proto)),
      severityScore(score),
      timestamp(std::move(ts)),
      sourceType(std::move(srcType)),
      description(std::move(desc)),
      isFalsePositive(false),
      confidenceScore(0.0),
      category(ThreatCategory::UNKNOWN),
      priority(PriorityTier::FILTERED),
      geoCountry("UNKNOWN"),
      blufLine(""),
      correlationGroup(0)
{
    mitreTechnique = {"", "", ""};
}

int ThreatAlert::priorityRank() const {
    switch (priority) {
        case PriorityTier::CRITICAL:  return 1;
        case PriorityTier::HIGH:      return 2;
        case PriorityTier::MEDIUM:    return 3;
        case PriorityTier::LOW:       return 4;
        case PriorityTier::FILTERED:  return 5;
    }
    return 5;
}

std::string ThreatAlert::priorityLabel() const {
    switch (priority) {
        case PriorityTier::CRITICAL: return "CRITICAL";
        case PriorityTier::HIGH:     return "HIGH";
        case PriorityTier::MEDIUM:   return "MEDIUM";
        case PriorityTier::LOW:      return "LOW";
        case PriorityTier::FILTERED: return "FILTERED";
    }
    return "UNKNOWN";
}

std::string ThreatAlert::categoryLabel() const {
    switch (category) {
        case ThreatCategory::RECONNAISSANCE:      return "Reconnaissance";
        case ThreatCategory::INITIAL_ACCESS:      return "Initial Access";
        case ThreatCategory::LATERAL_MOVEMENT:    return "Lateral Movement";
        case ThreatCategory::EXFILTRATION:        return "Exfiltration";
        case ThreatCategory::COMMAND_AND_CONTROL: return "Command & Control";
        case ThreatCategory::IMPACT:              return "Impact";
        case ThreatCategory::DENIAL_OF_SERVICE:   return "Denial of Service";
        case ThreatCategory::UNKNOWN:             return "Unknown";
    }
    return "Unknown";
}

// Helper: escape a string for safe JSON embedding
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

std::string ThreatAlert::toJson() const {
    std::stringstream ss;
    ss << "    {\n"
       << "      \"id\": \""              << jsonEscape(id)                      << "\",\n"
       << "      \"timestamp\": \""       << jsonEscape(timestamp)               << "\",\n"
       << "      \"sourceIP\": \""        << jsonEscape(sourceIP)                << "\",\n"
       << "      \"destinationIP\": \""   << jsonEscape(destinationIP)           << "\",\n"
       << "      \"protocol\": \""        << jsonEscape(protocol)                << "\",\n"
       << "      \"severityScore\": "     << severityScore                       << ",\n"
       << "      \"sourceType\": \""      << jsonEscape(sourceType)              << "\",\n"
       << "      \"geoCountry\": \""      << jsonEscape(geoCountry)              << "\",\n"
       << "      \"isFalsePositive\": "   << (isFalsePositive ? "true" : "false") << ",\n"
       << "      \"confidenceScore\": "   << std::fixed << std::setprecision(2) << confidenceScore << ",\n"
       << "      \"priority\": \""        << priorityLabel()                     << "\",\n"
       << "      \"category\": \""        << categoryLabel()                     << "\",\n"
       << "      \"correlationGroup\": "  << correlationGroup                    << ",\n"
       << "      \"mitre\": {\n"
       << "        \"techniqueId\": \""   << jsonEscape(mitreTechnique.techniqueId) << "\",\n"
       << "        \"name\": \""          << jsonEscape(mitreTechnique.name)        << "\",\n"
       << "        \"tactic\": \""        << jsonEscape(mitreTechnique.tactic)      << "\"\n"
       << "      },\n"
       << "      \"description\": \""     << jsonEscape(description)             << "\",\n"
       << "      \"blufLine\": \""        << jsonEscape(blufLine)                << "\"\n"
       << "    }";
    return ss.str();
}

// =============================================================================
// AlertManager — Static GeoIP lookup table
// =============================================================================

static const std::map<std::string, std::string> GEO_TABLE = {
    {"185.15.59",  "Russia (RU)"},
    {"45.33.22",   "United States (US)"},
    {"91.108.4",   "Russia (RU)"},
    {"94.102.49",  "Netherlands (NL)"},
    {"198.51.100", "Reserved (Documentation)"},
    {"203.0.113",  "Reserved (Documentation)"},
    {"66.240.219", "United States (US)"},
    {"112.213.89", "China (CN)"},
    {"80.82.77",   "Netherlands (NL)"},
    {"104.21.44",  "United States (US)"},
    {"31.184.196", "Russia (RU)"},
    {"45.155.205", "Ukraine (UA)"},
    {"179.60.147", "Venezuela (VE)"},
    {"8.8.8",      "United States (US)"},
    {"1.1.1",      "Australia (AU)"},
};

std::string AlertManager::geoLookup(const std::string& ip) const {
    // Match on first three octets
    auto pos = ip.rfind('.');
    if (pos == std::string::npos) return "Unknown";
    std::string prefix = ip.substr(0, pos);
    auto it = GEO_TABLE.find(prefix);
    if (it != GEO_TABLE.end()) return it->second;
    // Private / loopback ranges
    if (ip.find("192.168.") == 0) return "Private Network";
    if (ip.find("10.") == 0)      return "Private Network";
    if (ip.find("172.16.") == 0)  return "Private Network";
    if (ip == "127.0.0.1")        return "Loopback";
    return "Unknown";
}

// =============================================================================
// AlertManager — Pipeline Steps
// =============================================================================

void AlertManager::addAlert(const ThreatAlert& alert) {
    alerts.push_back(alert);
}

bool AlertManager::ingestFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Cannot open feed file: " << filename << "\n";
        return false;
    }

    std::string line;
    int lineNum = 0;
    while (std::getline(file, line)) {
        ++lineNum;
        // Skip blank lines and comment lines
        if (line.empty() || line[0] == '#') continue;

        std::stringstream ss(line);
        std::string id, srcIp, dstIp, proto, scoreStr, ts, srcType, desc;

        std::getline(ss, id,       ',');
        std::getline(ss, srcIp,    ',');
        std::getline(ss, dstIp,    ',');
        std::getline(ss, proto,    ',');
        std::getline(ss, scoreStr, ',');
        std::getline(ss, ts,       ',');
        std::getline(ss, srcType,  ',');
        std::getline(ss, desc,     '\n');

        // Trim leading/trailing whitespace from all fields
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
        };
        trim(id); trim(srcIp); trim(dstIp); trim(proto);
        trim(scoreStr); trim(ts); trim(srcType); trim(desc);

        if (id.empty() || scoreStr.empty()) {
            std::cerr << "[WARN] Skipping malformed line " << lineNum << "\n";
            continue;
        }

        try {
            int score = std::stoi(scoreStr);
            alerts.emplace_back(id, srcIp, dstIp, proto, score, ts, srcType, desc);
        } catch (...) {
            std::cerr << "[WARN] Invalid score on line " << lineNum << ", skipping\n";
        }
    }

    file.close();
    std::cout << "[INFO] Ingested " << alerts.size() << " alerts from " << filename << "\n";
    return true;
}

// ---------------------------------------------------------------------------
// Step 1 — False Positive Filtering
// ---------------------------------------------------------------------------
void AlertManager::filterFalsePositives() {
    for (auto& a : alerts) {
        // Loopback always FP
        if (a.sourceIP == "127.0.0.1" || a.sourceIP == "::1") {
            a.isFalsePositive = true; continue;
        }
        // Private RFC-1918 ranges are internal — treat as FP for external threat feeds
        if (a.sourceIP.find("192.168.") == 0 ||
            a.sourceIP.find("10.") == 0 ||
            a.sourceIP.find("172.16.") == 0 ||
            a.sourceIP.find("172.17.") == 0 ||
            a.sourceIP.find("172.18.") == 0 ||
            a.sourceIP.find("172.19.") == 0 ||
            a.sourceIP.find("172.2") == 0 ||
            a.sourceIP.find("172.30.") == 0 ||
            a.sourceIP.find("172.31.") == 0) {
            a.isFalsePositive = true; continue;
        }
        // Low-severity UDP noise (beacons, multicast noise)
        if (a.protocol == "UDP" && a.severityScore < 30) {
            a.isFalsePositive = true; continue;
        }
        // Low-severity ICMP (ping sweeps at minimal score)
        if (a.protocol == "ICMP" && a.severityScore < 20) {
            a.isFalsePositive = true; continue;
        }
        // Known benign DNS resolvers flagged by mistake (8.8.8.8 legitimate unless very high score)
        if ((a.sourceIP == "8.8.8.8" || a.sourceIP == "1.1.1.1") && a.severityScore < 50) {
            a.isFalsePositive = true; continue;
        }
    }
}

// ---------------------------------------------------------------------------
// Step 2 — MITRE ATT&CK Mapping
// ---------------------------------------------------------------------------
void AlertManager::mapMitreTechniques() {
    for (auto& a : alerts) {
        if (a.isFalsePositive) continue;

        std::string desc = a.description;
        std::string proto = a.protocol;

        // Convert to lower for matching
        std::transform(desc.begin(),  desc.end(),  desc.begin(),  ::tolower);
        std::transform(proto.begin(), proto.end(), proto.begin(), ::tolower);

        // --- C2 / Beaconing ---
        if (desc.find("beacon") != std::string::npos ||
            desc.find("c2") != std::string::npos ||
            desc.find("command and control") != std::string::npos ||
            (proto == "tcp" && a.severityScore >= 70 && desc.find("periodic") != std::string::npos)) {
            a.mitreTechnique = {"T1071", "Application Layer Protocol", "Command and Control"};
        }
        // --- Exfiltration ---
        else if (desc.find("exfil") != std::string::npos ||
                 desc.find("data transfer") != std::string::npos ||
                 desc.find("large upload") != std::string::npos) {
            a.mitreTechnique = {"T1041", "Exfiltration Over C2 Channel", "Exfiltration"};
        }
        // --- Port/Vulnerability Scanning (Reconnaissance) ---
        else if (desc.find("scan") != std::string::npos ||
                 desc.find("probe") != std::string::npos ||
                 desc.find("recon") != std::string::npos) {
            a.mitreTechnique = {"T1046", "Network Service Discovery", "Reconnaissance"};
        }
        // --- Brute Force / Credential Access ---
        else if (desc.find("brute") != std::string::npos ||
                 desc.find("login attempt") != std::string::npos ||
                 desc.find("auth fail") != std::string::npos ||
                 desc.find("password") != std::string::npos) {
            a.mitreTechnique = {"T1110", "Brute Force", "Credential Access"};
        }
        // --- Phishing / Initial Access ---
        else if (desc.find("phish") != std::string::npos ||
                 desc.find("spear") != std::string::npos ||
                 desc.find("malicious email") != std::string::npos) {
            a.mitreTechnique = {"T1566", "Phishing", "Initial Access"};
        }
        // --- Lateral Movement (SMB/RDP) ---
        else if (desc.find("lateral") != std::string::npos ||
                 desc.find("smb") != std::string::npos ||
                 desc.find("rdp") != std::string::npos ||
                 desc.find("pivot") != std::string::npos) {
            a.mitreTechnique = {"T1021", "Remote Services", "Lateral Movement"};
        }
        // --- DDoS / Impact ---
        else if (desc.find("ddos") != std::string::npos ||
                 desc.find("flood") != std::string::npos ||
                 (proto == "udp" && a.severityScore >= 60)) {
            a.mitreTechnique = {"T1498", "Network Denial of Service", "Impact"};
        }
        // --- DNS Tunnelling ---
        else if (proto == "dns" || desc.find("dns tunnel") != std::string::npos) {
            a.mitreTechnique = {"T1071.004", "DNS", "Command and Control"};
        }
        // --- Exploit / Malware Delivery ---
        else if (desc.find("exploit") != std::string::npos ||
                 desc.find("malware") != std::string::npos ||
                 desc.find("shellcode") != std::string::npos) {
            a.mitreTechnique = {"T1203", "Exploitation for Client Execution", "Execution"};
        }
        // --- Default: map by protocol ---
        else if (proto == "tcp") {
            a.mitreTechnique = {"T1049", "System Network Connections Discovery", "Discovery"};
        } else if (proto == "udp") {
            a.mitreTechnique = {"T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"};
        } else if (proto == "icmp") {
            a.mitreTechnique = {"T1018", "Remote System Discovery", "Reconnaissance"};
        } else {
            a.mitreTechnique = {"T1059", "Command and Scripting Interpreter", "Execution"};
        }
    }
}

// ---------------------------------------------------------------------------
// Step 3 — Category Classification
// ---------------------------------------------------------------------------
void AlertManager::classifyCategories() {
    for (auto& a : alerts) {
        if (a.isFalsePositive) continue;

        const std::string& tactic = a.mitreTechnique.tactic;

        if (tactic == "Reconnaissance")     a.category = ThreatCategory::RECONNAISSANCE;
        else if (tactic == "Initial Access") a.category = ThreatCategory::INITIAL_ACCESS;
        else if (tactic == "Lateral Movement") a.category = ThreatCategory::LATERAL_MOVEMENT;
        else if (tactic == "Exfiltration")   a.category = ThreatCategory::EXFILTRATION;
        else if (tactic == "Command and Control") a.category = ThreatCategory::COMMAND_AND_CONTROL;
        else if (tactic == "Impact")         a.category = ThreatCategory::IMPACT;
        else                                 a.category = ThreatCategory::UNKNOWN;
    }
}

// ---------------------------------------------------------------------------
// Step 4 — Priority & Confidence Assignment
// ---------------------------------------------------------------------------
void AlertManager::assignPriorities() {
    for (auto& a : alerts) {
        if (a.isFalsePositive) {
            a.priority = PriorityTier::FILTERED;
            a.confidenceScore = 0.0;
            continue;
        }

        // Base confidence from severity (normalised to 0–1)
        double base = a.severityScore / 100.0;

        // Boost for high-value source types
        double sourceBoost = 0.0;
        if (a.sourceType == "INTEL_REPORT")  sourceBoost = 0.15;
        else if (a.sourceType == "SIEM")     sourceBoost = 0.10;
        else if (a.sourceType == "SATELLITE") sourceBoost = 0.05;

        // Boost for critical MITRE tactics
        double tacticBoost = 0.0;
        const std::string& tid = a.mitreTechnique.techniqueId;
        if (tid == "T1041" || tid == "T1071" || tid == "T1110") tacticBoost = 0.10;
        else if (tid == "T1566" || tid == "T1021")               tacticBoost = 0.08;

        a.confidenceScore = std::min(1.0, base + sourceBoost + tacticBoost);

        // Assign tier based on severity + confidence
        if (a.severityScore >= 85 && a.confidenceScore >= 0.80) {
            a.priority = PriorityTier::CRITICAL;
        } else if (a.severityScore >= 60) {
            a.priority = PriorityTier::HIGH;
        } else if (a.severityScore >= 35) {
            a.priority = PriorityTier::MEDIUM;
        } else {
            a.priority = PriorityTier::LOW;
        }
    }
}

// ---------------------------------------------------------------------------
// Step 5 — Campaign Correlation
// ---------------------------------------------------------------------------
void AlertManager::correlateAlerts() {
    int nextGroup = 1;
    // Group alerts that share source IP (same attacker infrastructure)
    std::map<std::string, int> ipGroups;

    for (auto& a : alerts) {
        if (a.isFalsePositive) continue;
        auto it = ipGroups.find(a.sourceIP);
        if (it != ipGroups.end()) {
            a.correlationGroup = it->second;
        } else {
            // Also check if same /24 subnet has a group (campaign spreading within block)
            std::string subnet;
            auto pos = a.sourceIP.rfind('.');
            if (pos != std::string::npos) subnet = a.sourceIP.substr(0, pos);

            for (auto& [ip, grp] : ipGroups) {
                std::string existSubnet;
                auto ep = ip.rfind('.');
                if (ep != std::string::npos) existSubnet = ip.substr(0, ep);
                if (!subnet.empty() && existSubnet == subnet) {
                    a.correlationGroup = grp;
                    ipGroups[a.sourceIP] = grp;
                    break;
                }
            }
            if (a.correlationGroup == 0) {
                a.correlationGroup = nextGroup;
                ipGroups[a.sourceIP] = nextGroup++;
            }
        }
    }

    // Count distinct groups
    std::map<int, int> groupCount;
    for (const auto& a : alerts)
        if (!a.isFalsePositive) groupCount[a.correlationGroup]++;
    stats.correlationGroups = static_cast<int>(groupCount.size());
}

// ---------------------------------------------------------------------------
// Step 6 — Per-Alert BLUF Line Generation
// ---------------------------------------------------------------------------
void AlertManager::generateAlertBLUF() {
    for (auto& a : alerts) {
        if (a.isFalsePositive) {
            a.blufLine = "Filtered — false positive; no action required.";
            continue;
        }
        std::ostringstream bluf;
        bluf << "[" << a.priorityLabel() << "] "
             << a.categoryLabel() << " activity from " << a.sourceIP
             << " (" << a.geoCountry << ") via " << a.protocol
             << ". MITRE " << a.mitreTechnique.techniqueId
             << " (" << a.mitreTechnique.name << "). "
             << "Confidence: " << static_cast<int>(a.confidenceScore * 100) << "%.";
        a.blufLine = bluf.str();
    }
}

// ---------------------------------------------------------------------------
// Main pipeline entry point
// ---------------------------------------------------------------------------
void AlertManager::processAlerts() {
    std::cout << "[INFO] Starting correlation pipeline...\n";

    filterFalsePositives();

    // Enrich with GeoIP
    for (auto& a : alerts)
        a.geoCountry = geoLookup(a.sourceIP);

    mapMitreTechniques();
    classifyCategories();
    assignPriorities();
    correlateAlerts();
    generateAlertBLUF();

    // Sort: genuine threats first, then by priority rank, then by severity desc
    std::sort(alerts.begin(), alerts.end(), [](const ThreatAlert& x, const ThreatAlert& y) {
        if (x.isFalsePositive != y.isFalsePositive)
            return !x.isFalsePositive;
        if (x.priorityRank() != y.priorityRank())
            return x.priorityRank() < y.priorityRank();
        return x.severityScore > y.severityScore;
    });

    // Compute stats
    stats.totalIngested = static_cast<int>(alerts.size());
    for (const auto& a : alerts) {
        if (a.isFalsePositive) { ++stats.falsePositives; continue; }
        ++stats.genuineThreats;
        switch (a.priority) {
            case PriorityTier::CRITICAL: ++stats.criticalCount; break;
            case PriorityTier::HIGH:     ++stats.highCount;     break;
            case PriorityTier::MEDIUM:   ++stats.mediumCount;   break;
            case PriorityTier::LOW:      ++stats.lowCount;      break;
            default: break;
        }
    }

    std::cout << "[INFO] Pipeline complete. "
              << stats.genuineThreats << " genuine threats, "
              << stats.falsePositives << " false positives, "
              << stats.correlationGroups << " campaign group(s).\n";
}

const ProcessingStats& AlertManager::getStats() const { return stats; }

// =============================================================================
// AlertManager — Export: JSON
// =============================================================================
void AlertManager::exportJson() const {
    std::cout << "{\n"
              << "  \"generated_at\": \"" << __DATE__ << " " << __TIME__ << "\",\n"
              << "  \"stats\": {\n"
              << "    \"total\": "          << stats.totalIngested    << ",\n"
              << "    \"genuine\": "        << stats.genuineThreats   << ",\n"
              << "    \"false_positives\": " << stats.falsePositives  << ",\n"
              << "    \"critical\": "       << stats.criticalCount    << ",\n"
              << "    \"high\": "           << stats.highCount        << ",\n"
              << "    \"medium\": "         << stats.mediumCount      << ",\n"
              << "    \"low\": "            << stats.lowCount         << ",\n"
              << "    \"campaign_groups\": " << stats.correlationGroups << "\n"
              << "  },\n"
              << "  \"alerts\": [\n";

    for (size_t i = 0; i < alerts.size(); ++i) {
        std::cout << alerts[i].toJson();
        if (i < alerts.size() - 1) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "  ]\n}\n";
}

// =============================================================================
// AlertManager — Export: CSV
// =============================================================================
void AlertManager::exportCsv(const std::string& filename) const {
    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cerr << "[ERROR] Cannot write CSV to " << filename << "\n";
        return;
    }
    f << "id,timestamp,sourceIP,destinationIP,protocol,severityScore,"
      << "sourceType,geoCountry,isFalsePositive,confidenceScore,"
      << "priority,category,mitreId,mitreName,mitreTactic,"
      << "correlationGroup,description\n";

    for (const auto& a : alerts) {
        f << a.id << ","
          << a.timestamp << ","
          << a.sourceIP << ","
          << a.destinationIP << ","
          << a.protocol << ","
          << a.severityScore << ","
          << a.sourceType << ","
          << a.geoCountry << ","
          << (a.isFalsePositive ? "true" : "false") << ","
          << std::fixed << std::setprecision(2) << a.confidenceScore << ","
          << a.priorityLabel() << ","
          << a.categoryLabel() << ","
          << a.mitreTechnique.techniqueId << ","
          << a.mitreTechnique.name << ","
          << a.mitreTechnique.tactic << ","
          << a.correlationGroup << ","
          << "\"" << a.description << "\"\n";
    }
    f.close();
    std::cout << "[INFO] CSV exported to " << filename << "\n";
}

// =============================================================================
// AlertManager — BLUF Report (stdout)
// =============================================================================
void AlertManager::printBLUFReport() const {
    const std::string sep(70, '=');
    const std::string thin(70, '-');

    std::cout << "\n" << sep << "\n";
    std::cout << "  THREAT INTELLIGENCE BLUF REPORT\n";
    std::cout << "  Bottom Line Up Front — Commander Summary\n";
    std::cout << sep << "\n\n";

    std::cout << "SITUATION:\n";
    std::cout << "  " << stats.totalIngested << " alerts ingested from multi-source threat feeds.\n";
    std::cout << "  " << stats.falsePositives << " noise/false-positive alerts filtered automatically.\n";
    std::cout << "  " << stats.genuineThreats << " genuine threats confirmed requiring action.\n";
    std::cout << "  " << stats.correlationGroups << " distinct adversary campaign group(s) identified.\n\n";

    std::cout << "PRIORITY BREAKDOWN:\n";
    std::cout << "  [CRITICAL] " << stats.criticalCount << "\n";
    std::cout << "  [HIGH]     " << stats.highCount     << "\n";
    std::cout << "  [MEDIUM]   " << stats.mediumCount   << "\n";
    std::cout << "  [LOW]      " << stats.lowCount      << "\n\n";

    std::cout << "COMMANDER ACTIONS:\n";
    if (stats.criticalCount > 0)
        std::cout << "  >> IMMEDIATE: " << stats.criticalCount << " CRITICAL alert(s) demand immediate response.\n";
    if (stats.highCount > 0)
        std::cout << "  >> URGENT: " << stats.highCount << " HIGH alert(s) require analyst attention within 1 hour.\n";
    if (stats.mediumCount > 0)
        std::cout << "  >> MONITOR: " << stats.mediumCount << " MEDIUM alert(s) — schedule investigation today.\n";
    if (stats.lowCount > 0)
        std::cout << "  >> TRACK: " << stats.lowCount << " LOW alert(s) — log and review during next cycle.\n";

    std::cout << "\n" << thin << "\n";
    std::cout << "PRIORITISED ALERT DETAILS:\n";
    std::cout << thin << "\n";

    int rank = 1;
    for (const auto& a : alerts) {
        if (a.isFalsePositive) continue;
        std::cout << "\n  #" << rank++ << " | " << a.id
                  << " | " << a.priorityLabel()
                  << " | Score: " << a.severityScore << "/100"
                  << " | Confidence: " << static_cast<int>(a.confidenceScore * 100) << "%\n";
        std::cout << "     Source: " << a.sourceIP << " (" << a.geoCountry << ")"
                  << "  ->  " << a.destinationIP << "\n";
        std::cout << "     Protocol: " << a.protocol
                  << "  |  Source Type: " << a.sourceType
                  << "  |  Campaign Group: " << a.correlationGroup << "\n";
        std::cout << "     MITRE: " << a.mitreTechnique.techniqueId
                  << " — " << a.mitreTechnique.name
                  << " [" << a.mitreTechnique.tactic << "]\n";
        std::cout << "     Category: " << a.categoryLabel() << "\n";
        std::cout << "     BLUF: " << a.blufLine << "\n";
    }

    std::cout << "\n" << sep << "\n";
    std::cout << "  END OF BLUF REPORT\n";
    std::cout << sep << "\n\n";
}

// =============================================================================
// AlertManager — HTML Commander Dashboard
// =============================================================================
void AlertManager::generateDashboard(const std::string& filename) const {
    std::ofstream f(filename);
    if (!f.is_open()) {
        std::cerr << "[ERROR] Cannot create dashboard: " << filename << "\n";
        return;
    }

    // Helper lambda: map priority to CSS class
    auto priorityCss = [](const std::string& p) -> std::string {
        if (p == "CRITICAL") return "badge-critical";
        if (p == "HIGH")     return "badge-high";
        if (p == "MEDIUM")   return "badge-medium";
        if (p == "LOW")      return "badge-low";
        return "badge-filtered";
    };

    f << R"(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Threat Intelligence Commander Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      font-size: 14px;
      line-height: 1.6;
    }
    a { color: #58a6ff; text-decoration: none; }

    /* ── Top Bar ── */
    .topbar {
      background: #161b22;
      border-bottom: 1px solid #30363d;
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .topbar h1 {
      font-size: 18px;
      font-weight: 700;
      color: #f0f6fc;
      letter-spacing: 0.3px;
    }
    .topbar-meta {
      font-size: 12px;
      color: #8b949e;
    }
    .live-dot {
      display: inline-block;
      width: 8px; height: 8px;
      border-radius: 50%;
      background: #3fb950;
      margin-right: 6px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.4; }
    }

    /* ── Layout ── */
    .main { max-width: 1200px; margin: 0 auto; padding: 24px; }

    /* ── BLUF Card ── */
    .bluf-card {
      background: #0f1923;
      border: 1px solid #1e4976;
      border-left: 4px solid #388bfd;
      border-radius: 8px;
      padding: 20px 24px;
      margin-bottom: 24px;
    }
    .bluf-title {
      font-size: 13px;
      font-weight: 700;
      color: #388bfd;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 10px;
    }
    .bluf-card p { color: #c9d1d9; margin-bottom: 8px; }
    .bluf-card p:last-child { margin-bottom: 0; }
    .bluf-label { color: #8b949e; font-weight: 600; margin-right: 4px; }

    /* ── Stats Grid ── */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }
    .stat-card .stat-value {
      font-size: 28px;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 4px;
    }
    .stat-card .stat-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: #8b949e;
    }
    .stat-critical .stat-value { color: #f85149; }
    .stat-high     .stat-value { color: #d29922; }
    .stat-medium   .stat-value { color: #e3b341; }
    .stat-low      .stat-value { color: #3fb950; }
    .stat-total    .stat-value { color: #58a6ff; }
    .stat-fp       .stat-value { color: #8b949e; }

    /* ── Section Header ── */
    .section-header {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: #8b949e;
      border-bottom: 1px solid #30363d;
      padding-bottom: 8px;
      margin-bottom: 16px;
    }

    /* ── Priority Badges ── */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .badge-critical { background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }
    .badge-high     { background: #2d2000; color: #d29922; border: 1px solid #d29922; }
    .badge-medium   { background: #2d2400; color: #e3b341; border: 1px solid #e3b341; }
    .badge-low      { background: #0d2116; color: #3fb950; border: 1px solid #3fb950; }
    .badge-filtered { background: #161b22; color: #8b949e; border: 1px solid #30363d; }

    /* ── Table ── */
    .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; }
    thead { background: #161b22; }
    th {
      padding: 10px 14px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: #8b949e;
      border-bottom: 1px solid #30363d;
      white-space: nowrap;
    }
    td {
      padding: 10px 14px;
      border-bottom: 1px solid #21262d;
      vertical-align: top;
    }
    tr:last-child td { border-bottom: none; }
    tr.row-critical { background: #1a0d0d; }
    tr.row-high     { background: #1a1200; }
    tr.row-filtered { opacity: 0.55; }
    tr:hover td { background: rgba(56,139,253,0.05); }
    .ip-code {
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 12px;
      color: #79c0ff;
    }
    .mitre-id {
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 11px;
      color: #d2a8ff;
    }
    .mitre-name { font-size: 12px; color: #c9d1d9; }
    .tactic-tag {
      display: inline-block;
      background: #1f2d3d;
      color: #79c0ff;
      border-radius: 3px;
      padding: 1px 6px;
      font-size: 11px;
    }
    .score-bar-wrap { display: flex; align-items: center; gap: 8px; }
    .score-bar {
      height: 4px;
      border-radius: 2px;
      background: #21262d;
      flex: 1;
      overflow: hidden;
    }
    .score-fill { height: 100%; border-radius: 2px; }
    .geo-tag { font-size: 11px; color: #8b949e; }
    .confidence-val { font-size: 12px; color: #3fb950; font-weight: 600; }
    .grp-badge {
      display: inline-block;
      background: #1f2d3d;
      color: #58a6ff;
      border-radius: 3px;
      padding: 1px 6px;
      font-size: 11px;
      font-family: monospace;
    }
    .bluf-cell { font-size: 12px; color: #8b949e; max-width: 260px; }

    /* ── Footer ── */
    .footer {
      text-align: center;
      padding: 24px 0 12px;
      font-size: 12px;
      color: #484f58;
      border-top: 1px solid #21262d;
      margin-top: 32px;
    }
  </style>
</head>
<body>

<div class="topbar">
  <h1>&#128737; Threat Intelligence Correlation &amp; Alert Prioritisation Assistant</h1>
  <span class="topbar-meta"><span class="live-dot"></span>Live Feed Processed</span>
</div>

<div class="main">

  <!-- BLUF Summary Card -->
  <div class="bluf-card">
    <div class="bluf-title">&#9632; BLUF — Bottom Line Up Front / Commander Summary</div>
)";

    // Dynamic BLUF content
    f << "    <p><span class=\"bluf-label\">SITUATION:</span>"
      << stats.totalIngested << " alerts ingested from multi-source feeds. "
      << stats.falsePositives << " filtered as noise. "
      << "<strong style=\"color:#f0f6fc\">" << stats.genuineThreats << " genuine threats</strong> confirmed across "
      << stats.correlationGroups << " adversary campaign group(s).</p>\n";

    f << "    <p><span class=\"bluf-label\">PRIORITY BREAKDOWN:</span>"
      << "<span style=\"color:#f85149\">&#9632; " << stats.criticalCount << " CRITICAL</span> &nbsp;"
      << "<span style=\"color:#d29922\">&#9632; " << stats.highCount << " HIGH</span> &nbsp;"
      << "<span style=\"color:#e3b341\">&#9632; " << stats.mediumCount << " MEDIUM</span> &nbsp;"
      << "<span style=\"color:#3fb950\">&#9632; " << stats.lowCount << " LOW</span></p>\n";

    f << "    <p><span class=\"bluf-label\">COMMANDER ACTION:</span>";
    if (stats.criticalCount > 0)
        f << "<strong style=\"color:#f85149\">IMMEDIATE RESPONSE REQUIRED — "
          << stats.criticalCount << " CRITICAL alert(s) active.</strong> ";
    if (stats.highCount > 0)
        f << stats.highCount << " HIGH priority alert(s) require analyst attention within 1 hour. ";
    if (stats.mediumCount > 0)
        f << stats.mediumCount << " MEDIUM alert(s) scheduled for investigation today. ";
    if (stats.genuineThreats == 0)
        f << "No genuine threats detected at this time.";
    f << "</p>\n";

    f << "  </div>\n\n";

    // Stats Grid
    f << "  <div class=\"stats-grid\">\n"
      << "    <div class=\"stat-card stat-total\"><div class=\"stat-value\">" << stats.totalIngested   << "</div><div class=\"stat-label\">Total Ingested</div></div>\n"
      << "    <div class=\"stat-card stat-critical\"><div class=\"stat-value\">" << stats.criticalCount << "</div><div class=\"stat-label\">Critical</div></div>\n"
      << "    <div class=\"stat-card stat-high\"><div class=\"stat-value\">"     << stats.highCount     << "</div><div class=\"stat-label\">High</div></div>\n"
      << "    <div class=\"stat-card stat-medium\"><div class=\"stat-value\">"   << stats.mediumCount   << "</div><div class=\"stat-label\">Medium</div></div>\n"
      << "    <div class=\"stat-card stat-low\"><div class=\"stat-value\">"      << stats.lowCount      << "</div><div class=\"stat-label\">Low</div></div>\n"
      << "    <div class=\"stat-card stat-fp\"><div class=\"stat-value\">"       << stats.falsePositives << "</div><div class=\"stat-label\">Filtered / FP</div></div>\n"
      << "    <div class=\"stat-card stat-total\"><div class=\"stat-value\">"    << stats.correlationGroups << "</div><div class=\"stat-label\">Campaign Groups</div></div>\n"
      << "  </div>\n\n";

    // Alert Table
    f << "  <div class=\"section-header\">Prioritised Alert Feed</div>\n"
      << "  <div class=\"table-wrap\">\n"
      << "  <table>\n"
      << "    <thead><tr>\n"
      << "      <th>#</th><th>Alert ID</th><th>Priority</th><th>Score</th>"
      << "<th>Source IP</th><th>Destination</th><th>Protocol</th>"
      << "<th>Source Type</th><th>MITRE Technique</th><th>Tactic</th>"
      << "<th>Category</th><th>Confidence</th><th>Campaign</th><th>BLUF Summary</th>"
      << "\n    </tr></thead>\n    <tbody>\n";

    int rowNum = 0;
    for (const auto& a : alerts) {
        ++rowNum;
        std::string rowClass;
        if (a.isFalsePositive)          rowClass = " class=\"row-filtered\"";
        else if (a.priority == PriorityTier::CRITICAL) rowClass = " class=\"row-critical\"";
        else if (a.priority == PriorityTier::HIGH)     rowClass = " class=\"row-high\"";

        // Severity bar colour
        std::string barColour;
        if      (a.severityScore >= 85) barColour = "#f85149";
        else if (a.severityScore >= 60) barColour = "#d29922";
        else if (a.severityScore >= 35) barColour = "#e3b341";
        else                            barColour = "#3fb950";

        std::string pCss = priorityCss(a.priorityLabel());

        f << "      <tr" << rowClass << ">\n"
          << "        <td style=\"color:#484f58;font-size:11px\">" << rowNum << "</td>\n"
          << "        <td style=\"font-weight:600;color:#f0f6fc\">" << a.id << "</td>\n"
          << "        <td><span class=\"badge " << pCss << "\">" << a.priorityLabel() << "</span></td>\n"
          << "        <td>\n"
          << "          <div class=\"score-bar-wrap\">\n"
          << "            <span style=\"font-weight:700;color:" << barColour << ";min-width:26px\">" << a.severityScore << "</span>\n"
          << "            <div class=\"score-bar\"><div class=\"score-fill\" style=\"width:" << a.severityScore << "%;background:" << barColour << "\"></div></div>\n"
          << "          </div>\n"
          << "        </td>\n"
          << "        <td><span class=\"ip-code\">" << a.sourceIP << "</span><br><span class=\"geo-tag\">" << a.geoCountry << "</span></td>\n"
          << "        <td><span class=\"ip-code\">" << a.destinationIP << "</span></td>\n"
          << "        <td style=\"font-family:monospace;font-size:12px\">" << a.protocol << "</td>\n"
          << "        <td style=\"font-size:12px;color:#8b949e\">" << a.sourceType << "</td>\n"
          << "        <td>\n"
          << "          <span class=\"mitre-id\">" << a.mitreTechnique.techniqueId << "</span><br>\n"
          << "          <span class=\"mitre-name\">" << a.mitreTechnique.name << "</span>\n"
          << "        </td>\n"
          << "        <td><span class=\"tactic-tag\">" << a.mitreTechnique.tactic << "</span></td>\n"
          << "        <td style=\"font-size:12px\">" << a.categoryLabel() << "</td>\n"
          << "        <td><span class=\"confidence-val\">" << static_cast<int>(a.confidenceScore * 100) << "%</span></td>\n"
          << "        <td><span class=\"grp-badge\">G" << a.correlationGroup << "</span></td>\n"
          << "        <td class=\"bluf-cell\">" << a.blufLine << "</td>\n"
          << "      </tr>\n";
    }

    f << "    </tbody>\n  </table>\n  </div>\n";

    f << R"(
  <div class="footer">
    Threat Intelligence Correlation &amp; Alert Prioritisation Assistant &mdash; Made with IBM Bob
  </div>

</div>
</body>
</html>)";

    f.close();
    std::cout << "[INFO] Commander dashboard generated: " << filename << "\n";
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char* argv[]) {
    std::string feedFile = "threat_feed.txt";
    if (argc > 1) feedFile = argv[1];

    AlertManager manager;

    // Ingest feed
    if (!manager.ingestFromFile(feedFile)) return 1;

    // Run full pipeline
    manager.processAlerts();

    // Print BLUF report to console
    manager.printBLUFReport();

    // Export artefacts
    manager.exportJson();
    manager.exportCsv("threat_report.csv");
    manager.generateDashboard("index.html");

    return 0;
}
