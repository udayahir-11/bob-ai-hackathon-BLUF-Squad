#ifndef THREAT_ALERT_H
#define THREAT_ALERT_H

#include <string>
#include <vector>

// MITRE ATT&CK technique record
struct MitreTechnique {
    std::string techniqueId;   // e.g. "T1071"
    std::string name;          // e.g. "Application Layer Protocol"
    std::string tactic;        // e.g. "Command and Control"
};

// Threat category classification
enum class ThreatCategory {
    UNKNOWN,
    RECONNAISSANCE,
    INITIAL_ACCESS,
    LATERAL_MOVEMENT,
    EXFILTRATION,
    COMMAND_AND_CONTROL,
    IMPACT,
    DENIAL_OF_SERVICE
};

// Priority tier for commander action
enum class PriorityTier {
    CRITICAL,   // Score >= 85, genuine threat
    HIGH,       // Score >= 60, genuine threat
    MEDIUM,     // Score >= 35, genuine threat
    LOW,        // Score < 35, genuine threat
    FILTERED    // False positive
};

class ThreatAlert {
public:
    // Core fields (parsed from feed)
    std::string id;
    std::string sourceIP;
    std::string destinationIP;
    std::string protocol;
    int         severityScore;      // 0–100 raw score from sensor
    std::string timestamp;          // ISO-8601 string
    std::string sourceType;         // "SIEM" | "SATELLITE" | "CYBER_SENSOR" | "INTEL_REPORT"
    std::string description;

    // Enriched fields (set during processing)
    bool               isFalsePositive;
    double             confidenceScore;   // 0.0–1.0 correlation confidence
    ThreatCategory     category;
    PriorityTier       priority;
    MitreTechnique     mitreTechnique;
    std::string        geoCountry;        // Source IP geolocation (static lookup)
    std::string        blufLine;          // One-line BLUF summary for this alert
    int                correlationGroup;  // 0 = uncorrelated, >0 = grouped campaign ID

    ThreatAlert(std::string alertId,
                std::string srcIp,
                std::string dstIp,
                std::string proto,
                int score,
                std::string ts,
                std::string srcType,
                std::string desc);

    // Returns a formatted JSON block for this alert
    std::string toJson() const;

    // Returns the string name of the priority tier
    std::string priorityLabel() const;

    // Returns the string name of the threat category
    std::string categoryLabel() const;

    // Converts PriorityTier to a numeric rank (lower = more urgent)
    int priorityRank() const;
};

#endif // THREAT_ALERT_H
