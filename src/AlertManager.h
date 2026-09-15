#ifndef ALERT_MANAGER_H
#define ALERT_MANAGER_H

#include <vector>
#include <string>
#include <map>
#include "ThreatAlert.h"

// Aggregated statistics produced after processAlerts()
struct ProcessingStats {
    int totalIngested      = 0;
    int genuineThreats     = 0;
    int falsePositives     = 0;
    int criticalCount      = 0;
    int highCount          = 0;
    int mediumCount        = 0;
    int lowCount           = 0;
    int correlationGroups  = 0;
};

class AlertManager {
private:
    std::vector<ThreatAlert> alerts;
    ProcessingStats          stats;

    // --- Internal correlation helpers ---

    // Step 1: Mark false positives based on IP/protocol/score heuristics
    void filterFalsePositives();

    // Step 2: Assign MITRE ATT&CK technique based on protocol, port hints, description
    void mapMitreTechniques();

    // Step 3: Classify each genuine alert into a ThreatCategory
    void classifyCategories();

    // Step 4: Assign PriorityTier and confidence score
    void assignPriorities();

    // Step 5: Group related alerts into campaign correlation groups
    void correlateAlerts();

    // Step 6: Generate a one-line BLUF summary per alert
    void generateAlertBLUF();

    // Step 7: Static GeoIP lookup (embedded table for demo)
    std::string geoLookup(const std::string& ip) const;

public:
    // Add a single alert to the queue
    void addAlert(const ThreatAlert& alert);

    // Ingest all alerts from a CSV threat feed file
    // Format: id,srcIP,dstIP,protocol,score,timestamp,sourceType,description
    bool ingestFromFile(const std::string& filename);

    // Run the full correlation + enrichment pipeline
    void processAlerts();

    // Compute and return aggregated statistics
    const ProcessingStats& getStats() const;

    // Export all alerts to JSON on stdout
    void exportJson() const;

    // Export all alerts to a CSV file
    void exportCsv(const std::string& filename) const;

    // Generate the full commander HTML dashboard
    void generateDashboard(const std::string& filename = "index.html") const;

    // Print BLUF summary report to stdout
    void printBLUFReport() const;
};

#endif // ALERT_MANAGER_H
