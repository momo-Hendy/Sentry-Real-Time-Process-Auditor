#include <stdio.h>
#include <time.h>
#include "sentry_types.h"

// This function acts as the "Bridge"
void bridge_to_ai(ComplianceFinding finding) {
    // In a real bank, we'd send this over a network. 
    // Here, we'll print it as valid JSON so Mohamed's AI can read it.
    printf("\n[SENTRY_BRIDGE_OUT]\n");
    printf("{\n");
    printf("  \"finding_id\": %d,\n", finding.finding_id);
    printf("  \"severity\": %d,\n", finding.severity);
    printf("  \"iso_reference\": \"%s\",\n", finding.iso_ref);
    printf("  \"event_description\": \"%s\"\n", finding.description);
    printf("}\n");
    printf("[END_TRANSMISSION]\n");
}

int main() {
    // Let's simulate a critical threat for Day 1
    ComplianceFinding log_threat;
    log_threat.finding_id = 1;
    log_threat.severity = 5; // We decided this is Critical for deleted logs!
    
    // Using safe string copying
    snprintf(log_threat.iso_ref, sizeof(log_threat.iso_ref), "A.12.4.1");
    snprintf(log_threat.description, sizeof(log_threat.description), "CRITICAL: Security logs were deleted to hide activity.");

    // Send it across the bridge
    bridge_to_ai(log_threat);

    return 0;
}