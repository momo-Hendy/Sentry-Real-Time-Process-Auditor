#ifndef SENTRY_TYPES_H
#define SENTRY_TYPES_H

// This is the "Shared Form" for your whole team
typedef struct {
    int finding_id;          // Unique ID for the event
    int severity;            // Scale of 1 (Low) to 5 (Critical)
    char iso_ref[20];        // ISO 27001 Reference (e.g., "A.12.4.1")
    char description[256];   // Human-readable description
    char source_app[50];     // Which app was being audited?
    char timestamp[32];      // When it happened
} ComplianceFinding;

#endif