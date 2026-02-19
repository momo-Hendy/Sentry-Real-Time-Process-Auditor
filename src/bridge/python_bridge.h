#ifndef PYTHON_BRIDGE_H
#define PYTHON_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

// Simple result struct for v1
typedef struct {
    char risk[16];        // "low"|"medium"|"high"|"unknown"
    char summary[512];    // user-facing summary
} ai_result_t;

// Analyze a process via Python AI script.
// Returns 0 on success, non-zero on failure (fills result with safe fallback).
int ai_analyze_process_json(
    const char *python_exe,
    const char *script_module,   // e.g., "ai.inference" (used with -m)
    const char *request_json,
    ai_result_t *out_result
);

#ifdef __cplusplus
}
#endif

#endif