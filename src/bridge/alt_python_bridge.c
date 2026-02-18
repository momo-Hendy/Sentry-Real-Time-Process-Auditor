#include "python_bridge.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
  #define POPEN  _popen
  #define PCLOSE _pclose
#else
  #define POPEN  popen
  #define PCLOSE pclose
#endif

static void set_fallback(ai_result_t *out, const char *risk, const char *summary) {
    if (!out) return;
    strncpy(out->risk, risk ? risk : "unknown", sizeof(out->risk) - 1);
    out->risk[sizeof(out->risk) - 1] = '\0';

    strncpy(out->summary, summary ? summary : "AI analysis unavailable.", sizeof(out->summary) - 1);
    out->summary[sizeof(out->summary) - 1] = '\0';
}

// VERY naive JSON field extractor (v1).
// TODO: Replace with a real JSON parser (cJSON/jansson) once team agrees.
static void extract_json_string_field(const char *json, const char *key, char *dst, size_t dst_sz) {
    if (!json || !key || !dst || dst_sz == 0) return;

    // Look for: "key":"value"
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *p = strstr(json, pattern);
    if (!p) return;

    p = strchr(p, ':');
    if (!p) return;
    p++;

    // skip whitespace and opening quote
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '\"') return;
    p++;

    // copy until next quote (no escape handling here)
    size_t i = 0;
    while (*p && *p != '\"' && i + 1 < dst_sz) {
        dst[i++] = *p++;
    }
    dst[i] = '\0';
}

int ai_analyze_process_json(
    const char *python_exe,
    const char *script_module,
    const char *request_json,
    ai_result_t *out_result
) {
    set_fallback(out_result, "unknown", "AI analysis unavailable. Please verify this process manually.");

    if (!python_exe || !script_module || !request_json || !out_result) {
        return 1;
    }

    // Build command: python -m ai.inference
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s -m %s", python_exe, script_module);

    FILE *pipe = POPEN(cmd, "w+"); // may not work on all platforms; if it fails, switch to temp-file or two-pipe approach
    if (!pipe) {
        set_fallback(out_result, "unknown", "AI analysis unavailable. Failed to start Python.");
        return 2;
    }

    // Send request JSON to stdin
    fputs(request_json, pipe);
    fputs("\n", pipe);
    fflush(pipe);

    // Read response JSON from stdout
    char resp[2048];
    memset(resp, 0, sizeof(resp));

    // Some popen implementations only support "r" OR "w".
    // If this doesn’t work in your environment, switch to:
    //  - write request to a temp file, run python reading it, capture stdout
    //  - or use platform-specific pipes.
    if (!fgets(resp, sizeof(resp) - 1, pipe)) {
        PCLOSE(pipe);
        set_fallback(out_result, "unknown", "AI analysis unavailable. No response from Python.");
        return 3;
    }

    PCLOSE(pipe);

    // Extract fields (naive)
    extract_json_string_field(resp, "risk", out_result->risk, sizeof(out_result->risk));
    extract_json_string_field(resp, "summary", out_result->summary, sizeof(out_result->summary));

    // Ensure non-empty
    if (out_result->risk[0] == '\0') strncpy(out_result->risk, "unknown", sizeof(out_result->risk)-1);
    if (out_result->summary[0] == '\0') strncpy(out_result->summary, "AI analysis unavailable.", sizeof(out_result->summary)-1);

    return 0;
}