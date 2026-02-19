#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../shared/sentry_types.h"

#define AUDIT_LOG "/app/logs/audit.json"

/*
 * Writes a JSON-escaped string (with surrounding quotes) to f.
 * Handles backslash, double-quote, and ASCII control characters.
 */
static void write_json_string(FILE *f, const char *src) {
    fputc('"', f);
    for (; *src != '\0'; src++) {
        switch (*src) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            default:
                if ((unsigned char)*src < 0x20) {
                    fprintf(f, "\\u%04x", (unsigned char)*src);
                } else {
                    fputc(*src, f);
                }
        }
    }
    fputc('"', f);
}

/*
 * bridge_to_ai - Receives a ComplianceFinding from the scanner engine
 * and appends it as a JSON object (NDJSON, one object per line) to
 * AUDIT_LOG for downstream AI analysis.
 *
 * ISO 27001:A.12.4.1 — Protection of log information.
 * fflush() is called before fclose() to guarantee the record is
 * written to disk even if the process is interrupted immediately after.
 */
void bridge_to_ai(ComplianceFinding finding) {
    FILE *log_file = fopen(AUDIT_LOG, "a");
    if (log_file == NULL) {
        fprintf(stderr, "[bridge_to_ai] ERROR: cannot open %s\n", AUDIT_LOG);
        return;
    }

    /* One JSON object per line (NDJSON) — valid JSON, easy to stream/parse */
    fprintf(log_file, "{");
    fprintf(log_file, "\"finding_id\":%d,",   finding.finding_id);
    fprintf(log_file, "\"severity\":%d,",     finding.severity);
    fprintf(log_file, "\"iso_ref\":");         write_json_string(log_file, finding.iso_ref);
    fprintf(log_file, ",\"description\":");    write_json_string(log_file, finding.description);
    fprintf(log_file, ",\"source_app\":");     write_json_string(log_file, finding.source_app);
    fprintf(log_file, ",\"timestamp\":");      write_json_string(log_file, finding.timestamp);
    fprintf(log_file, "}\n");

    fflush(log_file);   /* Flush to kernel buffer before close */
    fclose(log_file);

    fprintf(stdout,
            "[Sentry Bridge] Finding logged → severity=%d  iso_ref=%s\n",
            finding.severity, finding.iso_ref);
}
