#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#include "monitor/scanner.h"

#define CONFIG_PATH      "config/sentry.conf"
#define DEFAULT_TARGET   "/app/test_files"
#define DEFAULT_INTERVAL 30000          /* ms — used only if config is missing */

/* ── Graceful shutdown ───────────────────────────────────────────────── */

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void ensure_dir(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return;
    fprintf(stderr, "[main] WARNING: cannot create directory %s: %s\n",
            path, strerror(errno));
}

/*
 * Minimal KEY=VALUE parser.  Only SCAN_TARGET and SCAN_INTERVAL are read;
 * all other lines (including comments starting with #) are skipped.
 */
static void parse_config(const char *path,
                          char *target, size_t target_len,
                          int  *interval_ms) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[main] WARNING: cannot open %s — using defaults\n", path);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';           /* strip newline */

        if (line[0] == '#' || line[0] == '\0')      /* skip comments / blanks */
            continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        if (strcmp(key, "SCAN_TARGET") == 0) {
            snprintf(target, target_len, "%s", val);
        } else if (strcmp(key, "SCAN_INTERVAL") == 0) {
            *interval_ms = atoi(val);
        }
    }

    fclose(f);
}

/* ── Entry point ─────────────────────────────────────────────────────── */

int main(void) {
    /* Register SIGINT (Ctrl+C) and SIGTERM for clean shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Defaults (overridden by config file) */
    char target[256];
    int  interval_ms = DEFAULT_INTERVAL;
    snprintf(target, sizeof(target), "%s", DEFAULT_TARGET);

    parse_config(CONFIG_PATH, target, sizeof(target), &interval_ms);

    if (interval_ms <= 0) {
        fprintf(stderr, "[main] WARNING: invalid SCAN_INTERVAL in config, "
                        "defaulting to %d ms\n", DEFAULT_INTERVAL);
        interval_ms = DEFAULT_INTERVAL;
    }

    /* Ensure required directories are present before the first scan */
    ensure_dir("/var/lib/sentry");
    ensure_dir("/var/log");
    ensure_dir("/app/logs");

    fprintf(stdout,
            "[Sentry] Started  —  target='%s'  interval=%d ms\n"
            "[Sentry] Send SIGINT (Ctrl+C) or SIGTERM to stop.\n",
            target, interval_ms);

    /* ── Main scan loop ── */
    while (keep_running) {
        fprintf(stdout, "[Sentry] Scanning '%s' ...\n", target);
        fflush(stdout);

        scan_directory(target);

        /*
         * Sleep in 100 ms slices so Ctrl+C is noticed quickly
         * rather than blocking for the full interval.
         */
        int remaining_ms = interval_ms;
        while (keep_running && remaining_ms > 0) {
            struct timespec ts = {
                .tv_sec  = 0,
                .tv_nsec = 100L * 1000000L  /* 100 ms */
            };
            nanosleep(&ts, NULL);
            remaining_ms -= 100;
        }
    }

    fprintf(stdout, "\n[Sentry] Shutdown signal received — exiting cleanly.\n");
    return 0;
}
