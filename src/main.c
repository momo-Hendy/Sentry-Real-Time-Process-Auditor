/* Platform detection must come before any includes */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define _WIN32_WINNT 0x0600
#  include <windows.h>
#  include <direct.h>           /* _mkdir */
#else
#  define _POSIX_C_SOURCE 200809L
#  include <unistd.h>
#  include <time.h>
#endif

#include "monitor/scanner.h"    /* scan_directory — now works on both platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

#define CONFIG_PATH      "config/sentry.conf"
#define DEFAULT_INTERVAL 30000  /* ms */

#ifdef _WIN32
#  define DEFAULT_TARGET   "test_files"
#else
#  define DEFAULT_TARGET   "/app/test_files"
#endif

/* ── Graceful shutdown ───────────────────────────────────────────────── */

static volatile int keep_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void ensure_dir(const char *path) {
#ifdef _WIN32
    int rc = _mkdir(path);
#else
    int rc = mkdir(path, 0755);
#endif
    if (rc == 0 || errno == EEXIST)
        return;
    fprintf(stderr, "[main] WARNING: cannot create directory '%s': %s\n",
            path, strerror(errno));
}

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts = {
        .tv_sec  = 0,
        .tv_nsec = (long)ms * 1000000L
    };
    nanosleep(&ts, NULL);
#endif
}

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
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

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
#ifdef _WIN32
    signal(SIGINT, handle_signal);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif

    char target[256];
    int  interval_ms = DEFAULT_INTERVAL;
    snprintf(target, sizeof(target), "%s", DEFAULT_TARGET);

    parse_config(CONFIG_PATH, target, sizeof(target), &interval_ms);

    if (interval_ms <= 0) {
        fprintf(stderr, "[main] WARNING: invalid SCAN_INTERVAL — defaulting to %d ms\n",
                DEFAULT_INTERVAL);
        interval_ms = DEFAULT_INTERVAL;
    }

    /*
     * Directory setup — platform specific:
     *   Linux  : /var/lib/sentry  /var/log  /app/logs
     *   Windows: .\db             .\logs    (relative, portable)
     */
#ifdef _WIN32
    ensure_dir("logs");   /* audit.json and sentry.log live here */
    ensure_dir("db");     /* baseline.db and baseline.hash live here */
#else
    ensure_dir("/var/lib/sentry");
    ensure_dir("/var/log");
    ensure_dir("/app/logs");
#endif

    fprintf(stdout,
            "[Sentry] Started  —  target='%s'  interval=%d ms\n"
            "[Sentry] Press Ctrl+C to stop.\n",
            target, interval_ms);

    while (keep_running) {
        fprintf(stdout, "[Sentry] Scanning '%s' ...\n", target);
        fflush(stdout);

        scan_directory(target);

        /* Responsive sleep: check keep_running every 100 ms */
        int remaining_ms = interval_ms;
        while (keep_running && remaining_ms > 0) {
            sleep_ms(100);
            remaining_ms -= 100;
        }
    }

    fprintf(stdout, "\n[Sentry] Shutdown signal received — exiting cleanly.\n");
    return 0;
}
