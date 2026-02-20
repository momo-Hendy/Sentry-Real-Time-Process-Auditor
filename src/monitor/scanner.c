#ifndef _WIN32
#  define _XOPEN_SOURCE 700
#endif

#include "../../shared/sentry_win_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifndef _WIN32
#  include <dirent.h>
#  include <unistd.h>
#  include <limits.h>
#endif

#include "../../shared/sentry_types.h"
#include "scanner.h"
#include "baseline.h"
#include "../comparator/hasher.h"

extern void bridge_to_ai(ComplianceFinding finding);

/* ── Platform-specific paths ─────────────────────────────────────────── */
#ifdef _WIN32
#  define LOG_FILE           "logs\\sentry.log"
#  define BASELINE_PATH      "db\\baseline.db"
#  define BASELINE_HASH_PATH "db\\baseline.hash"
#else
#  define LOG_FILE           "/var/log/sentry.log"
#  define BASELINE_PATH      "/var/lib/sentry/baseline.db"
#  define BASELINE_HASH_PATH "/var/lib/sentry/baseline.hash"
#endif

#define SOURCE_APP "SentryScanner-C"
#define ISO_REF    "ISO27001:A.12.4.1"

/* ── Forward declarations ─────────────────────────────────────────────── */
static void log_event(const char *filepath, const char *event_type);
static void deletion_alert(const char *path);
static void check_file(const char *filepath);
static void scan_directory_internal(const char *path);

/* ── Finding helpers ──────────────────────────────────────────────────── */

/*
 * init_finding — zero the struct and fill the constant fields.
 * Uses a single static counter for the finding_id.
 */
static void init_finding(ComplianceFinding *f) {
    static int next_id = 1;
    memset(f, 0, sizeof(ComplianceFinding));
    f->finding_id = next_id++;
    strncpy(f->iso_ref,    ISO_REF,    sizeof(f->iso_ref)    - 1);
    strncpy(f->source_app, SOURCE_APP, sizeof(f->source_app) - 1);
}

/* stamp_finding — write the ISO-8601 timestamp just before dispatch */
static void stamp_finding(ComplianceFinding *f) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(f->timestamp, sizeof(f->timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);
}

/* ── ISO-compliant event logger ───────────────────────────────────────── */

static void log_event(const char *filepath, const char *event_type) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    char timestamp[64];
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log, "[%s] EVENT=%s PATH=%s\n", timestamp, event_type, filepath);
    fclose(log);
}

/* ── Baseline integrity check ─────────────────────────────────────────── */

static int verify_baseline_integrity(void) {
    char current_hash[65];
    char stored_hash[65];

    if (calculate_sha256(BASELINE_PATH, current_hash) != 0)
        return -1;

    FILE *file = fopen(BASELINE_HASH_PATH, "r");
    if (!file)
        return 0;   /* First run — no stored hash yet */

    if (!fgets(stored_hash, sizeof(stored_hash), file)) {
        fclose(file);
        return -1;
    }
    fclose(file);

    stored_hash[strcspn(stored_hash, "\n")] = '\0';

    if (strcmp(current_hash, stored_hash) != 0) {
        log_event(BASELINE_PATH, "BASELINE_TAMPERED");

        ComplianceFinding finding;
        init_finding(&finding);
        finding.severity = 10;
        snprintf(finding.description, sizeof(finding.description),
                 "Baseline file integrity compromised");
        stamp_finding(&finding);
        bridge_to_ai(finding);
        return -1;
    }
    return 0;
}

static void update_baseline_hash(void) {
    char hash[65];
    if (calculate_sha256(BASELINE_PATH, hash) != 0) return;

    FILE *file = fopen(BASELINE_HASH_PATH, "w");
    if (!file) return;
    fprintf(file, "%s\n", hash);
    fclose(file);
}

/* ── Per-file integrity check (shared, both platforms) ───────────────── */

static void check_file(const char *filepath) {
    struct stat file_stat;

    /*
     * lstat() → stat() on Windows (compat header).
     * S_ISLNK() → always 0 on Windows (compat header).
     */
    if (lstat(filepath, &file_stat) != 0)
        return;

    if (S_ISLNK(file_stat.st_mode)) {
        log_event(filepath, "SYMLINK_DETECTED");

        ComplianceFinding finding;
        init_finding(&finding);
        finding.severity = 5;
        snprintf(finding.description, sizeof(finding.description),
                 "Symbolic link detected: %s", filepath);
        stamp_finding(&finding);
        bridge_to_ai(finding);
        return;
    }

    if (!S_ISREG(file_stat.st_mode))
        return;

    char   current_hash[65];
    char   stored_hash[65];
    mode_t stored_mode;
    uid_t  stored_uid;
    gid_t  stored_gid;

    /*
     * On Windows, st_uid / st_gid are always 0 (MinGW convention).
     * The baseline will also store 0, so the ownership comparison
     * never triggers a false positive.
     */
    mode_t current_mode = file_stat.st_mode;
    uid_t  current_uid  = (uid_t)file_stat.st_uid;
    gid_t  current_gid  = (gid_t)file_stat.st_gid;

    if (calculate_sha256(filepath, current_hash) != 0)
        return;

    /* New file — record baseline, no finding */
    if (get_file_metadata(filepath, stored_hash,
                          &stored_mode, &stored_uid, &stored_gid) != 0) {
        update_file_metadata(filepath, current_hash,
                             current_mode, current_uid, current_gid);
        return;
    }

    /* Detect any change: hash, permissions, or ownership */
    if (strcmp(stored_hash, current_hash) != 0 ||
        stored_mode != current_mode           ||
        stored_uid  != current_uid            ||
        stored_gid  != current_gid) {

        log_event(filepath, "INTEGRITY_VIOLATION");
        update_file_metadata(filepath, current_hash,
                             current_mode, current_uid, current_gid);

        ComplianceFinding finding;
        init_finding(&finding);
        finding.severity = 5;
        snprintf(finding.description, sizeof(finding.description),
                 "File integrity changed: %s", filepath);
        stamp_finding(&finding);
        bridge_to_ai(finding);
    }
}

/* ── Directory walker — Windows (Win32 API) ──────────────────────────── */

#ifdef _WIN32

static void scan_directory_internal(const char *path) {
    char search_path[PATH_MAX];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(ffd.cFileName, ".")  == 0 ||
            strcmp(ffd.cFileName, "..") == 0)
            continue;

        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", path, ffd.cFileName);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            /*
             * Reparse points cover NTFS symlinks and junctions.
             * Log and skip — don't follow them.
             */
            log_event(fullpath, "SYMLINK_DETECTED");

        } else if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory_internal(fullpath);

        } else {
            check_file(fullpath);
        }

    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
}

/* ── Directory walker — Linux (POSIX opendir/readdir) ────────────────── */

#else

static void scan_directory_internal(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    char fullpath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".")  == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat statbuf;
        if (lstat(fullpath, &statbuf) != 0)
            continue;

        if (S_ISLNK(statbuf.st_mode)) {
            log_event(fullpath, "SYMLINK_DETECTED");
        } else if (S_ISDIR(statbuf.st_mode)) {
            scan_directory_internal(fullpath);
        } else if (S_ISREG(statbuf.st_mode)) {
            check_file(fullpath);
        }
    }

    closedir(dir);
}

#endif /* _WIN32 */

/* ── Deletion alert (shared) ─────────────────────────────────────────── */

static void deletion_alert(const char *path) {
    log_event(path, "FILE_DELETED");

    ComplianceFinding finding;
    init_finding(&finding);
    finding.severity = 5;
    snprintf(finding.description, sizeof(finding.description),
             "Critical file deleted: %s", path);
    stamp_finding(&finding);
    bridge_to_ai(finding);
}

/* ── Public entry point (shared) ─────────────────────────────────────── */

void scan_directory(const char *path) {
    verify_baseline_integrity();
    load_baseline();
    scan_directory_internal(path);
    detect_deleted_files(deletion_alert);
    save_baseline();
    update_baseline_hash();
}
