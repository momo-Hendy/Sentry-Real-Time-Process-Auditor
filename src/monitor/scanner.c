#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include "../../shared/sentry_types.h"
#include "scanner.h"
#include "baseline.h"
#include "../comparator/hasher.h"

extern void bridge_to_ai(ComplianceFinding finding);

#define LOG_FILE "/var/log/sentry.log"
#define BASELINE_PATH "/var/lib/sentry/baseline.db"
#define BASELINE_HASH_PATH "/var/lib/sentry/baseline.hash"


/* Forward declarations */
static void deletion_alert(const char *path);
static void scan_directory_internal(const char *path);


static int verify_baseline_integrity() {

    char current_hash[65];
    char stored_hash[65];

    if (calculate_sha256(BASELINE_PATH, current_hash) != 0)
        return -1;

    FILE *file = fopen(BASELINE_HASH_PATH, "r");
    if (!file)
        return 0; // First run, no hash yet

    if (!fgets(stored_hash, sizeof(stored_hash), file)) {
        fclose(file);
        return -1;
    }

    fclose(file);

    stored_hash[strcspn(stored_hash, "\n")] = '\0';

    if (strcmp(current_hash, stored_hash) != 0) {

        log_event(BASELINE_PATH, "BASELINE_TAMPERED");

        ComplianceFinding finding;
        memset(&finding, 0, sizeof(ComplianceFinding));

        finding.severity = 10;

        strncpy(finding.iso_ref,
                "ISO27001:A.12.4.1",
                sizeof(finding.iso_ref) - 1);

        snprintf(finding.description,
                 sizeof(finding.description),
                 "Baseline file integrity compromised");

        bridge_to_ai(finding);

        return -1;
    }

    return 0;
}

static void update_baseline_hash() {

    char hash[65];

    if (calculate_sha256(BASELINE_PATH, hash) != 0)
        return;

    FILE *file = fopen(BASELINE_HASH_PATH, "w");
    if (!file) return;

    fprintf(file, "%s\n", hash);
    fclose(file);
}

/*
 * ISO-compliant logging
 */
static void log_event(const char *filepath,
                      const char *event_type) {

    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    char timestamp[64];
    struct tm *tm_info = localtime(&now);

    strftime(timestamp,
             sizeof(timestamp),
             "%Y-%m-%d %H:%M:%S",
             tm_info);

    fprintf(log,
            "[%s] EVENT=%s PATH=%s\n",
            timestamp,
            event_type,
            filepath);

    fclose(log);
}

/*
 * Secure file integrity check
 */
static void check_file(const char *filepath) {

    struct stat file_stat;

    /* Use lstat to prevent following symlinks */
    if (lstat(filepath, &file_stat) != 0)
        return;

    /* If it's a symlink → suspicious */
    if (S_ISLNK(file_stat.st_mode)) {
        log_event(filepath, "SYMLINK_DETECTED");

        ComplianceFinding finding;
        memset(&finding, 0, sizeof(ComplianceFinding));

        finding.severity = 5;
        strncpy(finding.iso_ref,
                "ISO27001:A.12.4.1",
                sizeof(finding.iso_ref) - 1);

        snprintf(finding.description,
                 sizeof(finding.description),
                 "Symbolic link detected: %s",
                 filepath);

        bridge_to_ai(finding);
        return;
    }

    if (!S_ISREG(file_stat.st_mode))
        return;

    char current_hash[65];
    char stored_hash[65];
    mode_t stored_mode;
    uid_t stored_uid;
    gid_t stored_gid;

    mode_t current_mode = file_stat.st_mode;
    uid_t  current_uid  = file_stat.st_uid;
    gid_t  current_gid  = file_stat.st_gid;

    if (calculate_sha256(filepath, current_hash) != 0)
        return;

    if (get_file_metadata(filepath,
                          stored_hash,
                          &stored_mode,
                          &stored_uid,
                          &stored_gid) != 0) {

        update_file_metadata(filepath,
                             current_hash,
                             current_mode,
                             current_uid,
                             current_gid);
        return;
    }

    if (strcmp(stored_hash, current_hash) != 0 ||
        stored_mode != current_mode ||
        stored_uid  != current_uid  ||
        stored_gid  != current_gid) {

        log_event(filepath, "INTEGRITY_VIOLATION");

        update_file_metadata(filepath,
                             current_hash,
                             current_mode,
                             current_uid,
                             current_gid);

        ComplianceFinding finding;
        memset(&finding, 0, sizeof(ComplianceFinding));

        finding.severity = 5;

        strncpy(finding.iso_ref,
                "ISO27001:A.12.4.1",
                sizeof(finding.iso_ref) - 1);

        snprintf(finding.description,
                 sizeof(finding.description),
                 "File integrity changed: %s",
                 filepath);

        bridge_to_ai(finding);
    }
}

/*
 * Secure recursive scan
 */
static void scan_directory_internal(const char *path) {

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    char fullpath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath,
                 sizeof(fullpath),
                 "%s/%s",
                 path,
                 entry->d_name);

        struct stat statbuf;

        /* Use lstat to avoid following symlinks */
        if (lstat(fullpath, &statbuf) != 0)
            continue;

        /* If symlink → log and skip */
        if (S_ISLNK(statbuf.st_mode)) {
            log_event(fullpath, "SYMLINK_DETECTED");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            scan_directory_internal(fullpath);
        } else if (S_ISREG(statbuf.st_mode)) {
            check_file(fullpath);
        }
    }

    closedir(dir);
}

/*
 * Public entry
 */
void scan_directory(const char *path) {

    verify_baseline_integrity();

    load_baseline();

    scan_directory_internal(path);

    detect_deleted_files(deletion_alert);

    save_baseline();

    update_baseline_hash();
}


/*
 * Deletion alert
 */
static void deletion_alert(const char *path) {

    log_event(path, "FILE_DELETED");

    ComplianceFinding finding;
    memset(&finding, 0, sizeof(ComplianceFinding));

    finding.severity = 5;

    strncpy(finding.iso_ref,
            "ISO27001:A.12.4.1",
            sizeof(finding.iso_ref) - 1);

    snprintf(finding.description,
             sizeof(finding.description),
             "Critical file deleted: %s",
             path);

    bridge_to_ai(finding);
}
