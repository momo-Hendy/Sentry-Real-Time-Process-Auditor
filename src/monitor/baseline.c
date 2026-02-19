#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "baseline.h"

#define BASELINE_FILE "/var/lib/sentry/baseline.db"
#define MAX_TRACKED_FILES 4096
#define HASH_LENGTH 65   // 64 hex chars + null

typedef struct {
    char path[PATH_MAX];
    char hash[HASH_LENGTH];
    mode_t mode;
    uid_t uid;
    gid_t gid;
    int seen;
} BaselineEntry;

static BaselineEntry entries[MAX_TRACKED_FILES];
static size_t entry_count = 0;

/*
 * Load baseline file into memory.
 * Format:
 * path|hash|mode|uid|gid
 */
int load_baseline() {

    FILE *file = fopen(BASELINE_FILE, "r");
    if (!file) return -1;

    char line[PATH_MAX + 256];

    while (fgets(line, sizeof(line), file)) {

        char *path = strtok(line, "|");
        char *hash = strtok(NULL, "|");
        char *mode_str = strtok(NULL, "|");
        char *uid_str = strtok(NULL, "|");
        char *gid_str = strtok(NULL, "\n");

        if (!path || !hash || !mode_str || !uid_str || !gid_str)
            continue;

        strncpy(entries[entry_count].path, path, PATH_MAX - 1);
        entries[entry_count].path[PATH_MAX - 1] = '\0';

        strncpy(entries[entry_count].hash, hash, HASH_LENGTH - 1);
        entries[entry_count].hash[HASH_LENGTH - 1] = '\0';

        entries[entry_count].mode = (mode_t)strtol(mode_str, NULL, 8);
        entries[entry_count].uid  = (uid_t)atoi(uid_str);
        entries[entry_count].gid  = (gid_t)atoi(gid_str);

        entries[entry_count].seen = 0;

        entry_count++;
    }

    fclose(file);
    return 0;
}

/*
 * Save baseline memory state to disk.
 */
int save_baseline() {

    FILE *file = fopen(BASELINE_FILE, "w");
    if (!file) return -1;

    for (size_t i = 0; i < entry_count; i++) {
        fprintf(file,
                "%s|%s|%o|%u|%u\n",
                entries[i].path,
                entries[i].hash,
                entries[i].mode,
                entries[i].uid,
                entries[i].gid);
    }

    fclose(file);
    return 0;
}

/*
 * Retrieve stored hash and metadata.
 */
int get_file_metadata(const char *path,
                      char *hash_out,
                      mode_t *mode,
                      uid_t *uid,
                      gid_t *gid) {

    for (size_t i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].path, path) == 0) {

            strcpy(hash_out, entries[i].hash);

            *mode = entries[i].mode;
            *uid  = entries[i].uid;
            *gid  = entries[i].gid;

            entries[i].seen = 1;
            return 0;
        }
    }

    return -1;
}

/*
 * Update or insert file metadata entry.
 */
int update_file_metadata(const char *path,
                         const char *new_hash,
                         mode_t mode,
                         uid_t uid,
                         gid_t gid) {

    for (size_t i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].path, path) == 0) {

            strcpy(entries[i].hash, new_hash);
            entries[i].mode = mode;
            entries[i].uid  = uid;
            entries[i].gid  = gid;
            entries[i].seen = 1;
            return 0;
        }
    }

    if (entry_count < MAX_TRACKED_FILES) {

        strncpy(entries[entry_count].path, path, PATH_MAX - 1);
        entries[entry_count].path[PATH_MAX - 1] = '\0';

        strncpy(entries[entry_count].hash, new_hash, HASH_LENGTH - 1);
        entries[entry_count].hash[HASH_LENGTH - 1] = '\0';

        entries[entry_count].mode = mode;
        entries[entry_count].uid  = uid;
        entries[entry_count].gid  = gid;
        entries[entry_count].seen = 1;

        entry_count++;
        return 0;
    }

    return -1;
}

/*
 * Detect deleted files.
 */
int detect_deleted_files(void (*alert_callback)(const char *path)) {

    int changes = 0;

    for (size_t i = 0; i < entry_count; i++) {

        if (entries[i].seen == 0) {

            alert_callback(entries[i].path);

            for (size_t j = i; j < entry_count - 1; j++) {
                entries[j] = entries[j + 1];
            }

            entry_count--;
            i--;
            changes++;
        }
    }

    return changes;
}
