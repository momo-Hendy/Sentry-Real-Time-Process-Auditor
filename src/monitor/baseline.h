#ifndef SENTRY_BASELINE_H
#define SENTRY_BASELINE_H

#include "../../shared/sentry_win_compat.h"  /* uid_t, gid_t on Windows */
#include <sys/types.h>

int load_baseline();
int save_baseline();

int get_file_metadata(const char *path,
                      char *hash_out,
                      mode_t *mode,
                      uid_t *uid,
                      gid_t *gid);

int update_file_metadata(const char *path,
                         const char *new_hash,
                         mode_t mode,
                         uid_t uid,
                         gid_t gid);

int detect_deleted_files(void (*alert_callback)(const char *path));

#endif
