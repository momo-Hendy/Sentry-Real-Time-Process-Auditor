#ifndef SENTRY_WIN_COMPAT_H
#define SENTRY_WIN_COMPAT_H

/*
 * sentry_win_compat.h
 *
 * Thin compatibility shim so Sentry's C sources compile cleanly under
 * x86_64-w64-mingw32-gcc without modifying Linux behaviour.
 *
 * Include this header in any translation unit that uses uid_t, gid_t,
 * lstat(), or S_ISLNK() — AFTER your feature-test macros but BEFORE
 * the first POSIX system header that needs these types.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sys/stat.h>   /* struct stat, stat(), S_ISREG, S_ISDIR */

/* ── PATH_MAX ─────────────────────────────────────────────────────────
 * Windows calls it MAX_PATH (260).  Define PATH_MAX if not present.  */
#ifndef PATH_MAX
#  define PATH_MAX MAX_PATH
#endif

/* ── POSIX uid / gid types ────────────────────────────────────────────
 * MinGW-w64 does not define uid_t / gid_t in <sys/types.h>.
 * We use unsigned int (matches the %u format specifier used in
 * baseline.c) and guard against double-definition.               */
#ifndef _UID_T_DEFINED
   typedef unsigned int uid_t;
#  define _UID_T_DEFINED
#endif

#ifndef _GID_T_DEFINED
   typedef unsigned int gid_t;
#  define _GID_T_DEFINED
#endif

/* ── lstat → stat ─────────────────────────────────────────────────────
 * Windows has no POSIX symlinks, so lstat and stat are equivalent.
 * All S_ISLNK checks will return 0 (see below), so the scanner's
 * symlink-detection branch is safely skipped on Windows.          */
#ifndef lstat
#  define lstat(path, buf) stat((path), (buf))
#endif

/* ── S_ISLNK ──────────────────────────────────────────────────────────
 * Always evaluates to 0 on Windows: no symlink warnings will fire,
 * which is the correct behaviour for a Windows filesystem target.  */
#ifndef S_ISLNK
#  define S_ISLNK(m) (0)
#endif

#endif /* _WIN32 */

#endif /* SENTRY_WIN_COMPAT_H */
