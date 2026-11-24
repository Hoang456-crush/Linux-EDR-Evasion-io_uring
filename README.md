# Linux EDR Evasion & Telemetry Assessment Lab (`io_uring` & `LD_PRELOAD`)

[![Build & Security CI](https://github.com/Hoang456-crush/Linux-EDR-Evasion-io_uring/actions/workflows/ci.yml/badge.svg)](https://github.com/Hoang456-crush/Linux-EDR-Evasion-io_uring/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Kernel: 5.1+](https://img.shields.io/badge/Linux%20Kernel-5.1%2B-green.svg)](https://kernel.org)
[![EDR Tested: Elastic Defend](https://img.shields.io/badge/EDR-Elastic%20Defend-orange.svg)](https://elastic.co)
[![Framework: Purple Team](https://img.shields.io/badge/Methodology-Purple%20Team-purple.svg)]()
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)]()
[![Sigma Rules: 13](https://img.shields.io/badge/Sigma%20Rules-13%20Verified-blueviolet.svg)]()

An enterprise-ready **Purple Team Security Assessment Framework and Telemetry Benchmarking Laboratory**. Evaluates Linux kernel asynchronous I/O (`io_uring`) and userspace dynamic linker hooking (`LD_PRELOAD`) against modern Endpoint Detection and Response (EDR) platforms, complemented by resilient Blue Team detection engineering (Sigma, Elastic SIEM, and Behavioral Machine Learning).

---

## 📌 Project Architecture

```
Linux-EDR-Evasion-io_uring/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions CI: Automated build, smoke test & Sigma linting
├── Dockerfile                     # Isolated Ubuntu 22.04 container with liburing-dev
├── docker-compose.yml             # Privileged testing container configuration
├── src/
│   ├── Makefile                   # Multi-target build script (all, legacy, clean, help)
│   ├── include/
│   │   └── evasion_lab.h          # Core prototypes, structs & CLI definitions
│   ├── hooks/
│   │   └── ld_hooks.c             # 13 userspace hooks (compiles to libevasion_hooks.so)
│   ├── engine/
│   │   └── uring_ops.c            # 10 io_uring asynchronous ring-buffer operations
│   ├── cli/
│   │   └── main.c                 # Multi-mode CLI interface with safe-mode & dry-run
│   └── legacy/
│       └── evasion_toolkit_monolithic.c # Preserved original monolithic thesis source
├── detections/
│   ├── sigma/                     # 13 Standard Sigma YAML detection rules
│   │   ├── sys_iouring_setup_chokepoint.yml
│   │   ├── lnx_ld_preload_injection.yml
│   │   ├── lnx_reaper_kernel_tracing_disabled.yml
│   │   └── ... (all 13 rules)
│   ├── rules/
│   │   └── all_13_rules.txt       # Elastic KQL/EQL implementation guides
│   ├── elastic_ml/
│   │   └── elastic_ml_anomaly_jobs.txt # 3 Elastic Machine Learning Anomaly Detection Jobs
│   └── kibana_dashboard/
│       └── kibana_soc_dashboard_guide.txt # 6-panel Kibana SOC Dashboard configuration
├── docs/
│   ├── thesis/
│   │   └── Research_Executive_Summary.md # Academic summary, methodology & detection metrics
│   ├── presentation/
│   │   ├── PSB7030CE_DO-DINH-HUY-HOANG.pptx # 27-slide defense presentation
│   │   └── defense_presentation_script.txt  # Slide-by-slide defense script
│   └── architecture/              # Telemetry matrices and design documentation
├── demo/
│   ├── attack_execution_guide.txt # Step-by-step experiment reproduction guide
│   └── README.md                  # Video demo guidance & Release asset links
├── .gitignore                     # Git ignore rules for binaries and temporary artifacts
└── README.md                      # Comprehensive lab documentation & CI/CD guides
```

---

## 🔬 Core Scientific Finding: The "ACTION vs. EFFECT" Paradigm

Traditional Linux EDRs place eBPF kprobes and tracepoints on syscall entry points (`openat`, `read`, `write`, `connect`). By delegating I/O operations into the `io_uring` submission ring queue, kernel worker threads (`io_wq`) execute requests asynchronously from kernel context, completely bypassing standard syscall entry dispatch paths.

| Telemetry Vector | Traditional Syscall Path | `io_uring` Asynchronous Path | Detection Strategy |
| :--- | :--- | :--- | :--- |
| **ACTION** *(Syscall invocation)* | Traced by `auditd`, `strace`, eBPF kprobes | **EVADED** *(Kernel worker threads execute requests)* | Audit `io_uring_setup` chokepoint |
| **EFFECT** *(State changes)* | Observable (Files, sockets, memory changes) | **OBSERVABLE** *(Disk, permissions, eBPF maps altered)* | FIM, State Telemetry, ML Anomaly |

* **Empirical Validation**: While default EDR telemetry captured only **25%** of unprivileged attack actions, our multi-layered defense engineering raised the detection rate to **83% True Positive Rate (TPR)** with a low **4.1% False Positive Rate (FPR)**.

---

## 🗺️ MITRE ATT&CK & MITRE D3FEND Mapping Matrix

| Phase | Adversary Technique (ATT&CK) | Technique ID | Defensive Countermeasure (D3FEND) | Detection Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Hijack Execution Flow | `T1574.006` | System Call Analysis (`d3f:SystemCallAnalysis`) | Sigma Rule 1 (`io_uring_setup`), ML Job 1 |
| **Phase 2** | Non-Application Layer Protocol | `T1095` | Network Traffic Analysis (`d3f:InboundTrafficFiltering`) | ML Job 2 (Rare socket anomalies) |
| **Phase 3a** | Impair Defenses: Disable Tools | `T1562.001` | File Integrity Monitoring (`d3f:FileIntegrityMonitoring`) | Sigma Rule 5 (`tracing_on` tamper) |
| **Phase 3b** | Impair Defenses: Disable Sensor | `T1562.001` | Process Telemetry Verification | Sigma Rule 6 (`/sys/fs/bpf/*` unpinned) |
| **Phase 3c** | Impair Defenses: Terminate EDR | `T1562.001` | Process Termination Prevention | Sigma Rule 7 (Signals to EDR) |
| **Phase 4** | OS Credential Dumping | `T1003.008` | File Access Monitoring (`d3f:FileAccessPatternAnalysis`) | Sigma Rule 8 (`/etc/shadow`), ML Job 3 |
| **Phase 5** | Hijack Execution: Dynamic Linker | `T1574.006` | File Integrity Monitoring (`d3f:FileIntegrityMonitoring`) | Sigma Rule 4 (`ld.so.preload`) |
| **Phase 5** | Indicator Removal: File Deletion | `T1070.004` | Audit Log Ingestion (`d3f:ProcessLineageAnalysis`) | Sigma Rule 10 (Self-unlinking) |

---

## 🐳 One-Click Docker Laboratory Setup

The repository includes a containerized laboratory environment for immediate testing without modifying host OS packages:

```bash
# Clone the repository
git clone https://github.com/Hoang456-crush/Linux-EDR-Evasion-io_uring.git
cd Linux-EDR-Evasion-io_uring

# Build and start container environment
docker compose up -d

# Drop into the interactive testing shell
docker compose exec evasion-lab bash

# Run the benchmark assessment
./evasion_lab --mode benchmark
```

---

## 🚀 Native Compilation & Quick Start

### Prerequisites
* Linux distribution with Kernel 5.1+ (Tested on Ubuntu 22.04 LTS / 24.04 LTS)
* Build tools: `gcc`, `make`, `liburing-dev`

```bash
# Install dependencies
sudo apt update && sudo apt install -y build-essential liburing-dev

# Compile modular framework
cd src
make
```

### Generated Artifacts
1. `libevasion_hooks.so`: Userspace shared object hook library.
2. `evasion_lab`: Modular CLI benchmarking and assessment tool.

---

## 🛠️ CLI Tool Usage (`evasion_lab`)

The framework includes built-in safety controls (`--safe-mode` by default and `--dry-run`) allowing security researchers to test EDR telemetry without endangering host system integrity.

```bash
# 1. Run full telemetry assessment in SAFE SANDBOX mode (Default: /tmp/evasion_lab)
./evasion_lab --mode benchmark

# 2. Test an isolated phase with simulated dry-run (no disk writes)
./evasion_lab --mode test-phase --phase 4 --dry-run

# 3. Simulate C2 beaconing to a specified test listener
./evasion_lab --mode test-phase --phase 2 --c2-ip 192.168.1.100 --port 4444

# 4. Clean up temporary lab sandbox files
./evasion_lab --mode cleanup
```

### Command Line Options Reference

```text
Core Execution Modes:
  -m, --mode <mode>        benchmark   : Comprehensive telemetry gap test (Default)
                           test-phase  : Run an isolated attack phase (-p required)
                           simulate    : Full Purple Team detection simulation
                           cleanup     : Remove sandbox artifacts and reset

Phase Selection:
  -p, --phase <1-5|all>    1 : io_uring Ring Buffer Init & Chokepoint Probe
                           2 : Asynchronous C2 Channel
                           3 : REAPER Defense Suppression (BPF & Tracing)
                           4 : Sensitive State Telemetry Probe (Shadow extraction)
                           5 : Persistence Audit & Binary Self-Unlink

Safety & Environment:
  -s, --safe-mode          Target isolated sandbox /tmp/evasion_lab (Enabled by default)
      --live-mode          Target live system files (/etc, /sys) [REQUIRES ROOT]
  -d, --dry-run            Log planned SQE ring operations without executing
  -c, --c2-ip <IP>         Target C2 IP for Phase 2 (Default: 127.0.0.1)
      --port <PORT>        Target C2 Port (Default: 4444)
  -v, --verbose            Enable detailed debug telemetry
  -h, --help               Display help guide
```

---

## 🛡️ Detection Engineering (13 Sigma Rules)

All detection rules are packaged in [detections/sigma/](detections/sigma/) and follow the industry-standard Sigma format:

* [`sys_iouring_setup_chokepoint.yml`](detections/sigma/sys_iouring_setup_chokepoint.yml): Audit `io_uring_setup` entry chokepoint.
* [`lnx_ld_preload_injection.yml`](detections/sigma/lnx_ld_preload_injection.yml): Dynamic linker hook detection.
* [`lnx_ld_audit_interception.yml`](detections/sigma/lnx_ld_audit_interception.yml): LD_AUDIT abuse detection.
* [`lnx_persistence_ld_so_preload.yml`](detections/sigma/lnx_persistence_ld_so_preload.yml): Preload file integrity tampering.
* [`lnx_reaper_kernel_tracing_disabled.yml`](detections/sigma/lnx_reaper_kernel_tracing_disabled.yml): Kernel debug tracing disabling.
* [`lnx_reaper_bpf_maps_unpinned.yml`](detections/sigma/lnx_reaper_bpf_maps_unpinned.yml): Deletion of `/sys/fs/bpf/*` maps.
* [`lnx_reaper_edr_agent_killed.yml`](detections/sigma/lnx_reaper_edr_agent_killed.yml): Signal termination targeted at EDR agents.
* [`lnx_sensitive_credential_access.yml`](detections/sigma/lnx_sensitive_credential_access.yml): Anomalous shadow access.
* [`lnx_persistence_shell_profile.yml`](detections/sigma/lnx_persistence_shell_profile.yml): Shell configuration modifications.
* [`lnx_binary_self_deletion.yml`](detections/sigma/lnx_binary_self_deletion.yml): Asynchronous self-unlinking detection.
* [`lnx_iouring_burst_threshold.yml`](detections/sigma/lnx_iouring_burst_threshold.yml): Threshold on `io_uring_enter` bursts.
* [`lnx_reaper_attack_chain_correlation.yml`](detections/sigma/lnx_reaper_attack_chain_correlation.yml): Multi-phase defense suppression correlation.
* [`lnx_double_evasion_meta_rule.yml`](detections/sigma/lnx_double_evasion_meta_rule.yml): High-severity meta-alert.

---


---

## 🔄 CI/CD & Automated Testing Pipeline

This project employs a robust **Continuous Integration (CI)** pipeline powered by **GitHub Actions** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) to ensure code reliability, multi-target compilation integrity, and rule validation on every push or pull request.

```
+-----------------------------------------------------------------------------------+
|                           GitHub Actions CI Pipeline                              |
+-----------------------------------------------------------------------------------+
| 1. Environment Setup   --> Ubuntu 22.04 LTS + GCC + liburing-dev + PyYAML        |
| 2. Modular Build       --> make (libevasion_hooks.so & evasion_lab)               |
| 3. Legacy Target Build --> make legacy (evasion_hooks.so & evasion_ops)           |
| 4. CLI Smoke Testing   --> --help, --dry-run, --safe-mode, --cleanup              |
| 5. Sigma Linting       --> Automated YAML syntax & metadata validation (13 rules) |
+-----------------------------------------------------------------------------------+
```

### 1. What the Pipeline Verifies
* **Compiler & Linker Integrity**: Compiles both the modern modular framework (`evasion_lab`) and legacy monolithic binaries using GCC with `-Wall -Wextra -O2`, verifying that `liburing` and dynamic linker hooks (`-ldl`) link without errors or unresolved symbols.
* **Non-Destructive Smoke Tests**: Runs `evasion_lab` in `--dry-run` and `--safe-mode` across multiple phase arguments (Phase 1, Phase 4) to ensure the CLI parser, memory management, and argument validation work reliably without modifying host system state.
* **Detection-as-Code Quality Gate**: An embedded Python test suite lints all 13 Sigma rule files in [`detections/sigma/`](detections/sigma/) to enforce that all required schema keys (`title`, `id`, `status`, `description`, `logsource`, `detection`, `level`, `tags`) are present and compliant with the Sigma specification.

### 2. How to Run the CI Pipeline Locally

You can execute the exact same checks locally before pushing code to GitHub:

#### Option A: Native Command Line (Linux / WSL2)
```bash
# Step 1: Install dependencies
sudo apt-get update && sudo apt-get install -y build-essential liburing-dev python3-yaml

# Step 2: Compile both modular and legacy targets
cd src
make clean && make
make legacy

# Step 3: Run CLI smoke tests
./evasion_lab --help
./evasion_lab --mode benchmark --dry-run
./evasion_lab --mode test-phase --phase 1 --dry-run
./evasion_lab --mode cleanup
cd ..

# Step 4: Validate Sigma rules
python3 -c '
import os, yaml, sys
sigma_dir = "detections/sigma"
required_keys = ["title", "id", "status", "description", "logsource", "detection", "level", "tags"]
files = [f for f in os.listdir(sigma_dir) if f.endswith(".yml")]
print(f"Validating {len(files)} Sigma rules...")
for f in files:
    with open(os.path.join(sigma_dir, f)) as yf:
        data = yaml.safe_load(yf)
    for k in required_keys:
        assert k in data, f"{f} missing {k}"
print("[SUCCESS] All Sigma rules are valid!")
'
```

#### Option B: Using `act` (Run GitHub Actions Locally in Docker)
If you have [nektos/act](https://github.com/nektos/act) installed:
```bash
# Run the entire GitHub Actions workflow locally in a Docker container
act push
```

### 3. CI Status Badge
The badge at the top of the repository automatically reflects the real-time health of the `main` branch:
* 🟢 **Passing**: Both modular and legacy binaries compiled cleanly and all 13 Sigma rules passed validation.
* 🔴 **Failing**: A build error or malformed Sigma rule was detected, preventing broken code from silently entering the codebase.

## ⚠️ Legal & Ethical Disclaimer

This software and research artifacts are distributed strictly for **educational, academic, and authorized defensive testing purposes**. All experiments must be conducted on isolated test systems. The developers assume no liability for misuse or damage caused by this software.
