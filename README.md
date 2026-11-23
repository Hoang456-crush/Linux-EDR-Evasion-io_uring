# Linux EDR Evasion & Telemetry Assessment Lab (`io_uring` & `LD_PRELOAD`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Kernel: 5.1+](https://img.shields.io/badge/Linux%20Kernel-5.1%2B-green.svg)](https://kernel.org)
[![EDR Tested: Elastic Defend](https://img.shields.io/badge/EDR-Elastic%20Defend-orange.svg)](https://elastic.co)
[![Framework: Purple Team](https://img.shields.io/badge/Methodology-Purple%20Team-purple.svg)]()
[![Build: GCC](https://img.shields.io/badge/Build-GCC%20%7C%20Make-yellow.svg)]()

A modular Purple Team security assessment framework and benchmarking laboratory evaluating Linux kernel asynchronous I/O (`io_uring`) and userspace dynamic linker hooking (`LD_PRELOAD`) against modern Endpoint Detection and Response (EDR) platforms.

---

## 📌 Project Architecture

```
Linux-EDR-Evasion-io_uring/
├── src/
│   ├── Makefile                   # Modular build automation
│   ├── include/
│   │   └── evasion_lab.h          # Core prototypes, structs & CLI definitions
│   ├── hooks/
│   │   └── ld_hooks.c             # 13 userspace hooks (compiles to libevasion_hooks.so)
│   ├── engine/
│   │   └── uring_ops.c            # 10 io_uring asynchronous ring-buffer operations
│   ├── cli/
│   │   └── main.c                 # Multi-mode CLI interface with safe-mode & dry-run
│   └── legacy/
│       └── evasion_toolkit_monolithic.c # Preserved monolithic thesis source
├── detections/
│   ├── rules/
│   │   └── all_13_rules.txt       # 13 Elastic Detection Rules (KQL, EQL, Threshold, Correlation)
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
│   └── architecture/              # Diagrams and telemetry matrix
├── demo/
│   ├── attack_execution_guide.txt # Step-by-step experiment reproduction guide
│   └── README.md                  # Video demo guidance & Release asset links
├── .gitignore                     # Git ignore rules for binaries and temporary artifacts
└── README.md                      # Comprehensive lab documentation
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

## 🚀 Quick Start & Compilation

### Prerequisites
* Linux distribution with Kernel 5.1+ (Tested on Ubuntu 22.04 LTS / 24.04 LTS)
* Build tools: `gcc`, `make`, `liburing-dev`

```bash
# On Ubuntu / Debian
sudo apt update && sudo apt install -y build-essential liburing-dev

# Clone repository
git clone https://github.com/Hoang456-crush/Linux-EDR-Evasion-io_uring.git
cd Linux-EDR-Evasion-io_uring/src

# Compile modular framework
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

## 🛡️ Detection Engineering (Blue Team)

The repository provides 13 custom detection rules and 3 Machine Learning configurations:

1. **Chokepoint Rule 1 (KQL)**: Detection of `io_uring_setup` system calls.
2. **Rules 2–3 (EQL)**: Dynamic linker injection (`LD_PRELOAD`, `LD_AUDIT`).
3. **Rule 4 (KQL)**: Persistence targeting `/etc/ld.so.preload`.
4. **Rules 5–7**: Defense suppression detection (kernel tracing disabled, BPF maps unpinned, EDR agent termination).
5. **Rule 8 (EQL)**: Credential file exfiltration (`/etc/shadow`, `/etc/sudoers`).
6. **Rules 9–10**: Shell persistence and asynchronous binary self-deletion.
7. **Rule 11 (Threshold)**: High-frequency burst of `io_uring_enter` calls.
8. **Rules 12–13 (Correlation)**: REAPER multi-phase kill-chain and Double Evasion meta-alerts.

---

## ⚠️ Legal & Ethical Disclaimer

This software and research artifacts are distributed strictly for **educational, academic, and authorized defensive testing purposes**. All experiments must be conducted on isolated test systems. The developers assume no liability for misuse or damage caused by this software.
