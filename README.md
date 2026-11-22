# Linux EDR Evasion via io_uring & LD_PRELOAD: Red vs Blue Team Evaluation

A Purple Team research repository demonstrating asynchronous syscall-less execution techniques on Linux using `io_uring` and `LD_PRELOAD`, alongside defense engineering mechanisms with Elastic Security and Machine Learning.

---

## 📌 Repository Overview

This repository organizes the research artifacts, source code, detection rules, and presentation materials developed for the Master of Science in Cyber Security coursework project.

```
Linux-EDR-Evasion-io_uring/
├── src/
│   ├── evasion_toolkit.c          # C implementation of io_uring & LD_PRELOAD evasion
│   └── Makefile                   # Build automation for shared library and executable
├── detections/
│   ├── rules/
│   │   └── all_13_rules.txt       # 13 detection rules (KQL, EQL, Threshold, Correlation)
│   ├── elastic_ml/
│   │   └── elastic_ml_anomaly_jobs.txt # Elastic ML anomaly detection jobs
│   └── kibana_dashboard/
│       └── kibana_soc_dashboard_guide.txt # 6-panel SOC dashboard design guide
├── docs/
│   ├── thesis/
│   │   └── PSB7030CE_DO-DINH-HUY-HOANG.docx # Final master thesis report
│   └── presentation/
│       ├── PSB7030CE_DO-DINH-HUY-HOANG.pptx # Thesis defense slides (27 slides)
│       └── defense_presentation_script.txt  # Slide-by-slide presentation script
├── demo/
│   ├── attack_execution_guide.txt # Step-by-step test execution guide
│   └── README.md                  # Demonstration notes & video release guidance
├── .gitignore                     # Git ignore rules for binaries and temporary files
└── README.md                      # Project documentation
```

---

## 🔬 Core Concepts

### 1. The Evasion Architecture
* **Userspace Hooking (`LD_PRELOAD`)**: Hooks libc calls (`readdir`, `fopen`, `stat`, etc.) to hide malicious artifacts and processes from local administrators and userspace tools.
* **Kernel Bypass (`io_uring`)**: Offloads file and network operations to kernel worker threads (`io_wq`) via shared memory ring buffers, bypassing conventional syscall tracepoints and eBPF kprobes.

### 2. The ACTION vs EFFECT Paradigm
* **ACTION**: System call entry points can be evaded through `io_uring` asynchronous submission queues.
* **EFFECT**: System modifications (file tampering, privilege changes, network sessions) remain observable. Effective detection relies on multi-layered behavioral telemetry, File Integrity Monitoring (FIM), and Machine Learning anomalies rather than syscall-only interception.

---

## 🛠️ Build and Compilation

Tested on Linux distributions with kernel 5.1+:

```bash
cd src
make
```

Output:
* `evasion_hooks.so`: Shared library for userspace hooking.
* `evasion_ops`: Standalone executable performing `io_uring` asynchronous operations.

---

## 🛡️ Detection Engineering

The `detections/` directory includes detection logic for Elastic SIEM:
* **Chokepoint Monitoring**: Detection of `io_uring_setup` events.
* **Integrity Monitoring**: Auditing `/etc/ld.so.preload` and dynamic linker activities.
* **Defense Suppression Detection**: Identifying attempts to tamper with BPF maps or kernel tracing.
* **Behavioral Machine Learning**: Anomaly detection jobs for rare `io_uring` usage patterns.

---

## ⚠️ Disclaimer

This project is published solely for educational, academic, and defensive security research. All demonstrations and experiments were executed in isolated laboratory environments.
