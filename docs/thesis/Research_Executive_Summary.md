# Research Executive Summary

## Title
**Evading Linux EDRs Through io_uring and LD_PRELOAD: A Red Team Approach to Syscall-Less Attack Chains with ML-Based Detection**

* **Discipline**: MSc in Cyber Security
* **Research Focus**: Purple Teaming, Linux Kernel Asynchronous I/O (`io_uring`), Userspace Hooking (`LD_PRELOAD`), Endpoint Detection & Response (EDR) Telemetry Gaps, Machine Learning Anomaly Detection.

---

## 1. Abstract & Problem Statement

Modern Linux Endpoint Detection and Response (EDR) platforms (e.g., Elastic Defend, CrowdStrike Falcon, SentinelOne Singularity) fundamentally rely on system call (syscall) interception via eBPF tracepoints, kprobes, and Linux Security Module (LSM) hooks (`openat`, `read`, `write`, `execve`). This architectural model assumes that any meaningful file, network, or process activity must pass through the standard kernel system call dispatch table.

The introduction of the `io_uring` asynchronous I/O subsystem in Linux 5.1 (2019) disrupts this assumption. By utilizing a shared memory ring buffer between userspace and kernelspace, `io_uring` allows applications to submit I/O requests as Submission Queue Entries (SQEs). Kernel worker threads (`io_wq`) execute these operations asynchronously from within the kernel context. Consequently, operations executed through `io_uring` bypass standard userspace syscall dispatch paths, remaining invisible to traditional tracing mechanisms (`strace`, `auditd`, Falco, and conventional eBPF kprobe hooks).

This research investigates this dual-layer evasion paradigm from a Purple Team perspective, evaluating an end-to-end attack chain while designing and validating an enterprise-grade Blue Team detection strategy.

---

## 2. Dual-Layer Evasion Architecture

The attack model integrates two complementary evasion layers:
1. **Userspace Hooking (`LD_PRELOAD`)**: Intercepts 13 standard C library functions (`readdir`, `fopen`, `stat`, `execve`, etc.) to manipulate directory listings, mask malicious processes, and deceive userspace monitoring utilities.
2. **Kernel Ring-Buffer Execution (`io_uring`)**: Implements 10 core primitives operating directly on submission and completion rings, executing asynchronous file reads, credential access, network sockets, and process management without triggering standard syscall audit logs.

### Five-Phase Attack Chain
* **Phase 1: Subsystem Initialization**: Establishing `io_uring` ring buffers and hidden configuration structures.
* **Phase 2: Asynchronous C2 Channel**: Initiating non-blocking outbound network sessions via `uring_connect` / `uring_send`.
* **Phase 3: REAPER (Defense Suppression)**:
  * *Phase 3a*: Disabling kernel debug tracing (`/sys/kernel/debug/tracing/tracing_on`).
  * *Phase 3b*: Unpinning and deleting active eBPF sensor maps (`/sys/fs/bpf/*`).
  * *Phase 3c*: Terminating endpoint telemetry agents via signal injection.
* **Phase 4: Credential Theft & Reconnaissance**: Asynchronous extraction of sensitive files (`/etc/shadow`, `/etc/sudoers`).
* **Phase 5: Persistence & Cleanup**: Injecting dynamic linker hooks and executing asynchronous binary self-unlinking.

---

## 3. Core Theoretical Finding: The ACTION vs. EFFECT Paradigm

A primary contribution of this research is formulating the **ACTION vs. EFFECT** detection boundary for asynchronous kernel subsystems:

| Dimension | Definition | io_uring Behavior | Defensive Implication |
| :--- | :--- | :--- | :--- |
| **ACTION** | The procedural invocation of a system call (e.g., `sys_enter_openat`, `sys_enter_read`) | **EVADED** — Executed inside kernel worker threads; bypasses userspace entry hooks. | Syscall-only interceptors fail to capture execution telemetry. |
| **EFFECT** | The resulting state modification on the operating system (disk artifacts, modified inodes, socket descriptors, unpinned maps) | **OBSERVABLE** — File state changes, permission modifications, and network connections cannot be hidden. | Detection must focus on State Telemetry, File Integrity Monitoring (FIM), and Behavioral ML. |

---

## 4. Blue Team Detection Engineering & Experimental Results

To address telemetry blind spots, an integrated defensive framework was engineered and tested in a live SOC lab environment:

### Defensive Components
1. **Chokepoint Auditing**: Capturing the initialization syscall `io_uring_setup` via `auditbeat` / `auditd`.
2. **13 Custom Detection Rules**: Built using KQL, EQL, Threshold, and Alert Correlation to identify execution sequences, defense suppression, and persistence attempts.
3. **3 Elastic Machine Learning Anomaly Jobs**:
   * Rare `io_uring_setup` binary analysis.
   * Population behavior profiling.
   * Correlated sensitive file access anomalies.

### Empirical Performance
* **Baseline Detection**: Default EDR configurations exhibited only a **25%** detection rate against unprivileged attacks and **46–62%** under elevated sudo privileges.
* **Enhanced Multi-Layer Model**: Integrating custom chokepoint rules, FIM correlation, and ML anomaly detection achieved **83% True Positive Rate (TPR)** with a low **4.1% False Positive Rate (FPR)**.

---

## 5. Ethical Guidelines & Research Integrity

All code, rules, and telemetry models within this project are developed strictly for academic evaluation, defensive telemetry engineering, and authorized security assessments. The tools include configurable safe-mode simulation boundaries to prevent unintentional impact on operational environments.
