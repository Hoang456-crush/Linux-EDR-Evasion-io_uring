# SOC Analyst Triage Playbook: Investigating io_uring & LD_PRELOAD Evasion

## 🎯 Purpose & Scope
This incident response playbook provides Level 1 (Triage), Level 2 (Incident Analysis), and Level 3 (Threat Hunting) SOC Analysts with an end-to-end procedural workflow for investigating, pivoting, and scoping alerts associated with asynchronous I/O (`io_uring`) kernel evasion and userspace dynamic linker hijacking (`LD_PRELOAD`).

Unlike Detection Engineers who write static rules, SOC Analysts operate through **Identifier-Driven Pivoting (ID Pivoting)**, **Process Lineage Reconstruction**, and **Entity Analytics** to confirm malicious intent, determine blast radius, and execute containment.

---

## 🚨 Incident Workflow at a Glance

```
[1. Alert Ingestion] 
       │ (Rule 1: io_uring_setup OR Rule 4: /etc/ld.so.preload)
       ▼
[2. Extract Key IDs] 
       ├── process.entity_id (Execution instance UUID)
       ├── process.parent.entity_id (Spawning ancestor)
       ├── user.id & auditd.auid (True login user vs effective user)
       ├── host.id / agent.id (Asset criticality)
       └── destination.ip / file.hash.sha256 (Threat Intel indicators)
       │
       ▼
[3. Temporal & Lineage Pivoting]
       ├── Backward Pivot: Trace ancestry back to interactive session (SSH/bash)
       └── Forward Pivot: Trace all child processes, sockets, and file writes
       │
       ▼
[4. True Positive (TP) vs False Positive (FP) Verification Matrix]
       │
       ▼
[5. Containment & Remediation]
       ├── Isolate endpoint via EDR agent
       ├── Kill target process tree via process.entity_id
       └── Remediate persistence artifacts (/etc/ld.so.preload)
```

---

## 📋 Phase 1: Key Identifier Extraction

Upon receiving an alert (e.g., `Suspicious io_uring Subsystem Initialization` or `Modification of Global Linker Preload File`), immediately extract the following primary identifiers from the SIEM event JSON:

| Field Name (ECS / Elastic) | Alternative Name (CrowdStrike / Splunk) | Operational Value |
| :--- | :--- | :--- |
| `process.entity_id` | `TargetProcessId` / `process_guid` | Unique lifecycle UUID of the process. **Immune to Linux PID recycling**. |
| `process.parent.entity_id`| `ParentProcessId` / `parent_guid` | Ancestor process instance. Identifies root cause and entry vector. |
| `auditd.data.auid` | `login_uid` / `audit_uid` | Immutable login UID from kernel PAM session. Exposes unauthorized privilege escalation. |
| `user.id` / `process.euid` | `effective_uid` / `user_id` | Privilege level at execution time (`0` = root, `1000+` = standard user). |
| `host.id` / `host.name` | `aid` / `ComputerName` | Asset identity. Used to assess blast radius across the enterprise fleet. |
| `destination.ip` / `port` | `RemoteAddress` / `dest_ip` | C2 or exfiltration socket endpoint. |
| `file.hash.sha256` | `SHA256HashData` | File integrity hash for Threat Intelligence cross-referencing. |

---

## 🔍 Phase 2: Process Lineage Reconstruction (Pivoting)

### Step 2.1: Backward Pivot (Root Cause Analysis)
* **Goal**: Determine how the executable arrived and who executed it.
* **Query in SIEM / Discover**:
  ```kql
  host.id: "<HOST_ID>" and process.entity_id: "<PROCESS_PARENT_ENTITY_ID>"
  ```
* **Investigative Questions**:
  1. Was the parent process an interactive shell (`/bin/bash`, `/bin/zsh`)?
  2. If spawned by `sshd`, what was the source IP and session timestamp (`system.auth.ssh.remote_ip`)?
  3. Was it spawned by a compromised web service (e.g., `www-data`, `nginx`, `apache2`)? If yes, suspect a web exploit or webshell.

### Step 2.2: Forward Pivot (Scope of Impact)
* **Goal**: Discover all actions taken by this specific process instance, even if syscalls were masked by `io_uring`.
* **Query in SIEM / Discover**:
  ```kql
  host.id: "<HOST_ID>" and (process.entity_id: "<PROCESS_ENTITY_ID>" or process.parent.entity_id: "<PROCESS_ENTITY_ID>")
  ```
* **Inspect the Timeline (`@timestamp` window: alert time ± 10 minutes)**:
  * **File Writes**: Did the process write to `/etc/ld.so.preload`, `/etc/profile`, or `/tmp/*.so`?
  * **Network Connections**: Did the process establish outbound connections to non-RFC1918 public IP addresses?
  * **Child Processes**: Did it spawn reconnaissance binaries (`whoami`, `id`, `ip route`, `ps aux`)?

### Step 2.3: Privilege Anomaly Analysis (`auid` vs `euid`)
* Compare `auditd.data.auid` against `process.euid`:
  * `auid: 1001 (victim)` + `euid: 1001 (victim)`: Unprivileged attack attempt.
  * `auid: 1001 (victim)` + `euid: 0 (root)`: **High-priority privilege escalation**.
    * Query auth logs: `host.id: "<HOST_ID>" and event.category: "authentication" and user.name: "victim"`
    * Check if `sudo` was executed with `NOPASSWD` or if credential stuffing occurred.

---

## ⚖️ Phase 3: True Positive (TP) vs False Positive (FP) Matrix

Before escalating or containing, benchmark the alert context against this matrix:

| Scenario / Attribute | True Positive (Malicious) | False Positive (Benign) |
| :--- | :--- | :--- |
| **Executable Identity** | Custom binary in `/tmp/`, `/dev/shm/`, user home directory | Standard production server binary (`/usr/bin/qemu-system-x86_64`, `/usr/sbin/mysqld`, `/usr/bin/redis-server`) |
| **`io_uring` Context** | Standalone utility opening `/etc/shadow` or unpinned `/sys/fs/bpf/*` | Database storage engine performing high-throughput block I/O on `/var/lib/mysql/` |
| **`LD_PRELOAD` Context** | Preload pointing to `/tmp/evil.so` or unknown shared object | Performance profiler (Google `perftools`, `valgrind`, APM tracers) running in development |
| **Process Lineage** | Spawned via interactive SSH, cron, or web daemon shell | Spawned by `systemd` with dedicated service unit file |
| **Network Destination** | Raw TCP connection to unknown public IP / non-standard port (`4444`, `1337`) | Connection to internal replica, database cluster, or DNS server |

---

## 🌐 Phase 4: Enterprise Blast Radius & Lateral Movement Check

Once confirmed as True Positive on the initial host:
1. **Search for identical binary hashes enterprise-wide**:
   ```kql
   file.hash.sha256: "<EXTRACTED_SHA256>"
   ```
2. **Search for C2 communication across all network sensors**:
   ```kql
   destination.ip: "<C2_IP>" and not host.id: "<INITIAL_HOST_ID>"
   ```
3. **Audit user account activity**:
   ```kql
   user.name: "<COMPROMISED_USER>" and event.category: "authentication"
   ```

---

## 🛑 Phase 5: Containment & Remediation Actions

When True Positive is confirmed:

1. **Host Isolation**:
   * Trigger EDR **Network Isolation** to sever active C2 connections while maintaining agent-to-SIEM management tunnels.
2. **Process Termination**:
   * Terminate the entire process group associated with `process.entity_id`:
     ```bash
     sudo kill -9 <PID>
     ```
3. **Persistence Removal**:
   * Inspect and clean `/etc/ld.so.preload`:
     ```bash
     sudo rm -f /etc/ld.so.preload
     ```
   * Remove any unauthorized `.so` files found in `/tmp/`, `/dev/shm/`, or `/usr/local/lib/`.
4. **Subsystem Reset**:
   * Re-enable kernel tracing if REAPER Phase 3a was executed:
     ```bash
     echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on
     ```
   * Inspect active eBPF programs and maps:
     ```bash
     sudo bpftool prog show
     sudo bpftool map show
     ```
5. **Post-Incident Analysis**:
   * Preserve `/var/log/audit/audit.log` for forensic timeline preservation.
