# Threat Hunting & SOC Triage Queries Library (`event.code` & Elements Reference)

## 🎯 Purpose
In an enterprise SOC, analysts do not rely on static signature matching alone. They actively triage alerts and hunt threats by pivoting on specific **Event Codes (`event.code`)**, **Syscall Numbers**, and **Sub-element Fields** (such as `auditd.data.a0`, `auditd.data.auid`, and `file.path`).

This library provides production-ready query templates formatted in **Elastic KQL**, **Elastic ES|QL**, **Splunk SPL**, and **Sysmon for Linux** for rapid filtering in SIEM search bars.

---

## ⚡ Quick-Filter Cheat Sheet (Kibana Search Bar Ready)

| Triage Goal | Quick Copy-Paste Query (KQL) | Key Element Checked |
| :--- | :--- | :--- |
| **`io_uring_setup` Syscall** | `event.code: "425" AND auditd.data.a0: "16" AND NOT process.executable: ("/usr/bin/qemu-system-x86_64" OR "/usr/sbin/mysqld")` | `event.code: "425"`, `auditd.data.a0: "16"` (Queue depth) |
| **`LD_PRELOAD` Hooking** | `event.code: "1" AND process.command_line: "*LD_PRELOAD=*"` | Sysmon `event.code: "1"`, `process.command_line` |
| **Suspicious `.so` Image Load** | `event.code: "7" AND file.path: ("/tmp/*.so" OR "*/evil.so" OR "*/evasion_hooks.so")` | Sysmon `event.code: "7"` (ImageLoad), `file.path` |
| **Sudo NOPASSWD Abuse** | `event.code: "USER_CMD" AND auditd.data.auid: "1001" AND user.id: "0" AND auditd.data.cmd: "*evasion_lab*"` | `event.code: "USER_CMD"`, `auid: 1001` vs `euid: 0` |
| **Preload Persistence** | `event.category: "file" AND file.path: "/etc/ld.so.preload" AND event.action: ("creation" OR "modification")` | `file.path: "/etc/ld.so.preload"`, `event.action` |
| **REAPER Tracing Disable** | `event.category: "file" AND file.path: "/sys/kernel/debug/tracing/tracing_on" AND event.action: "modification"` | `file.path: ".../tracing_on"`, `event.action` |
| **eBPF Map Tampering** | `event.category: "file" AND file.path: /sys/fs/bpf/* AND event.action: "deleted"` | `file.path: "/sys/fs/bpf/*"`, `event.action: "deleted"` |

---

## 🔎 Detailed Hunting Campaigns

### Campaign 1: Chokepoint Syscall `io_uring_setup` (Event Code 425)

#### Objective
Detect processes initializing the `io_uring` ring buffer with queue depth 16 outside legitimate server binaries.

* **Elastic KQL**:
  ```kql
  event.code: "425" 
  AND auditd.data.a0: "16" 
  AND NOT process.executable: ("/usr/bin/qemu-system-x86_64" OR "/usr/sbin/mysqld" OR "/usr/bin/redis-server") 
  AND host.name: "ubuntu-target"
  ```

* **Elastic ES|QL (Piped Query)**:
  ```esql
  FROM auditbeat-*, logs-endpoint.*
  | WHERE event.code == "425" OR auditd.data.syscall == "io_uring_setup"
  | WHERE auditd.data.a0 == "16"
  | WHERE NOT process.executable IN (
      "/usr/bin/qemu-system-x86_64",
      "/usr/sbin/mysqld",
      "/usr/bin/redis-server",
      "/usr/bin/containerd",
      "/usr/bin/dockerd"
    )
  | STATS count = COUNT() BY host.name, process.name, process.executable, user.name, auditd.data.auid
  | SORT count ASC
  | LIMIT 50
  ```

* **Splunk SPL**:
  ```spl
  index=os_linux (event_id="425" OR syscall="io_uring_setup") a0="16"
  NOT [| inputlookup benign_iouring_binaries.csv | fields app]
  | stats count by host, app, process_exec, user, audit_uid
  | sort + count
  ```

---

### Campaign 2: Sudo Privilege Escalation Correlation (`event.code: "USER_CMD"`)

#### Objective
Uncover silent privilege escalation where a user logged in as an unprivileged user (`auid != 0`) executed commands as `root` (`user.id == 0`).

* **Elastic KQL**:
  ```kql
  event.code: "USER_CMD" 
  AND auditd.data.auid: "1001" 
  AND user.id: "0" 
  AND auditd.data.cmd: "*evasion_lab*"
  ```

* **Elastic ES|QL**:
  ```esql
  FROM auditbeat-*, logs-endpoint.*
  | WHERE event.code == "USER_CMD" OR event.category == "authentication"
  | WHERE auditd.data.auid != "0" AND user.id == "0"
  | WHERE auditd.data.cmd LIKE "*evasion_lab*" OR auditd.data.cmd LIKE "*LD_PRELOAD*"
  | KEEP @timestamp, host.name, auditd.data.cmd, auditd.data.terminal, auditd.data.auid, user.name
  | SORT @timestamp DESC
  ```

* **Splunk SPL**:
  ```spl
  index=os_linux sourcetype=auditd (event_type="USER_CMD" OR syscall="59")
  | eval auid=tonumber(audit_uid), euid=tonumber(user_id)
  | where auid != 0 AND euid == 0
  | search (cmd="*evasion_lab*" OR cmdline="*LD_PRELOAD*")
  | table _time, host, app, cmd, audit_uid, user_id
  ```

---

### Campaign 3: Sysmon for Linux Dynamic Linker Interception (Event Codes 1 & 7)

#### Objective
Track process creation and dynamic library loading when Sysmon for Linux is deployed.

* **Sysmon Event Code 1 (Process Creation with LD_PRELOAD)**:
  ```kql
  event.code: "1" 
  AND process.command_line: "*LD_PRELOAD=*" 
  AND host.name: "ubuntu-target"
  ```

* **Sysmon Event Code 7 (Suspicious Shared Object Image Load)**:
  ```kql
  event.code: "7" 
  AND file.path: ("/tmp/*.so" OR "*/evil.so" OR "*/evasion_hooks.so")
  ```

---

### Campaign 4: Rootkit Persistence & Defense Suppression

#### Objective
Audit direct file tampering against `/etc/ld.so.preload` and kernel tracing interfaces.

* **Rootkit Preload Creation**:
  ```kql
  event.category: "file" 
  AND file.path: "/etc/ld.so.preload" 
  AND event.action: ("creation" OR "modification")
  ```

* **Kernel Tracing Disabled (REAPER Phase 3a)**:
  ```kql
  event.category: "file" 
  AND file.path: ("/sys/kernel/debug/tracing/tracing_on" OR "/sys/kernel/tracing/tracing_on") 
  AND event.action: "modification"
  ```

* **eBPF Sensor Maps Destroyed (REAPER Phase 3b)**:
  ```kql
  event.category: "file" 
  AND file.path: /sys/fs/bpf/* 
  AND event.action: "deleted"
  ```

---

### Campaign 5: Direct Host Investigation via Linux `ausearch`

When performing live host triage on the compromised Linux endpoint:

```bash
# 1. Search for io_uring_setup syscall invocations (425)
sudo ausearch -sc 425 -i

# 2. Search for all sudo commands executed by victim user (auid 1001)
sudo ausearch -m USER_CMD -ui 1001 -i

# 3. Search for file access to /etc/ld.so.preload
sudo ausearch -f /etc/ld.so.preload -i

# 4. Search for modifications to kernel tracing
sudo ausearch -f /sys/kernel/debug/tracing/tracing_on -i
```
