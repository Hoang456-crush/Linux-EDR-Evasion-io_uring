# Key Identifiers Reference Dictionary (Cross-Platform Field Mapping)

## Overview
In modern Security Operations Centers (SOC), analysts must navigate heterogeneous log sources, correlating telemetry across native Linux audit daemons, EDR agent sensors, and multi-vendor SIEM data models.

This reference provides a definitive cross-platform field mapping between **Elastic Common Schema (ECS)**, **Linux `auditd`**, **Splunk CIM (Endpoint Data Model)**, and **CrowdStrike Falcon (FDR)**.


---

## 🔄 Windows vs. Linux Event Codes & Elements Comparison

Many SOC analysts transition from Windows incident response (where they frequently query `event.code: "4625" AND winlog.event_data.LogonType: "10"`). 

The table below bridges the gap by showing the direct Linux/Elastic equivalents for each critical evasion technique:

| Threat Behavior | Windows Event Code & Sub-Elements | Linux Equivalent (Elastic / Auditd / Sysmon) |
| :--- | :--- | :--- |
| **Process Execution** | `event.code: "4688"` (Process Creation)<br>`winlog.event_data.CommandLine: "..."`<br>`winlog.event_data.ParentProcessName` | **Sysmon Linux `event.code: "1"`** OR Auditd `syscall: "59"` (`execve`)<br>`process.command_line: "*LD_PRELOAD=*"`<br>`process.parent.executable` |
| **Ring Buffer Subsystem Setup (`io_uring`)** | N/A *(Windows leverages I/O Completion Ports `IOCP`)* | **`event.code: "425"`** *(x86_64 Syscall 425 = `io_uring_setup`)*<br>`auditd.data.a0: "16"` *(Queue depth = 16)*<br>`auditd.result: "success"` |
| **Module / Library Ingestion** | `event.code: "7"` (Sysmon ImageLoaded)<br>`winlog.event_data.ImageLoaded: "*.dll"` | **Sysmon Linux `event.code: "7"`**<br>`file.path: ("/tmp/*.so" OR "*/evil.so")` |
| **Privilege Escalation / Auth Token** | `event.code: "4624"` (LogonType 2 - Interactive)<br>`winlog.event_data.ElevatedToken: "%%1842"` | **`event.code: "USER_CMD"`** *(Auditd Sudo execution)*<br>`auditd.data.cmd: "*evasion_lab*"`<br>`auditd.data.auid: "1001"` AND `user.id: "0"` |
| **Persistence Creation** | `event.code: "11"` (FileCreate)<br>`winlog.event_data.TargetFilename` | **`event.code: "257"`** *(Syscall 257 = `openat` with `O_CREAT`)*<br>`file.path: "/etc/ld.so.preload"`<br>`event.action: ("creation" OR "modification")` |
| **Defense Suppression / Agent Tamper** | `event.code: "7045"` / Service Terminated<br>`winlog.event_data.ServiceName` | **`file.path: "/sys/kernel/debug/tracing/tracing_on"`**<br>`event.category: "process"` AND `signal: "SIGKILL"` |

---

## 🗺️ Cross-Platform Field Mapping Matrix

| Investigative Purpose | Elastic Common Schema (ECS) | Linux `auditd` (Raw Log) | Splunk CIM (Endpoint) | CrowdStrike Falcon (FDR) |
| :--- | :--- | :--- | :--- | :--- |
| **Unique Process UUID** | `process.entity_id` | N/A *(Derivable from `timestamp:id`)* | `process_guid` / `process_id` | `TargetProcessId` |
| **Process OS ID (PID)** | `process.pid` | `pid` | `process_id` | `TargetProcessId` (low 32-bit) |
| **Parent Process UUID** | `process.parent.entity_id` | N/A | `parent_process_guid` | `ParentProcessId` |
| **Parent OS ID (PPID)** | `process.ppid` | `ppid` | `parent_process_id` | `ParentProcessId` (low 32-bit) |
| **Executable Full Path** | `process.executable` | `exe` | `process_path` / `app` | `ImageFileName` |
| **Command Line String** | `process.command_line` | `type=EXECVE` `a0`, `a1` | `process_exec` / `cmdline` | `CommandLine` |
| **Original Login UID** | `auditd.data.auid` | `auid` | `audit_uid` / `user_id` | `OriginalLoginUser` |
| **Effective User (Execution)** | `user.id` / `process.euid` | `euid` | `user_id` / `user` | `UID` / `UserName` |
| **Asset / Host Identifier** | `host.id` / `agent.id` | N/A *(Configured host name)* | `dest` / `dest_host` | `aid` (Agent ID) |
| **Host Hostname** | `host.name` | `node` | `dest_nt_host` / `host` | `ComputerName` |
| **File Target Path** | `file.path` | `name` (in `type=PATH`) | `file_path` / `file_name` | `TargetFileName` |
| **File Hash (SHA256)** | `file.hash.sha256` | N/A *(Requires IMA subsystem)* | `file_hash` | `SHA256HashData` |
| **Destination Network IP** | `destination.ip` | `saddr` (in `type=SOCKADDR`) | `dest_ip` | `RemoteAddress` |
| **Destination Port** | `destination.port` | `saddr` (port decoded) | `dest_port` | `RemotePort` |
| **Syscall Architecture** | `host.architecture` | `arch` (`c000003e` = x86_64) | N/A | `Platform` |
| **Syscall Number** | `event.code` | `syscall` (`425` = `io_uring_setup`) | `event_id` | N/A *(Kernel telemetry)* |

---

## 🔬 Real-World Log Samples & Identification Anatomy

### 1. Linux Auditd Multi-Line Record Anatomy
In raw audit logs (`/var/log/audit/audit.log`), a single system call generates multiple lines linked together by the **Audit Event Identifier**: `msg=audit(<EPOCH_TIMESTAMP>:<SEQUENCE_ID>)`:

```text
type=SYSCALL msg=audit(1700812345.678:9921): arch=c000003e syscall=425 success=yes exit=3 a0=10 a1=0 a2=0 a3=0 items=0 ppid=2451 pid=3140 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 tty=pts0 ses=3 comm="evasion_lab" exe="/tmp/evasion_lab" key="io_uring_monitor"
type=PROCTITLE msg=audit(1700812345.678:9921): proctitle=2E2F65766173696F6E5F6C6162002D2D6D6F64650062656E63686D61726B
```

#### Anatomical Breakdown:
* `msg=audit(1700812345.678:9921)`: The **Audit Event ID (`9921`)**. Every record with this ID belongs to the exact same execution instance.
* `syscall=425`: The system call number. On Linux x86_64 (`arch=c000003e`), `425` corresponds to `sys_io_uring_setup`.
* `auid=1001`: The **Audit UID**. User `1001` (victim) logged in via SSH/console.
* `euid=0`: The **Effective UID**. The process ran with root privileges (indicating `sudo` or SUID abuse).
* `comm="evasion_lab"`: Process command name.
* `exe="/tmp/evasion_lab"`: Path on disk. Notice it executed out of `/tmp`, a primary indicator of anomalous execution.

---

### 2. Elastic Common Schema (ECS) Normalized JSON Event

When normalized by Auditbeat or Elastic Agent, the raw audit line becomes structured JSON:

```json
{
  "@timestamp": "2026-11-24T06:32:25.678Z",
  "event": {
    "action": "executed",
    "category": ["process"],
    "type": ["start"],
    "code": "425"
  },
  "process": {
    "entity_id": "YWdlbnRfaWQ6aG9zdF9uYW1lOjE3MDA4MTIzNDU6MzE0MA==",
    "pid": 3140,
    "ppid": 2451,
    "name": "evasion_lab",
    "executable": "/tmp/evasion_lab",
    "command_line": "./evasion_lab --mode benchmark",
    "parent": {
      "entity_id": "YWdlbnRfaWQ6aG9zdF9uYW1lOjE3MDA4MTIzMDA6MjQ1MQ==",
      "pid": 2451,
      "name": "bash",
      "executable": "/usr/bin/bash"
    }
  },
  "user": {
    "name": "root",
    "id": "0"
  },
  "auditd": {
    "data": {
      "auid": "1001",
      "syscall": "io_uring_setup"
    },
    "result": "success",
    "sequence": 9921
  },
  "host": {
    "id": "ubuntu-lab-target-01",
    "name": "ubuntu-target",
    "ip": ["192.168.10.15"]
  }
}
```

---

## 🎯 Practical Application in Incident Triage

### 1. Correlating PID Recycling
* **Problem**: In Linux, high-volume batch servers churn through 32,768 PIDs quickly. Searching `process.pid: 3140` over a 24-hour window returns multiple unrelated processes (e.g. `cron`, `grep`, `systemd-journal`).
* **Solution**: Always query `process.entity_id` instead of `process.pid`. The entity ID is globally unique across time and space.

### 2. Exposing "Sudo NOPASSWD" Abuse
* When an unprivileged attacker elevates privileges silently via misconfigured sudoers, traditional authentication logs may not fire an alert.
* **Triage Rule**: Any process where `auditd.data.auid != 0` AND `user.id == 0` running non-standard binaries must be treated as **Privilege Escalation** requiring review of `/var/log/auth.log` for sudo execution records.
