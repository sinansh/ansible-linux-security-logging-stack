# Ansible Linux Security Logging Stack

This Ansible project prepares Linux servers to forward security-focused logs (Sysmon for Linux and Auditd) to a remote SIEM using Rsyslog.

## Overview

This repository contains an Ansible project that installs and configures a minimal but highly effective Linux security logging stack. The configuration is optimized to reduce noise by leveraging the strengths of each tool:

* **Sysmon for Linux:** Handles high-volume operational data (Process execution, Network connections, File operations).
* **Auditd:** Focuses on sensitive configuration changes, persistence mechanisms, and system integrity (FIM).
* **Rsyslog:** Forwards combined logs to a remote SIEM over TCP/UDP/RELP.

## Detection Capabilities

Based on the applied configurations, the following events are captured:

### 1. Sysmon for Linux (Operational Visibility)
| Event ID | Name | Description |
| :--- | :--- | :--- |
| **1** | Process Create | Logs every process started (Command line, hashes, parent process). |
| **3** | Network Connect | Logs all outbound/inbound network connections. |
| **5** | Process Terminate | Logs when a process ends. |
| **9** | RawAccessRead | Detects direct read operations on drive volumes (anti-forensics/wipers). |
| **11** | File Create | Logs all file creation events globally. |
| **23** | File Delete | Logs all file deletion events globally. |

### 2. Auditd (Compliance & Integrity)
Specific rules are configured to detect changes in critical system areas. Note that standard process execution (`execve`) logging is **disabled** in Auditd to avoid overlap with Sysmon Event ID 1.

* **Identity & Authentication:**
    * Modifications to `/etc/passwd`, `/etc/shadow`, `/etc/group`.
    * Changes to Sudoers (`/etc/sudoers`, `/etc/sudoers.d`).
    * Execution of `sudo` and `passwd` binaries.
    * PAM configuration changes.
* **System Integrity & Persistence:**
    * **Kernel Modules:** Loading/Unloading (`insmod`, `rmmod`, `modprobe`).
    * **Systemd:** Changes to unit files in `/etc/systemd/system` and `/lib/systemd/system`.
    * **Cron:** Modifications to crontab and cron directories.
    * **Mounts:** Execution of `mount` command and changes to `/etc/fstab`.
* **Network Configuration:**
    * Hostname/Domain name changes.
    * Modifications to `/etc/hosts` and `/etc/NetworkManager`.
* **Package Management:**
    * Execution of `rpm`, `yum`, `dnf`, `dpkg`, `apt`.
    * Writes to package manager logs (`dpkg.log`, `yum.log`).
* **Suspicious Activity:**
    * **Ptrace:** Detection of process injection attempts.
    * **System State:** Usage of `shutdown`, `reboot`, `poweroff`.

## Quick Start

### 1. Configure SIEM Connection
Edit `group_vars/all.yml` to set your remote log destination:

```yaml
siem_host: "192.168.1.50"
siem_port: "514"
siem_protocol: "tcp" # or udp
```
### 2. Run the Playbook

Run the main playbook against your inventory:

Bash

```
ansible-playbook -i inventory/hosts.ini playbooks/site.yml

```

## Test & Verification

Apply the playbook to a test host first, then verify the stack is running and capturing events.

### Service Checks (On Target Host)

Bash

```
# Check Sysmon status (Service name: sysmon)
sudo systemctl status sysmon

# Check Auditd rules are loaded
sudo auditctl -l

# Check Rsyslog status
sudo systemctl status rsyslog

```

### Generate Test Events

Execute the following commands on the target host to trigger specific rules:

Bash

```
# Trigger: Sysmon ProcessCreate (ID 1) & Auditd Package Mgmt
sudo apt-get update 

# Trigger: Auditd Network Config & Sysmon FileCreate (ID 11)
sudo touch /etc/NetworkManager/test_alert

# Trigger: Auditd Persistence (Systemd) & Sysmon FileCreate
sudo bash -c 'echo "[Unit]" > /etc/systemd/system/malicious.service'

# Trigger: Sysmon NetworkConnect (ID 3)
curl -I [https://www.google.com](https://www.google.com)

# Trigger: Auditd Identity Change
sudo touch /etc/sudoers.d/test_privesc

# Trigger: Auditd Ptrace (Injection)
strace ls

```

### Check Local Logs

Verify that logs are being generated locally before checking the SIEM:

Bash

```
# Check recent Sysmon logs (via Journal)
sudo journalctl -u sysmon -n 20 --no-pager

# Check recent Auditd logs (via ausearch)
sudo ausearch -m CONFIG_CHANGE,SYSCALL -ts recent

```

## Production Notes

-   **Sensitive Variables:** Always use Ansible Vault for sensitive data (e.g., SIEM credentials if used).
    
-   **Performance:** Sysmon Event ID 11 (FileCreate) and ID 23 (FileDelete) on `*` (all files) can be noisy on high-traffic file servers or database servers. Tune the `sysmon-config.xml` if necessary.
    
-   **Privileges:** The `rsyslog` service is configured with ACLs to read `/var/log/audit/audit.log` without running as full root (if configured via ACL method).### 2. Run the Playbook

Run the main playbook against your inventory:

Bash

```
ansible-playbook -i inventory/hosts.ini playbooks/site.yml

```

## Test & Verification

Apply the playbook to a test host first, then verify the stack is running and capturing events.

### Service Checks (On Target Host)

Bash

```
# Check Sysmon status (Service name: sysmon)
sudo systemctl status sysmon

# Check Auditd rules are loaded
sudo auditctl -l

# Check Rsyslog status
sudo systemctl status rsyslog

```

### Generate Test Events

Execute the following commands on the target host to trigger specific rules:

Bash

```
# Trigger: Sysmon ProcessCreate (ID 1) & Auditd Package Mgmt
sudo apt-get update 

# Trigger: Auditd Network Config & Sysmon FileCreate (ID 11)
sudo touch /etc/NetworkManager/test_alert

# Trigger: Auditd Persistence (Systemd) & Sysmon FileCreate
sudo bash -c 'echo "[Unit]" > /etc/systemd/system/malicious.service'

# Trigger: Sysmon NetworkConnect (ID 3)
curl -I [https://www.google.com](https://www.google.com)

# Trigger: Auditd Identity Change
sudo touch /etc/sudoers.d/test_privesc

# Trigger: Auditd Ptrace (Injection)
strace ls

```

### Check Local Logs

Verify that logs are being generated locally before checking the SIEM:

Bash

```
# Check recent Sysmon logs (via Journal)
sudo journalctl -u sysmon -n 20 --no-pager

# Check recent Auditd logs (via ausearch)
sudo ausearch -m CONFIG_CHANGE,SYSCALL -ts recent

```

## Production Notes

-   **Sensitive Variables:** Always use Ansible Vault for sensitive data (e.g., SIEM credentials if used).
    
-   **Performance:** Sysmon Event ID 11 (FileCreate) and ID 23 (FileDelete) on `*` (all files) can be noisy on high-traffic file servers or database servers. Tune the `sysmon-config.xml` if necessary.
    
-   **Privileges:** The `rsyslog` service is configured with ACLs to read `/var/log/audit/audit.log` without running as full root (if configured via ACL method).