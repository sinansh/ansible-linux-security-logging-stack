# Ansible Linux Security Logging Stack

This Ansible project prepares Linux servers to forward security-focused logs (Sysmon for Linux and Auditd) to a remote SIEM using Rsyslog.

## Overview

This repository installs and configures a minimal but effective Linux security logging stack, tuned to reduce noise by leveraging the strengths of each tool:

* **Sysmon for Linux:** High-volume operational data (process execution, network connections, file operations). Sysmon emits events to the local **syslog** (program name `sysmon`, provider `Linux-Sysmon`).
* **Auditd:** Sensitive configuration changes, persistence mechanisms, and system integrity (FIM). Written to `/var/log/audit/audit.log`.
* **Rsyslog:** Forwards both sources to a remote SIEM over TCP/UDP — Sysmon by program name, Auditd by reading its log file with `imfile`.

## Architecture / How logs reach the SIEM

```
Sysmon ──syslog(tag=sysmon)───────────────┐
Auditd ──/var/log/audit/audit.log──(imfile)┤
Bash command history ──logger(local6)──────┼─▶ rsyslog (30-siem.conf) ──omfwd──▶ SIEM
auth/authpriv/kern facilities ─────────────┘                                    (siem_host:siem_port)
```

Four telemetry streams reach the SIEM:
1. **Sysmon** — process/network/file events (`$programname == "sysmon"`).
2. **Auditd** — `audit.log` read via `imfile` (tag `auditd`).
3. **Bash command history** — every interactive command via `logger -p local6` (tag `Bash_History`),
   deployed by the `command_logging` role. ⚠️ This forwards full command lines (including secrets typed
   on the CLI) to the SIEM — a SOC requirement; confirm it fits your privacy/compliance posture.
4. **Standard security facilities** — `auth`, `authpriv`, `kern` (+ `local1`/`local6`) forwarded and
   still kept locally. Tune via `siem_forward_facilities` (empty list disables).

Important facts (verified in a lab):

* **Sysmon for Linux does NOT write events to a file or stdout.** `sysmon -i` installs its own systemd unit
  (`/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service`) and the collector sends events to **syslog** with
  program name `sysmon`. The role therefore does **not** deploy a custom unit or a log file — it just lets
  `sysmon -i` manage the service, and rsyslog forwards messages where `$programname == "sysmon"`.
* **Auditd readability:** rsyslog must read `audit.log`.
  * **Ubuntu/Debian:** rsyslog runs as the `syslog` user. We set auditd's own `log_group = syslog` so `audit.log`
    becomes `root:syslog 0640` and stays readable **across rotation** (ACLs are not used — auditd re-`chmod`s the
    file on rotation and would wipe an ACL mask).
  * **RHEL/CentOS 8:** rsyslog runs as **root** (no `syslog` user). DAC is fine, but SELinux blocks the read, so the
    role installs a tiny custom SELinux module letting `syslogd_t` read `auditd_log_t`. Outbound forwarding to the
    **standard syslog port 514** (`syslog_port_t`) is already permitted by the base policy, so no boolean is needed;
    the legacy `syslogd_can_network_connect` boolean was **removed in RHEL/CentOS 8**, so the role only flips it when
    it still exists (RHEL 7). For a **non-standard** `siem_port` under SELinux enforcing, label it first:
    `semanage port -a -t syslog_port_t -p tcp <port>`.
* No `StandardOutput=append:` is used, so there is **no systemd-239 problem** on CentOS 8.

## Detection Capabilities

### 1. Sysmon for Linux (Operational Visibility)
| Event ID | Name | Description |
| :--- | :--- | :--- |
| **1** | Process Create | Logs process starts. Excludes noisy system processes (cron, monit, splunkd, nginx, dbus, journald). |
| **3** | Network Connect | Logs network connections. Excludes loopback and configurable internal/monitoring destinations. |
| **5** | Process Terminate | Disabled (low value, catch-all exclude). |
| **9** | RawAccessRead | Disabled (high noise on Linux). |
| **11** | File Create | Critical paths only (`/etc`, `/boot`, `/usr/(local/)bin`, `/usr/sbin`, `/var/www`). |
| **23** | File Delete | Critical paths only (`/etc`, `/boot`, `/var/www`, `/var/log`). |

### 2. Auditd (Compliance & Integrity)
Standard process-execution (`execve`) logging is **disabled** in Auditd to avoid overlap with Sysmon Event ID 1.

The rule set (`roles/auditd/templates/audit.rules.j2`) is a **superset aligned to the SOC's required
keys** (e.g. `sudo_conf`, `etcpasswd`, `susp_activity`, `tmp_exec`, `sshd`, `sysctl_conf`, `cron_conf`)
plus this project's extra hardening (audit self-monitoring, kernel modules, `ptrace`, mounts, login
records, package logs). Keys are kept identical to the SOC script so their SIEM detections match.

* **Identity & Auth:** `/etc/passwd`, `/etc/shadow`, `/etc/group`, sudoers, `sudo`/`passwd` execution, PAM.
* **Integrity & Persistence:** kernel modules (insmod/rmmod/modprobe/kmod), systemd unit files, cron, mounts/fstab.
* **Network config:** hostname/domain changes, `/etc/hosts`, `/etc/NetworkManager`.
* **Package management:** writes to `dpkg.log`, `apt/history.log`, `yum.log`.
* **Suspicious activity:** `ptrace` (injection), `shutdown`/`reboot`/`poweroff`.

## Quick Start

### 1. Configure the SIEM connection
Edit **`inventory/group_vars/all.yml`** (this is the file Ansible auto-loads — *not* a top-level `group_vars/`):

```yaml
siem_host: "192.168.1.50"
siem_port: 514
siem_protocol: "tcp"   # or udp
```

### 2. Add your hosts
Edit `inventory/hosts.ini` and put hosts under `[ubuntu_servers]` / `[centos_servers]`.

### 3. Run the playbook

```bash
ansible-playbook -i inventory/hosts.ini playbooks/site.yml
# parolalı sudo ise:
ansible-playbook -i inventory/hosts.ini playbooks/site.yml -K
```

> **Control node:** Ansible does not run natively on Windows. Use WSL or a small Linux VM as the control node.
> See [docs/lab-testing.md](docs/lab-testing.md) for a full VMware Workstation walkthrough (this is exactly how the
> stack was validated end-to-end).

## Test & Verification

### Service checks (on a target host)
```bash
sudo systemctl status sysmon       # active (running)  /opt/sysmon/sysmon ... -service
sudo auditctl -l
sudo systemctl status rsyslog
```

### Confirm logs are produced locally (do this BEFORE blaming the SIEM)
```bash
# Sysmon events arrive in the journal/syslog tagged 'sysmon' (XML <Event>...Linux-Sysmon...)
sudo journalctl -t sysmon -n 5 --no-pager
# Auditd events
sudo ausearch -m CONFIG_CHANGE,SYSCALL -ts recent | tail
# Can rsyslog (syslog user) read audit.log? (Ubuntu)
sudo -u syslog head -c1 /var/log/audit/audit.log && echo OK
```

### Generate test events
```bash
sudo apt-get update || sudo dnf -y makecache          # ProcessCreate (ID 1) + pkg activity
sudo touch /etc/NetworkManager/test_alert             # Auditd network + Sysmon FileCreate (ID 11)
sudo bash -c 'echo "[Unit]" > /etc/systemd/system/malicious.service'  # Auditd persistence + FileCreate
curl -I https://www.google.com                        # Sysmon NetworkConnect (ID 3)
sudo touch /etc/sudoers.d/test_privesc                # Auditd identity change
strace ls                                             # Auditd ptrace (injection)
```

### Confirm delivery to the SIEM
```bash
sudo ss -tanp | grep ':514'                                   # forwarding connection ESTAB?
sudo timeout 5 tcpdump -ni any host <siem_host> and port <siem_port>
```
On the SIEM/collector you should see messages tagged `auditd` and `sysmon`.

## Production Notes

* **Sensitive variables:** use Ansible Vault for any credentials. Do **not** keep SSH/become passwords in the
  inventory the way the lab does.
* **Performance:** Sysmon FileCreate (ID 11) / FileDelete (ID 23) can be noisy on busy file/DB servers — tune
  `roles/sysmon_linux/templates/sysmon-config.xml.j2`.
* **SELinux/AppArmor:** the roles handle the common CentOS 8 SELinux cases; if you run enforcing with extra
  confinement, check `ausearch -m AVC -ts recent`.
* **RHEL/CentOS 8 (Rocky 8) — validated end-to-end** with SELinux enforcing: Sysmon + Auditd both reach the SIEM,
  `0` AVC denials, idempotent (`changed=0` on re-run). Two role behaviors worth knowing: (a) audit rules are loaded
  by an explicit self-healing task (`augenrules --load` fires when `auditctl -l` is empty or the rules file changed —
  `augenrules --check` returns rc 0 even on drift, so it can't be trusted); (b) the custom SELinux audit-read module
  is re-installed whenever `semodule -l` doesn't list it, not only when the `.te` source changes.
* **`syslog` group ordering:** on Debian, auditd's `log_group=syslog` needs the `syslog` group to exist (created by
  the rsyslog package, which is present by default on Ubuntu/Debian).
* **Ubuntu 24.04 / 26.04 with older ansible-core (≤2.14):** verified working end-to-end. Two environment caveats are
  documented in [docs/lab-testing.md](docs/lab-testing.md): the Microsoft-repo download uses the target's `wget`
  (ansible's `get_url` breaks on Python 3.12+ with old ansible-core), and Ubuntu 26.04 ships `sudo-rs` which breaks
  password `become` (use NOPASSWD, classic sudo, or a newer ansible-core).
