# ansible-linux-security-logging-stack

This Ansible project prepares Linux servers to forward security-focused logs (Sysmon for Linux and auditd) to a remote SIEM.

Overview
- This repository contains an Ansible project that installs and configures a minimal Linux security logging stack: Sysmon for Linux (where available), `auditd` with focused rules, and `rsyslog` forwarding to a remote SIEM.

Quick start
- Configure SIEM connection in `group_vars/all.yml` (set `siem_host`, `siem_port`, `siem_protocol`).

Run (example)
```powershell
ansible-playbook -i inventory/hosts.ini playbooks/site.yml
```

Test & Verification
- Apply to a test host group first, then verify `auditd` rules and `rsyslog` behaviour. See commands below.

Auditd checks (on target host):
```bash
sudo cat {{ audit_rules_path }}
sudo augenrules || true
sudo systemctl restart auditd
sudo auditctl -l
```

Rsyslog checks (on target host):
```bash
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo journalctl -u rsyslog -n 200 --no-pager
```

Example events (generate on target host):
```bash
ssh nonexist@localhost    # failed SSH login (simulate)
sudo apt-get update && sudo apt-get install -y sl || true
sudo bash -c 'echo -e "[Unit]\nDescription=Fake" > /etc/systemd/system/fake-test.service'
sudo systemctl daemon-reload
sudo ausearch -k pkg_management -i
sudo ausearch -m USER_LOGIN -sv no --raw
```

Notes
- For production, store sensitive variables in Ansible Vault and validate package sources and checksums before pinning releases.
