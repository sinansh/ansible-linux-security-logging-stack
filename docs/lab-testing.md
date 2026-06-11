# Lab Testing on VMware Workstation

Uçtan uca test: playbook'u Ubuntu ve CentOS 8 hedeflerine uygula, logların gerçekten
bir "SIEM"e ulaştığını doğrula. SIEM yerine basit bir **collector** VM (rsyslog TCP
dinleyici) kullanıyoruz — gelen her satırı bir dosyaya yazar, böylece teslimi gözle görürüz.

---

## 1. Topoloji

| Rol | OS | Örnek IP | Not |
| :-- | :-- | :-- | :-- |
| Control node | WSL (Ubuntu) **veya** küçük Linux VM | — | Ansible buradan çalışır |
| Target A | Ubuntu 22.04 | 192.168.42.131 | hedef |
| Target B | CentOS 8 / Rocky 8 / Alma 8 | 192.168.42.141 | hedef (systemd 239 + SELinux) |
| Collector | Ubuntu 22.04 (SIEM yerine) | 192.168.42.129 | TCP/514 dinler |

> **Neden CentOS 8 yerine Rocky/Alma 8 olabilir?** CentOS 8 EOL'dür; varsayılan repoları
> kapandı (`dnf` çalışmaz, bkz. §6). Rocky 8 / Alma 8 **aynı systemd 239 + SELinux**
> davranışını verir, yani CentOS 8'i sadık biçimde temsil eder. Gerçekten CentOS 8 test
> edecekseniz önce vault repolarına geçin (§6).

VMware ağı: hepsi aynı **Host-only** veya **NAT** ağında, birbirini görebilsin. (192.168.42.0/24 örnek.)

---

## 2. Control node hazırlığı

Windows'ta Ansible doğrudan çalışmaz. WSL (öneri) veya bir Linux VM kullanın:

```bash
# WSL / Linux control node
sudo apt update && sudo apt install -y ansible git        # veya pipx install ansible
ansible --version

# Bu repoyu klonla, içine gir
git clone <repo-url> ansible-linux-security-logging-stack
cd ansible-linux-security-logging-stack

# Rollerin ihtiyaç duyduğu koleksiyonlar (acl, seboolean, ini_file)
ansible-galaxy collection install -r requirements.yml
```

SSH anahtarını hedeflere dağıtın (parolasız sudo varsa en kolayı):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/lab -N ""
ssh-copy-id -i ~/.ssh/lab.pub op@192.168.42.131
ssh-copy-id -i ~/.ssh/lab.pub op@192.168.42.141
```

---

## 3. Collector VM (SIEM yerine) — gelen logları dosyaya yaz

Collector üzerinde (192.168.42.129) TCP/514 dinleyip gelenleri ayrı bir dosyaya yazıyoruz:

```bash
sudo tee /etc/rsyslog.d/10-collector.conf >/dev/null <<'EOF'
module(load="imtcp")
input(type="imtcp" port="514")

template(name="IncomingFmt" type="string"
         string="%timegenerated% from=%fromhost-ip% tag=%syslogtag% %msg%\n")

# Uzaktan gelen (loopback olmayan) her şeyi tek dosyaya yaz ve durdur.
if ($fromhost-ip != "127.0.0.1") then {
    action(type="omfile" file="/var/log/siem-incoming.log" template="IncomingFmt")
    stop
}
EOF

sudo systemctl restart rsyslog

# Ubuntu collector ise UFW'de portu aç (kapalıysa)
sudo ufw allow 514/tcp 2>/dev/null || true

# Canlı izle:
sudo tail -f /var/log/siem-incoming.log
```

> UDP test edecekseniz `imtcp`→`imudp`, `omfile` aynı; ve `siem_protocol: "udp"` yapın.
> **Lab için TCP önerilir:** bağlantı kurulup kurulmadığını `ss`/`tcpdump` ile net görürsünüz.

---

## 4. Repoyu yapılandır

`inventory/hosts.ini`:

```ini
[ubuntu_servers]
ubuntu1 ansible_host=192.168.42.131 ansible_user=op

[centos_servers]
centos1 ansible_host=192.168.42.141 ansible_user=op

[linux_servers:children]
ubuntu_servers
centos_servers

[linux_servers:vars]
ansible_become=true
ansible_become_method=sudo
ansible_ssh_private_key_file=~/.ssh/lab
```

`inventory/group_vars/all.yml` — SIEM'i collector'a yönlendir:

```yaml
siem_host: "192.168.42.129"
siem_port: 514
siem_protocol: "tcp"
```

Bağlantıyı doğrula:

```bash
ansible -i inventory/hosts.ini linux_servers -m ping
```

---

## 5. Çalıştır

```bash
# Önce ne yapacağını gör (opsiyonel)
ansible-playbook -i inventory/hosts.ini playbooks/site.yml --check --diff

# Uygula  (parolalı sudo ise -K ekleyin)
ansible-playbook -i inventory/hosts.ini playbooks/site.yml
```

İlk önce tek bir hedefe sınırlamak isterseniz: `--limit ubuntu1`.

---

## 6. CentOS 8'e özel: EOL repo düzeltmesi (gerçek CentOS 8 ise)

CentOS 8 mirror'ları kapandı; paket kurulumları (auditd, rsyslog, sysmon, checkpolicy)
**başarısız olur**. Playbook'tan ÖNCE hedefte vault'a geçin:

```bash
sudo sed -i 's/mirrorlist/#mirrorlist/g; s|#\?baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' \
  /etc/yum.repos.d/CentOS-*.repo
sudo dnf clean all && sudo dnf -y makecache
```

(Rocky 8 / Alma 8 kullanıyorsanız bu adım gerekmez.)

---

## 7. Katman katman doğrulama

Aşağıyı **her iki hedefte** sırayla çalıştırın. Sorun hangi katmanda kesiliyorsa orada durur.

### Katman 1 — Olaylar yerelde üretiliyor mu?
```bash
# Test olayları üret
sudo touch /etc/sudoers.d/test_privesc
curl -I https://www.google.com
sudo bash -c 'echo "[Unit]" > /etc/systemd/system/zz-test.service'

# Sysmon olayları syslog'a (tag=sysmon) yazıyor mu? (EN KRİTİK — XML <Event> görmelisiniz)
sudo journalctl -t sysmon -n 5 --no-pager
sudo systemctl is-active sysmon            # active (running) olmalı

# Auditd yazıyor mu?
sudo ausearch -m CONFIG_CHANGE,SYSCALL -ts recent | tail -n 20
sudo tail -n 5 /var/log/audit/audit.log
```

### Katman 2 — rsyslog audit.log'u OKUYABİLİYOR mu?
```bash
# Ubuntu: syslog kullanıcısı audit.log'u okuyabiliyor mu? (log_group=syslog sayesinde RC=0)
sudo -u syslog head -c1 /var/log/audit/audit.log >/dev/null; echo "audit read RC=$?"
stat -c '%a %U:%G' /var/log/audit/audit.log    # 640 root:syslog beklenir (Debian)

# CentOS: SELinux denial var mı? (boş çıkmalı)
sudo ausearch -m AVC -ts recent 2>/dev/null | grep -i rsyslog

# rsyslog config sağlam mı?
sudo rsyslogd -N1
sudo systemctl status rsyslog --no-pager
```

### Katman 3 — Paketler SIEM'e çıkıyor mu?
```bash
# Forwarding bağlantısı kurulu mu? (tcp'de ESTAB beklenir)
sudo ss -tanp | grep ':514'
# Paketler gerçekten gidiyor mu?
sudo timeout 5 tcpdump -ni any host 192.168.42.129 and port 514
```

### Katman 4 — Collector alıyor mu?
Collector'da:
```bash
sudo tail -f /var/log/siem-incoming.log
# 'tag=sysmon' ve 'tag=auditd' satırlarını görmelisiniz.
```

---

## 8. Sorun giderme hızlı tablo

| Belirti | Olası neden | Bakılacak |
| :-- | :-- | :-- |
| Collector'a hiç satır gelmiyor ama 140→141 ESTAB | collector çıktı dosyası rsyslog (syslog) tarafından yazılamıyor | `journalctl -u rsyslog` → `omfile suspended`; `chown syslog:adm /var/log/siem-incoming.log` |
| `tag=sysmon` gelmiyor (auditd geliyor) | sysmon servisi yok / programname eşleşmiyor | `systemctl is-active sysmon`; `journalctl -t sysmon -n5`; kuralda `$programname == "sysmon"` |
| `tag=auditd` gelmiyor (sysmon geliyor) | rsyslog audit.log'u okuyamıyor | Ubuntu: `stat -c %U:%G /var/log/audit/audit.log` → `root:syslog`; CentOS: SELinux AVC |
| CentOS'ta audit logu gelmiyor | SELinux `syslogd_t`→`auditd_log_t` reddi | `ausearch -m AVC -ts recent`; `semodule -l \| grep rsyslog_read_audit` |
| Hiç paket çıkmıyor (CentOS) | SELinux outbound boolean | `getsebool syslogd_can_network_connect` → `on` olmalı |
| `ss` boş, tcpdump boş | yanlış `siem_host`, firewall, collector dinlemiyor | collector'da `ss -tanp \| grep 514`; arada firewall |
| `sysmon -i` config'i reddediyor | şema sürümü uyumsuz | `sysmon -? `; gerekiyorsa `sysmon-config.xml.j2` schemaversion'ı düşürün |

---

## 9. Temiz başlangıç (yeniden test)

Bir hedefi sıfırlamak için (snapshot yoksa):
```bash
sudo systemctl stop rsyslog
sudo /usr/bin/sysmon -u force 2>/dev/null || true     # sysmon servis+config kaldır
sudo rm -f /etc/rsyslog.d/30-siem.conf /etc/rsyslog.d/99-siem.conf
sudo systemctl daemon-reload
# CentOS: yüklenen SELinux modülünü kaldır
sudo semodule -r rsyslog_read_audit 2>/dev/null || true
```
**Öneri:** her hedefin temiz halinde bir VMware **snapshot** alın; her test turundan sonra
snapshot'a dönmek en hızlı yöntemdir.
