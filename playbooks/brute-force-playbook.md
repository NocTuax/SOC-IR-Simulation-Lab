# 🔐 Playbook: SSH Brute Force Attack

**Playbook ID:** PB-001  
**Version:** 1.0  
**Author:** Muhamad Yusril Malakaini  
**Framework:** NIST SP 800-61  
**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)  
**Severity:** HIGH  
**SLA Response Time:** 30 menit

---

## 📋 Overview

SSH Brute Force adalah serangan yang mencoba ribuan kombinasi username/password secara otomatis untuk mendapatkan akses ke sistem via SSH (Port 22).

```
Attack Flow:
Attacker → Hydra/tools → Target SSH Port 22
               ↓
        Coba ribuan password
               ↓
        Berhasil login → Unauthorized Access!
               ↓
        Wazuh detect (Rule 5710)
               ↓
        Active Response → Auto-block IP!
```

---

## 🚨 Detection Indicators

### Alert yang Muncul di Wazuh:
| Rule ID | Description | Level |
|---|---|---|
| 5710 | sshd: brute force (multiple auth failures) | 10 |
| 5503 | PAM: User login failed | 3 |
| 5715 | sshd: authentication success | 3 |

### IOC Yang Harus Dicari:
```
- Ratusan login failed dalam waktu singkat
- Dari 1 IP yang sama
- Ke port 22 (SSH)
- Berbagai username dicoba
- Diikuti login success = CRITICAL!
```

### KQL Query untuk Deteksi:
```kql
# Cari semua brute force alerts
rule.id: 5710

# Cari dari IP attacker spesifik
agent.ip: "192.168.1.17" AND rule.id: 5503

# Cari login success setelah brute force
rule.id: 5715 AND @timestamp >= "now-1h"

# Cari semua SSH events level tinggi
rule.groups: "sshd" AND rule.level: >= 10
```

---

## 📊 NIST IR Flow

### PHASE 1 — PREPARATION ✅
```
Checklist sebelum insiden:
□ Wazuh SIEM sudah aktif
□ Rule 5710 sudah dikonfigurasi
□ Active Response sudah aktif
□ Alert notification sudah disetup
□ Playbook ini sudah dibaca & dipahami
```

---

### PHASE 2 — IDENTIFICATION 🔍
```
Langkah deteksi & konfirmasi:

1. Cek alert di Wazuh Dashboard
   □ Rule 5710 muncul?
   □ Berapa banyak attempts?
   □ Dari IP berapa?
   □ Jam berapa terjadi?

2. Konfirmasi True/False Positive
   □ Apakah IP dari internal/eksternal?
   □ Apakah user yang dicoba valid?
   □ Apakah ada login success setelahnya?
   □ Apakah ini aktivitas legitimate admin?

3. Tentukan Severity
   □ CRITICAL = Brute force + login success!
   □ HIGH     = Brute force banyak, belum berhasil
   □ MEDIUM   = Brute force sedikit
```

---

### PHASE 3 — CONTAINMENT 🛡️

**Short Term (Lakukan SEGERA):**
```
□ Blokir IP attacker di firewall
  Command: iptables -A INPUT -s [IP] -j DROP

□ Cek apakah Active Response sudah blokir
  Lihat: /var/ossec/logs/active-responses.log

□ Disable akun yang dikompromikan (jika ada)
  Command: passwd -l [username]

□ Eskalasi ke L2/L3 jika login berhasil!
```

**Long Term (Setelah situasi terkendali):**
```
□ Implementasi fail2ban
□ Ubah SSH port dari 22 ke port lain
□ Implementasi SSH key authentication
□ Disable password authentication di SSH
□ Whitelist IP yang boleh akses SSH
```

---

### PHASE 4 — ERADICATION 🗑️
```
□ Hapus SSH session yang aktif dari attacker
  Command: who | grep [IP attacker]
           pkill -9 -u [username]

□ Cek apakah attacker sempat install sesuatu
  Command: ls -la /tmp/
           find / -newer /tmp -type f 2>/dev/null

□ Cek crontab untuk persistence
  Command: crontab -l
           cat /etc/crontab

□ Cek user baru yang mungkin dibuat attacker
  Command: cat /etc/passwd | tail -10
           lastlog
```

---

### PHASE 5 — RECOVERY 🔄
```
□ Restore akun yang di-disable (kalau legitimate)
□ Update password semua akun yang dicoba
□ Enable kembali service yang di-disable
□ Monitor ketat 24 jam setelah recovery
□ Verifikasi sistem berjalan normal
```

---

### PHASE 6 — LESSONS LEARNED 📝
```
Pertanyaan yang harus dijawab:
□ Bagaimana attacker tahu port SSH terbuka?
□ Apakah password policy sudah kuat?
□ Berapa lama waktu deteksi?
□ Apakah Active Response berjalan otomatis?
□ Apa yang perlu diperbaiki?

Rekomendasi:
□ Implementasi MFA untuk SSH
□ Strengthen password policy
□ Regular review SSH access logs
□ Update detection rules jika perlu
```

---

## 📋 Escalation Matrix

| Kondisi | Eskalasi ke | Waktu |
|---|---|---|
| Brute force terdeteksi | SOC L2 | 15 menit |
| Login berhasil setelah brute force | SOC L2/L3 + Management | SEGERA |
| Data exfiltration terdeteksi | SOC L2/L3 + Management + Legal | SEGERA |

---

## 🔗 Related Playbooks

- PB-002: Malware Infection
- PB-003: Data Exfiltration
- PB-004: Web Attack

---

## 📚 References

- NIST SP 800-61 Rev 2
- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- Wazuh Rules: https://documentation.wazuh.com/current/user-manual/ruleset/
