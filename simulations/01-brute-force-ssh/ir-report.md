# 📋 Incident Response Report
## Skenario 1: SSH Brute Force Attack

**Report ID:** INC-001  
**Analyst:** Muhamad Yusril Malakaini  
**Date:** 26 Mei 2026  
**Severity:** HIGH  
**Status:** RESOLVED ✅  
**Framework:** NIST SP 800-61  

---

## 1. Executive Summary

Pada tanggal 25 Mei 2026 pukul 18:42 UTC, sistem SIEM Wazuh mendeteksi serangan **SSH Brute Force** dari IP **192.168.1.29** (Kali Linux) terhadap server **JH Target Server (192.168.1.17)**. Attacker mencoba berbagai kombinasi password untuk akun root via SSH (Port 22). Serangan berhasil dideteksi oleh Wazuh dan Active Response otomatis memblokir IP attacker menggunakan iptables firewall-drop dalam hitungan detik.

**Hasil:** Serangan berhasil dideteksi dan dimitigasi secara otomatis. Tidak ada unauthorized access yang berhasil.

---

## 2. Timeline of Events

| Timestamp | Event | Rule ID | Level |
|---|---|---|---|
| 18:42:29 UTC | Login failed pertama dari 192.168.1.29 | 5503 | 5 |
| 18:42:30 UTC | PAM authentication failure | 5503 | 5 |
| 18:42:33 UTC | SSH Brute Force detected! | 5763 | 10 |
| 18:42:37 UTC | Multiple auth failures (>3x) | 2502 | 10 |
| 19:04:34 UTC | Host Blocked by firewall-drop! | 651 | 3 |
| 19:04:34 UTC | iptables DROP rule diterapkan | - | - |

---

## 3. Attack Details

### 3.1 Attack Vector
```
Type        : SSH Brute Force
Tool        : Hydra
Source IP   : 192.168.1.29 (Kali Linux - Attacker)
Target IP   : 192.168.1.17 (JH Target Server)
Target Port : 22 (SSH)
Username    : root
Method      : Dictionary attack (wordlist)
Threads     : 4 parallel connections
```

### 3.2 Attack Flow
```
192.168.1.29 (Attacker)
        ↓
Hydra brute force SSH Port 22
        ↓
Multiple failed login attempts
[password, 123456, admin, root, 
 toor, kali, password123, abc123,
 letmein, welcome]
        ↓
Wazuh Agent detect via /var/log/auth.log
        ↓
Rule 5763 trigger (level 10)
        ↓
Active Response: firewall-drop
        ↓
iptables DROP 192.168.1.29
        ↓
IP Attacker TERBLOKIR! 🚨
```

### 3.3 MITRE ATT&CK Mapping
| Tactic | Technique | ID | Description |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | SSH password brute force |
| Credential Access | Password Guessing | T1110.001 | Dictionary attack |
| Lateral Movement | Remote Services | T1021.004 | SSH |

---

## 4. Detection Analysis

### 4.1 Alert Rules Triggered
| Rule ID | Description | Level | Count |
|---|---|---|---|
| 5503 | PAM: User login failed | 5 | 4 |
| 5760 | sshd: authentication failed | 5 | 8+ |
| 5763 | sshd: brute force detected | 10 | 1 |
| 2502 | User missed password >1 time | 10 | 2 |
| 651 | Host blocked by firewall-drop | 3 | 1 |

### 4.2 KQL Query Used
```kql
# Deteksi semua brute force alerts
rule.id: 5763

# Filter by MITRE technique
rule.mitre.technique: "Brute Force"

# Cari semua SSH events dari attacker
data.srcip: "192.168.1.29" AND rule.groups: "sshd"

# Cari active response trigger
rule.id: 651
```

### 4.3 Log Evidence
```
May 25 18:42:29 jh-server sshd[8395]: 
pam_unix(sshd:auth): authentication failure; 
logname= uid=0 euid=0 tty=ssh ruser= 
rhost=192.168.1.29 user=root

May 25 18:42:33 jh-server sshd[8395]: 
Failed password for root from 192.168.1.29 
port 47770 ssh2

May 25 19:04:32 jh-server sshd[18146]: 
Failed password for root from 192.168.1.29 
port 59118 ssh2
```

---

## 5. IOC Report

```
=== IOC REPORT ===
Case ID  : INC-001
Analyst  : Yusril
Date     : 26 Mei 2026
Severity : HIGH

🌐 NETWORK IOC
IP Attacker    : 192.168.1.29
IP Victim      : 192.168.1.17
Port Targeted  : 22 (SSH)
Protocol       : TCP

👤 ACCOUNT IOC
Username Target : root
Login Attempts  : 10+ attempts
Status          : Semua GAGAL ✅

🖥️ SYSTEM IOC
Log Source      : /var/log/auth.log
Agent           : JH (ID: 001)
Decoder         : sshd

⏰ BEHAVIORAL IOC
Start Time      : 18:42:29 UTC
End Time        : 19:04:34 UTC
Duration        : ~22 menit
Pattern         : Multiple rapid login failures
                  dari 1 IP yang sama
Ports Used      : 47770, 47778, 47782, 47794,
                  59110, 59118, 59120, 59122

🎯 MITRE ATT&CK
Technique       : T1110 (Brute Force)
Sub-technique   : T1110.001 (Password Guessing)
Tactic          : Credential Access
```

---

## 6. Response Actions

### 6.1 Automated Response (Active Response)
```
✅ Wazuh Active Response triggered otomatis
✅ Command: firewall-drop
✅ iptables rule diterapkan:
   Chain INPUT: DROP all from 192.168.1.29
✅ Timeout: 60 detik
✅ Hasil: IP 192.168.1.29 TERBLOKIR TOTAL
   Ping test: 100% packet loss ✅
```

### 6.2 Manual Response (SOC L1 Actions)
```
✅ Alert dikonfirmasi sebagai True Positive
✅ Timeline disusun
✅ IOC didokumentasikan
✅ Evidence di-capture (screenshots)
✅ IR Report dibuat
✅ Escalation ke L2 (simulasi)
```

---

## 7. Impact Assessment

```
Dampak Aktual    : MINIMAL
Data Breach      : TIDAK ADA
Unauthorized Access: TIDAK ADA
Service Disruption: TIDAK ADA

Kenapa minimal?
└── Semua login attempts GAGAL
└── Active Response blokir attacker
    sebelum berhasil masuk
└── Tidak ada lateral movement
└── Tidak ada persistence mechanism
```

---

## 8. Root Cause Analysis

```
Penyebab serangan bisa terjadi:
1. SSH Port 22 terbuka ke semua IP
2. Password authentication masih enabled
3. Tidak ada rate limiting awal
4. Akun root SSH login masih dibolehkan

Kenapa berhasil dideteksi:
1. Wazuh rule 5763 aktif ✅
2. Active Response dikonfigurasi ✅
3. Log monitoring aktif ✅
```

---

## 9. Recommendations

### Immediate Actions:
```
□ Ganti SSH default port (22 → port lain)
□ Disable SSH root login
  /etc/ssh/sshd_config: PermitRootLogin no
□ Implementasi SSH key authentication
□ Disable password authentication
□ Whitelist IP yang boleh akses SSH
```

### Long Term:
```
□ Implementasi MFA untuk SSH
□ Regular review SSH access logs
□ Implementasi fail2ban sebagai backup
□ Network segmentation untuk SSH access
□ Regular password audit
```

---

## 10. Lessons Learned

```
Yang Berjalan Baik:
✅ Wazuh berhasil detect brute force
✅ Active Response otomatis blokir attacker
✅ Alert level 10 langsung visible di dashboard
✅ MITRE mapping membantu analisis

Yang Perlu Diperbaiki:
⚠️ Active Response log tidak tercatat
   (bug di logging, fungsi tetap berjalan)
⚠️ SSH default port masih 22
⚠️ Root login via SSH masih dibolehkan
⚠️ Tidak ada rate limiting awal

Waktu Deteksi  : ~2 menit setelah serangan
Waktu Respons  : Otomatis (Active Response)
Waktu Resolusi : ~22 menit total
```

---

## 11. Evidence

| No | Evidence | Keterangan |
|---|---|---|
| 1 | ss1-dashboard-overview.png | 234 total alerts, MITRE chart |
| 2 | ss2-alert-detail-5763.png | Detail rule brute force |
| 3 | ss3-alert-list.png | List semua SSH alerts |
| 4 | ss4-mitre-t1110.png | MITRE T1110 mapping |
| 5 | ss5-rule651-detail.png | Host blocked detail |
| 6 | ss6-iptables-drop.png | iptables DROP rule |
| 7 | ss7-ping-blocked.png | 100% packet loss |

---

*Report dibuat oleh: Muhamad Yusril Malakaini*  
*Tanggal: 26 Mei 2026*  
*Framework: NIST SP 800-61*
