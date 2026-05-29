# 🌐 Playbook: Web Attack (SQL Injection + LFI)

**Playbook ID:** PB-004  
**Version:** 1.0  
**Author:** Muhamad Yusril Malakaini  
**Framework:** NIST SP 800-61  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing App), T1083 (File Discovery)  
**Severity:** HIGH — CRITICAL  
**SLA Response Time:** 30 menit

---

## 📋 Overview

Web attacks mengeksploitasi kerentanan di aplikasi web. SQL Injection memanipulasi query database, sementara LFI (Local File Inclusion) memungkinkan attacker membaca file sensitif di server.

```
SQL Injection Flow:
Input form → Payload SQL → Database query
                               ↓
                     Database dump / bypass login!

LFI Flow:
URL parameter → ../../../../etc/passwd
                          ↓
                  File sensitif terbaca!
```

---

## 🚨 Detection Indicators

### Red Flags di Log:
```
SQL Injection:
- Request dengan karakter: ' " ; -- OR AND
- Response 200 pada request mencurigakan
- Banyak request 500 (server error)
- Query time sangat lama (time-based SQLi)

LFI:
- Request dengan: ../ ..\\ %2e%2e
- Akses ke /etc/passwd, /etc/shadow
- Response 200 pada path traversal
- Request dengan null byte: %00
```

### KQL Query untuk Deteksi:
```kql
# Cari SQL Injection attempts
data.url: *SELECT* OR
data.url: *UNION* OR
data.url: *DROP* OR
data.url: *'\''*

# Cari LFI attempts
data.url: *../* OR
data.url: *etc/passwd* OR
data.url: *etc/shadow*

# Cari web attack alerts dari Suricata
rule.groups: "suricata" AND
rule.level: >= 8

# Cari response 200 pada serangan
data.id: "200" AND
(data.url: *../* OR data.url: *SELECT*)
```

---

## 📊 NIST IR Flow

### PHASE 1 — PREPARATION ✅
```
□ WAF (Web Application Firewall) aktif
□ Suricata rules untuk web attacks aktif
□ Web server logging aktif (access + error)
□ Database query logging aktif
□ Input validation di aplikasi sudah ada
```

---

### PHASE 2 — IDENTIFICATION 🔍
```
1. Konfirmasi serangan
   □ Jenis serangan apa? (SQLi/LFI/XSS?)
   □ Berhasil atau gagal?
   □ Response code berapa? (200 = berhasil!)
   □ Data apa yang exposed?

2. Identifikasi scope
   □ Endpoint mana yang diserang?
   □ Database apa yang diakses?
   □ File apa yang dibaca (LFI)?
   □ Berapa lama serangan berlangsung?

3. Cek evidence di Suricata alerts
   □ Rule mana yang trigger?
   □ IP attacker berapa?
   □ User-agent apa yang dipakai?
```

---

### PHASE 3 — CONTAINMENT 🛡️

**Short Term:**
```
□ Blokir IP attacker di WAF/firewall
  iptables -A INPUT -s [IP] -j DROP

□ Disable endpoint yang vulnerable
  (kalau memungkinkan)

□ Block payload pattern di WAF
  Tambah rule untuk block ' OR UNION dll

□ Preserve web server logs
  cp /var/log/apache2/access.log /tmp/evidence/
```

**Long Term:**
```
□ Patch vulnerability di aplikasi
□ Implementasi WAF rules lebih ketat
□ Input validation & sanitization
□ Prepared statements untuk SQL
□ Disable directory listing
```

---

### PHASE 4 — ERADICATION 🗑️
```
□ Fix vulnerable code
  - Gunakan prepared statements
  - Sanitasi semua input
  - Disable error messages ke user

□ Cek apakah attacker upload webshell
  find /var/www -name "*.php" -newer [date]

□ Review semua database queries
  Cek apakah ada data yang dimodifikasi

□ Reset database credentials
```

---

### PHASE 5 — RECOVERY 🔄
```
□ Deploy fixed version aplikasi
□ Restore database jika perlu
□ Verifikasi tidak ada webshell tersisa
□ Update WAF rules
□ Penetration test ulang setelah fix
```

---

### PHASE 6 — LESSONS LEARNED 📝
```
□ Kenapa vulnerability ini ada?
□ Apakah ada code review sebelum deploy?
□ Apakah WAF bisa mencegah ini?
□ Berapa lama vulnerability sudah ada?
□ Ada data sensitif yang exposed?
```

---

## 🔍 Manual Investigation Steps

```bash
# Cek web server logs
grep "UNION\|SELECT\|DROP" /var/log/apache2/access.log

# Cek LFI attempts
grep "\.\./" /var/log/apache2/access.log

# Cek response 200 pada serangan
grep "200" /var/log/apache2/access.log | grep "\.\.\/"

# Cek webshell yang mungkin diupload
find /var/www -name "*.php" -newer /var/www/index.php

# Cek database untuk unauthorized access
grep "error\|warning" /var/log/mysql/error.log
```

---

## 📋 Escalation Matrix

| Kondisi | Eskalasi ke | Waktu |
|---|---|---|
| Web attack terdeteksi | SOC L2 | 30 menit |
| Database breach terkonfirmasi | SOC L2/L3 + Management | SEGERA |
| Customer data exposed | L2/L3 + Management + Legal | SEGERA |
