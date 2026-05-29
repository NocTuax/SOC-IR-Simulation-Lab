# 📤 Playbook: Data Exfiltration

**Playbook ID:** PB-003  
**Version:** 1.0  
**Author:** Muhamad Yusril Malakaini  
**Framework:** NIST SP 800-61  
**MITRE ATT&CK:** T1041 (Exfiltration over C2), T1048 (Exfiltration over Alt Protocol)  
**Severity:** CRITICAL  
**SLA Response Time:** 15 menit

---

## 📋 Overview

Data Exfiltration adalah pencurian data dari dalam jaringan perusahaan ke luar tanpa izin. Ini adalah tahap akhir dari kebanyakan serangan APT dan merupakan insiden paling merugikan.

```
Attack Flow:
Initial Access → Lateral Movement
      ↓
 Collect Data (dokumen, kredensial, DB)
      ↓
 Compress & Encrypt data
      ↓
 Transfer keluar via HTTP/DNS/FTP
      ↓
 Data sampai ke attacker!
```

---

## 🚨 Detection Indicators

### Red Flags:
```
- Transfer data sangat besar (GB) keluar
- Ke IP/domain asing yang tidak dikenal
- Di jam tidak wajar (malam/weekend)
- Via port yang tidak biasa
- Pola transfer teratur (scheduled)
- User mengakses data di luar scope tugasnya
```

### KQL Query untuk Deteksi:
```kql
# Cari outbound traffic besar
network.bytes: >= 1000000 AND
network.direction: "outbound"

# Cari koneksi ke IP asing
NOT source.ip: "192.168.*" AND
NOT source.ip: "10.*" AND
network.direction: "outbound"

# Cari aktivitas di jam tidak wajar
@timestamp >= "now-8h" AND
(hour(@timestamp) >= 22 OR
 hour(@timestamp) <= 6)

# Cari transfer via port tidak biasa
NOT destination.port: (80 OR 443 OR 22) AND
network.direction: "outbound"
```

---

## 📊 NIST IR Flow

### PHASE 1 — PREPARATION ✅
```
□ DLP solution aktif
□ Network monitoring aktif
□ Baseline traffic sudah didokumentasi
□ Alert threshold untuk transfer besar aktif
□ Legal team sudah di-brief tentang prosedur
```

---

### PHASE 2 — IDENTIFICATION 🔍
```
1. Konfirmasi exfiltration
   □ Berapa volume data yang keluar?
   □ Ke mana data pergi?
   □ Data apa yang dicuri?
   □ Siapa yang melakukan?
   □ Kapan dimulai?

2. Tentukan scope
   □ Hanya 1 host atau lebih?
   □ Data apa saja yang exposed?
   □ Masih berlangsung atau sudah selesai?
```

---

### PHASE 3 — CONTAINMENT 🛡️

**Short Term (SEGERA):**
```
□ Blokir koneksi ke destination IP
  iptables -A OUTPUT -d [IP] -j DROP

□ Isolasi host yang melakukan exfiltration

□ Preserve semua log & network captures
  (jangan hapus evidence!)

□ Screenshot semua alert di Wazuh

□ Eskalasi ke Management & Legal SEGERA
  (ada kewajiban lapor regulasi!)
```

**Long Term:**
```
□ Review semua akses ke data sensitif
□ Implementasi DLP lebih ketat
□ Network segmentation
□ Zero-trust architecture
```

---

### PHASE 4 — ERADICATION 🗑️
```
□ Identifikasi & hapus malware/tools
  yang digunakan untuk exfiltration

□ Revoke semua credentials yang exposed

□ Audit semua akses ke data sensitif
  dalam 30 hari terakhir

□ Patch vulnerability yang dieksploitasi
```

---

### PHASE 5 — RECOVERY 🔄
```
□ Restore data dari backup jika perlu
□ Reset semua credentials
□ Implementasi monitoring lebih ketat
□ Brief seluruh tim tentang insiden
□ Notifikasi pihak yang data nya dicuri
   (regulatory requirement!)
```

---

### PHASE 6 — LESSONS LEARNED 📝
```
□ Data apa yang paling sensitif?
□ Apakah DLP bisa mencegah ini?
□ Berapa lama exfiltration berlangsung?
□ Ada regulasi yang dilanggar?
□ Apa dampak bisnis dari insiden ini?
```

---

## ⚠️ Legal Considerations

```
Data breach mungkin memerlukan:
□ Laporan ke BSSN (jika di Indonesia)
□ Notifikasi ke customer yang terdampak
□ Laporan ke regulator industri
□ Dokumentasi untuk keperluan hukum

JANGAN hapus evidence sebelum
berkonsultasi dengan Legal team!
```

---

## 📋 Escalation Matrix

| Kondisi | Eskalasi ke | Waktu |
|---|---|---|
| Exfiltration terdeteksi | SOC L2/L3 | SEGERA |
| Data sensitif terkonfirmasi dicuri | Management + Legal | SEGERA |
| Regulasi dilanggar | C-Level + Legal + BSSN | SEGERA |
