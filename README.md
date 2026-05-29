# 🛡️ SOC Incident Response Simulation Lab

**Author:** Muhamad Yusril Malakaini  
**Framework:** NIST SP 800-61 (Computer Security Incident Handling Guide)  
**Environment:** VirtualBox — Isolated Lab  

---

## 🎯 Overview

Proyek ini adalah simulasi lengkap siklus **Incident Response** menggunakan framework **NIST SP 800-61** dengan environment lab terdistribusi berbasis **Wazuh SIEM** dan **ELK Stack**.

Setiap skenario mensimulasikan insiden keamanan nyata yang umum ditemui di SOC, mulai dari deteksi, analisis, containment, eradication, hingga recovery — lengkap dengan dokumentasi IOC Report dan Lessons Learned.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                    LAB ENVIRONMENT                   │
│                                                     │
│  ┌──────────────┐        ┌──────────────────────┐   │
│  │  Kali Linux  │ ──────▶│   JH Target Server   │   │
│  │  (Attacker)  │        │   Ubuntu 20.04 LTS   │   │
│  │ 192.168.1.29 │        │    192.168.1.17      │   │
│  └──────────────┘        └──────────┬───────────┘   │
│                                     │ Wazuh Agent   │
│                                     ▼               │
│                          ┌──────────────────────┐   │
│                          │   JH-serverWazuh     │   │
│                          │  Wazuh + ELK Stack   │   │
│                          │   Suricata IDS       │   │
│                          │    192.168.1.18      │   │
│                          └──────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

| Host | Role | OS | IP Address |
|---|---|---|---|
| Kali Linux | Attacker | Kali Rolling 2026 | 192.168.1.29 |
| JH Target Server | Victim | Ubuntu 20.04 LTS | 192.168.1.17 |
| JH-serverWazuh | SIEM | Ubuntu Server | 192.168.1.18 |

---

## 🔧 Stack & Tools

| Kategori | Tools |
|---|---|
| SIEM | Wazuh v4.5.4 |
| Log Management | Elasticsearch 7.17 + Kibana 7.17 |
| IDS | Suricata 8.0.4 |
| Endpoint Monitoring | Wazuh Agent + FIM + auditd |
| Threat Intelligence | VirusTotal API |
| Attack Tools | Nmap, Hydra, SQLMap, Metasploit |
| Query Language | KQL (Kibana Query Language) |

---

## 📋 IR Framework — NIST SP 800-61

Setiap skenario mengikuti 6 tahap IR berikut:

```
1. PREPARATION      → Siapkan tools, playbook, environment
        ↓
2. IDENTIFICATION   → Deteksi & konfirmasi insiden
        ↓
3. CONTAINMENT      → Isolasi ancaman (short & long term)
        ↓
4. ERADICATION      → Hapus malware & penyebab insiden
        ↓
5. RECOVERY         → Pulihkan sistem ke kondisi normal
        ↓
6. LESSONS LEARNED  → Dokumentasi & evaluasi
```

---

## 🎯 Simulations

| No | Skenario | Attack Tool | Status |
|---|---|---|---|
| 1 | Brute Force SSH + Unauthorized Access | Hydra | 🔄 In Progress |
| 2 | Malware Infection + C2 Communication | Custom Script | ⏳ Upcoming |
| 3 | Data Exfiltration | Netcat | ⏳ Upcoming |
| 4 | Web Attack (SQL Injection + LFI) | SQLMap | ⏳ Upcoming |

---

## 🧠 MITRE ATT&CK Coverage

| Technique | ATT&CK ID | Skenario |
|---|---|---|
| Brute Force | T1110 | Skenario 1 |
| Valid Accounts | T1078 | Skenario 1 |
| Command and Control | T1071 | Skenario 2 |
| Exfiltration Over C2 | T1041 | Skenario 3 |
| Exploit Public-Facing App | T1190 | Skenario 4 |
| OS Credential Dumping | T1003 | Skenario 1 |

---

## 📁 Project Structure

```
SOC-IR-Simulation-Lab/
│
├── README.md
│
├── architecture/
│   ├── lab-diagram.png
│   └── network-topology.md
│
├── playbooks/
│   ├── brute-force-playbook.md
│   ├── malware-c2-playbook.md
│   ├── exfiltration-playbook.md
│   └── web-attack-playbook.md
│
├── simulations/
│   ├── 01-brute-force-ssh/
│   │   ├── README.md
│   │   ├── attack-steps.md
│   │   ├── evidence/
│   │   │   ├── screenshots/
│   │   │   └── logs/
│   │   └── ir-report.md
│   │
│   ├── 02-malware-c2/
│   ├── 03-data-exfiltration/
│   └── 04-web-attacks/
│
├── ioc-reports/
│   ├── ioc-template.md
│   └── [IOC report tiap skenario]
│
├── kql-queries/
│   └── useful-queries.md
│
└── lessons-learned/
    └── summary.md
```

---

## 🔍 KQL Queries Used

```kql
# Cari semua brute force attempts
rule.description: "sshd: brute force"

# Cari login dari IP tertentu
agent.ip: "192.168.1.29"

# Cari alert level tinggi
rule.level: >= 10

# Cari event dalam range waktu
@timestamp >= "2026-05-01" AND @timestamp <= "2026-05-31"

# Cari port scanning
rule.description: *scan* AND rule.level: >= 6
```

---

## 📊 Detection Rules Active

| Rule ID | Description | Level | Response |
|---|---|---|---|
| 100200 | Nmap Scripting Engine Detected | 12 | Auto-block IP |
| 5710 | SSH Brute Force | 10 | Auto-block IP |
| 87105 | VirusTotal Malware Detected | 12 | Auto-delete file |
| 100250 | Command Injection Detected | 12 | Alert |

---

## ⚠️ Disclaimer

> Semua simulasi dilakukan di lingkungan **lab terisolasi (VirtualBox)** untuk tujuan **edukasi dan penelitian keamanan**. Jangan dijalankan ke sistem produksi tanpa otorisasi. Penulis tidak bertanggung jawab atas penyalahgunaan materi ini.

---

## 👨‍💻 Author

**Muhamad Yusril Malakaini**  
SOC Analyst (in training) | Semester 4

🔗 **GitHub:** [NocTuax](https://github.com/NocTuax)  
🔗 **Project Sebelumnya:** [Distributed-SIEM-Wazuh-ELK](https://github.com/NocTuax/Distributed-SIEM-Wazuh-ELK)
