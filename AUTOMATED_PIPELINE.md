# PUPMAS - Automated Pipeline Guide

## 🚀 One Command = Sıraya Gitme Yok!

PUPMAS artık **tek bir komutla** baştan sona tarama yapabiliyor. Nmap, sqlmap vs bireysel çalıştırmana gerek yok!

---

## 📋 Kullanım

### En Basit Kullanım
```bash
python3 pupmas.py --auto-scan --auto-target <TARGET>
```

### Örnekler

**1. CTF Kutusu Çözmek (Hızlı)**
```bash
python3 pupmas.py --auto-scan --auto-target 10.10.10.5 --auto-profile active --auto-type ctf
```
- Port taraması ✓
- Service detection ✓
- CVE bulma ✓
- Web zafiyetleri test etme ✓
- Timeline oluşturma ✓
- Rapor ✓

**2. Penetrasyon Testi (Detaylı)**
```bash
python3 pupmas.py --auto-scan --auto-target example.com --auto-profile aggressive --auto-type pentest
```
- DNS enumeration ✓
- Subdomain bulma ✓
- Aggressive port scan (top 1000) ✓
- Service fingerprinting ✓
- Exploitation testing ✓
- Detaylı rapor ✓

**3. Red Team Operasyonu**
```bash
python3 pupmas.py --auto-scan --auto-target target.local --auto-profile aggressive --auto-type redteam
```

**4. Blue Team Analysis (Exploit Yok)**
```bash
python3 pupmas.py --auto-scan --auto-target 192.168.1.1 --auto-no-exploit --auto-type blueteam
```

---

## ⚙️ Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|----------|-----------|
| `--auto-scan` | Otomatik tarama başlat (ZORUNLU) | - |
| `--auto-target` | Hedef IP/domain (ZORUNLU) | - |
| `--auto-profile` | Tarama agresifliği: `passive`, `active`, `aggressive` | `active` |
| `--auto-type` | İşlem tipi: `pentest`, `ctf`, `redteam`, `blueteam` | `pentest` |
| `--auto-report` | Rapor formatı: `html`, `json` | `html` |
| `--auto-no-exploit` | Exploitation fazını atla | - |
| `--auto-no-db` | Veritabanına kaydetme | - |

---

## 📊 Pipeline Aşamaları

### Phase 1: Reconnaissance
- Hostname resolution
- Port scanning (common ports / aggressive)
- Service detection & version
- Banner grabbing
- DNS enumeration
- Subdomain enumeration (active/aggressive)
- HTTP title grabbing

### Phase 2: Exploitation Testing
- SQL Injection tests
- XSS vulnerability tests
- Command Injection (RCE) tests
- LFI/RFI tests
- Default credentials check
- Authentication bypass tests
- Path traversal tests

### Phase 3: CVE Analysis
- Service-specific CVE matching
- CVSS scoring
- Risk assessment
- Exploitability check

### Phase 4: Timeline & MITRE Mapping
- MITRE ATT&CK technique mapping
- Timeline event creation
- Attack chain analysis
- Automatic technique detection

### Phase 5: SIEM Analysis
- Log generation
- Event correlation
- Detection rule generation
- Alert creation

### Phase 6: Finalization
- Database saving
- Report generation (HTML/JSON)
- Summary printing

---

## 📈 Çıktılar

### Otomatik Olarak Oluşturulan Dosyalar

1. **Recon Results** (JSON)
   - Port information
   - Service versions
   - CVE mapping
   - DNS records
   - Subdomains

2. **Report** (HTML/JSON)
   - Summary
   - Open ports with services
   - Vulnerabilities found
   - CVEs with details
   - Recommendations

3. **Timeline** (Veritabanında)
   - Recon events
   - Exploitation events
   - CVE findings
   - MITRE technique mapping

4. **Database Entry**
   - Operation session
   - All findings
   - Metadata
   - Timestamps

---

## ⏱️ Taraf Karşılaştırması

| Metod | Süre | Komut Sayısı |
|-------|------|-------------|
| **Manual (nmap + sqlmap + ...)**  | 15+ dakika | 8-15+ komut | ❌
| **PUPMAS Auto Pipeline** | 2-5 dakika | **1 komut** | ✅

---

## 🔥 Gerçek Örnekler

### Örnek 1: HTB Box Çözmek

```bash
# BEFORE (Eski Yöntem)
nmap -sV 10.10.10.5 -p- > ports.txt
cat ports.txt | grep open
nikto -h 10.10.10.5
sqlmap -u "http://10.10.10.5/search.php?q=test" --dbs
burp (manual)
...

# AFTER (PUPMAS)
python3 pupmas.py --auto-scan --auto-target 10.10.10.5

# 3-5 dakikada:
✓ Port scan
✓ Service detection
✓ Web zafiyetleri test
✓ CVE bulma
✓ Timeline oluşturma
✓ Rapor
```

### Örnek 2: Penetrasyon Testi

```bash
# Tek komut ile
python3 pupmas.py --auto-scan --auto-target client.com --auto-profile aggressive --auto-type pentest

# Otomatik olarak:
✓ Domain enumeration
✓ Subdomain bulma
✓ Port scan (top 1000)
✓ Service fingerprinting
✓ Vulnerability testing
✓ CVE matching
✓ Professional rapor
```

---

## 🎯 Her Profil Nedir?

### Passive
- No active port scanning
- DNS enumeration only
- Quick & stealthy
- **Süre:** 30 saniye - 2 dakika

### Active (Default)
- Common ports only (22, 80, 443, 3306, ...)
- Service version detection
- Subdomain enumeration
- **Süre:** 2-5 dakika

### Aggressive
- Top 1000 ports
- Full version fingerprinting
- Extended subdomain list
- All vulnerability tests
- **Süre:** 5-15 dakika

---

## 💡 Örnek Senaryolar

### Senaryo 1: Hızlı CTF
```bash
python3 pupmas.py --auto-scan --auto-target 10.10.10.50 --auto-type ctf
```
**Yapacakları:** Port scan → Web test → CVE → Rapor

### Senaryo 2: Detaylı Pentest
```bash
python3 pupmas.py --auto-scan --auto-target target.com --auto-profile aggressive --auto-type pentest
```
**Yapacakları:** DNS enum → Subdomain → Aggressive scan → All tests → Timeline → Rapor

### Senaryo 3: Blue Team Defense
```bash
python3 pupmas.py --auto-scan --auto-target 192.168.1.1 --auto-no-exploit --auto-type blueteam
```
**Yapacakları:** Recon only → Log analysis → SIEM rules → No exploitation

### Senaryo 4: Red Team
```bash
python3 pupmas.py --auto-scan --auto-target 10.0.0.1 --auto-profile aggressive --auto-type redteam
```
**Yapacakları:** Full recon → Full exploitation → MITRE mapping → Timeline

---

## 🛠️ Troubleshooting

### Tarama çok yavaş
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-profile passive
```
(Passive profile kullan)

### Sadece recon, exploit yok
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-no-exploit
```

### Veritabanına kaydetme
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-no-db
```

### JSON rapor
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-report json
```

---

## 📖 Sonrası?

Rapor oluştuktan sonra:

```bash
# Raporu göster
cat reports/pupmas_report_*.html

# Veritabanında kayıtlı olanları gör
python3 pupmas.py --db-stats

# Daha detaylı TUI analizi
python3 pupmas.py --mode tui
```

---

## 🚀 Hızlı Komutlar

```bash
# 1-liner: Hızlı tarama
python3 pupmas.py --auto-scan --auto-target 10.10.10.5

# Aggressive: Detaylı tarama
python3 pupmas.py --auto-scan --auto-target target.com --auto-profile aggressive

# CTF mode: En hızlı
python3 pupmas.py --auto-scan --auto-target 10.10.10.50 --auto-type ctf --auto-profile active

# Full-auto everything:
python3 pupmas.py --auto-scan --auto-target target --auto-profile aggressive --auto-type pentest
```

---

## ✅ Yapı Kontrol Listesi

Herhangi bir target için otomatik olarak:

- ✓ Recon (IP, ports, services)
- ✓ Service detection & versioning
- ✓ DNS enumeration & subdomains
- ✓ Web vulnerability testing
- ✓ CVE analysis & matching
- ✓ Default credentials check
- ✓ LFI/RFI testing
- ✓ SQL injection testing
- ✓ XSS testing
- ✓ Command injection testing
- ✓ Timeline creation
- ✓ MITRE ATT&CK mapping
- ✓ SIEM log analysis
- ✓ Detection rule generation
- ✓ Professional report
- ✓ Database archiving

**Birisi yapıyor. Seni beklemiyor.**

---

**Sonuç:** Bir komutla yapabilir, 15 komut yazmazsan! 🎯
