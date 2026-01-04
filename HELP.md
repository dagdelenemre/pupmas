# PUPMAS - Detaylı Kullanım Kılavuzu

## 🆕 Son Değişiklikler (v1.0.0 - Ocak 2026)

### ✨ Yeni Özellikler
- ✅ **11 Yeni Güvenlik Açığı Testi**: IDOR, XXE, SSRF, SSTI, Open Redirect, Blind SQLi, CORS, Security Headers
- ✅ **Python 3.13 Tam Desteği**: SQLAlchemy 2.0.45+ ile tam uyumluluk
- ✅ **Akıllı Deduplikasyon**: Aynı güvenlik açığını birden fazla kez raporlamaz
- ✅ **Cloudflare Tespit ve Bypass**: Otomatik CDN/WAF tespiti
- ✅ **TLS Banner Grabbing**: SSL-only portlar için banner grabbing (465, 993, 995)
- ✅ **Non-CDN Subdomain Tarama**: Sadece Cloudflare olmayan IP'leri tarar

### 🔧 Düzeltmeler
- ✅ **--recon Komutu Düzeltildi**: Artık `--target` parametresi çalışıyor
- ✅ **--exfil-test Komutu Düzeltildi**: Tüm exfiltration metotları test edilebilir
- ✅ **AttackPhase Enum**: `exfiltration` phase eklendi
- ✅ **Rapor Süresi**: Scan duration artık doğru hesaplanıyor
- ✅ **Subdomain Port Scanning**: Subdomain'lerin açık portları HTML raporunda görünüyor

### 📦 Güncellenmiş Bağımlılıklar
- sqlalchemy >= 2.0.45 (Python 3.13 uyumluluğu)
- textual >= 7.0.0 (TUI iyileştirmeleri)
- rich >= 14.2.0 (Terminal output formatting)
- dnspython >= 2.8.0 (DNS resolution)

---

## 📚 İçindekiler

1. [Kurulum](#kurulum)
2. [Temel Kullanım](#temel-kullanım)
3. [Komutlar ve Parametreler](#komutlar-ve-parametreler)
4. [Otomatik Pipeline](#otomatik-pipeline)
5. [Manuel Modüller](#manuel-modüller)
6. [Kullanım Senaryoları](#kullanım-senaryoları)
7. [Çıktılar ve Raporlar](#çıktılar-ve-raporlar)
8. [Sorun Giderme](#sorun-giderme)
9. [İpuçları ve Best Practices](#i̇puçları-ve-best-practices)

---

## 🔧 Kurulum

### Gereksinimler
- **Python 3.9 veya üstü** (Python 3.13 tam desteklenir)
- **İşletim Sistemi**: Linux (Kali önerilir), macOS, Windows
- **Bağımlılıklar**: `requirements.txt` içinde listelendi
- **Önemli**: Python 3.13 kullanıyorsanız SQLAlchemy 2.0.45+ gereklidir

### Adım 1: Repository'yi İndirin
```bash
git clone https://github.com/dagdelenemre/pupmas.git
cd pupmas
```

### Adım 2: Sanal Ortam Oluşturun (Önerilir)
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

### Adım 3: Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt

# Python 3.13 için özel güncelleme (gerekirse)
pip install --upgrade sqlalchemy textual dnspython rich
```

### Adım 4: Konfigürasyonu Kontrol Edin
```bash
# Config dosyasını düzenleyin (isteğe bağlı)
nano config/config.yaml
```

### Adım 5: Test Edin
```bash
python3 pupmas.py --help
```

**Başarılı kurulum:** Komut listesi görünecektir.

### Kurulum Sorunları ve Çözümleri

#### Python 3.13'te SQLAlchemy Hatası
```bash
# Hata: TypeError: Can't replace canonical symbol for '__firstlineno__'
# Çözüm:
pip install --upgrade sqlalchemy>=2.0.45
```

#### Textual Modülü Bulunamadı
```bash
pip install textual
```

#### DNS Modülü Hatası
```bash
pip install dnspython
```

---

## 🚀 Temel Kullanım

PUPMAS iki şekilde kullanılabilir:

### 1. Otomatik Pipeline (Önerilen)
Tek komutla tüm işlemleri yapar:
```bash
# Tam sözdizimi
python3 pupmas.py --auto-scan <HEDEF>

# Kısayol komutları
python3 pupmas.py -auS <HEDEF>          # Tam tarama
python3 pupmas.py -M1 <HEDEF>           # Hızlı tarama
python3 pupmas.py -M2 <HEDEF>           # Dengeli tarama
python3 pupmas.py -M3 <HEDEF>           # Derin tarama
```

### 2. Manuel Modüller
Her modülü tek tek çalıştırır:
```bash
# MITRE ATT&CK sorguları
python3 pupmas.py --mitre T1059.001

# CVE araması
python3 pupmas.py --cve CVE-2021-44228

# Reconnaissance (yeni düzeltildi)
python3 pupmas.py --recon --target scanme.nmap.org --recon-profile passive

# Exfiltration testi (yeni düzeltildi)
python3 pupmas.py --exfil-test --method dns
```

### 3. Yeni Kısayol Komutları
```bash
-auS    # --auto-scan için kısayol
-M1     # Passive profil ile hızlı tarama
-M2     # Active profil ile dengeli tarama
-M3     # Aggressive profil ile derin tarama
-n      # --no-prompt (rapor açma sorusunu atla)
```

---

## 📋 Komutlar ve Parametreler

### 🎯 Otomatik Pipeline Komutları

#### `--auto-scan`
**Açıklama:** Otomatik pipeline'ı başlatır. Tüm fazları sırayla çalıştırır.

**Zorunlu Parametre:** Evet (pipeline kullanıyorsanız)

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target 10.10.10.50
```

**Ne Yapar:**
1. Port tarama (reconnaissance)
2. Servis tespiti
3. Zafiyet taraması (exploitation)
4. CVE analizi
5. Timeline oluşturma
6. SIEM log analizi
7. Rapor üretme

---

#### `--auto-target <IP/DOMAIN>`
**Açıklama:** Tarama yapılacak hedef IP adresi veya domain adı.

**Zorunlu Parametre:** Evet (`--auto-scan` kullanıyorsanız)

**Desteklenen Formatlar:**
- IP adresi: `192.168.1.100`
- Domain: `example.com`
- Subdomain: `test.example.com`

**Örnekler:**
```bash
# IP ile
python3 pupmas.py --auto-scan --auto-target 10.10.10.50

# Domain ile
python3 pupmas.py --auto-scan --auto-target hackthebox.com

# Subdomain ile
python3 pupmas.py --auto-scan --auto-target admin.target.com
```

**Dikkat:**
- HTTPS kullanılacaksa `https://` prefix'i gerekmez
- Port belirtmek isterseniz: `target.com:8080` (otomatik algılanır)

---

#### `--auto-profile <PROFILE>`
**Açıklama:** Tarama agresiflik seviyesini belirler.

**Zorunlu Parametre:** Hayır (default: `active`)

**Seçenekler:**

##### 1. `passive` (Gizli Mod)
**Ne Yapar:**
- Minimum ağ trafiği
- Sadece common portlar (20 port)
- DNS pasif sorgu
- Subdomain brute-force yok
- Zafiyet taraması hafif

**Süre:** 30 saniye - 2 dakika

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-profile passive
```

**Ne Zaman Kullanılır:**
- Red team operasyonlarında tespit edilmemek için
- IDS/IPS sistemlerinden kaçınmak için
- Basit bir keşif için

##### 2. `active` (Varsayılan - Dengeli Mod)
**Ne Yapar:**
- Orta seviye tarama
- 100 common port
- DNS full enumeration
- 15 subdomain wordlist
- SQL injection, XSS, RCE testleri
- Banner grabbing

**Süre:** 2-5 dakika

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-profile active
# veya sadece
python3 pupmas.py --auto-scan --auto-target target
```

**Ne Zaman Kullanılır:**
- Çoğu penetrasyon testi için (önerilen)
- CTF yarışmaları için
- Balanced risk/reward istediğinizde

##### 3. `aggressive` (Kapsamlı Mod)
**Ne Yapar:**
- Top 1000 port taraması
- Tüm servis versiyonları
- Geniş subdomain brute-force
- Tüm zafiyet payloadları (30+)
- Deep web crawling
- Authentication bypass denemeleri

**Süre:** 5-15 dakika

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-profile aggressive
```

**Ne Zaman Kullanılır:**
- Resmi penetrasyon testlerinde (izin alındıktan sonra)
- Lab ortamlarında
- CTF final atakları için
- Kapsamlı zafiyet değerlendirmesi gerektiğinde

**Dikkat:** IDS/IPS alarmlarını tetikleyebilir!

---

#### `--auto-type <TYPE>`
**Açıklama:** Operasyon tipini belirler. Timeline ve MITRE mapping'i etkiler.

**Zorunlu Parametre:** Hayır (default: `pentest`)

**Seçenekler:**

##### 1. `pentest` (Varsayılan)
**Açıklama:** Standart penetrasyon testi
**Timeline Türü:** Pentest timeline
**MITRE Mapping:** TA0043 (Reconnaissance), TA0042 (Resource Development)

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-type pentest
```

##### 2. `ctf`
**Açıklama:** Capture The Flag yarışması
**Timeline Türü:** Attack timeline
**MITRE Mapping:** Exploit odaklı (T1190, T1078, T1059)

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-type ctf
```

##### 3. `redteam`
**Açıklama:** Red team operasyonu
**Timeline Türü:** Attack + Exfiltration timeline
**MITRE Mapping:** Full kill chain (TA0001-TA0010)

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-type redteam
```

##### 4. `blueteam`
**Açıklama:** Blue team analizi (savunma)
**Timeline Türü:** Reconnaissance only
**MITRE Mapping:** Detection & Response (TA0009, TA0040)

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-type blueteam
```

**Özel:** Exploitation fazı otomatik devre dışı kalır.

---

#### `--auto-report <FORMAT>`
**Açıklama:** Rapor formatını belirler.

**Zorunlu Parametre:** Hayır (default: `html`)

**Seçenekler:**

##### 1. `html` (Varsayılan)
**Açıklama:** Web tarayıcısında açılabilir HTML rapor

**Özellikler:**
- Renkli grafikler
- Interaktif tablolar
- CSS ile şık tasarım
- Timeline görselleştirme
- MITRE ATT&CK matrix

**Dosya Adı:** `pupmas_report_<timestamp>.html`

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-report html
```

**Raporu Açma:**
```bash
# Linux
firefox pupmas_report_20260104_153045.html

# macOS
open pupmas_report_20260104_153045.html

# Windows
start pupmas_report_20260104_153045.html
```

##### 2. `json`
**Açıklama:** Makine tarafından okunabilir JSON rapor

**Özellikler:**
- Programatik erişim için ideal
- API entegrasyonu kolay
- Diğer araçlara import edilebilir
- Parse etmesi kolay

**Dosya Adı:** `pupmas_report_<timestamp>.json`

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-report json
```

**JSON'ı Okuma:**
```bash
# Pretty print
cat pupmas_report_20260104_153045.json | jq .

# Specific field
cat pupmas_report_20260104_153045.json | jq '.vulnerabilities'
```

**JSON Yapısı:**
```json
{
  "target": "10.10.10.50",
  "scan_time": "2026-01-04T15:30:45",
  "profile": "active",
  "recon_results": {
    "open_ports": [...],
    "services": [...],
    "subdomains": [...]
  },
  "exploitation_results": {
    "vulnerabilities": [...],
    "successful_exploits": 5
  },
  "cve_analysis": [...],
  "timeline_id": "timeline_123",
  "report_path": "./pupmas_report_20260104_153045.json"
}
```

---

#### `--auto-no-exploit`
**Açıklama:** Exploitation fazını atlar. Sadece reconnaissance yapar.

**Zorunlu Parametre:** Hayır

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-no-exploit
```

**Ne Yapar:**
- ✅ Port taraması yapılır
- ✅ Servis tespiti yapılır
- ✅ DNS enumeration yapılır
- ✅ Subdomain bulunur
- ❌ SQL injection test edilmez
- ❌ XSS test edilmez
- ❌ RCE test edilmez
- ❌ Default credentials denenmez

**Ne Zaman Kullanılır:**
- Blue team analizi için
- Sadece keşif yapılacaksa
- Zafiyet testine izin yoksa
- Hızlı bir scan için (2x daha hızlı)

**Dikkat:** Timeline yine oluşturulur ancak sadece recon eventleri içerir.

---

#### `--auto-no-db`
**Açıklama:** Sonuçları veritabanına kaydetmez.

**Zorunlu Parametre:** Hayır

**Kullanım:**
```bash
python3 pupmas.py --auto-scan --auto-target target --auto-no-db
```

**Ne Yapar:**
- ❌ SQLite veritabanına kayıt yapılmaz
- ✅ Rapor yine oluşturulur (HTML/JSON)
- ✅ Tüm fazlar normal çalışır
- ✅ Terminal'de özet yazdırılır

**Ne Zaman Kullanılır:**
- Tek seferlik testler için
- Disk alanı sınırlıysa
- Geçmiş takibi gerekmiyorsa
- CI/CD pipeline'da otomatik testler için

**Database Lokasyonu (kullanılıyorsa):**
```
data/pupmas.db
```

**Database'i Görüntüleme:**
```bash
sqlite3 data/pupmas.db
> .tables
> SELECT * FROM scans LIMIT 5;
> .exit
```

---

### 🛠️ Manuel Modül Komutları

#### MITRE ATT&CK Modülü

##### `--mitre --list-tactics`
**Açıklama:** Tüm MITRE ATT&CK taktiklerini listeler.

**Kullanım:**
```bash
python3 pupmas.py --mitre --list-tactics
```

**Çıktı Örneği:**
```
TA0001: Initial Access
TA0002: Execution
TA0003: Persistence
TA0004: Privilege Escalation
...
```

---

##### `--mitre --list-techniques`
**Açıklama:** Tüm teknikleri listeler.

**Kullanım:**
```bash
python3 pupmas.py --mitre --list-techniques
```

**Filtreleme:**
```bash
# Sadece Reconnaissance
python3 pupmas.py --mitre --list-techniques | grep TA0043

# Sadece Execution
python3 pupmas.py --mitre --list-techniques | grep TA0002
```

---

##### `--mitre --technique <TECHNIQUE_ID>`
**Açıklama:** Belirli bir tekniğin detaylarını gösterir.

**Kullanım:**
```bash
python3 pupmas.py --mitre --technique T1190
```

**Çıktı İçeriği:**
- Technique ID ve ismi
- Açıklama
- Hangi taktiklere ait olduğu
- Detection yöntemleri
- Mitigation önerileri
- Gerçek dünya örnekleri

---

##### `--mitre --map-event <EVENT>`
**Açıklama:** Bir security event'ini MITRE framework'üne map'ler.

**Kullanım:**
```bash
python3 pupmas.py --mitre --map-event "SQL injection attempt on login form"
```

**Çıktı:**
- İlgili MITRE technique(ler)
- Tactic'ler
- Severity assessment

---

#### Reconnaissance Modülü (YENİ - DÜZELTİLDİ)

##### `--recon --target <TARGET>`
**Açıklama:** Standalone reconnaissance modülü. Port tarama, servis tespiti ve subdomain enumeration yapar.

**Zorunlu Parametre:** `--target`

**Kullanım:**
```bash
# Passive recon (port tarama yok)
python3 pupmas.py --recon --target example.com --recon-profile passive

# Active recon (common portlar)
python3 pupmas.py --recon --target scanme.nmap.org --recon-profile active

# Aggressive recon (tüm portlar + subdomain brute-force)
python3 pupmas.py --recon --target 10.10.10.50 --recon-profile aggressive
```

**Profil Açıklamaları:**

**Passive:**
- DNS resolution
- DNS records (A, AAAA, MX, NS, TXT)
- Subdomain enumeration (DNS-only)
- ⚠️ Port tarama YOK
- Süre: 10-30 saniye

**Active:**
- Tüm passive işlemler
- ✅ Common port tarama (100 port)
- Service detection
- Banner grabbing
- Süre: 1-3 dakika

**Aggressive:**
- Tüm active işlemler
- ✅ Top 1000 port tarama
- Deep service detection
- Subdomain brute-force
- Cloudflare bypass denemeleri
- TLS/SSL banner grabbing
- Süre: 3-10 dakika

**Çıktı Örneği:**
```
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Property   ┃ Value        ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ IP Address │ 45.33.32.156 │
│ Status     │ ✓ Alive      │
│ Open Ports │ 2            │
│ Services   │ 2            │
│ Subdomains │ 5            │
└────────────┴──────────────┘

┏━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ Service ┃ Banner                        ┃
┡━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 22   │ SSH     │ SSH-2.0-OpenSSH_6.6.1p1      │
│ 80   │ HTTP    │ Apache/2.4.7 (Ubuntu)         │
└──────┴─────────┴───────────────────────────────┘
```

**Not:** Bu komut tek başına çalışır, otomatik pipeline gerektirmez.

---

#### Exfiltration Test Modülü (YENİ - DÜZELTİLDİ)

##### `--exfil-test --method <METHOD>`
**Açıklama:** Data exfiltration metotlarını test eder (simüle edilmiş).

**Zorunlu Parametre:** `--method`

**Desteklenen Metotlar:**
- `dns` - DNS tunneling
- `http` - HTTP exfiltration
- `https` - HTTPS exfiltration
- `icmp` - ICMP tunneling
- `smtp` - Email exfiltration

**Kullanım:**
```bash
# DNS exfiltration testi
python3 pupmas.py --exfil-test --method dns

# HTTP exfiltration testi
python3 pupmas.py --exfil-test --method http

# HTTPS exfiltration testi (en güvenli)
python3 pupmas.py --exfil-test --method https

# ICMP tunneling testi
python3 pupmas.py --exfil-test --method icmp

# SMTP exfiltration testi
python3 pupmas.py --exfil-test --method smtp
```

**Çıktı Örneği:**
```
      DNS Exfiltration Test       
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Test      ┃ Result             ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ Method    │ DNS                │
│ Detection │ ✓ Method available │
│ Stealth   │ Medium             │
│ Bandwidth │ Variable           │
└───────────┴────────────────────┘
```

**Özellikler:**
- Simüle edilmiş test (gerçek data exfiltration yapmaz)
- Stealth seviyesi gösterir
- Detection riski değerlendirir
- Bandwidth kapasitesini tahmin eder

**Not:** Bu komut güvenlik testleri içindir. Gerçek data exfiltration yasadışıdır!

---

#### CVE Modülü

##### `--cve --search <QUERY>`
**Açıklama:** CVE veritabanında arama yapar.

**Kullanım:**
```bash
# CVE ID ile
python3 pupmas.py --cve --search CVE-2021-44228

# Keyword ile
python3 pupmas.py --cve --search "log4j"

# Software ile
python3 pupmas.py --cve --search "Apache 2.4.49"
```

**Çıktı İçeriği:**
- CVE ID
- CVSS score
- Severity (Critical, High, Medium, Low)
- Açıklama
- Affected versions
- References

---

##### `--cve --cvss-min <SCORE>`
**Açıklama:** Minimum CVSS score'u belirler.

**Kullanım:**
```bash
# Sadece Critical (9.0+)
python3 pupmas.py --cve --search "Apache" --cvss-min 9.0

# High ve üzeri (7.0+)
python3 pupmas.py --cve --search "nginx" --cvss-min 7.0
```

---

##### `--cve --year <YEAR>`
**Açıklama:** Belirli yıldaki CVE'leri filtreler.

**Kullanım:**
```bash
python3 pupmas.py --cve --search "WordPress" --year 2023
```

---

#### Timeline Modülü

##### `--timeline --create <TYPE>`
**Açıklama:** Yeni timeline oluşturur.

**Kullanım:**
```bash
# Attack timeline
python3 pupmas.py --timeline --create attack

# Pentest timeline
python3 pupmas.py --timeline --create pentest

# Reconnaissance timeline
python3 pupmas.py --timeline --create recon

# Exfiltration timeline
python3 pupmas.py --timeline --create exfiltration
```

**Çıktı:** Timeline ID döner (örn: `timeline_1234567890`)

---

##### `--timeline --add-event`
**Açıklama:** Timeline'a event ekler.

**Kullanım:**
```bash
python3 pupmas.py --timeline --timeline-id timeline_1234567890 \
  --add-event "Port scan completed" \
  --event-type "reconnaissance"
```

**Event Types:**
- `reconnaissance` - Keşif aktiviteleri
- `exploitation` - Zafiyet sömürme
- `privilege_escalation` - Yetki yükseltme
- `lateral_movement` - Yan hareket
- `data_exfiltration` - Veri çalma
- `command_and_control` - C2 bağlantısı

---

##### `--timeline --list`
**Açıklama:** Tüm timeline'ları listeler.

**Kullanım:**
```bash
python3 pupmas.py --timeline --list
```

---

##### `--timeline --show <ID>`
**Açıklama:** Belirli timeline'ın detaylarını gösterir.

**Kullanım:**
```bash
python3 pupmas.py --timeline --show timeline_1234567890
```

**Çıktı:**
- Timeline türü
- Oluşturulma zamanı
- Event sayısı
- Tüm eventler (kronolojik sırada)

---

#### SIEM Modülü

##### `--siem --generate-logs`
**Açıklama:** Test SIEM logları üretir.

**Kullanım:**
```bash
python3 pupmas.py --siem --generate-logs --count 100
```

**Log Formatları:**
- CEF (Common Event Format)
- JSON
- Syslog

---

##### `--siem --correlate`
**Açıklama:** Log korelasyonu yapar.

**Kullanım:**
```bash
python3 pupmas.py --siem --correlate --timeline-id timeline_1234567890
```

**Ne Yapar:**
- Timeline eventlerini analiz eder
- İlişkili logları bulur
- Attack pattern'leri tespit eder
- Alert üretir

---

##### `--siem --create-rule`
**Açıklama:** SIEM detection rule oluşturur.

**Kullanım:**
```bash
python3 pupmas.py --siem --create-rule \
  --rule-type "sql_injection" \
  --severity "high"
```

**Rule Types:**
- `sql_injection`
- `xss`
- `command_injection`
- `brute_force`
- `port_scan`
- `privilege_escalation`

**Çıktı:** Sigma rule format (YAML)

---

#### Attack Schema Modülü

##### `--schema --create <SCHEMA_NAME>`
**Açıklama:** Yeni attack schema oluşturur.

**Kullanım:**
```bash
python3 pupmas.py --schema --create web_attack
```

---

##### `--schema --list`
**Açıklama:** Mevcut schemaları listeler.

**Kullanım:**
```bash
python3 pupmas.py --schema --list
```

---

##### `--schema --validate <SCHEMA_FILE>`
**Açıklama:** Schema'yı validate eder.

**Kullanım:**
```bash
python3 pupmas.py --schema --validate schemas/web_attack.yaml
```

---

#### Database Modülü

##### `--db --export <FORMAT>`
**Açıklama:** Veritabanını export eder.

**Kullanım:**
```bash
# JSON export
python3 pupmas.py --db --export json --output backup.json

# CSV export
python3 pupmas.py --db --export csv --output backup.csv
```

---

##### `--db --import <FILE>`
**Açıklama:** Veritabanını import eder.

**Kullanım:**
```bash
python3 pupmas.py --db --import backup.json
```

---

##### `--db --clean`
**Açıklama:** Eski kayıtları temizler.

**Kullanım:**
```bash
# 30 günden eski kayıtları sil
python3 pupmas.py --db --clean --days 30
```

---

## 📊 Kullanım Senaryoları

### Senaryo 1: HTB (Hack The Box) Machine Çözme

**Hedef:** HTB'de bir makineyi çözmek

**Komut:**
```bash
python3 pupmas.py --auto-scan \
  --auto-target 10.10.10.50 \
  --auto-profile active \
  --auto-type ctf \
  --auto-report html
```

**Süre:** 3-5 dakika

**Adımlar:**
1. VPN bağlantısı kur: `sudo openvpn lab_connection.ovpn`
2. Ping at: `ping 10.10.10.50`
3. PUPMAS çalıştır
4. Raporu oku: `firefox pupmas_report_*.html`
5. Açık portları ve servisleri analiz et
6. Zafiyetleri exploitla

**Beklenen Çıktı:**
- Açık portlar (örn: 22, 80, 443)
- Servis versiyonları (Apache 2.4.49, OpenSSH 8.2)
- Web zafiyetleri (SQL injection, LFI)
- CVE'ler (CVE-2021-41773)
- Exploitation başarı oranı

---

### Senaryo 2: Resmi Penetrasyon Testi

**Hedef:** Müşteri sistemini test etmek

**Komut:**
```bash
python3 pupmas.py --auto-scan \
  --auto-target customer-web.com \
  --auto-profile aggressive \
  --auto-type pentest \
  --auto-report html
```

**Süre:** 10-15 dakika

**Adımlar:**
1. Test izni al (Scope of Work imzala)
2. IP aralıklarını not et
3. PUPMAS ile kapsamlı tarama yap
4. Bulguları dokümante et
5. Raporu müşteriye sun

**Rapor İçeriği:**
- Executive Summary
- Technical Findings
- Risk Assessment
- Remediation Recommendations
- Timeline of Activities

---

### Senaryo 3: Red Team Operasyonu

**Hedef:** Kurumun savunma mekanizmalarını test etmek

**Komut:**
```bash
# Faz 1: Passive recon (tespit edilmeden)
python3 pupmas.py --auto-scan \
  --auto-target target-corp.com \
  --auto-profile passive \
  --auto-type redteam \
  --auto-no-exploit

# Faz 2: Active exploitation
python3 pupmas.py --auto-scan \
  --auto-target 192.168.10.50 \
  --auto-profile aggressive \
  --auto-type redteam \
  --auto-report json
```

**Süre:** 2-3 saat (çok fazlı)

**Özel Dikkat:**
- IDS/IPS tespit edilirse operasyonu durdur
- SOC alarmlarını izle
- Lateral movement için timeline'ı takip et
- Blue team ile koordinasyon kur

---

### Senaryo 4: Blue Team / Defensive Analysis

**Hedef:** Sistemlerdeki açık portları ve zafiyetleri tespit etmek

**Komut:**
```bash
python3 pupmas.py --auto-scan \
  --auto-target internal-server.local \
  --auto-profile active \
  --auto-type blueteam \
  --auto-report json
```

**Süre:** 3-5 dakika

**Ne Yapar:**
- Açık portları listeler
- Güncel olmayan servisleri bulur
- CVE'leri risklerine göre sıralar
- SIEM detection ruleları üretir
- Remediation önerileri sunar

**Exploitation:** Otomatik devre dışı (blueteam tipi)

---

### Senaryo 5: Bug Bounty Hunting

**Hedef:** Bir web uygulamasında zafiyet bulmak

**Komut:**
```bash
python3 pupmas.py --auto-scan \
  --auto-target app.bugcrowd-target.com \
  --auto-profile active \
  --auto-type pentest \
  --auto-report html
```

**Süre:** 5-10 dakika

**Özel Notlar:**
- Rate limiting'e dikkat et
- Scope dışı domainleri tarama
- WAF bypass teknikleri otomatik denenecek
- JSON rapor al, Burp Suite'e import et

---

### Senaryo 6: CTF Competition

**Hedef:** CTF makinelerini hızlıca enumerate et

**Komut:**
```bash
# Her makine için
for ip in 10.10.10.{50..55}; do
  python3 pupmas.py --auto-scan \
    --auto-target $ip \
    --auto-profile aggressive \
    --auto-type ctf \
    --auto-report json &
done
wait
```

**Süre:** 5-10 dakika (paralel)

**Avantajlar:**
- 6 makineyi aynı anda tara
- JSON raporları karşılaştır
- En kolay hedefi belirle
- Hızlı flag yakala

---

### Senaryo 7: Sadece Recon (Exploitation Yok)

**Hedef:** Hedef hakkında bilgi toplamak

**Komut:**
```bash
python3 pupmas.py --auto-scan \
  --auto-target example.com \
  --auto-profile passive \
  --auto-no-exploit \
  --auto-report json
```

**Süre:** 1-2 dakika

**Ne Elde Edilir:**
- IP adresi
- Açık portlar (az sayıda)
- DNS kayıtları (A, MX, TXT, NS)
- Subdomainler (wordlist based)
- HTTP başlıkları

**Exploitation Yok:** Hiçbir payload gönderilmez

---

## 📁 Çıktılar ve Raporlar

### Rapor Lokasyonu
```
./pupmas_report_YYYYMMDD_HHMMSS.html
./pupmas_report_YYYYMMDD_HHMMSS.json
```

### HTML Rapor Yapısı

#### 1. Executive Summary
- Tarama özeti
- Hedef bilgileri
- Tarama süresi
- Bulgu sayıları

#### 2. Reconnaissance Results
- **Open Ports Table:**
  - Port numarası
  - Protocol (TCP/UDP)
  - State (open/closed)
  - Service
  - Version
  - Banner

- **DNS Records:**
  - A records
  - AAAA records
  - MX records
  - NS records
  - TXT records

- **Subdomains:**
  - Subdomain listesi
  - IP adresleri
  - HTTP status codes

#### 3. Exploitation Results
- **Vulnerabilities Table:**
  - Zafiyet tipi (SQL injection, XSS, RCE, LFI, etc.)
  - Severity (Critical, High, Medium, Low)
  - URL
  - Parameter
  - Payload used
  - Response snippet
  - Associated CVE

### 🔍 Tespit Edilen Güvenlik Açıkları

PUPMAS aşağıdaki güvenlik açıklarını otomatik olarak tespit eder:

#### 1. **SQL Injection (SQLi)**
- **Tespit Yöntemi:** Error-based ve time-based injection
- **Test Payloadları:** `' OR '1'='1`, `1' AND SLEEP(5)--`
- **Severity:** Critical
- **Örnek:** `http://target/page?id=1'`

#### 2. **Cross-Site Scripting (XSS)**
- **Tespit Yöntemi:** Reflected XSS detection
- **Test Payloadları:** `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- **Severity:** High
- **Örnek:** `http://target/search?q=<script>alert(1)</script>`

#### 3. **Remote Code Execution (RCE)**
- **Tespit Yöntemi:** OS command injection
- **Test Payloadları:** `; ls`, `| whoami`, `& ping -c 3 127.0.0.1`
- **Severity:** Critical
- **Örnek:** `http://target/cmd?exec=ls`

#### 4. **IDOR (Insecure Direct Object References)**
- **Tespit Yöntemi:** Parameter tampering
- **Test:** ID parametrelerini değiştirerek unauthorized access testi
- **Severity:** High
- **Örnek:** `http://target/user?id=1` → `id=2` (başkasının profili)

#### 5. **XXE (XML External Entity)**
- **Tespit Yöntemi:** XML parser exploitation
- **Test Payloadları:** `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- **Severity:** Critical
- **Örnek:** XML upload/parsing yapan endpoint'ler

#### 6. **SSRF (Server-Side Request Forgery)**
- **Tespit Yöntemi:** Internal network probing
- **Test Payloadları:** `http://localhost`, `http://169.254.169.254/`
- **Severity:** High
- **Örnek:** `http://target/fetch?url=http://localhost:8080`

#### 7. **SSTI (Server-Side Template Injection)**
- **Tespit Yöntemi:** Template engine detection
- **Test Payloadları:** `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- **Severity:** Critical
- **Örnek:** Jinja2, Twig, Freemarker şablonları

#### 8. **Open Redirect**
- **Tespit Yöntemi:** Redirect parameter manipulation
- **Test Payloadları:** `?redirect=https://evil.com`
- **Severity:** Medium
- **Örnek:** `http://target/login?next=http://evil.com`

#### 9. **Blind SQL Injection**
- **Tespit Yöntemi:** Time-based inference
- **Test Payloadları:** `' AND SLEEP(5)--`, `'; WAITFOR DELAY '00:00:05'--`
- **Severity:** Critical
- **Örnek:** Response süresini ölçerek SQL injection tespiti

#### 10. **CORS Misconfiguration**
- **Tespit Yöntemi:** Access-Control-Allow-Origin header kontrolü
- **Risk:** Wildcard (*) veya null origin kabul edilmesi
- **Severity:** Medium
- **Örnek:** `Access-Control-Allow-Origin: *`

#### 11. **Security Headers**
PUPMAS aşağıdaki eksik/hatalı headerları tespit eder:
- ❌ **X-Frame-Options** (Clickjacking riski)
- ❌ **Strict-Transport-Security** (HTTPS zorunlu değil)
- ❌ **X-Content-Type-Options** (MIME sniffing riski)
- ❌ **X-XSS-Protection** (XSS koruma yok)
- ❌ **Content-Security-Policy** (CSP eksik)
- **Severity:** Low-Medium

### 📊 Güvenlik Açığı Deduplikasyonu

PUPMAS akıllı deduplikasyon sistemi ile aynı güvenlik açığını birden fazla kez raporlamaz:

**Deduplikasyon Kriterleri:**
- Zafiyet tipi (örn: SQL Injection)
- Normalized URL path (query string hariç)
- Aynı subdomain'deki portlar arasında

**Örnek:**
```
✓ http://example.com/page?id=1    → SQL Injection bulundu
✗ http://example.com/page?id=2    → Aynı, tekrar raporlanmaz
✓ http://example.com/admin?id=1   → Farklı path, raporlanır
```

- **Successful Exploits:**
  - Total attempts
  - Successful count
  - Success rate (%)

#### 4. CVE Analysis
- **CVE List:**
  - CVE ID
  - CVSS Score
  - Severity
  - Description
  - Affected service/version
  - References

#### 5. Timeline Visualization
- Kronolojik event listesi
- Event tipleri (color-coded)
- Timestamps
- MITRE technique mapping

#### 6. MITRE ATT&CK Mapping
- Tactics used
- Techniques applied
- Sub-techniques
- Detection methods
- Mitigation strategies

#### 7. SIEM Integration
- Generated logs
- Correlation results
- Detection rules (Sigma format)
- Alert thresholds

#### 8. Recommendations
- Immediate actions
- Short-term fixes
- Long-term strategies
- Security best practices

### JSON Rapor Yapısı

```json
{
  "metadata": {
    "scan_id": "scan_1234567890",
    "target": "10.10.10.50",
    "start_time": "2026-01-04T15:30:45",
    "end_time": "2026-01-04T15:35:12",
    "duration_seconds": 267,
    "profile": "active",
    "operation_type": "pentest"
  },
  "reconnaissance": {
    "target_ip": "10.10.10.50",
    "hostname": "target.htb",
    "alive": true,
    "open_ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 8.2p1",
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
        "cves": ["CVE-2021-41617"]
      },
      {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "version": "Apache 2.4.41",
        "banner": "Apache/2.4.41 (Ubuntu)",
        "cves": ["CVE-2021-44790", "CVE-2021-41773"]
      }
    ],
    "dns_records": {
      "A": ["10.10.10.50"],
      "MX": ["mail.target.htb"],
      "TXT": ["v=spf1 include:_spf.google.com ~all"]
    },
    "subdomains": [
      "admin.target.htb",
      "dev.target.htb",
      "api.target.htb"
    ]
  },
  "exploitation": {
    "total_attempts": 150,
    "successful_exploits": 7,
    "vulnerabilities": [
      {
        "type": "sql_injection",
        "severity": "critical",
        "url": "http://10.10.10.50/login",
        "parameter": "username",
        "payload": "admin' OR '1'='1'--",
        "response_snippet": "Welcome, admin",
        "cve": "N/A",
        "exploitable": true
      },
      {
        "type": "xss",
        "severity": "high",
        "url": "http://10.10.10.50/search",
        "parameter": "q",
        "payload": "<script>alert('XSS')</script>",
        "response_snippet": "<script>alert('XSS')</script>",
        "cve": "N/A",
        "exploitable": true
      }
    ]
  },
  "cve_analysis": [
    {
      "cve_id": "CVE-2021-44790",
      "cvss_score": 9.8,
      "severity": "critical",
      "description": "Apache HTTP Server mod_lua buffer overflow",
      "affected_version": "Apache 2.4.41",
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44790"
      ]
    }
  ],
  "timeline": {
    "timeline_id": "timeline_1641311445",
    "events": [
      {
        "timestamp": "2026-01-04T15:30:45",
        "event_type": "reconnaissance",
        "description": "Port scan started",
        "mitre_technique": "T1046"
      },
      {
        "timestamp": "2026-01-04T15:32:10",
        "event_type": "exploitation",
        "description": "SQL injection successful on /login",
        "mitre_technique": "T1190"
      }
    ]
  },
  "mitre_mapping": {
    "tactics": ["TA0043", "TA0001", "TA0002"],
    "techniques": ["T1046", "T1190", "T1059"],
    "coverage": "32%"
  },
  "siem": {
    "logs_generated": 245,
    "correlation_results": [
      {
        "pattern": "sql_injection_attempt",
        "occurrences": 12,
        "severity": "high"
      }
    ],
    "detection_rules": [
      {
        "rule_id": "rule_001",
        "rule_type": "sql_injection",
        "sigma_rule": "..."
      }
    ]
  },
  "summary": {
    "total_vulnerabilities": 7,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 0,
    "risk_score": 8.5
  }
}
```

### Database Yapısı

**Tablo: scans**
```sql
CREATE TABLE scans (
  id INTEGER PRIMARY KEY,
  scan_id TEXT UNIQUE,
  target TEXT,
  profile TEXT,
  operation_type TEXT,
  start_time TEXT,
  end_time TEXT,
  duration_seconds INTEGER,
  report_path TEXT
);
```

**Tablo: vulnerabilities**
```sql
CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY,
  scan_id TEXT,
  vuln_type TEXT,
  severity TEXT,
  url TEXT,
  parameter TEXT,
  payload TEXT,
  exploitable BOOLEAN,
  FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
);
```

**Tablo: timelines**
```sql
CREATE TABLE timelines (
  id INTEGER PRIMARY KEY,
  timeline_id TEXT UNIQUE,
  timeline_type TEXT,
  created_at TEXT
);
```

**Tablo: timeline_events**
```sql
CREATE TABLE timeline_events (
  id INTEGER PRIMARY KEY,
  timeline_id TEXT,
  timestamp TEXT,
  event_type TEXT,
  description TEXT,
  mitre_technique TEXT,
  FOREIGN KEY(timeline_id) REFERENCES timelines(timeline_id)
);
```

---

## 🐛 Sorun Giderme

### Problem 1: ModuleNotFoundError
**Hata:**
```
ModuleNotFoundError: No module named 'requests'
```

**Çözüm:**
```bash
pip install -r requirements.txt
```

---

### Problem 2: Permission Denied (Port Scanning)
**Hata:**
```
PermissionError: [Errno 1] Operation not permitted
```

**Çözüm:**
```bash
# Linux/macOS - sudo ile çalıştır
sudo python3 pupmas.py --auto-scan --auto-target target

# veya capabilities ayarla
sudo setcap cap_net_raw+ep $(which python3)
```

---

### Problem 3: Connection Timeout
**Hata:**
```
ConnectionError: Max retries exceeded
```

**Çözüm:**
1. Hedef online mı kontrol et: `ping <target>`
2. Firewall kurallarını kontrol et
3. VPN bağlantısını kontrol et (HTB için)
4. Timeout süresini artır (config.yaml)

---

### Problem 4: SSL Certificate Error
**Hata:**
```
SSLError: certificate verify failed
```

**Çözüm:**
```bash
# SSL doğrulamasını devre dışı bırak (kendi risk)
export PYTHONHTTPSVERIFY=0
python3 pupmas.py --auto-scan --auto-target target
```

---

### Problem 5: No Vulnerabilities Found
**Durum:** Tüm testler başarısız

**Çözümler:**
1. Profile'i aggressive yap: `--auto-profile aggressive`
2. WAF var mı kontrol et
3. Hedef gerçekten zafiyet içeriyor mu?
4. Manuel test yap: `curl http://target/page?id=1'`

---

### Problem 6: Out of Memory
**Hata:**
```
MemoryError: Unable to allocate array
```

**Çözüm:**
1. Passive profile kullan: `--auto-profile passive`
2. Exploit'i devre dışı bırak: `--auto-no-exploit`
3. Parallel thread sayısını azalt (code içinde düzenle)

---

### Problem 7: Database Locked
**Hata:**
```
sqlite3.OperationalError: database is locked
```

**Çözüm:**
```bash
# Başka PUPMAS instance'ı kapatın
killall python3

# veya database kullanmayın
python3 pupmas.py --auto-scan --auto-target target --auto-no-db
```

---

### Problem 8: JSON Parse Error (Rapor)
**Hata:**
```
json.decoder.JSONDecodeError: Expecting value
```

**Çözüm:**
1. HTML rapor kullan: `--auto-report html`
2. JSON'u pretty print ile kontrol et: `cat report.json | jq .`
3. Corrupt ise silip tekrar scan et

---

## 💡 İpuçları ve Best Practices

### 1. Tarama Öncesi Hazırlık
```bash
# VPN bağlantısını kontrol et (HTB için)
ping 10.10.10.50

# Hedefin canlı olduğunu kontrol et
nmap -sn 10.10.10.50

# Scope dokümanını oku
cat scope.txt
```

### 2. Optimal Profile Seçimi
- **Passive:** IDS/IPS varsa veya stealth gerekiyorsa
- **Active:** Çoğu durum için (önerilen)
- **Aggressive:** Kapsamlı test gerekiyorsa

### 3. Rapor Yönetimi
```bash
# Raporları organize et
mkdir -p reports/$(date +%Y-%m)
mv pupmas_report_*.html reports/$(date +%Y-%m)/

# Eski raporları sil
find reports/ -name "*.html" -mtime +30 -delete
```

### 4. Multiple Target Scanning
```bash
# IP aralığı için
for ip in 192.168.1.{1..254}; do
  python3 pupmas.py --auto-scan --auto-target $ip --auto-no-db &
done

# Domain listesi için
cat domains.txt | while read domain; do
  python3 pupmas.py --auto-scan --auto-target $domain
done
```

### 5. Log Analizi
```bash
# Error loglarını kontrol et
grep ERROR data/logs/pupmas.log

# Successful exploits
grep "Successful exploit" data/logs/pupmas.log
```

### 6. Performance Optimization
```bash
# Hız için
python3 pupmas.py --auto-scan --auto-target target \
  --auto-profile passive \
  --auto-no-db

# Doğruluk için
python3 pupmas.py --auto-scan --auto-target target \
  --auto-profile aggressive
```

### 7. False Positive Reduction
- XSS: Response body'de payloadın tam halini ara
- SQL Injection: Error message pattern match yap
- RCE: Command output'u kontrol et

### 8. Rapor Sunumu (Müşteriye)
```bash
# HTML'den PDF oluştur
wkhtmltopdf pupmas_report.html pupmas_report.pdf

# Screenshots ekle
firefox pupmas_report.html
# Print to PDF yap
```

### 9. Timeline Tracking
```bash
# Timeline export et
python3 pupmas.py --timeline --show timeline_123 > timeline.txt

# Visualization için
python3 pupmas.py --timeline --show timeline_123 --export svg
```

### 10. Credential Management
```bash
# API keys için
cp config/api_keys.yaml.example config/api_keys.yaml
nano config/api_keys.yaml

# .env kullan
echo "SHODAN_API_KEY=your_key" > .env
```

---

## 🔒 Güvenlik ve Yasal Uyarılar

### Yasal Kullanım
1. **İzin alın:** Hedef sistemlerin sahibinden yazılı izin alın
2. **Scope'a uyun:** Belirlenen IP/domain dışına çıkmayın
3. **NDA imzalayın:** Gizlilik anlaşması yapın
4. **DoS yapmayın:** Rate limiting kullanın

### Etik Kullanım
1. Bulduğunuz zafiyetleri sorumlu şekilde bildirin
2. Exploitation sonrası sistemi eski haline getirin
3. Verileri güvende tutun
4. Penetrasyon testi standardlarına uyun (PTES, OWASP)

### Risk Yönetimi
1. Test ortamında deneyin
2. Production'da dikkatli olun
3. Backup alın
4. Rollback planı yapın

---

## 📚 Ek Kaynaklar

### Dokümantasyon
- [README.md](README.md) - Genel bakış
- [QUICKSTART.md](QUICKSTART.md) - Hızlı başlangıç
- [AUTOMATED_PIPELINE.md](AUTOMATED_PIPELINE.md) - Pipeline detayları
- [CONTRIBUTING.md](CONTRIBUTING.md) - Katkıda bulunma

### Harici Kaynaklar
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CVE Database](https://cve.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PTES Standard](http://www.pentest-standard.org/)

### Topluluk
- GitHub Issues: [github.com/dagdelenemre/pupmas/issues](https://github.com/dagdelenemre/pupmas/issues)
- Discussions: [github.com/dagdelenemre/pupmas/discussions](https://github.com/dagdelenemre/pupmas/discussions)

---

## 📞 Destek

### Soru Sormak İçin
1. GitHub Issues açın
2. Detaylı açıklama yapın
3. Log dosyalarını paylaşın
4. Environment bilgilerini verin

### Bug Bildirimi
```bash
# System info
python3 --version
uname -a

# PUPMAS version
python3 pupmas.py --version

# Error log
cat data/logs/pupmas.log | tail -50
```

---

**Son Güncelleme:** 4 Ocak 2026  
**Versiyon:** 1.0.0  
**Lisans:** MIT
