<div align="center">

# 🛡️ AFN RiskScan — Community Edition

### Türkçe Siber Risk Tarayıcı  •  Tek PowerShell Dosyası  •  Kurulum Yok

[![Stars](https://img.shields.io/github/stars/afnteknoloji/AfnRiskScan-CE?style=for-the-badge&color=F5A623)](https://github.com/afnteknoloji/AfnRiskScan-CE/stargazers)
[![Downloads](https://img.shields.io/github/downloads/afnteknoloji/AfnRiskScan-CE/total?style=for-the-badge&color=00C853)](https://github.com/afnteknoloji/AfnRiskScan-CE/releases)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Made in Türkiye](https://img.shields.io/badge/Made_in-Türkiye-E30A17?style=for-the-badge)](https://afnteknoloji.com)

**Bir komutla** ağınızdaki cihazları keşfedin, açık portları bulun, Windows güvenlik açıklarını tespit edin.
Yöneticiye sunulabilir **HTML/CSV rapor** otomatik üretilir — hem de **tamamen Türkçe**.

[🚀 Hızlı Başla](#-hızlı-başla) • [⚡ Özellikler](#-özellikler) • [📸 Ekran Görüntüleri](#-ekran-görüntüleri) • [💎 Pro Sürüm](#-afn-riskscan-pro) • [🤝 Katkıda Bulun](#-katkıda-bulun)

</div>

---

## 🚀 Hızlı Başla

### Tek Satırla Çalıştır (Kurulum Yok)

```powershell
irm https://raw.githubusercontent.com/afnteknoloji/AfnRiskScan-CE/main/AfnRiskScan.ps1 | iex
```

> ⚠️ Tek satır komut yerel ağınızı otomatik tespit edip tarar. Tarama süresi: **~2 dakika**.

### Veya İndirip Çalıştır

```powershell
# 1. İndir
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/afnteknoloji/AfnRiskScan-CE/main/AfnRiskScan.ps1" -OutFile AfnRiskScan.ps1

# 2. Execution policy (gerekirse)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Çalıştır
.\AfnRiskScan.ps1
```

---

## ⚡ Özellikler

| Yetenek | CE (Bedava) | [Pro](https://afnteknoloji.com/afnriskscan) |
|---|:---:|:---:|
| 🌐 Ağ keşfi (Ping sweep + ARP) | ✅ | ✅ |
| 🔌 Çoklu host port taraması (Top 100/1000/Custom) | ✅ | ✅ |
| 🔍 Servis fingerprint + banner grab | ✅ | ✅ |
| 🛡️ Windows yerel güvenlik kontrolleri (8 madde) | ✅ | ✅ |
| 📄 HTML + CSV rapor (Türkçe) | ✅ | ✅ |
| 🏢 Active Directory derin denetim (Kerberoasting, DCSync, KRBTGT, Ghost) | ❌ | ✅ |
| 🔥 FortiGate / Sophos API denetim | ❌ | ✅ |
| ☁️ ESXi / vCenter / Veeam audit | ❌ | ✅ |
| 📧 Microsoft 365 (Graph API) — MFA, CA, Secure Score | ❌ | ✅ |
| 🤖 AI destekli Türkçe yönetici raporu (GPT-4 / Claude / Gemini) | ❌ | ✅ |
| 🎯 MITRE ATT&CK — Tehdit aktör eşlemesi (Conti, LockBit, BlackCat...) | ❌ | ✅ |
| 📊 Sektör benchmark karşılaştırması | ❌ | ✅ |
| ⚖️ KVKK / ISO 27001 / NIST CSF / CIS Controls eşleme | ❌ | ✅ |
| 🔧 PowerShell auto-fix script üretimi | ❌ | ✅ |
| 📑 Yönetici PDF + sözleşme şablonları | ❌ | ✅ |

### 🛡️ CE'nin Kontrol Ettiği Windows Riskleri

- ✔️ **SMB1 protokolü aktif** (EternalBlue / WannaCry / NotPetya vektörü)
- ✔️ **Print Spooler — PrintNightmare** (CVE-2021-34527, DC takeover)
- ✔️ **WDigest cleartext credential** (Mimikatz LSASS dump riski)
- ✔️ **LM Hash storage** (Rainbow table ile saniyede kırılır)
- ✔️ **Yerel Guest hesabı**
- ✔️ **TLS 1.0 / 1.1** etkinliği
- ✔️ **LLMNR / NBT-NS** (Responder credential capture)
- ✔️ **RDP NLA** durumu (BlueKeep koruması)

### 🔥 Yüksek Riskli Açık Port Tespiti

Bulunan açık portlar otomatik olarak risk değerlendirmesinden geçer:

| Port | Servis | Risk |
|---|---|:---:|
| 23 | Telnet | 🔴 Kritik |
| 2375 | Docker API | 🔴 Kritik |
| 6379 | Redis | 🔴 Kritik |
| 9200 | Elasticsearch | 🔴 Kritik |
| 27017 | MongoDB | 🔴 Kritik |
| 3389 | RDP | 🟠 Yüksek |
| 1433 | MSSQL | 🟠 Yüksek |
| 21 | FTP | 🟠 Yüksek |
| 445 | SMB (ext) | 🟡 Orta |
| ... | +15 servis | |

---

## 📸 Ekran Görüntüleri

<div align="center">

### Renkli Konsol Çıktısı
<img src="docs/screenshots/console.png" alt="Console Output" width="800"/>

### HTML Rapor — Dark Theme
<img src="docs/screenshots/report.png" alt="HTML Report" width="800"/>

</div>

---

## 📖 Kullanım Örnekleri

```powershell
# 1. Yerel ağı otomatik tara (varsayılan)
.\AfnRiskScan.ps1

# 2. Belirli bir /24 ağı + Top 1000 port
.\AfnRiskScan.ps1 -Target 192.168.1.0/24 -Ports Top1000

# 3. IP aralığı + yerel Windows kontrolleri
.\AfnRiskScan.ps1 -Target 10.10.10.1-50 -LocalCheck

# 4. Tek host + özel port listesi
.\AfnRiskScan.ps1 -Target server01 -Ports 22,80,443,3389,5985

# 5. Tam port taraması (yavaş)
.\AfnRiskScan.ps1 -Target 192.168.1.10 -Ports All

# 6. Özel çıktı klasörü
.\AfnRiskScan.ps1 -OutputPath C:\Raporlar\Musteri-X
```

### Parametreler

| Parametre | Açıklama | Varsayılan |
|---|---|---|
| `-Target` | IP, CIDR, aralık veya hostname | Otomatik tespit |
| `-Ports` | `Top100`, `Top1000`, `All` veya `80,443,3389` | `Top100` |
| `-LocalCheck` | Yerel Windows kontrollerini de çalıştır | `false` |
| `-OutputPath` | Rapor çıktı klasörü | `.\AfnRiskScan-Reports` |
| `-Timeout` | Port bağlantı timeout (ms) | `400` |
| `-Threads` | Paralel ping/port sayısı | `100` |

---

## 💎 AFN RiskScan Pro

CE — saatler içinde **yüzeysel** risk haritası verir.
**Pro** — günler süren gerçek bir penetrasyon testi seviyesinde derin denetim yapar.

<div align="center">

### Pro sürümde sizi bekleyenler

🏢 **Active Directory Derin Denetim**
Kerberoasting, AS-REP roastable, DCSync, KRBTGT yaşı, Unconstrained Delegation, Ghost devices, Stale admins

🤖 **AI Destekli Türkçe Yönetici Raporu**
GPT-4 / Claude / Gemini ile yöneticinize sunulacak hale getirilmiş Türkçe analiz, eylem planı, 30/60/90 gün roadmap

🎯 **MITRE ATT&CK + Tehdit Aktör Eşlemesi**
"Ortamınız %78 LockBit 3.0 saldırı kalıbına uyuyor" — Conti, LockBit, BlackCat, FIN7, Volt Typhoon, Lazarus, EsxiArgs, DeadBolt

📊 **Sektör Benchmark Karşılaştırması**
"Finans sektörü ortalamasından %42 daha riskli durumdasınız" — Türkiye KOBİ'leri için 15+ sektör profili

⚖️ **KVKK / ISO 27001 / NIST CSF / CIS Controls**
Her bulgu için uyumluluk kontrol maddesi eşlemesi — denetim hazırlığı için kanıt seti

🔧 **PowerShell Auto-Fix Script**
PrintNightmare, SMB1, WDigest, LM Hash, TLS 1.0, Office Macro, KRBTGT rotate — 12+ bulgu için hazır .ps1

[**🚀 Pro Demo Talep Et — afnteknoloji.com/afnriskscan**](https://afnteknoloji.com/afnriskscan)

</div>

---

## 🔐 Güvenlik & Etik Kullanım

> **⚠️ UYARI**
> Bu aracı **SADECE yetkili olduğunuz ağlarda** kullanın.
> Yetkisiz ağ taraması Türkiye'de 5237 sayılı TCK 243. madde (bilişim sistemine girme) kapsamında **suç teşkil eder.**

CE script tamamen **offline** çalışır. Hiçbir veriniz internete gönderilmez.
Kod **MIT lisansı** altında açıktır — istediğiniz gibi inceleyin, değiştirin, paylaşın.

---

## 🤝 Katkıda Bulun

Pull request açın, issue raporlayın, ⭐ verin!

- 🐛 **Bug Report** — [Issue aç](https://github.com/afnteknoloji/AfnRiskScan-CE/issues/new)
- 💡 **Özellik Önerisi** — [Discussion başlat](https://github.com/afnteknoloji/AfnRiskScan-CE/discussions)
- 📝 **Dokümantasyon iyileştirmesi** — PR gönderin

### Geliştirme Yol Haritası

- [ ] IPv6 desteği
- [ ] Nmap XML çıktısı export
- [ ] Linux / macOS PowerShell Core uyumluluğu
- [ ] Zafiyet tarama eklentisi (Nuclei template'leri)
- [ ] Slack / Teams webhook entegrasyonu

---

## ❓ S.S.S.

**Nessus / OpenVAS varken neden bunu kullanayım?**
Nessus pahalı, OpenVAS karmaşık. CE — **2 dakikada Türkçe rapor** üretir. Pro sürüm ise Türkiye KOBİ'lerine özel KVKK/sektör eşlemesi ile **lokal pazarda eşsizdir**.

**Antivirus uyarı veriyor?**
Bazı AV ürünleri PowerShell tabanlı tarayıcıları "potansiyel zararlı" olarak işaretler. Kod açık — incelemenizi öneririz. İmza istiyorsanız Pro sürümde dijital imzalı binary mevcut.

**Hangi PowerShell sürümünde çalışır?**
Windows PowerShell **5.1+** ve PowerShell Core **7+**. Paralel işlemler için PS 7+ önerilir.

**Yönetici hakkı gerekli mi?**
Sadece **`-LocalCheck`** parametresi için. Ağ tarama normal kullanıcıyla çalışır.

---

## 👥 AFN Teknoloji Hakkında

**AFN Teknoloji Bilişim Destek ve Danışmanlık**, Türkiye'de KOBİ ve kurumsal firmalara **siber güvenlik, sistem yönetimi, yedekleme ve felaket kurtarma** çözümleri sunan bir BT danışmanlık firmasıdır.

🤝 İş Ortaklıklarımız: **Fortinet • Veeam Silver Partner • VMware • Microsoft • Sophos • Dell • HPE • Aruba**

🌐 [afnteknoloji.com](https://afnteknoloji.com) — 📧 [info@afnteknoloji.com](mailto:info@afnteknoloji.com) — 📞 İletişim: [afnteknoloji.com/iletisim](https://afnteknoloji.com/iletisim)

---

<div align="center">

**Bu araç işine yaradıysa ⭐ vermeyi unutma!**

Made with ❤️ in Türkiye by [AFN Teknoloji](https://afnteknoloji.com)

</div>
