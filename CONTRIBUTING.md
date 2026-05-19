# Katkıda Bulunma Rehberi

AFN RiskScan CE'ye katkıda bulunmak istediğiniz için teşekkürler! 🎉

## Nasıl Katkıda Bulunabilirsiniz?

### 🐛 Bug Raporlamak

[Issues](https://github.com/Afn-Teknoloji/AfnRiskScan-CE/issues/new) sayfasından açın. Lütfen şunları belirtin:

- PowerShell sürümü (`$PSVersionTable`)
- Windows sürümü
- Kullandığınız komut
- Hata mesajı (tam)
- Beklenen davranış

### 💡 Yeni Özellik Önermek

[Discussions](https://github.com/Afn-Teknoloji/AfnRiskScan-CE/discussions) açın. Özelliğin:
- Hangi sorunu çözeceğini
- Hedef kullanıcı kitlesini
- Pro sürümle çakışmayan bir özellik olduğunu (örn. AI, AD modülü Pro'ya aittir)

### 🔧 Kod Katkısı (Pull Request)

1. Repoyu fork'layın
2. Feature branch açın: `git checkout -b feature/yeni-ozellik`
3. Değişikliklerinizi commit edin: `git commit -m 'Yeni: özellik açıklaması'`
4. Branch'inizi push'layın: `git push origin feature/yeni-ozellik`
5. Pull Request açın

### 📝 Kod Standartları

- PowerShell **5.1** ve **7+** uyumluluğunu koruyun
- Fonksiyon isimleri PowerShell konvansiyonunda (Verb-Noun): `Get-`, `Invoke-`, `Test-`
- Türkçe yorumlar tercih edilir (kullanıcı kitlesi Türk)
- `Write-Host` yerine `Write-Verbose` / `Write-Output` kullanın (çıktı kısımları hariç)

## Pro Sürüme Ait Olan Konular

CE bedava ve açık kalacak. Aşağıdaki özellikler Pro sürüme aittir, **CE'ye PR olarak gönderilmemelidir**:

- AI entegrasyonu (OpenAI / Anthropic / Gemini)
- Active Directory derin denetim (Kerberoasting, DCSync, KRBTGT)
- FortiGate / Sophos REST API
- ESXi / vCenter / Veeam audit
- Microsoft 365 Graph API
- MITRE ATT&CK eşlemesi
- KVKK / ISO 27001 uyumluluk modülleri
- PowerShell auto-fix script üretimi

Bu özellikler için iş ortaklığı veya ticari lisanslama için: [info@afnteknoloji.com](mailto:info@afnteknoloji.com)

## Lisans

Tüm katkılar **MIT lisansı** altında kabul edilir.
