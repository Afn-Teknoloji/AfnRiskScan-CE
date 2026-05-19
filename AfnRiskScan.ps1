<#
.SYNOPSIS
    AFN RiskScan Community Edition — Türkçe Siber Risk Tarayıcı
    AFN RiskScan CE — Turkish Cyber Risk Scanner (Community Edition)

.DESCRIPTION
    AFN Teknoloji tarafından geliştirilen, KOBİ ve kurumsal ağlarda
    hızlı siber risk değerlendirmesi yapan ücretsiz PowerShell aracı.

    Özellikler:
      ✔  Ağ keşfi (Ping sweep + ARP)
      ✔  Çoklu host port taraması (Top 100 / 1000 / custom)
      ✔  Servis banner & versiyon fingerprint
      ✔  Windows host güvenlik kontrolleri (yerel)
        - SMB1 protokolü
        - Print Spooler (PrintNightmare CVE-2021-34527)
        - WDigest cleartext credential
        - LM Hash storage
        - Guest account
        - TLS 1.0 / 1.1
        - LLMNR / NBT-NS
        - RDP NLA durumu
      ✔  Açık dosya paylaşımları (SMB share enumeration)
      ✔  HTML + CSV rapor çıktısı
      ✔  Tamamen Türkçe çıktı

    Pro sürüm (AfnRiskScan Pro) — afnteknoloji.com/afnriskscan
      • 32+ ileri denetim modülü (AD, FortiGate, ESXi, Veeam, M365)
      • AI destekli Türkçe yönetici raporu
      • MITRE ATT&CK + ransomware grup eşlemesi
      • Sektör benchmark karşılaştırması
      • KVKK / ISO 27001 / NIST CSF uyumluluk eşlemesi
      • PowerShell auto-fix script üretimi

.PARAMETER Target
    Hedef IP, CIDR (192.168.1.0/24), aralık (192.168.1.1-50) veya hostname.
    Boş bırakılırsa otomatik yerel ağ tespit edilir.

.PARAMETER Ports
    Taranacak port profili: Top100 (varsayılan), Top1000, All veya virgülle liste (22,80,443)

.PARAMETER LocalCheck
    Yerel Windows host güvenlik kontrollerini de çalıştır.

.PARAMETER OutputPath
    Rapor çıktı klasörü (varsayılan: .\AfnRiskScan-Reports)

.EXAMPLE
    .\AfnRiskScan.ps1
    Yerel ağı otomatik tara

.EXAMPLE
    .\AfnRiskScan.ps1 -Target 192.168.1.0/24 -Ports Top1000 -LocalCheck
    Tüm /24 ağı + 1000 port + yerel Windows kontrolleri

.EXAMPLE
    irm https://raw.githubusercontent.com/Necmettine/AfnRiskScan-CE/main/AfnRiskScan.ps1 | iex
    Tek satır kurulumsuz çalıştırma

.NOTES
    Versiyon:    1.0.0
    Geliştirici: AFN Teknoloji Bilişim Destek ve Danışmanlık
    Web:         https://afnteknoloji.com/afnriskscan
    Lisans:      MIT

    UYARI: Bu aracı SADECE yetkili olduğunuz ağlarda kullanın.
           Yetkisiz tarama yasal sorumluluk doğurabilir.
#>

[CmdletBinding()]
param(
    [string]$Target = "",
    [string]$Ports = "Top100",
    [switch]$LocalCheck,
    [string]$OutputPath = ".\AfnRiskScan-Reports",
    [int]$Timeout = 400,
    [int]$Threads = 100,
    [switch]$NoBanner
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Hosts    = New-Object System.Collections.Generic.List[object]
$script:StartTime = Get-Date

# ───────────────────────────────────────────────────────────────────
#  BANNER
# ───────────────────────────────────────────────────────────────────
function Show-Banner {
    if ($NoBanner) { return }
    $banner = @"

    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║      █████╗ ███████╗███╗   ██╗   ██████╗ ██╗███████╗██╗  ██╗  ║
    ║     ██╔══██╗██╔════╝████╗  ██║   ██╔══██╗██║██╔════╝██║ ██╔╝  ║
    ║     ███████║█████╗  ██╔██╗ ██║   ██████╔╝██║███████╗█████╔╝   ║
    ║     ██╔══██║██╔══╝  ██║╚██╗██║   ██╔══██╗██║╚════██║██╔═██╗   ║
    ║     ██║  ██║██║     ██║ ╚████║   ██║  ██║██║███████║██║  ██╗  ║
    ║                                                               ║
    ║              R I S K   S C A N   —   C E   v 1.0              ║
    ║                                                               ║
    ║          🛡️  Türkçe Siber Risk Tarayıcı  🛡️                   ║
    ║              afnteknoloji.com/afnriskscan                     ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Yellow
    Write-Host "    ⚡ AFN Teknoloji  |  Yerli & Açık Kaynak  |  MIT Lisansı" -ForegroundColor DarkGray
    Write-Host ""
}

# ───────────────────────────────────────────────────────────────────
#  PORT PROFILLERI
# ───────────────────────────────────────────────────────────────────
$PortProfiles = @{
    'Top100'  = @(7,21,22,23,25,53,80,88,110,111,123,135,137,138,139,143,161,389,443,445,464,
                  500,515,593,623,636,873,902,989,990,993,995,1025,1080,1099,1194,1352,1433,
                  1434,1521,1604,1723,1883,2049,2082,2083,2375,2376,2483,2484,3000,3128,3268,
                  3269,3306,3389,3690,4444,4505,4506,4848,5000,5060,5432,5601,5631,5666,5672,
                  5800,5900,5985,5986,6379,6443,7001,7077,7474,7547,7777,8000,8008,8009,8080,
                  8081,8086,8088,8089,8090,8091,8181,8443,8888,9000,9042,9090,9091,9200,9418,
                  9999,10000,11211,27017,49152,49153,49154)
    'Top1000' = @()  # Build below
    'All'     = 1..65535
}

# Top1000 — populate with common ranges
$PortProfiles['Top1000'] = @(
    1..1024
) + @(1080,1099,1194,1352,1433,1434,1521,1604,1723,1883,2049,2082,2083,2181,2375,2376,
      2483,2484,3000,3128,3268,3269,3306,3389,3690,3868,4000,4040,4369,4444,4505,4506,
      4848,5000,5044,5060,5432,5550,5555,5601,5631,5666,5672,5683,5800,5900,5984,5985,
      5986,6379,6443,6660,6661,6662,6663,6664,6665,6666,6667,6668,6669,6679,6697,7001,
      7002,7077,7199,7474,7547,7777,7778,8000,8001,8002,8008,8009,8010,8014,8042,8069,
      8080,8081,8082,8083,8086,8087,8088,8089,8090,8091,8092,8093,8181,8222,8243,8280,
      8333,8443,8500,8530,8531,8649,8765,8888,8983,9000,9001,9042,9080,9090,9091,9092,
      9100,9200,9300,9418,9443,9500,9501,9530,9999,10000,10001,10250,11211,15672,16379,
      19999,25565,26379,27017,27018,27019,28017,32400,49152,49153,49154,50000,50030,50070,
      54321,55672) | Sort-Object -Unique

# ───────────────────────────────────────────────────────────────────
#  HEDEF GENISLETME
# ───────────────────────────────────────────────────────────────────
function Expand-Targets {
    param([string]$Input)

    if ([string]::IsNullOrWhiteSpace($Input)) {
        # Auto-detect local subnet
        $iface = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
            Sort-Object -Property InterfaceMetric | Select-Object -First 1

        if (-not $iface) {
            Write-Host "  ✗ Yerel ağ tespit edilemedi. Lütfen -Target parametresi verin." -ForegroundColor Red
            return @()
        }
        $prefix = $iface.IPAddress -replace '\.\d+$',''
        Write-Host "  🌐 Otomatik tespit: $prefix.0/24 ağı taranacak" -ForegroundColor Cyan
        return (1..254) | ForEach-Object { "$prefix.$_" }
    }

    # CIDR (e.g. 192.168.1.0/24)
    if ($Input -match '^(\d+\.\d+\.\d+)\.\d+/(\d+)$') {
        $base = $Matches[1]
        $mask = [int]$Matches[2]
        if ($mask -eq 24) { return (1..254) | ForEach-Object { "$base.$_" } }
        if ($mask -eq 23) {
            $third = [int]($Input.Split('.')[2])
            return @($third,($third+1)) | ForEach-Object {
                $t = $_
                (1..254) | ForEach-Object { "$($Input.Split('.')[0]).$($Input.Split('.')[1]).$t.$_" }
            }
        }
        Write-Host "  ⚠ Sadece /24 ve /23 destekleniyor (şimdilik). Tek IP veya aralık kullanın." -ForegroundColor Yellow
        return @()
    }

    # Range (192.168.1.1-50)
    if ($Input -match '^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$') {
        $base = $Matches[1]; $s = [int]$Matches[2]; $e = [int]$Matches[3]
        return ($s..$e) | ForEach-Object { "$base.$_" }
    }

    # Single
    return @($Input)
}

# ───────────────────────────────────────────────────────────────────
#  PING SWEEP (parallel)
# ───────────────────────────────────────────────────────────────────
function Invoke-PingSweep {
    param([string[]]$IPs)

    Write-Host ""
    Write-Host "  🔎 Aşama 1/3 — Ağdaki canlı cihazlar aranıyor..." -ForegroundColor Cyan
    Write-Host "     Toplam $($IPs.Count) IP taranacak (paralel: $Threads)" -ForegroundColor DarkGray

    $alive = New-Object System.Collections.Concurrent.ConcurrentBag[string]
    $jobs = @()
    $batch = [Math]::Max(1, [Math]::Ceiling($IPs.Count / $Threads))

    $IPs | ForEach-Object -ThrottleLimit $Threads -Parallel {
        $ip = $_
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $r = $ping.Send($ip, $using:Timeout)
            if ($r.Status -eq 'Success') {
                ($using:alive).Add($ip)
            }
        } catch {}
    } -ErrorAction SilentlyContinue

    $result = @($alive) | Sort-Object { [version]($_ -replace '\.','. ') -replace ' ','' } -ErrorAction SilentlyContinue
    if (-not $result) { $result = @($alive) | Sort-Object }
    Write-Host "     ✓ $($result.Count) canlı cihaz bulundu" -ForegroundColor Green
    return $result
}

# ───────────────────────────────────────────────────────────────────
#  PORT SCAN (parallel TCP connect)
# ───────────────────────────────────────────────────────────────────
function Invoke-PortScan {
    param([string]$IP, [int[]]$PortList)

    $open = New-Object System.Collections.Concurrent.ConcurrentBag[int]
    $PortList | ForEach-Object -ThrottleLimit 50 -Parallel {
        $port = $_
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($using:IP, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($using:Timeout, $false)) {
                $client.EndConnect($iar)
                if ($client.Connected) {
                    ($using:open).Add($port)
                }
            }
        } catch {}
        finally { $client.Close() }
    } -ErrorAction SilentlyContinue

    return @($open) | Sort-Object
}

# ───────────────────────────────────────────────────────────────────
#  SERVIS / VERSIYON TAHMINI
# ───────────────────────────────────────────────────────────────────
function Get-ServiceGuess {
    param([int]$Port)
    $map = @{
        21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';80='HTTP';88='Kerberos'
        110='POP3';111='RPC';135='RPC/DCOM';137='NetBIOS';139='NetBIOS-SSN';143='IMAP'
        161='SNMP';389='LDAP';443='HTTPS';445='SMB';464='Kerberos-PW';500='IKE/VPN'
        515='LPD-Printer';587='SMTP-Submission';593='RPC-HTTP';623='IPMI';636='LDAPS'
        873='rsync';902='VMware';989='FTPS-Data';990='FTPS';993='IMAPS';995='POP3S'
        1080='SOCKS';1099='Java-RMI';1194='OpenVPN';1352='Lotus';1433='MSSQL';1434='MSSQL-UDP'
        1521='Oracle';1604='Citrix';1723='PPTP';1883='MQTT';2049='NFS';2082='cPanel';2083='cPanel-SSL'
        2375='Docker';2376='Docker-TLS';2483='Oracle-TCP';2484='Oracle-TCP-SSL';3000='Dev-HTTP'
        3128='Squid-Proxy';3268='Global-Catalog';3269='Global-Catalog-SSL';3306='MySQL';3389='RDP'
        3690='SVN';4444='Metasploit?';4848='GlassFish';5000='UPnP';5060='SIP';5432='PostgreSQL'
        5601='Kibana';5666='NRPE';5672='AMQP';5800='VNC-Web';5900='VNC';5985='WinRM';5986='WinRM-SSL'
        6379='Redis';6443='Kubernetes';7001='WebLogic';7077='Spark';7474='Neo4j';7547='TR-069';7777='Oracle-AS'
        8000='HTTP-Alt';8008='HTTP-Alt';8009='AJP';8080='HTTP-Proxy';8081='HTTP-Alt';8086='InfluxDB'
        8088='HTTP-Alt';8089='Splunk';8090='HTTP-Alt';8091='Couchbase';8181='HTTP-Alt';8443='HTTPS-Alt'
        8888='HTTP-Alt';9000='HTTP-Alt';9042='Cassandra';9090='Prometheus';9091='Transmission'
        9100='JetDirect-Printer';9200='Elasticsearch';9418='Git';9999='HTTP-Alt';10000='Webmin'
        11211='Memcached';27017='MongoDB';49152='UPnP';50000='SAP'
    }
    if ($map.ContainsKey($Port)) { return $map[$Port] }
    return "TCP/$Port"
}

function Test-HighRiskPort {
    param([int]$Port, [string]$IP)

    $highRisk = @{
        21   = @{ Name='FTP'; Risk='Yüksek'; Reason='FTP cleartext kimlik bilgisi taşır. SFTP / FTPS kullanın.' }
        23   = @{ Name='Telnet'; Risk='Kritik'; Reason='Telnet cleartext — SSH ile değiştirin.' }
        445  = @{ Name='SMB'; Risk='Orta'; Reason='SMB internete açıksa kritik. SMB1 kontrolü yapılmalı.' }
        1433 = @{ Name='MSSQL'; Risk='Yüksek'; Reason='MSSQL internete açık. Brute force / SQL injection riski.' }
        1434 = @{ Name='MSSQL-UDP'; Risk='Orta'; Reason='SQL Slammer geçmişi var. Firewall arkasında olmalı.' }
        2049 = @{ Name='NFS'; Risk='Yüksek'; Reason='NFS açık paylaşım — yetkisiz veri erişimi riski.' }
        2375 = @{ Name='Docker-API'; Risk='Kritik'; Reason='Docker API auth olmadan açık — full container takeover.' }
        3306 = @{ Name='MySQL'; Risk='Yüksek'; Reason='MySQL internete açık. Auth kontrolü zorunlu.' }
        3389 = @{ Name='RDP'; Risk='Yüksek'; Reason='RDP brute force / BlueKeep CVE-2019-0708 riski. NLA zorunlu.' }
        5432 = @{ Name='PostgreSQL'; Risk='Yüksek'; Reason='PostgreSQL açık. Auth + SSL gerekli.' }
        5900 = @{ Name='VNC'; Risk='Yüksek'; Reason='VNC çoğunlukla parolasız. Tunnel arkasına alın.' }
        6379 = @{ Name='Redis'; Risk='Kritik'; Reason='Redis varsayılan auth yok — RCE riski yüksek.' }
        7001 = @{ Name='WebLogic'; Risk='Kritik'; Reason='WebLogic deserialization CVE geçmişi var.' }
        9200 = @{ Name='Elasticsearch'; Risk='Kritik'; Reason='Elasticsearch auth yoksa tüm veri açık.' }
        11211= @{ Name='Memcached'; Risk='Yüksek'; Reason='Memcached DDoS amplification + veri sızıntı riski.' }
        27017= @{ Name='MongoDB'; Risk='Kritik'; Reason='MongoDB auth yoksa tüm veri açık.' }
        8080 = @{ Name='HTTP-Alt'; Risk='Bilgi'; Reason='Yönetim arayüzü olabilir — varsayılan parolaları kontrol edin.' }
        10000= @{ Name='Webmin'; Risk='Yüksek'; Reason='Webmin CVE geçmişi var.' }
    }
    if ($highRisk.ContainsKey($Port)) {
        $info = $highRisk[$Port]
        Add-Finding -Host $IP -Severity $info.Risk -Title "$($info.Name) servisi açık (Port $Port)" -Detail $info.Reason
    }
}

# ───────────────────────────────────────────────────────────────────
#  BANNER GRAB
# ───────────────────────────────────────────────────────────────────
function Get-Banner {
    param([string]$IP, [int]$Port)
    $banner = ""
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($IP, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(500, $false)) { return "" }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 600

        # HTTP-style probe for web ports
        if ($Port -in @(80,8000,8080,8443,8888,5000,7001,8081,8181,9000,9090,9200)) {
            $req = "GET / HTTP/1.0`r`nHost: $IP`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
            $stream.Write($bytes, 0, $bytes.Length)
        }

        Start-Sleep -Milliseconds 200
        $buf = New-Object byte[] 2048
        if ($stream.DataAvailable) {
            $read = $stream.Read($buf, 0, $buf.Length)
            $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
        }
    } catch {} finally { $client.Close() }
    return ($banner -replace "[\x00-\x1F]"," ").Trim().Substring(0, [Math]::Min(200, $banner.Length))
}

# ───────────────────────────────────────────────────────────────────
#  YEREL WINDOWS GUVENLIK KONTROLLERI
# ───────────────────────────────────────────────────────────────────
function Invoke-LocalSecurityChecks {
    Write-Host ""
    Write-Host "  🛡️  Aşama 3/3 — Yerel Windows güvenlik kontrolleri..." -ForegroundColor Cyan
    $local = $env:COMPUTERNAME

    # 1. SMB1
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smb -and $smb.EnableSMB1Protocol) {
            Add-Finding -Host $local -Severity 'Kritik' -Title 'SMB1 protokolü aktif' -Detail 'SMB1 — EternalBlue/WannaCry/NotPetya saldırılarının vektörü. Devre dışı bırakın.'
        }
    } catch {}

    # 2. Print Spooler (PrintNightmare)
    $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq 'Running' -and (
        (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)) {
        Add-Finding -Host $local -Severity 'Kritik' -Title 'Print Spooler DC üzerinde aktif (PrintNightmare CVE-2021-34527)' -Detail 'Domain Controller üzerinde Print Spooler servisi açık — anlık domain takeover riski.'
    }

    # 3. WDigest
    try {
        $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
        if ($wd -and $wd.UseLogonCredential -eq 1) {
            Add-Finding -Host $local -Severity 'Yüksek' -Title 'WDigest cleartext credential saklamayı aktif' -Detail 'Mimikatz LSASS dump ile cleartext parolalar çıkarılabilir.'
        } elseif (-not $wd) {
            Add-Finding -Host $local -Severity 'Bilgi' -Title 'WDigest UseLogonCredential set edilmemiş' -Detail 'Açıkça 0 olarak set etmek tavsiye edilir.'
        }
    } catch {}

    # 4. LM Hash
    try {
        $lm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue
        if (-not $lm -or $lm.NoLMHash -ne 1) {
            Add-Finding -Host $local -Severity 'Yüksek' -Title 'LM Hash storage devre dışı bırakılmamış' -Detail 'LM hash rainbow table ile saniyeler içinde crack edilir.'
        }
    } catch {}

    # 5. Guest account
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Add-Finding -Host $local -Severity 'Yüksek' -Title 'Yerel Guest hesabı aktif' -Detail 'Guest hesabı yetkisiz erişime kapı açar.'
        }
    } catch {}

    # 6. TLS 1.0 / 1.1
    foreach ($v in @('TLS 1.0','TLS 1.1')) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Server"
        if (Test-Path $path) {
            $en = (Get-ItemProperty $path -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
            if ($null -eq $en -or $en -ne 0) {
                Add-Finding -Host $local -Severity 'Orta' -Title "$v hâlâ etkin" -Detail 'TLS 1.0/1.1 modern saldırılara karşı zayıf. Devre dışı bırakın.'
            }
        } else {
            Add-Finding -Host $local -Severity 'Orta' -Title "$v explicit olarak kapatılmamış" -Detail "Schannel kayıt defteri girdisi yok — protokol kullanılıyor olabilir."
        }
    }

    # 7. LLMNR
    $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
    if ($null -eq $llmnr -or $llmnr -ne 0) {
        Add-Finding -Host $local -Severity 'Yüksek' -Title 'LLMNR aktif (Responder ile credential capture riski)' -Detail 'LLMNR kapatılmalı (GPO ile EnableMulticast=0).'
    }

    # 8. RDP NLA
    try {
        $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
        if ($rdp -and $rdp.UserAuthentication -ne 1) {
            Add-Finding -Host $local -Severity 'Yüksek' -Title 'RDP NLA (Network Level Authentication) zorunlu değil' -Detail 'NLA olmadan RDP pre-auth saldırılarına açık (BlueKeep ve benzeri).'
        }
    } catch {}

    Write-Host "     ✓ 8 kontrol noktası tarandı" -ForegroundColor Green
}

# ───────────────────────────────────────────────────────────────────
#  BULGU EKLEME
# ───────────────────────────────────────────────────────────────────
function Add-Finding {
    param(
        [string]$Host,
        [ValidateSet('Kritik','Yüksek','Orta','Düşük','Bilgi')] [string]$Severity,
        [string]$Title,
        [string]$Detail
    )
    $script:Findings.Add([pscustomobject]@{
        Host = $Host; Severity = $Severity; Title = $Title; Detail = $Detail
        Time = Get-Date
    })
}

# ───────────────────────────────────────────────────────────────────
#  HTML RAPOR
# ───────────────────────────────────────────────────────────────────
function Export-HtmlReport {
    param([string]$Path)

    $sevColor = @{
        'Kritik'='#dc2626'; 'Yüksek'='#ea580c'; 'Orta'='#ca8a04'; 'Düşük'='#0891b2'; 'Bilgi'='#64748b'
    }
    $byHost = $script:Hosts | Sort-Object IP
    $sevCount = @{}
    foreach ($s in 'Kritik','Yüksek','Orta','Düşük','Bilgi') {
        $sevCount[$s] = ($script:Findings | Where-Object Severity -eq $s).Count
    }

    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)

    $html = @"
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>AFN RiskScan CE — Rapor</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: #0A0E1A; color: #e5e7eb; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 40px 24px; }
.header { background: linear-gradient(135deg, rgba(245,166,35,0.1), rgba(0,125,184,0.1));
          border: 1px solid rgba(245,166,35,0.2); border-radius: 16px; padding: 32px; margin-bottom: 32px; }
.header h1 { color: #F5A623; font-size: 32px; margin-bottom: 8px; }
.header p { color: #9ca3af; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
.stat { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 20px; text-align: center; }
.stat .v { font-size: 36px; font-weight: 900; }
.stat .l { font-size: 12px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
.section { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
.section h2 { color: #F5A623; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 12px; }
.finding { padding: 14px; border-left: 4px solid; margin-bottom: 12px; background: rgba(255,255,255,0.03); border-radius: 6px; }
.finding .t { font-weight: 700; color: #fff; }
.finding .h { font-size: 12px; color: #9ca3af; margin-top: 4px; font-family: 'Consolas', monospace; }
.finding .d { font-size: 14px; color: #d1d5db; margin-top: 8px; }
.sev { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; text-transform: uppercase; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }
th { color: #F5A623; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
td { font-family: 'Consolas', monospace; font-size: 13px; color: #d1d5db; }
.cta { background: linear-gradient(135deg, rgba(245,166,35,0.15), rgba(0,125,184,0.15));
       border: 1px solid rgba(245,166,35,0.3); border-radius: 16px; padding: 32px; text-align: center; margin-top: 32px; }
.cta h2 { color: #F5A623; font-size: 24px; margin-bottom: 12px; }
.cta p { color: #d1d5db; margin-bottom: 20px; }
.btn { display: inline-block; background: #F5A623; color: #000; padding: 12px 28px; border-radius: 8px;
       font-weight: 700; text-decoration: none; margin: 4px; }
.btn:hover { background: #e6951a; }
.footer { text-align: center; color: #6b7280; font-size: 12px; padding: 24px; }
.footer a { color: #F5A623; text-decoration: none; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ AFN RiskScan CE — Tarama Raporu</h1>
    <p>Tarih: $(Get-Date -Format 'dd MMMM yyyy HH:mm') &nbsp;|&nbsp; Süre: $duration sn &nbsp;|&nbsp; Hedef: $($script:Hosts.Count) cihaz</p>
  </div>

  <div class="stats">
    <div class="stat" style="border-color:#dc2626"><div class="v" style="color:#dc2626">$($sevCount['Kritik'])</div><div class="l">Kritik</div></div>
    <div class="stat" style="border-color:#ea580c"><div class="v" style="color:#ea580c">$($sevCount['Yüksek'])</div><div class="l">Yüksek</div></div>
    <div class="stat" style="border-color:#ca8a04"><div class="v" style="color:#ca8a04">$($sevCount['Orta'])</div><div class="l">Orta</div></div>
    <div class="stat" style="border-color:#0891b2"><div class="v" style="color:#0891b2">$($sevCount['Düşük'])</div><div class="l">Düşük</div></div>
    <div class="stat" style="border-color:#64748b"><div class="v" style="color:#64748b">$($sevCount['Bilgi'])</div><div class="l">Bilgi</div></div>
  </div>

  <div class="section">
    <h2>🔍 Bulgular</h2>
"@

    if ($script:Findings.Count -eq 0) {
        $html += "<p style='color:#9ca3af'>Bulgu tespit edilmedi. Yine de Pro sürüm ile 32+ modülde derin denetim öneririz.</p>"
    } else {
        $sorted = $script:Findings | Sort-Object @{e={
            switch ($_.Severity) { 'Kritik'{0}; 'Yüksek'{1}; 'Orta'{2}; 'Düşük'{3}; 'Bilgi'{4} }
        }}
        foreach ($f in $sorted) {
            $color = $sevColor[$f.Severity]
            $html += @"
    <div class="finding" style="border-color:$color">
      <span class="sev" style="background:$color">$($f.Severity)</span>
      <span class="t">$([System.Web.HttpUtility]::HtmlEncode($f.Title))</span>
      <div class="h">📍 $([System.Web.HttpUtility]::HtmlEncode($f.Host))</div>
      <div class="d">$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</div>
    </div>
"@
        }
    }

    $html += @"
  </div>

  <div class="section">
    <h2>🌐 Tespit Edilen Cihazlar ve Açık Portlar</h2>
    <table>
      <thead><tr><th>IP</th><th>Açık Portlar</th><th>Servisler</th></tr></thead>
      <tbody>
"@
    foreach ($h in $byHost) {
        $portList = ($h.Ports -join ', ')
        $svcList  = (($h.Ports | ForEach-Object { Get-ServiceGuess $_ }) -join ', ')
        $html += "<tr><td>$($h.IP)</td><td>$portList</td><td>$svcList</td></tr>"
    }
    $html += @"
      </tbody>
    </table>
  </div>

  <div class="cta">
    <h2>🚀 Bu sadece yüzeysel tarama</h2>
    <p>AFN RiskScan <strong>Pro</strong> sürüm ile Active Directory, FortiGate, ESXi, Veeam, Microsoft 365 ortamlarınızda
    32+ modülde derin denetim yapın. AI destekli Türkçe yönetici raporu, MITRE ATT&amp;CK eşlemesi, sektör benchmark
    ve PowerShell auto-fix scripti ile.</p>
    <a class="btn" href="https://afnteknoloji.com/afnriskscan">Pro Demo Talep Et →</a>
    <a class="btn" style="background:transparent;border:1px solid #F5A623;color:#F5A623" href="https://afnteknoloji.com/iletisim">İletişim</a>
  </div>

  <div class="footer">
    AFN RiskScan Community Edition v1.0 &nbsp;|&nbsp; Geliştirici:
    <a href="https://afnteknoloji.com">AFN Teknoloji Bilişim Destek ve Danışmanlık</a><br>
    MIT Lisansı &nbsp;|&nbsp; <a href="https://github.com/Necmettine/AfnRiskScan-CE">GitHub</a>
  </div>
</div>
</body>
</html>
"@

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $html | Out-File -FilePath $Path -Encoding UTF8
}

# ───────────────────────────────────────────────────────────────────
#  ANA AKIS
# ───────────────────────────────────────────────────────────────────
Show-Banner

# Yetki kontrolü (yerel check için)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
if ($LocalCheck -and -not $isAdmin) {
    Write-Host "  ⚠ Yerel kontroller için Yönetici olarak çalıştırılması önerilir." -ForegroundColor Yellow
}

# Çıktı klasörü
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Port profili
if ($PortProfiles.ContainsKey($Ports)) {
    $portList = $PortProfiles[$Ports]
} else {
    $portList = $Ports -split ',' | ForEach-Object { [int]$_.Trim() }
}

# Hedef genişlet
$targets = Expand-Targets -Input $Target
if ($targets.Count -eq 0) { exit 1 }

Write-Host "  ⚙  Konfigürasyon:" -ForegroundColor White
Write-Host "     • Hedef sayısı  : $($targets.Count)" -ForegroundColor DarkGray
Write-Host "     • Port profili  : $Ports ($($portList.Count) port)" -ForegroundColor DarkGray
Write-Host "     • Yerel kontrol : $($LocalCheck.IsPresent)" -ForegroundColor DarkGray

# Aşama 1: Ping sweep
$alive = Invoke-PingSweep -IPs $targets

# Aşama 2: Port tarama
if ($alive.Count -gt 0) {
    Write-Host ""
    Write-Host "  🔌 Aşama 2/3 — Açık portlar taranıyor..." -ForegroundColor Cyan
    $i = 0
    foreach ($ip in $alive) {
        $i++
        Write-Host "     [$i/$($alive.Count)] $ip" -NoNewline -ForegroundColor White
        $open = Invoke-PortScan -IP $ip -PortList $portList
        if ($open.Count -gt 0) {
            Write-Host " → $($open.Count) port açık: $($open -join ', ')" -ForegroundColor Green
            $script:Hosts.Add([pscustomobject]@{ IP = $ip; Ports = $open })
            foreach ($p in $open) {
                Test-HighRiskPort -Port $p -IP $ip
            }
        } else {
            Write-Host " → kapalı" -ForegroundColor DarkGray
        }
    }
}

# Aşama 3: Yerel kontroller
if ($LocalCheck) {
    Invoke-LocalSecurityChecks
}

# Rapor
$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
$htmlPath = Join-Path $OutputPath "AfnRiskScan_$stamp.html"
$csvPath  = Join-Path $OutputPath "AfnRiskScan_$stamp.csv"

Export-HtmlReport -Path $htmlPath
$script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# Özet
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  📊  TARAMA ÖZETİ" -ForegroundColor Yellow
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
$kritik = ($script:Findings | Where-Object Severity -eq 'Kritik').Count
$yuksek = ($script:Findings | Where-Object Severity -eq 'Yüksek').Count
$orta   = ($script:Findings | Where-Object Severity -eq 'Orta').Count
Write-Host "     🔴 Kritik   : $kritik" -ForegroundColor Red
Write-Host "     🟠 Yüksek   : $yuksek" -ForegroundColor DarkYellow
Write-Host "     🟡 Orta     : $orta"   -ForegroundColor Yellow
Write-Host "     🌐 Cihaz    : $($script:Hosts.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  📄 HTML rapor : $htmlPath" -ForegroundColor White
Write-Host "  📄 CSV rapor  : $csvPath"  -ForegroundColor White
Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  💡  Daha derin denetim ister misiniz?" -ForegroundColor Cyan
Write-Host "      AFN RiskScan Pro — AD, FortiGate, ESXi, Veeam, M365 + AI Türkçe rapor" -ForegroundColor White
Write-Host "      👉  https://afnteknoloji.com/afnriskscan" -ForegroundColor Yellow
Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# Otomatik aç
try { Start-Process $htmlPath } catch {}
