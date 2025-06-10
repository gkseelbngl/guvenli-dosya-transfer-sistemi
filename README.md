# 🚀 Gelişmiş Güvenli Dosya Transfer Sistemi

Bu proje, **şifreli iletim**, **kimlik doğrulama** ve **bütünlük doğrulaması** ile güvenli ve verimli dosya transferi sağlayan kapsamlı bir sistem geliştirmeyi amaçlamaktadır.  
Aynı zamanda düşük seviyeli IP başlık manipülasyonu, ağ performans ölçümleri ve güvenlik analizleri ile bilgisayar ağları, siber güvenlik ve ağ analizi konularında uygulamalı deneyim sunar.

---

## ✨ Özellikler

### 🔐 Temel Güvenli Dosya Aktarım Özellikleri
- Ağ üzerinden güvenli dosya gönderme ve alma desteği.
- Büyük dosyalar için manuel paket parçalama ve alıcıda yeniden birleştirme.
- SHA-256 hash ile dosya bütünlüğü doğrulaması ve hata algılama.

### 🛡️ Güvenlik Mekanizmaları
- **AES-256-CBC** ile dosya şifreleme.
- **RSA 2048-bit** ile AES anahtarı değişimi.
- Önceden paylaşılan token ile istemci kimlik doğrulaması.

### 🧠 Düşük Seviyeli IP Başlık İşleme
- TTL, DF bayrağı gibi IP başlıklarının manuel olarak ayarlanması.
- IP sağlama toplamı manuel hesaplanarak doğrulama yapılması.
- Paket parçalama ve yeniden birleştirme analizi.

### 📡 Ağ Performans Ölçümü
- RTT (Round Trip Time) ile gecikme analizi.
- **iPerf3** ile bant genişliği ölçümü.
- **tc (Traffic Control)** ile ağ tıkanıklığı ve paket kaybı simülasyonu.
- Farklı ağ ortamlarının karşılaştırmalı performans analizi.

### 🛡️ Güvenlik Analizi ve Saldırı Simülasyonu
- **Scapy** ile paket yakalama ve analiz.
- Şifreli veri trafiğinde düz metin kaçağının olmadığını doğrulama.
- MITM ve paket enjeksiyonu saldırılarının simülasyonu.
- Yakalanan paketlerin Wireshark ile görüntülenmesi.

### 🎁 Bonus Özellikler
- Ağ durumuna göre TCP/UDP protokol seçimi (şu an rastgele).
- Dinamik sıkışıklık kontrolü ile hız adaptasyonu.
- **Tkinter GUI** ile basit görsel kullanıcı arayüzü.
- Gelişmiş saldırı simülasyonları ve tespit mekanizmaları.

---

## 🛠️ Kullanılan Teknolojiler

| Bileşen         | Teknoloji                           |
|-----------------|--------------------------------------|
| **Dil**         | Python 3.x                           |
| **GUI**         | Tkinter                              |
| **Şifreleme**   | cryptography (AES, RSA, SHA-256)     |
| **Ağ Araçları** | Scapy, iPerf3, tc, netstat, ping     |
| **Kütüphaneler**| `os`, `threading`, `socket`, `uuid`, `struct`, vb. |

---

## ⚙️ Kurulum ve Çalıştırma

### 🔧 Gereksinimler
- Python 3.x
- `pip install scapy cryptography`
- Aşağıdaki harici araçlar:
  - iPerf3 → `sudo apt install iperf3` veya `brew install iperf3`
  - Wireshark → `sudo apt install wireshark`
  - tc (Linux sistemlerde yerleşiktir)

### 🧱 Adımlar

#### 1. Depoyu Klonlayın
```bash
git clone https://github.com/kullanici_adiniz/guvenli-dosya-transfer-sistemi.git
cd guvenli-dosya-transfer-sistemi
```

#### 2. Gerekli Python Kütüphanelerini Yükleyin
```bash
pip install -r requirements.txt
# veya manuel olarak:
pip install scapy cryptography
```

#### 3. Sunucuyu Başlatın
Yeni bir terminal açın ve sunucuyu başlatın:
```bash
python server.py
```

#### 4. İstemci GUI'sini Başlatın
```bash
python client_gui.py
```

## 🚀 Kullanım

İstemci GUI'si üzerinden sunucu IP'sini ve portlarını ayarlayabilir, dosya seçebilir ve aşağıdaki işlemleri gerçekleştirebilirsiniz:

- Dosya Gönder: Dosyayı güvenli ve şifreli olarak sunucuya gönderir.
- Ping Testi: RTT süresini ölçer.
- Ağ Analizi: Bant genişliği, gecikme ve paket kaybı testleri yapar.
- Güvenlik Analizi: Trafik yakalama ve şifreleme etkinliği analizi yapar.
- MITM Simülasyonu: Man-in-the-Middle saldırısı gerçekleştirir.
- Paket Enjeksiyonu: Ağa sahte paketler enjekte eder.
- Wireshark Aç: capture.pcap dosyasını Wireshark ile görüntüler.

Tüm işlemler GUI’deki ilerleme çubuğu ve log penceresiyle takip edilebilir.

## 📁 Proje Yapısı

```bash
.
├── client_gui.py           # Tkinter tabanlı istemci arayüzü
├── server.py               # TCP/UDP tabanlı sunucu kodu
├── ip_manipulator.py       # IP başlık manipülasyonu
├── network_analyzer.py     # Ağ analiz ve performans ölçümü
├── security_analyzer.py    # Güvenlik analizleri ve simülasyonları
├── requirements.txt        # Python bağımlılıkları
├── README.md               # Proje dökümantasyonu
└── uploads_secure/         # Alınan dosyaların saklandığı klasör
```

## 🤝 Katkıda Bulunma

Geliştirmeye katkıda bulunmak isterseniz:

- Bir pull request gönderebilir
- Ya da bir issue oluşturarak bildirimde bulunabilirsiniz.

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır.

## ✉️ İletişim

📧 E-posta: gkseelbngl34@gmail.com

🔗 LinkedIn: https://www.linkedin.com/in/gkseelbngl/

📺 Proje Demo Videosu: https://www.youtube.com/watch?v=KmPX3SUIaqs
