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

Gerekli Python Kütüphanelerini Yükleyin:

pip install -r requirements.txt

(Eğer requirements.txt dosyanız yoksa manuel olarak: pip install scapy cryptography)

Sunucuyu Başlatın:
Yeni bir terminal açın ve sunucuyu başlatın:

python server.py

Sunucu, RSA anahtarları oluşturacak/yükleyecek ve TCP/UDP portlarında (varsayılan 12345 ve 12346) dinlemeye başlayacaktır.

İstemci GUI'sini Başlatın:
Başka bir terminal açın ve istemci GUI'sini başlatın:

python client_gui.py

Kullanım

İstemci GUI'si üzerinden sunucu IP'sini ve portlarını ayarlayabilir, dosya seçebilir ve aşağıdaki işlemleri gerçekleştirebilirsiniz:

Dosya Gönder: Seçilen dosyayı sunucuya şifreli ve güvenli bir şekilde gönderir.

Ping Testi: Sunucuya ping atarak RTT (Gidiş-Dönüş Süresi) ölçümü yapar.

Ağ Analizi: Bant genişliği ve gecikme ölçümleri yapar, ayrıca paket kaybı simülasyonunu test eder.

Güvenlik Analizi: Ağ trafiğini yakalar ve şifreleme etkinliğini (düz metin sızıntısı olup olmadığını) analiz eder.

MITM Simülasyonu: Basit bir Man-in-the-Middle saldırısını simüle eder.

Paket Enjeksiyonu: Ağa sahte paketler enjekte eder.

Wireshark Aç: Yakalanan capture.pcap dosyasını Wireshark ile açar.

Operasyonlar, GUI'deki ilerleme çubuğu ve log penceresi aracılığıyla izlenebilir.

Proje Yapısı

.
├── client_gui.py          # Tkinter tabanlı istemci arayüzü ve operasyonları
├── server.py              # TCP ve UDP bağlantılarını yöneten, dosya alımı yapan sunucu
├── ip_manipulator.py      # Düşük seviyeli IP başlığı manipülasyonu ve sağlama toplamı hesaplamaları
├── network_analyzer.py    # iPerf3, tc ve ping ile ağ performans ölçümleri ve simülasyonları
├── security_analyzer.py   # Scapy ile paket yakalama, MITM simülasyonu ve güvenlik analizi
├── requirements.txt       # Proje bağımlılıkları
├── README.md              # Bu dosya
└── uploads_secure/        # Gelen dosyaların kaydedileceği dizin (sunucu tarafı)

Katkıda Bulunma

Geliştirmeye katkıda bulunmak isterseniz, lütfen bir pull request açmaktan veya bir issue bildirmekten çekinmeyin.

Lisans

Bu proje, MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına (eğer mevcutsa) bakınız.

İletişim

Adınız Soyadınız - [E-posta adresiniz] - [LinkedIn Profiliniz (isteğe bağlı)]
