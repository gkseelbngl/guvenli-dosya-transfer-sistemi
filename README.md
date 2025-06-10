Gelişmiş Güvenli Dosya Transfer Sistemi

Proje Genel Bakışı

Bu proje, şifreli iletim, kimlik doğrulama ve bütünlük doğrulaması ile güvenli ve verimli dosya transferi sağlayan kapsamlı bir sistem geliştirmeyi amaçlamaktadır. Ağ protokollerinin derinlemesine anlaşılması için düşük seviyeli IP başlık manipülasyonu (TTL, DF bayrağı, sağlama toplamı hesaplaması) entegre edilmiştir. Ayrıca, sistemin farklı ağ koşulları altındaki performansını değerlendirmek amacıyla ağ performansı analizleri (gecikme, bant genişliği, paket kaybı) ve güvenlik analizleri/saldırı simülasyonları gerçekleştirilmiştir.

Proje, bilgisayar ağları, siber güvenlik ve ağ performans analizi konularında uygulamalı bir deneyim sunar.

Özellikler

Bu sistem aşağıdaki temel ve ek özelliklere sahiptir:

Temel Özellikler

Dosya Aktarım Sistemi:

Ağ üzerinden güvenli dosya gönderme ve alma desteği.

Büyük dosyalar için manuel paket parçalanması ve alıcı tarafta yeniden birleştirme.

SHA-256 hash kullanarak bütünlük doğrulaması ve güvenilir hata algılama mekanizmaları.

Güvenlik Mekanizmaları:

Aktarım sırasında dosyaları korumak için AES-256-CBC simetrik şifrelemesi.

RSA (2048-bit) asimetrik şifreleme ile AES oturum anahtarı değişimi.

Önceden paylaşılan token ile istemci kimlik doğrulama.

Düşük Seviyeli IP Başlık İşleme:

IP başlıklarının (TTL, DF bayrağı) manuel olarak değiştirilmesi ve işlenmesi.

İletimden önce IP sağlama toplamının manuel hesaplanması ve doğrulanması.

Alıcı tarafta paket yeniden birleştirmesinin analizi.

Ağ Performans Ölçümü:

TCP bağlantısı üzerinden Gidiş-Dönüş Süresi (RTT) ile gecikme ölçümü.

iPerf3 entegrasyonu ile bant genişliği ölçümü.

tc (traffic control) kullanarak paket kaybı ve ağ tıkanıklığı simülasyonu.

Farklı ağ koşullarının (Wi-Fi, kablolu, yerel vs. uzak) performans karşılaştırması.

Güvenlik Analizi ve Saldırı Simülasyonu:

Scapy ile paket yakalama ve analizi (Wireshark benzeri).

Şifreli verilerin paket yakalamalarında okunamaz olduğunu doğrulama.

Basit Man-in-the-Middle (MITM) ve paket enjeksiyonu saldırısı simülasyonları.

Yakalanan paketleri Wireshark ile açma yeteneği.

Bonus Özellikler (Uygulama İçi Simülasyonlar)

Hibrit TCP/UDP Anahtarlama Simülasyonu: Ağ koşullarına (ping) göre otomatik protokol seçimi (şu an rastgele).

Dinamik Sıkışıklık Kontrolü Simülasyonu: Verimli bant genişliği kullanımı için hız adaptasyonu.

Grafiksel Kullanıcı Arayüzü (GUI): Dosya aktarım görselleştirmeleri için basit bir arayüz.

Gelişmiş Saldırı Simülasyonları: Daha karmaşık saldırı senaryoları ve tespit mekanizmaları.

Kullanılan Teknolojiler

Programlama Dili: Python 3.x

GUI: Tkinter

Şifreleme: cryptography kütüphanesi (AES, RSA, SHA-256)

Paket Manipülasyonu ve Yakalama: Scapy

Ağ Analizi Araçları: iPerf3, netstat, ping (simüle edilmiş), tc (Linux Traffic Control)

Diğer Python Kütüphaneleri: os, threading, time, math, uuid, random, re, subprocess, socket, struct

Kurulum ve Çalıştırma

Önkoşullar

Python 3.x yüklü olmalı.

Aşağıdaki Python kütüphaneleri pip ile yüklenmelidir:

pip install scapy cryptography

Harici ağ araçları yüklü olmalıdır:

iPerf3: Sisteminizde yüklü olmalı (örn. sudo apt install iperf3 veya brew install iperf3).

Wireshark: Paket yakalama ve analizi için yüklü olmalı (örn. sudo apt install wireshark).

tc (Traffic Control): Linux sistemlerde bulunur, ağ koşullarını simüle etmek için kullanılır.

ip_manipulator.py, security_analyzer.py ve network_analyzer.py gibi bazı modüllerin paket yakalama ve ağ manipülasyonu özellikleri root/administrator yetkileri gerektirebilir (sudo ile çalıştırmak gerekebilir).

Adımlar

Depoyu Klonlayın:

git clone https://github.com/kullanici_adiniz/guvenli-dosya-transfer-sistemi.git
cd guvenli-dosya-transfer-sistemi

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
