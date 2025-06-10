from scapy.all import sniff, IP, TCP, UDP, send, conf
import os
import subprocess
import sys

def get_available_interfaces():
    """Sistemdeki mevcut ağ arabirimlerini döndürür."""
    try:
        interfaces = []
        # Linux için /sys/class/net dizinini kontrol et
        if os.path.exists('/sys/class/net'):
            interfaces = [i for i in os.listdir('/sys/class/net') if i != 'lo']
        if not interfaces:
            interfaces = ['lo']  # Varsayılan olarak localhost
        return interfaces
    except Exception as e:
        print(f"[HATA] Arabirimler alınamadı: {e}")
        return ['lo']

def capture_packets(interface=None, filter_str="port 12345 or port 12346", count=10):
    """Wireshark benzeri paket yakalama yapar."""
    try:
        # Arabirim belirlenmemişse, varsayılan olarak ilk uygun arabirimi seç
        if not interface:
            available_interfaces = get_available_interfaces()
            interface = available_interfaces[0] if available_interfaces else 'lo'
            print(f"[BILGI] Varsayılan arabirim seçildi: {interface}")

        # Scapy'nin yetki kontrolü
        if os.geteuid() != 0:
            print("[HATA] Paket yakalama için root yetkileri gerekiyor. Lütfen programı 'sudo' ile çalıştırın.")
            return None

        print(f"[BILGI] Paket yakalama başlatılıyor: arabirim={interface}, filtre='{filter_str}', paket sayısı={count}")
        packets = sniff(iface=interface, filter=filter_str, count=count, timeout=10)
        if not packets:
            print("[UYARI] Hiç paket yakalanamadı. Arabirim veya filtreyi kontrol edin.")
            return None

        # Yakalanan paketleri .pcap dosyasına kaydet
        pcap_file = "capture.pcap"
        try:
            with open(pcap_file, "wb") as f:
                from scapy.utils import wrpcap
                wrpcap(f, packets)
            print(f"[Wireshark] {len(packets)} paket yakalandı ve {pcap_file} dosyasına kaydedildi.")
        except Exception as e:
            print(f"[HATA] capture.pcap dosyasına yazma başarısız: {e}")
    except PermissionError:
        print("[HATA] Paket yakalama için yeterli yetki yok. Programı 'sudo' ile çalıştırın.")
        return None
    except Exception as e:
        print(f"[HATA] Paket yakalama başarısız: {e}")
        return None

def simulate_mitm(src_ip, dst_ip, payload, transfer_id=None, port=12345):
    """Basit bir MITM simülasyonu yapar."""
    try:
        from scapy.all import IP, TCP
        # Scapy'nin yetki kontrolü
        if os.geteuid() != 0:
            print("[HATA] MITM simülasyonu için root yetkileri gerekiyor. Lütfen programı 'sudo' ile çalıştırın.")
            return False

        if transfer_id:
            payload = b"DATA" + transfer_id + payload
        forged_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=port, dport=port) / payload
        send(forged_packet, verbose=0)
        print(f"[MITM] Sahte paket gönderildi: {src_ip} -> {dst_ip}, Payload: {payload[:20]}...")
        return True
    except PermissionError:
        print("[HATA] Paket gönderimi için yeterli yetki yok. Programı 'sudo' ile çalıştırın.")
        return False
    except Exception as e:
        print(f"[HATA] MITM simülasyonu başarısız: {e}")
        return False

def analyze_pcap(file_path="capture.pcap"):
    """Yakalanan paketleri analiz eder."""
    try:
        from scapy.all import rdpcap
        if not os.path.exists(file_path):
            print(f"[HATA] {file_path} dosyası bulunamadı.")
            return

        packets = rdpcap(file_path)
        expected_ports = {12345, 12346}
        expected_ips = {"127.0.0.1"}
        plain_count = 0
        encrypted_count = 0

        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                if src_ip not in expected_ips:
                    print(f"[GÜVENLİK UYARISI] Beklenmeyen kaynak IP: {src_ip}")
                if TCP in pkt or UDP in pkt:
                    port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
                    if port not in expected_ports:
                        print(f"[GÜVENLİK UYARISI] Beklenmeyen port: {port}")
                    payload = bytes(pkt[IP].payload)
                    try:
                        payload.decode('utf-8')
                        print(f"[GÜVENLİK UYARISI] Düz metin tespit edildi: {payload[:20]}...")
                        plain_count += 1
                    except UnicodeDecodeError:
                        print("[GÜVENLİK] Payload şifreli, okunamıyor.")
                        encrypted_count += 1
        print(f"[GÜVENLİK] Analiz tamamlandı. Düz metin: {plain_count}, Şifreli: {encrypted_count}")
    except Exception as e:
        print(f"[HATA] Paket analizi başarısız: {e}")

def open_wireshark(pcap_file="capture.pcap"):
    """Wireshark ile pcap dosyasını açar."""
    try:
        if not os.path.exists(pcap_file):
            print(f"[HATA] {pcap_file} dosyası bulunamadı.")
            return False
        subprocess.run(["wireshark", pcap_file], check=True)
        print("[Wireshark] Wireshark başarıyla başlatıldı.")
        return True
    except FileNotFoundError:
        print("[HATA] Wireshark sistemde yüklü değil. Lütfen Wireshark'ı kurun.")
        return False
    except Exception as e:
        print(f"[HATA] Wireshark başlatılamadı: {e}")
        return False
