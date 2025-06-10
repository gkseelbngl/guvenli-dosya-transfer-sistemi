from scapy.all import IP, Raw, send
import struct
import socket
import os

def calculate_checksum(data):
    """IP veya TCP/UDP için sağlama toplamını hesaplar."""
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff
    return checksum

def send_custom_ip_packet(src_ip, dst_ip, payload, ttl=64, flags=0):
    """Özel IP paketi oluşturur ve gönderir."""
    ip_packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, flags=flags)
    ip_packet = ip_packet / Raw(payload)
    
    # Sağlama toplamını manuel olarak hesapla
    ip_packet.chksum = None
    raw_packet = bytes(ip_packet)
    ip_packet.chksum = calculate_checksum(raw_packet[:20])
    
    # Ham soket ile gönder
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.sendto(bytes(ip_packet), (dst_ip, 0))
    sock.close()

def receive_custom_ip_packet():
    """Özel IP paketlerini alır ve doğrular."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind(('0.0.0.0', 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    while True:
        packet, addr = sock.recvfrom(65535)
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        total_length = iph[2]
        chksum = iph[5]
        
        # Sağlama toplamını doğrula
        calc_chksum = calculate_checksum(ip_header)
        if calc_chksum != 0:
            print(f"[IP HATA] Sağlama toplamı doğrulaması başarısız: {chksum} != {calc_chksum}")
            continue
        
        payload = packet[ihl * 4:]
        return addr[0], payload

if __name__ == "__main__":
    # Test için
    send_custom_ip_packet("127.0.0.1", "127.0.0.1", b"Test Payload", ttl=32, flags="DF")
    src_ip, payload = receive_custom_ip_packet()
    print(f"[IP ALINDI] Kaynak: {src_ip}, Yük: {payload}")
