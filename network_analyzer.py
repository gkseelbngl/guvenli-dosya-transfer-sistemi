import subprocess
import time
import re
import socket
import os

def run_iperf(server_host, port=12345, duration=10):
    """iPerf ile bant genişliği ölçümü yapar."""
    try:
        cmd = f"iperf3 -c {server_host} -p {port} -t {duration} -J"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout
        match = re.search(r'"bits_per_second":\s*(\d+\.?\d*)', output)
        if match:
            bandwidth = float(match.group(1)) / 1e6  # Mbps
            return bandwidth
        return None
    except Exception as e:
        print(f"[iPerf HATA] {e}")
        return None

def simulate_packet_loss(loss_percentage=1):
    """tc ile paket kaybı simüle eder."""
    try:
        subprocess.run("sudo tc qdisc add dev lo root netem loss 1%", shell=True)
        print(f"[tc] {loss_percentage}% paket kaybı simülasyonu başlatıldı.")
    except Exception as e:
        print(f"[tc HATA] Paket kaybı simülasyonu başlatılamadı: {e}")

def remove_packet_loss():
    """tc ile paket kaybı simülasyonunu kaldırır."""
    try:
        subprocess.run("sudo tc qdisc del dev lo root", shell=True)
        print("[tc] Paket kaybı simülasyonu kaldırıldı.")
    except Exception as e:
        print(f"[tc HATA] Simülasyon kaldırılamadı: {e}")

def compare_network_conditions(server_host):
    """Farklı ağ koşullarında performans karşılaştırması yapar."""
    results = {}
    
    # Yerel ağ (loopback)
    results['local'] = {
        'ping': calculate_ping(server_host),
        'bandwidth': run_iperf(server_host)
    }
    
    # Paket kaybı simülasyonu
    simulate_packet_loss()
    time.sleep(2)
    results['lossy'] = {
        'ping': calculate_ping(server_host),
        'bandwidth': run_iperf(server_host)
    }
    remove_packet_loss()
    
    return results

def calculate_ping(host):
    try:
        start_time = time.time()
        with socket.create_connection((host, 12345), timeout=1) as s:
            s.sendall(b"PING")
            s.recv(1)
        end_time = time.time()
        return round((end_time - start_time) * 1000, 2)
    except:
        return float('inf')

if __name__ == "__main__":
    server_host = "127.0.0.1"
    results = compare_network_conditions(server_host)
    print(f"[SONUÇLAR] Yerel Ağ: Ping={results['local']['ping']}ms, Bant Genişliği={results['local']['bandwidth']}Mbps")
    print(f"[SONUÇLAR] Paket Kaybı: Ping={results['lossy']['ping']}ms, Bant Genişliği={results['lossy']['bandwidth']}Mbps")
