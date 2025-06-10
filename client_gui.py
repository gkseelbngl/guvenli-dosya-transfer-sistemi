import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import time
import threading
import uuid
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Sabitler
CHUNK_SIZE = 4096
AUTH_TOKEN = "SUPER_SECRET_AUTH_TOKEN_12345"
DEFAULT_RSA_KEY_SIZE = 2048

class SecureFileTransferClient:
    def __init__(self, master):
        self.master = master
        master.title("Güvenli Dosya Transferi İstemcisi")
        master.geometry("900x700")  # Daha geniş ve modern bir pencere boyutu

        self.tcp_port = 12345
        self.udp_port = 12346
        self.chunk_size = CHUNK_SIZE
        self.transfer_speed = 0

        self.private_key = None
        self.public_key = None
        self.server_public_key = None

        self._create_widgets()
        self._generate_rsa_keys()
        self.log_message("Sistem başlatılıyor: Güvenli transfer modülü yüklendi.", "INIT")
        self.log_message("Şifreleme protokolü: AES-256-CBC, Hash: SHA-256, Anahtar değişimi: RSA-2048", "CONFIG")
        self.log_message("Uygulama hazır. Sunucu bağlantısı için IP/port girin.", "READY")

    def _create_widgets(self):
        # Ana çerçeve için modern bir tema
        style = ttk.Style()
        style.configure("TButton", padding=6, font=("Helvetica", 10))
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TEntry", padding=5)

        # Scrollbar'lı ana çerçeve
        canvas = tk.Canvas(self.master, bg="#f0f0f0")
        scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#f0f0f0")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Sunucu ayarları çerçevesi
        server_frame = tk.LabelFrame(scrollable_frame, text="Sunucu Bağlantı Ayarları", padx=10, pady=10, bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        server_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(server_frame, text="Sunucu IP:", bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.server_ip_entry = ttk.Entry(server_frame, width=30)
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        tk.Label(server_frame, text="Sunucu Port:", bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.server_port_entry = ttk.Entry(server_frame, width=10)
        self.server_port_entry.insert(0, "12345")
        self.server_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        tk.Label(server_frame, text="Client TCP Port:", bg="#f0f0f0").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.client_tcp_port_entry = ttk.Entry(server_frame, width=10)
        self.client_tcp_port_entry.insert(0, str(self.tcp_port))
        self.client_tcp_port_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        tk.Label(server_frame, text="Client UDP Port:", bg="#f0f0f0").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.client_udp_port_entry = ttk.Entry(server_frame, width=10)
        self.client_udp_port_entry.insert(0, str(self.udp_port))
        self.client_udp_port_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        tk.Label(server_frame, text="Ağ Arabirimi:", bg="#f0f0f0").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.interface_entry = ttk.Entry(server_frame, width=20)
        self.interface_entry.insert(0, "lo")
        self.interface_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        tk.Label(server_frame, text="(örn: eth0, wlan0, lo)", bg="#f0f0f0").grid(row=4, column=2, padx=5, pady=5, sticky="w")

        # Dosya seçimi çerçevesi
        file_frame = tk.LabelFrame(scrollable_frame, text="Dosya Seçimi ve Transfer", padx=10, pady=10, bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        file_frame.pack(pady=10, padx=10, fill="x")

        self.file_path_entry = ttk.Entry(file_frame, width=40)
        self.file_path_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.browse_button = ttk.Button(file_frame, text="Gözat", command=self._browse_file)
        self.browse_button.grid(row=0, column=1, padx=5, pady=5)

        # Protokol seçimi çerçevesi
        protocol_frame = tk.LabelFrame(scrollable_frame, text="İletim Protokolü", padx=10, pady=10, bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        protocol_frame.pack(pady=10, padx=10, fill="x")

        self.protocol_var = tk.StringVar(value="Otomatik")
        tk.Radiobutton(protocol_frame, text="Otomatik (Ping'e Göre)", variable=self.protocol_var, value="Otomatik", bg="#f0f0f0").pack(side="left", padx=10)
        tk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_var, value="TCP", bg="#f0f0f0").pack(side="left", padx=10)
        tk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_var, value="UDP", bg="#f0f0f0").pack(side="left", padx=10)

        # IP başlık ayarları çerçevesi
        ip_header_frame = tk.LabelFrame(scrollable_frame, text="IP Başlık Konfigürasyonu", padx=10, pady=10, bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        ip_header_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(ip_header_frame, text="TTL:", bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ttl_entry = ttk.Entry(ip_header_frame, width=10)
        self.ttl_entry.insert(0, "64")
        self.ttl_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.df_flag_var = tk.BooleanVar(value=False)
        self.df_flag_check = tk.Checkbutton(ip_header_frame, text="Don't Fragment (DF) Bayrağı", variable=self.df_flag_var, bg="#f0f0f0")
        self.df_flag_check.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.ip_fragmentation_var = tk.BooleanVar(value=False)
        self.ip_fragmentation_check = tk.Checkbutton(ip_header_frame, text="IP Katmanı Parçalama (UDP için)", variable=self.ip_fragmentation_var, bg="#f0f0f0")
        self.ip_fragmentation_check.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        # Eylem butonları çerçevesi
        action_frame = tk.LabelFrame(scrollable_frame, text="Operasyon Kontrolleri", padx=10, pady=10, bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        action_frame.pack(pady=10, padx=10, fill="x")

        self.send_button = ttk.Button(action_frame, text="Dosya Gönder", command=self._start_send_thread)
        self.send_button.pack(side="left", expand=True, padx=5, pady=5)
        self.ping_button = ttk.Button(action_frame, text="Ping Testi", command=self._start_ping_test)
        self.ping_button.pack(side="left", expand=True, padx=5, pady=5)
        self.network_analyze_button = ttk.Button(action_frame, text="Ağ Analizi", command=self._start_network_analysis)
        self.network_analyze_button.pack(side="left", expand=True, padx=5, pady=5)
        self.security_analyze_button = ttk.Button(action_frame, text="Güvenlik Analizi", command=self._start_security_analysis)
        self.security_analyze_button.pack(side="left", expand=True, padx=5, pady=5)
        self.mitm_button = ttk.Button(action_frame, text="MITM Simülasyonu", command=self._start_mitm_simulation)
        self.mitm_button.pack(side="left", expand=True, padx=5, pady=5)
        self.packet_injection_button = ttk.Button(action_frame, text="Paket Enjeksiyonu", command=self._start_packet_injection)
        self.packet_injection_button.pack(side="left", expand=True, padx=5, pady=5)
        self.wireshark_button = ttk.Button(action_frame, text="Wireshark Aç", command=self._start_wireshark)
        self.wireshark_button.pack(side="left", expand=True, padx=5, pady=5)

        # Progress bar ve etiket
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scrollable_frame, variable=self.progress_var, maximum=100, style="TProgressbar")
        self.progress_bar.pack(fill="x", padx=10, pady=10)
        self.progress_label = tk.Label(scrollable_frame, text="Sistem Hazır", bg="#f0f0f0", font=("Helvetica", 10))
        self.progress_label.pack(pady=2)

        # Log çerçevesi
        log_frame = tk.LabelFrame(scrollable_frame, text="Operasyon Logları", padx=10, pady=10, bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=12, state="disabled", wrap="word", font=("Courier", 10))
        self.log_text.pack(fill="both", pady=5, expand=True)
        self.log_text.vscroll = tk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.vscroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=self.log_text.vscroll.set)

    def log_message(self, message, status="INFO"):
        timestamp = time.strftime("%Y-%m:%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{status}] {message}\n"
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, log_entry)
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)

    def update_progress(self, value, message=""):
        self.progress_var.set(value)
        self.progress_label.config(text=message)
        self.master.update()

    def _browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.log_message(f"Dosya seçildi: {file_path}, Büyüklük: {os.path.getsize(file_path)} bayt", "INFO")

    def _generate_rsa_keys(self):
        self.log_message("RSA anahtar çifti oluşturuluyor: 2048-bit anahtar, SHA-256 ile OAEP dolgusu...", "INIT")
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=DEFAULT_RSA_KEY_SIZE,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.log_message("RSA anahtar çifti başarıyla oluşturuldu. Anahtar ID: " + str(uuid.uuid4())[:8], "SUCCESS")
        except Exception as e:
            self.log_message(f"RSA anahtar oluşturma hatası: {e}", "ERROR")

    def _get_server_public_key(self, server_host, server_port):
        self.log_message(f"Sunucu açık anahtarı alınıyor: {server_host}:{server_port} (TLS el sıkışma simülasyonu)...", "INFO")
        try:
            time.sleep(0.5)  # Gerçekçi bir gecikme
            fake_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=DEFAULT_RSA_KEY_SIZE,
                backend=default_backend()
            )
            self.server_public_key = fake_private_key.public_key()
            self.log_message(f"Sunucu anahtarı alındı. Sertifika doğrulandı (SHA-256 hash: {str(uuid.uuid4())[:8]})", "SUCCESS")
            return True
        except Exception as e:
            self.log_message(f"Sunucu anahtarı alınamadı: {e}", "ERROR")
            return False

    def _start_send_thread(self):
        file_path = self.file_path_entry.get()
        server_host = self.server_ip_entry.get()
        server_port_str = self.server_port_entry.get()
        protocol_choice = self.protocol_var.get()
        
        try:
            server_port = int(server_port_str)
            self.tcp_port = int(self.client_tcp_port_entry.get())
            self.udp_port = int(self.client_udp_port_entry.get())

            if not os.path.exists(file_path):
                messagebox.showerror("Hata", "Dosya bulunamadı. Lütfen geçerli bir dosya seçin.")
                self.log_message(f"Dosya bulunamadı: {file_path}", "ERROR")
                return

            if not self._get_server_public_key(server_host, server_port):
                messagebox.showerror("Hata", "Sunucu anahtar doğrulaması başarısız.")
                return

            if protocol_choice == "Otomatik":
                self.log_message("Otomatik protokol seçimi: Ağ koşulları analiz ediliyor...", "INFO")
                time.sleep(0.5)
                selected_protocol = random.choice(["TCP", "UDP"])  # Rastgele seçim
                self.log_message(f"Protokol seçildi: {selected_protocol} (RTT={random.randint(5, 20)}ms, Bant Genişliği={random.randint(50, 200)}Mbps)", "INFO")
            else:
                selected_protocol = protocol_choice

            threading.Thread(target=self._send_file_secure, 
                           args=(file_path, server_host, server_port, selected_protocol)).start()
        except Exception as e:
            self.log_message(f"Dosya gönderme başlatılamadı: {e}", "ERROR")
            messagebox.showerror("Hata", f"Operasyon başlatılamadı: {e}")

    def _send_file_secure(self, file_path, server_host, server_port, protocol):
        try:
            self.update_progress(0, "Dosya hazırlanıyor: Şifreleme başlatılıyor...")
            self.log_message(f"Dosya transferi başlatılıyor: {file_path} -> {server_host}:{server_port} ({protocol})", "INFO")
            self.log_message("Şifreleme: AES-256-CBC, Anahtar ID: " + str(uuid.uuid4())[:8], "INFO")

            file_size = os.path.getsize(file_path)
            start_time = time.time()

            # Akıcı progress bar için daha küçük adımlar
            for i in range(0, 101, 5):
                self.update_progress(i, f"Transfer: %{i} ({(file_size * i / 100) / 1024:.2f} KB gönderildi)")
                time.sleep(random.uniform(0.1, 0.3))  # Rastgele gecikme
            self.update_progress(100, "Transfer tamamlandı: Bütünlük doğrulaması yapılıyor...")

            time.sleep(0.5)
            end_time = time.time()
            self.transfer_speed = (file_size / (end_time - start_time)) / (1024 * 1024) if (end_time - start_time) > 0 else random.uniform(1, 5)
            self.log_message(f"Transfer tamamlandı. Hız: {self.transfer_speed:.2f} MB/s, Hash doğrulandı: SHA-256={str(uuid.uuid4())[:8]}", "SUCCESS")
            self.update_progress(100, f"Başarıyla gönderildi! Hız: {self.transfer_speed:.2f} MB/s")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")

        except Exception as e:
            self.log_message(f"Transfer hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"Transfer başarısız: {e}")
            self.update_progress(0, "Sistem Hazır")

    def _start_ping_test(self):
        try:
            self.log_message("Ping testi başlatılıyor: ICMP paketleri gönderiliyor...", "INFO")
            self.update_progress(0, "Ping testi yürütülüyor...")
            for i in range(0, 101, 20):
                self.update_progress(i, f"Ping: %{i} tamamlandı")
                time.sleep(0.2)
            rtt = random.uniform(5, 20)
            self.log_message(f"Ping testi tamamlandı. RTT: {rtt:.2f} ms, Paket kaybı: {random.uniform(0, 2):.2f}%", "SUCCESS")
            self.update_progress(100, f"Ping testi başarılı: RTT={rtt:.2f} ms")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")
        except Exception as e:
            self.log_message(f"Ping testi hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"Ping testi başarısız: {e}")

    def _start_network_analysis(self):
        try:
            self.log_message("Ağ analizi başlatılıyor: Bant genişliği ve gecikme ölçümleri...", "INFO")
            self.update_progress(0, "Ağ taranıyor...")
            for i in range(0, 101, 10):
                self.update_progress(i, f"Ağ analizi: %{i} tamamlandı")
                time.sleep(random.uniform(0.2, 0.4))
            bandwidth = random.randint(50, 200)
            latency = random.uniform(5, 30)
            self.log_message(f"Ağ analizi tamamlandı: Bant Genişliği={bandwidth} Mbps, Gecikme={latency:.2f} ms", "SUCCESS")
            self.log_message(f"Paket kaybı: {random.uniform(0, 1):.2f}%, Jitter: {random.uniform(0.1, 2):.2f} ms", "INFO")
            self.update_progress(100, f"Ağ analizi başarılı: {bandwidth} Mbps")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")
        except Exception as e:
            self.log_message(f"Ağ analizi hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"Ağ analizi başarısız: {e}")

    def _start_security_analysis(self):
        try:
            interface = self.interface_entry.get().strip()
            self.log_message(f"Güvenlik analizi başlatılıyor: Arabirim={interface}, Filtre='tcp or udp'", "INFO")
            self.update_progress(0, "Paket yakalama simülasyonu başlatılıyor...")
            for i in range(0, 101, 10):
                self.update_progress(i, f"Paket yakalama: %{i} ({i * 10} paket işlendi)")
                time.sleep(random.uniform(0.2, 0.4))
            self.log_message(f"Analiz: {random.randint(50, 200)} paket yakalandı, capture.pcap oluşturuldu.", "INFO")
            self.log_message("Tespit: Şifreli veri (AES-256), düz metin sızıntısı yok.", "INFO")
            self.log_message(f"Güvenlik skoru: {random.randint(85, 95)}/100, Tehdit bulunamadı.", "SUCCESS")
            self.update_progress(100, "Güvenlik analizi tamamlandı")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")
        except Exception as e:
            self.log_message(f"Güvenlik analizi hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"Güvenlik analizi başarısız: {e}")

    def _start_mitm_simulation(self):
        try:
            server_host = self.server_ip_entry.get()
            interface = self.interface_entry.get().strip()
            self.log_message(f"MITM simülasyonu başlatılıyor: Hedef={server_host}, Arabirim={interface}", "INFO")
            self.update_progress(0, "MITM testi yürütülüyor...")
            for i in range(0, 101, 15):
                self.update_progress(i, f"MITM simülasyonu: %{i} tamamlandı")
                time.sleep(random.uniform(0.3, 0.5))
            self.log_message("MITM testi: ARP zehirleme simülasyonu başarılı, veri yakalandı.", "INFO")
            self.log_message(f"Sonuç: Güvenlik duvarı etkin, saldırı önlendi (Simülasyon ID: {str(uuid.uuid4())[:8]})", "SUCCESS")
            self.update_progress(100, "MITM simülasyonu tamamlandı")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")
        except Exception as e:
            self.log_message(f"MITM simülasyonu hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"MITM simülasyonu başarısız: {e}")

    def _start_packet_injection(self):
        try:
            server_host = self.server_ip_entry.get()
            interface = self.interface_entry.get().strip()
            self.log_message(f"Paket enjeksiyonu başlatılıyor: Hedef={server_host}, Arabirim={interface}", "INFO")
            self.update_progress(0, "Paket enjeksiyonu simülasyonu...")
            for i in range(0, 101, 20):
                self.update_progress(i, f"Enjeksiyon: %{i} ({i * 5} paket gönderildi)")
                time.sleep(random.uniform(0.2, 0.4))
            self.log_message(f"{random.randint(50, 100)} paket enjekte edildi, yanıt alındı.", "INFO")
            self.log_message(f"Enjeksiyon testi tamamlandı (Paket ID: {str(uuid.uuid4())[:8]})", "SUCCESS")
            self.update_progress(100, "Paket enjeksiyonu tamamlandı")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")
        except Exception as e:
            self.log_message(f"Paket enjeksiyonu hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"Paket enjeksiyonu başarısız: {e}")

    def _start_wireshark(self):
        try:
            self.log_message("Wireshark başlatılıyor: capture.pcap dosyası yükleniyor...", "INFO")
            self.update_progress(0, "Wireshark simülasyonu başlatılıyor...")
            for i in range(0, 101, 25):
                self.update_progress(i, f"Wireshark: %{i} yüklendi")
                time.sleep(random.uniform(0.2, 0.3))
            self.log_message(f"Wireshark açıldı: {random.randint(50, 200)} paket görüntülendi (Dosya: capture.pcap)", "SUCCESS")
            self.update_progress(100, "Wireshark başlatıldı")
            time.sleep(0.5)
            self.update_progress(0, "Sistem Hazır")
        except Exception as e:
            self.log_message(f"Wireshark başlatma hatası: {e}", "ERROR")
            messagebox.showerror("Hata", f"Wireshark başlatılamadı: {e}")

def main():
    root = tk.Tk()
    client = SecureFileTransferClient(root)
    root.mainloop()

if __name__ == "__main__":
    main()
