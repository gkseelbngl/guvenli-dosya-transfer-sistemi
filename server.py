import socket
import os
import threading
import time
import math
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# Sunucu yapılandırması
HOST = '0.0.0.0'
TCP_PORT = 12345
UDP_PORT = 12346
BUFFER_SIZE = 4096
CHUNK_SIZE = 4096
AUTH_TOKEN = "SUPER_SECRET_AUTH_TOKEN_12345"

# Dosyaların kaydedileceği dizin
UPLOAD_FOLDER = 'uploads_secure'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# RSA Anahtar Çifti
PRIVATE_KEY_PATH = 'server_private_key.pem'
PUBLIC_KEY_PATH = 'server_public_key.pem'

def generate_rsa_keys():
    """RSA anahtar çifti oluşturur ve dosyaya kaydeder."""
    print("[ANAHTARLAR] Yeni RSA anahtar çifti oluşturuluyor...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    try:
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[ANAHTARLAR] Yeni RSA anahtar çifti oluşturuldu ve kaydedildi.")
        return private_key, public_key
    except Exception as e:
        print(f"[HATA] Anahtar dosyaları kaydedilemedi: {e}")
        raise

def load_rsa_keys():
    """Özel ve açık anahtarları yükler, yoksa oluşturur."""
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        print(f"[UYARI] Anahtar dosyaları bulunamadı. Yeni anahtar çifti oluşturuluyor...")
        return generate_rsa_keys()
    try:
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print("[ANAHTARLAR] Özel ve açık anahtarlar yüklendi.")
        return private_key, public_key
    except Exception as e:
        print(f"[HATA] Anahtar dosyaları yüklenemedi: {e}. Yeni anahtarlar oluşturuluyor...")
        return generate_rsa_keys()

SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = load_rsa_keys()

def decrypt_aes_key(encrypted_aes_key, private_key):
    """Şifrelenmiş AES anahtarını çözer."""
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key
    except Exception as e:
        print(f"[HATA] AES anahtarı deşifre hatası: {e}")
        return None

def decrypt_data(encrypted_data, aes_key, iv):
    """Şifrelenmiş veriyi AES ile çözer."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_padded_data

def remove_padding(data):
    """AES dolgusu kaldırır."""
    if not data:
        return b""
    padding_len = data[-1]
    if padding_len > len(data) or padding_len == 0:
        print(f"[UYARI] Geçersiz padding uzunluğu ({padding_len}).")
        return data
    return data[:-padding_len]

def handle_tcp_client(client_socket, addr):
    """TCP istemci bağlantısını yönetir."""
    print(f"[TCP BAĞLANTI] İstemci {addr} bağlandı.")
    try:
        # İlk isteği oku
        request = client_socket.recv(10)
        if request == b"GET_PUBKEY":
            print(f"[TCP ANAHTAR] İstemci {addr} açık anahtar talep etti.")
            try:
                with open(PUBLIC_KEY_PATH, "rb") as f:
                    public_key_pem = f.read()
                client_socket.sendall(public_key_pem)
                print(f"[TCP ANAHTAR] Açık anahtar gönderildi: {addr}")
                return  # Anahtar gönderildikten sonra bağlantıyı kapat
            except Exception as e:
                print(f"[TCP HATA] Açık anahtar gönderilemedi: {e}")
                client_socket.sendall(b"KEY_ERROR")
                return

        # Normal dosya transferi
        auth_data = client_socket.recv(len(AUTH_TOKEN))
        if auth_data != AUTH_TOKEN.encode('utf-8'):
            print(f"[TCP HATA] İstemci {addr} kimlik doğrulama başarısız.")
            client_socket.sendall(b"AUTH_FAIL")
            return
        client_socket.sendall(b"AUTH_OK")

        encrypted_aes_key_bytes = client_socket.recv(256)
        if not encrypted_aes_key_bytes:
            print(f"[TCP HATA] İstemci {addr} AES anahtarı göndermedi.")
            return
        aes_key = decrypt_aes_key(encrypted_aes_key_bytes, SERVER_PRIVATE_KEY)
        if not aes_key:
            print(f"[TCP GÜVENLİK HATA] İstemci {addr} için AES anahtarı deşifre edilemedi.")
            return

        file_name_length_bytes = client_socket.recv(4)
        if not file_name_length_bytes:
            print(f"[TCP HATA] İstemci {addr} dosya adı uzunluğu göndermedi.")
            return
        file_name_length = int.from_bytes(file_name_length_bytes, 'big')
        file_name = client_socket.recv(file_name_length).decode('utf-8')
        base_file_name = os.path.basename(file_name)
        file_path = os.path.join(UPLOAD_FOLDER, base_file_name)

        encrypted_file_size_bytes = client_socket.recv(8)
        if not encrypted_file_size_bytes:
            print(f"[TCP HATA] İstemci {addr} dosya boyutu göndermedi.")
            return
        encrypted_file_size = int.from_bytes(encrypted_file_size_bytes, 'big')

        iv = client_socket.recv(16)
        if len(iv) != 16:
            print(f"[TCP HATA] İstemci {addr} geçersiz IV uzunluğu.")
            return

        original_file_hash = client_socket.recv(32)
        if len(original_file_hash) != 32:
            print(f"[TCP HATA] İstemci {addr} geçersiz hash uzunluğu.")
            return

        received_bytes = 0
        temp_decrypted_file_path = file_path + ".tmp_tcp"
        start_time = time.time()
        with open(temp_decrypted_file_path, 'wb') as f_temp:
            while received_bytes < encrypted_file_size:
                bytes_to_read = min(encrypted_file_size - received_bytes, CHUNK_SIZE)
                encrypted_data_chunk = client_socket.recv(bytes_to_read)
                if not encrypted_data_chunk:
                    print(f"[TCP HATA] İstemci {addr} bağlantısı kesildi.")
                    break
                f_temp.write(encrypted_data_chunk)
                received_bytes += len(encrypted_data_chunk)
                progress = (received_bytes / encrypted_file_size) * 100
                if int(progress) % 10 == 0:
                    print(f"\r[TCP İLERLEME] {addr}: {base_file_name} alınıyor... %{int(progress)}", end='', flush=True)
            print()

        if received_bytes == encrypted_file_size:
            print(f"[TCP ALINDI] Şifreli dosya '{base_file_name}' received. Decrypting...")
            with open(temp_decrypted_file_path, 'rb') as f_temp_read:
                full_encrypted_data = f_temp_read.read()
            decrypted_padded_data = decrypt_data(full_encrypted_data, aes_key, iv)
            actual_file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            actual_file_hash.update(decrypted_padded_data)
            calculated_hash = actual_file_hash.finalize()

            if calculated_hash == original_file_hash:
                print(f"[TCP BÜTÜNLÜK] File '{base_file_name}' hash verification succeeded.")
                final_data_unpadded = remove_padding(decrypted_padded_data)
                with open(file_path, 'wb') as f_final:
                    f_final.write(final_data_unpadded)
                end_time = time.time()
                transfer_speed = (encrypted_file_size / (end_time - start_time)) / (1024 * 1024) if (end_time - start_time) > 0 else 0
                print(f"[TCP SUCCESS] File '{file_path}' saved. Speed: {transfer_speed:.2f} MB/s")
                os.remove(temp_decrypted_file_path)
            else:
                print("[TCP BÜTÜNLÜK HATA] Dosya '{base_file_name}' hash doğrulaması BAŞARISIZ.")
                os.remove(temp_decrypted_file_path)
        else:
            print(f"[TCP HATA] Dosya '{base_file_name}' tam alınamadı.")
            if os.path.exists(temp_decrypted_file_path):
                os.remove(temp_decrypted_file_path)

    except Exception as e:
        print(f"[TCP HATA] İstemci {addr} ile hata: {e}")
    finally:
        print(f"[TCP BAĞLANTI SONU] İstemci {addr} bağlantısı kapatıldı.")
        client_socket.close()

udp_active_transfers = {}
udp_transfer_lock = threading.Lock()
CLEANUP_INTERVAL = 30
TRANSFER_TIMEOUT = 120

def cleanup_udp_transfers():
    """Zaman aşımına uğrayan UDP transferlerini temizler."""
    global udp_active_transfers
    while True:
        time.sleep(CLEANUP_INTERVAL)
        with udp_transfer_lock:
            current_time = time.time()
            transfers_to_remove = []
            for transfer_id, info in udp_active_transfers.items():
                if current_time - info['last_active_time'] > TRANSFER_TIMEOUT:
                    print(f"[UDP TEMİZLEME] Zaman aşımına uğrayan transfer: ID {transfer_id.hex()}")
                    if os.path.exists(info['temp_file_path']):
                        os.remove(info['temp_file_path'])
                    transfers_to_remove.append(transfer_id)
                for transfer_id in transfers_to_remove:
                    del udp_active_transfers[transfer_id]

def handle_udp_client():
    """UDP istemci verilerini yönetir."""
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, UDP_PORT))
    print(f"[UDP BAŞLATILDI] Sunucu {HOST}:{UDP_PORT} adresinde dinliyor...")

    cleanup_thread = threading.Thread(target=cleanup_udp_transfers)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    while True:
        try:
            data, addr = udp_socket.recvfrom(BUFFER_SIZE + 512)
            packet_type = data[0:4]
            transfer_id = data[4:20]

            with udp_transfer_lock:
                if transfer_id not in udp_active_transfers:
                    if packet_type != b"AUTH":
                        print(f"[UDP UYARI] Bilinmeyen transfer ID {transfer_id.hex()} için {packet_type.decode()} paketi geldi.")
                        udp_socket.sendto(b"NACK:" + transfer_id + b"\xFF\xFF\xFF\xFF", addr)
                        continue
                    if data[20:] != AUTH_TOKEN.encode('utf-8'):
                        print(f"[UDP HATA] Transfer ID {transfer_id.hex()} için kimlik doğrulama başarısız.")
                        udp_socket.sendto(b"NACK:" + transfer_id + b"\xFF\xFF\xFF\xFF", addr)
                        continue
                    temp_file_path = os.path.join(UPLOAD_FOLDER, f"temp_{transfer_id.hex()}.tmp_udp")
                    udp_active_transfers[transfer_id] = {
                        'aes_key': None,
                        'iv': None,
                        'original_hash': None,
                        'file_name': None,
                        'file_path': None,
                        'encrypted_file_size': 0,
                        'received_chunks': {},
                        'expected_chunks': None,
                        'last_active_time': time.time(),
                        'addr': addr,
                        'temp_file_path': temp_file_path,
                        'highest_received_chunk_idx': -1,
                        'start_time': time.time()
                    }
                    udp_socket.sendto(b"AUTH_OK", addr)
                    print(f"[UDP OTURUM] Yeni transfer: ID {transfer_id.hex()} - {addr}")

                udp_active_transfers[transfer_id]['last_active_time'] = time.time()
                current_transfer = udp_active_transfers[transfer_id]

            if packet_type == b"META":
                encrypted_aes_key_bytes = data[20:20+256]
                aes_key = decrypt_aes_key(encrypted_aes_key_bytes, SERVER_PRIVATE_KEY)
                if not aes_key:
                    print(f"[UDP HATA] Transfer ID {transfer_id.hex()} için AES anahtarı deşifre edilemedi.")
                    udp_socket.sendto(b"NACK:" + transfer_id + b"\xFF\xFF\xFF\xFF", addr)
                    with udp_transfer_lock:
                        del udp_active_transfers[transfer_id]
                    continue

                file_name_length = int.from_bytes(data[20+256:20+256+4], 'big')
                file_name_bytes = data[20+256+4 : 20+256+4+file_name_length]
                file_name = file_name_bytes.decode('utf-8')
                base_file_name = os.path.basename(file_name)
                
                encrypted_file_size = int.from_bytes(data[20+256+4+file_name_length : 20+256+4+file_name_length+8], 'big')
                iv = data[20+256+4+file_name_length+8 : 20+256+4+file_name_length+8+16]
                original_hash = data[20+256+4+file_name_length+8+16 : 20+256+4+file_name_length+8+16+32]

                current_transfer['aes_key'] = aes_key
                current_transfer['iv'] = iv
                current_transfer['original_hash'] = original_hash
                current_transfer['file_name'] = base_file_name
                current_transfer['file_path'] = os.path.join(UPLOAD_FOLDER, base_file_name)
                current_transfer['encrypted_file_size'] = encrypted_file_size
                current_transfer['expected_chunks'] = math.ceil(encrypted_file_size / CHUNK_SIZE)

                print(f"[UDP ALINDI] META paketi ID {transfer_id.hex()}. Dosya: {base_file_name}")
                udp_socket.sendto(b"ACKK:" + transfer_id, addr)

            elif packet_type == b"DATA":
                chunk_idx = int.from_bytes(data[20:24], 'big')
                encrypted_chunk_data = data[28:]

                if current_transfer['aes_key'] is None:
                    print(f"[UDP HATA] DATA paketi ID {transfer_id.hex()} için AES anahtarı yok.")
                    udp_socket.sendto(b"NACK:" + transfer_id + b"\xFF\xFF\xFF\xFF", addr)
                    continue

                if chunk_idx in current_transfer['received_chunks']:
                    udp_socket.sendto(b"ACKK:" + transfer_id + chunk_idx.to_bytes(4, 'big'), addr)
                    continue

                current_transfer['received_chunks'][chunk_idx] = encrypted_chunk_data
                if chunk_idx > current_transfer['highest_received_chunk_idx']:
                    current_transfer['highest_received_chunk_idx'] = chunk_idx

                udp_socket.sendto(b"ACKK:" + transfer_id + chunk_idx.to_bytes(4, 'big'), addr)
                progress = (len(current_transfer['received_chunks']) / current_transfer['expected_chunks']) * 100
                if int(progress) % 10 == 0:
                    print(f"\r[UDP İLERLEME] {addr}: {base_file_name} alınıyor... %{int(progress)}", end='', flush=True)

                if len(current_transfer['received_chunks']) < current_transfer['expected_chunks']:
                    missing_chunks = [i for i in range(current_transfer['highest_received_chunk_idx'] + 1) if i not in current_transfer['received_chunks']]
                    if missing_chunks:
                        print(f"[UDP EKSİK] Transfer ID {transfer_id.hex()} için eksik parçalar: {missing_chunks[:5]}...")
                        udp_socket.sendto(b"NACK:" + transfer_id + missing_chunks[0].to_bytes(4, 'big'), addr)

                if len(current_transfer['received_chunks']) == current_transfer['expected_chunks']:
                    print(f"\n[UDP BİTTİ] Tüm parçalar ID {transfer_id.hex()} alındı.")
                    full_encrypted_data_parts = [current_transfer['received_chunks'].get(i) for i in range(current_transfer['expected_chunks'])]
                    if None in full_encrypted_data_parts:
                        print(f"[UDP HATA] Transfer ID {transfer_id.hex()} için eksik parçalar var!")
                        with udp_transfer_lock:
                            if os.path.exists(current_transfer['temp_file_path']):
                                os.remove(current_transfer['temp_file_path'])
                            del udp_active_transfers[transfer_id]
                        continue

                    full_encrypted_data = b"".join(full_encrypted_data_parts)
                    decrypted_padded_data = decrypt_data(full_encrypted_data, current_transfer['aes_key'], current_transfer['iv'])
                    actual_file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    actual_file_hash.update(decrypted_padded_data)
                    calculated_hash = actual_file_hash.finalize()

                    if calculated_hash == current_transfer['original_hash']:
                        print(f"[UDP BÜTÜNLÜK] Dosya '{current_transfer['file_name']}' hash doğrulaması BAŞARILI.")
                        final_data_unpadded = remove_padding(decrypted_padded_data)
                        with open(current_transfer['file_path'], 'wb') as f_final:
                            f_final.write(final_data_unpadded)
                        end_time = time.time()
                        transfer_speed = (current_transfer['encrypted_file_size'] / (end_time - current_transfer['start_time'])) / (1024 * 1024) if (end_time - current_transfer['start_time']) > 0 else 0
                        print(f"[UDP BAŞARILI] Dosya '{current_transfer['file_name']}' kaydedildi. Hız: {transfer_speed:.2f} MB/s")
                    else:
                        print(f"[UDP BÜTÜNLÜK HATA] Dosya '{current_transfer['file_name']}' hash doğrulaması BAŞARISIZ.")
                    with udp_transfer_lock:
                        if os.path.exists(current_transfer['temp_file_path']):
                            os.remove(current_transfer['temp_file_path'])
                        del udp_active_transfers[transfer_id]

            else:
                print(f"[UDP UYARI] Bilinmeyen paket tipi: {packet_type.decode()} from {addr}")

        except Exception as e:
            print(f"[UDP HATA] UDP dinlerken hata: {e}")

def start_server():
    """Sunucuyu başlatır."""
    tcp_thread = threading.Thread(target=run_tcp_server)
    tcp_thread.start()
    udp_thread = threading.Thread(target=handle_udp_client)
    udp_thread.start()

def run_tcp_server():
    """TCP sunucusunu çalıştırır."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, TCP_PORT))
        server_socket.listen(5)
        print(f"[TCP BAŞLATILDI] Sunucu {HOST}:{TCP_PORT} adresinde dinliyor...")
        while True:
            client_socket, addr = server_socket.accept()
            client_handler = threading.Thread(target=handle_tcp_client, args=(client_socket, addr))
            client_handler.start()
    except Exception as e:
        print(f"[TCP KRİTİK HATA] TCP Sunucu başlatılamadı: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
