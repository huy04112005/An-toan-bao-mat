import socket
import base64
import json
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# Hàm padding AES
def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len

client_ip = "172.16.5.188"  # Địa chỉ IP của client (phải có trong server)
filename = "cv.pdf"
timestamp = "2025-06-26T12:00:00Z"
metadata = f"{filename}|{timestamp}|{client_ip}".encode()

#Tải  khóa RSA
with open("keys/client_private_key.pem", "rb") as f:
    client_key_pair = RSA.import_key(f.read())
with open("keys/server_public_key.pem", "rb") as f:
    server_public_key = RSA.import_key(f.read())

# Ký số metadata
hash_obj = SHA512.new(metadata)
signature = pkcs1_15.new(client_key_pair).sign(hash_obj)
print("[Client] Metadata signed.")

# Tạo AES key và IV mã hóa nd
session_key = get_random_bytes(32)
iv = get_random_bytes(16)

# Đọc file cần gửi
if not os.path.isfile(filename):
    print(f"[Client] ❌ Lỗi: File '{filename}' không tồn tại.")
    exit()

with open(filename, 'rb') as f:
    plaintext = f.read()

# Mã hóa bằng AES
cipher = AES.new(session_key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext))
print("[Client] File encrypted.")

# Mã hóa AES key bằng RSA
rsa_cipher = PKCS1_OAEP.new(server_public_key, hashAlgo=SHA512)
encrypted_session_key = rsa_cipher.encrypt(session_key)
print("[Client] Session key encrypted.")

# Tính hash kiểm tra toàn vẹn
hash_value = SHA512.new(iv + ciphertext).hexdigest()

# Gói tin
packet = {
    "iv": base64.b64encode(iv).decode(),
    "cipher": base64.b64encode(ciphertext).decode(),
    "hash": hash_value,
    "sig": base64.b64encode(signature).decode(),
    "ip": client_ip,
    "metadata": base64.b64encode(metadata).decode(),
    "encrypted_key": base64.b64encode(encrypted_session_key).decode()
}

# Kết nối tới server
print("[Client] Connecting to server...")
s = socket.socket()
s.connect(("172.16.6.134", 9000))

# Gửi Hello! + IP
greeting = f"Hello!{client_ip}"
s.sendall(greeting.encode())
print(f"[Client] Sent: {greeting}")
response = s.recv(1024).decode().strip()
print(f"[Client] Received: {response}")

if response != "Ready!":
    print("[Client] ❌ Server từ chối kết nối.")
    s.close()
    exit()

# Gửi gói tin JSON
s.sendall(json.dumps(packet).encode())
print("[Client] Packet sent.")

# Nhận phản hồi từ server
ack = s.recv(1024).decode().strip()
print(f"[Client] Server response: {ack}")

if ack.startswith("ACK"):
    print("[Client] ✅ Giao dịch thành công. File đã được xác minh và lưu.")
elif ack.startswith("NACK"):
    print(f"[Client] ❌ Giao dịch bị từ chối: {ack}")
else:
    print("[Client] ⚠️ Phản hồi không xác định từ server.")

s.close()
