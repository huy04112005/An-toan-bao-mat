import socket
import json
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import os

# Hàm bỏ padding sau khi giải mã AES
def unpad(data):
    return data[:-data[-1]]

# Danh sách IP được phép
valid_ips = ["172.16.6.134"]

# Load khóa của server và client
with open("keys/server_private_key.pem", "rb") as f:
    server_private_key = RSA.import_key(f.read())
with open("keys/client_public_key.pem", "rb") as f:
    client_public_key = RSA.import_key(f.read())

# Tạo socket và lắng nghe
server_port = 9000
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", server_port))
s.listen(1)
print("[Server] Waiting for connection...")

conn, addr = s.accept()
print(f"[Server] Connected from {addr}")

# Bắt đầu Handshake
hello = conn.recv(1024).decode().strip()
print(f"[Server] Received: {hello}")

if not hello.startswith("Hello!"):
    conn.sendall(b"Rejected!")
    print("[Server] Sent: Rejected!")
    conn.close()
    exit()

client_ip = hello.replace("Hello!", "")
print(f"[Server] IP: {client_ip}")

if client_ip not in valid_ips:
    conn.sendall(b"NACK: Invalid IP")
    print("[Server] NACK: Invalid IP")
    conn.close()
    exit()

conn.sendall(b"Ready!")
print("[Server] Sent: Ready!")

# Nhận packet từ client
try:
    data = conn.recv(10 * 1024 * 1024).decode()
    packet = json.loads(data)
    print("[Server] Packet received.")
except Exception:
    conn.sendall(b"NACK: Packet parse error")
    print("[Server] NACK: Cannot parse packet")
    conn.close()
    exit()

# Giải mã các thành phần trong packet
try:
    recv_iv = base64.b64decode(packet["iv"])
    recv_cipher = base64.b64decode(packet["cipher"])
    recv_hash = packet["hash"]
    recv_sig = base64.b64decode(packet["sig"])
    recv_metadata = base64.b64decode(packet["metadata"])
    recv_encrypted_key = base64.b64decode(packet["encrypted_key"])
    recv_ip = packet["ip"]
except Exception:
    conn.sendall(b"NACK: Invalid packet fields")
    print("[Server] NACK: Invalid packet fields")
    conn.close()
    exit()

# 1. Kiểm tra IP trong packet
if recv_ip not in valid_ips:
    conn.sendall(b"NACK: Invalid IP")
    print("[Server] NACK: Invalid IP (in packet)")
    conn.close()
    exit()

# 2. Kiểm tra tính toàn vẹn (hash)
computed_hash = SHA512.new(recv_iv + recv_cipher).hexdigest()
if computed_hash != recv_hash:
    conn.sendall(b"NACK: Integrity error")
    print("[Server] NACK: Integrity check failed")
    conn.close()
    exit()

# 3. Kiểm tra chữ ký
try:
    pkcs1_15.new(client_public_key).verify(SHA512.new(recv_metadata), recv_sig)
except Exception:
    conn.sendall(b"NACK: Authentication error")
    print("[Server] NACK: Signature invalid")
    conn.close()
    exit()

# 4. Giải mã AES key và file
try:
    session_key = PKCS1_OAEP.new(server_private_key, hashAlgo=SHA512).decrypt(recv_encrypted_key)
    aes = AES.new(session_key, AES.MODE_CBC, recv_iv)
    plaintext = unpad(aes.decrypt(recv_cipher))

    if not os.path.exists("received_files"):
        os.makedirs("received_files")

    output_path = os.path.join("received_files", "received_cv.pdf")
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[Server] File saved to {output_path}")
    conn.sendall(b"ACK")
except Exception:
    conn.sendall(b"NACK: Decryption error")
    print("[Server] NACK: Decryption failed")

conn.close()
