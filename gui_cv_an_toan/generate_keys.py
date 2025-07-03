from Crypto.PublicKey import RSA
import os

# Tạo thư mục "keys" nếu chưa tồn tại
if not os.path.exists("keys"):
    os.makedirs("keys")

# Tạo cặp khóa cho Server
server_key_pair = RSA.generate(2048) # Kích thước khóa 2048-bit
# Lưu khóa riêng tư của server
with open(os.path.join("keys", "server_private_key.pem"), "wb") as f:
    f.write(server_key_pair.export_key("PEM"))
# Lưu khóa công khai của server
with open(os.path.join("keys", "server_public_key.pem"), "wb") as f:
    f.write(server_key_pair.publickey().export_key("PEM"))

# Tạo cặp khóa cho Client
client_key_pair = RSA.generate(2048) # Kích thước khóa 2048-bit
# Lưu khóa riêng tư của client
with open(os.path.join("keys", "client_private_key.pem"), "wb") as f:
    f.write(client_key_pair.export_key("PEM"))
# Lưu khóa công khai của client
with open(os.path.join("keys", "client_public_key.pem"), "wb") as f:
    f.write(client_key_pair.publickey().export_key("PEM"))

print("Đã tạo thành công các cặp khóa cho client và server trong thư mục 'keys'.")
print("Vui lòng kiểm tra thư mục project của bạn, bạn sẽ thấy một thư mục mới có tên 'keys'.")