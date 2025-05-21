from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib # <- Đảm bảo dòng này có

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
DOWNLOAD_FOLDER = "downloads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# Hàm này sẽ tạo khóa AES từ khóa người dùng nhập vào
def derive_aes_key(input_key_string):
    """
    Sử dụng SHA256 để băm khóa đầu vào thành một khóa 32 byte (256 bit)
    phù hợp cho AES-256.
    """
    # Mã hóa khóa đầu vào thành bytes trước khi băm
    hashed_key = hashlib.sha256(input_key_string.encode('utf-8')).digest()
    return hashed_key # Trả về 32 bytes

def get_cipher(key_bytes): # Thay đổi tham số để nhận bytes
    return AES.new(key_bytes, AES.MODE_ECB)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        user_key = request.form["key"] # Lấy khóa người dùng nhập vào
        action = request.form["action"]
        file = request.files["file"]

        if not user_key: # Đảm bảo khóa không rỗng
            return "Khóa không được để trống.", 400

        # CHỖ NÀY ĐÃ ĐƯỢC THAY ĐỔI ĐỂ KHÔNG KIỂM TRA ĐỘ DÀI KEY NỮA
        # Chuyển đổi khóa người dùng nhập vào thành khóa AES 256-bit
        aes_key_bytes = derive_aes_key(user_key)

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        with open(filepath, "rb") as f:
            data = f.read()

        cipher = get_cipher(aes_key_bytes) # Truyền khóa dạng bytes đã được băm

        if action == "encrypt":
            encrypted = cipher.encrypt(pad(data, AES.block_size))
            output_file = os.path.join(DOWNLOAD_FOLDER, f"encrypted_{file.filename}")
        elif action == "decrypt":
            try:
                decrypted = unpad(cipher.decrypt(data), AES.block_size)
            except ValueError as e:
                return f"Giải mã thất bại. Sai khóa hoặc định dạng file không hợp lệ. Lỗi: {e}", 400
            except Exception as e:
                return f"Đã xảy ra lỗi không mong muốn trong quá trình giải mã: {e}", 500
            output_file = os.path.join(DOWNLOAD_FOLDER, f"decrypted_{file.filename}")
        else:
            return "Yêu cầu không hợp lệ.", 400

        with open(output_file, "wb") as f:
            f.write(encrypted if action == "encrypt" else decrypted)

        return send_file(output_file, as_attachment=True)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)