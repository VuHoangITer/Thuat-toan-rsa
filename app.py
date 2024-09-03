# app.py

from flask import Flask, render_template, request, redirect, url_for, send_file
import rsa_keys
from hashlib import sha1, sha256
import os

app = Flask(__name__)

# Cấu hình đường dẫn lưu trữ tạm thời cho các tệp đã tải lên
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Biến toàn cục để lưu trữ khóa, chữ ký, mã băm, mã hóa, giải mã và kết quả kiểm tra
public_key = None
private_key = None
signature = None
message_hash = None
verification_result = None
p = None
q = None
ciphertext = None
decrypted_message = None
key_size = 512  # Mặc định

@app.route('/')
def index():
    return render_template('index.html', 
                           public_key=public_key, 
                           private_key=private_key,
                           signature=signature,
                           message_hash=message_hash,
                           verification_result=verification_result,
                           p=p,  # Thêm p vào giao diện
                           q=q,  # Thêm q vào giao diện
                           ciphertext=ciphertext,  # Thêm ciphertext
                           decrypted_message=decrypted_message,  # Thêm decrypted_message
                           key_size=key_size)  # Thêm key_size

@app.route('/generate_keys', methods=['POST'])
def generate_keys_route():
    global public_key, private_key, p, q, key_size
    key_size = int(request.form.get('key_size', 512))  # Lấy kích thước khóa từ form
    public_key, private_key, p, q = rsa_keys.generate_keys(key_size)  # Truyền key_size vào hàm
    rsa_keys.save_key(public_key, rsa_keys.PUBLIC_KEY_FILE)
    rsa_keys.save_key(private_key, rsa_keys.PRIVATE_KEY_FILE)
    return redirect(url_for('index'))

@app.route('/sign', methods=['POST'])
def sign():
    global signature, message_hash
    
    # Kiểm tra xem người dùng nhập văn bản hay tải lên tệp
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Đọc nội dung tệp
        with open(file_path, 'rb') as f:
            message = f.read()
    else:
        message = request.form['message'].encode()

    # Tạo mã băm SHA-1 của thông điệp hoặc nội dung tệp
    message_hash = sha1(message).hexdigest()

    private_key = rsa_keys.load_key(rsa_keys.PRIVATE_KEY_FILE)
    signature = rsa_keys.sign_message_with_key(message, private_key)

    # Lưu chữ ký và mã băm vào tệp
    with open(os.path.join(app.config['UPLOAD_FOLDER'], 'signature.txt'), 'w') as sig_file:
        sig_file.write(str(signature))
    with open(os.path.join(app.config['UPLOAD_FOLDER'], 'message_hash.txt'), 'w') as hash_file:
        hash_file.write(message_hash)

    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

@app.route('/verify', methods=['POST'])
def verify():
    global verification_result
    
    # Kiểm tra xem người dùng nhập văn bản hay tải lên tệp
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Đọc nội dung tệp
        with open(file_path, 'rb') as f:
            message = f.read()
    else:
        message = request.form['verify_message'].encode()

    # Kiểm tra xem người dùng nhập chữ ký hay tải lên chữ ký
    if 'signature_file' in request.files and request.files['signature_file'].filename != '':
        signature_file = request.files['signature_file']
        signature_file_path = os.path.join(app.config['UPLOAD_FOLDER'], signature_file.filename)
        signature_file.save(signature_file_path)
        
        # Đọc chữ ký từ tệp
        with open(signature_file_path, 'r') as sig_file:
            signature = int(sig_file.read().strip())
    else:
        signature = int(request.form['signature_to_verify'])

    public_key = rsa_keys.load_key(rsa_keys.PUBLIC_KEY_FILE)
    
    # Kiểm tra tính hợp lệ của chữ ký
    verification = rsa_keys.verify_signature_with_key(message, signature, public_key)
    
    if verification:
        verification_result = "Xác minh thành công, tệp không bị thay đổi "
    else:
        verification_result = "Xác minh thất bại, tệp bị thay đổi khi trong quá trình truyền dữ liệu"

    return redirect(url_for('index'))

# Thêm route cho mã hóa
@app.route('/encrypt', methods=['POST'])
def encrypt():
    global ciphertext
    # Kiểm tra xem người dùng nhập văn bản hay tải lên tệp
    if 'encrypt_file' in request.files and request.files['encrypt_file'].filename != '':
        file = request.files['encrypt_file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Đọc nội dung tệp
        with open(file_path, 'rb') as f:
            message = f.read()
    else:
        message_text = request.form['encrypt_message']
        message = message_text.encode()

    public_key = rsa_keys.load_key(rsa_keys.PUBLIC_KEY_FILE)
    try:
        ciphertext = rsa_keys.encrypt_message(public_key, message)
        # Lưu ciphertext vào tệp
        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'ciphertext.txt'), 'w') as cipher_file:
            cipher_file.write(str(ciphertext))
    except ValueError as ve:
        ciphertext = str(ve)

    return redirect(url_for('index'))

# Thêm route cho giải mã
@app.route('/decrypt', methods=['POST'])
def decrypt():
    global decrypted_message
    # Kiểm tra xem người dùng nhập ciphertext hay tải lên tệp ciphertext
    if 'decrypt_file' in request.files and request.files['decrypt_file'].filename != '':
        file = request.files['decrypt_file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Đọc ciphertext từ tệp
        with open(file_path, 'r') as cipher_file:
            ciphertext_str = cipher_file.read().strip()
            try:
                ciphertext_int = int(ciphertext_str)
            except ValueError:
                decrypted_message = "Chữ ký không hợp lệ."
                return redirect(url_for('index'))
    else:
        ciphertext_input = request.form['decrypt_ciphertext']
        try:
            ciphertext_int = int(ciphertext_input)
        except ValueError:
            decrypted_message = "Chữ ký không hợp lệ."
            return redirect(url_for('index'))

    private_key = rsa_keys.load_key(rsa_keys.PRIVATE_KEY_FILE)
    try:
        decrypted_bytes = rsa_keys.decrypt_message(private_key, ciphertext_int)
        decrypted_message = decrypted_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        decrypted_message = f"Lỗi khi giải mã: {str(e)}"

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
