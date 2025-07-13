import os
import secrets
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InvalidSignature 
import base64
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    generated_key = secrets.token_hex(32) 
    with open('.env', 'a') as f:
        f.write(f"SECRET_KEY=\"{generated_key}\"\n")
    SECRET_KEY = generated_key
    print(f"Kunci AES baru dibuat dan disimpan di .env: {SECRET_KEY}")

try:
    GLOBAL_ENCRYPTION_KEY = bytes.fromhex(SECRET_KEY)
    if len(GLOBAL_ENCRYPTION_KEY) != 32:
        raise ValueError(f"Secret Key harus 32 byte, tapi yang ditemukan adalah {len(GLOBAL_ENCRYPTION_KEY)} byte.")
except (ValueError, TypeError) as e:
    print(f"ERROR: Secret Key tidak valid. Detail: {e}")
    exit(1)

# validasi kunci
def validate_key_param(key_hex_string):
    if not key_hex_string:
        return None, "Kunci tidak boleh kosong"
    try:
        key_bytes = bytes.fromhex(key_hex_string)
        if len(key_bytes) != 32:
            return None, "Kunci harus 32 byte, AES-256"
        return key_bytes, None
    except (ValueError, TypeError):
        return None, "Format kunci tidak valid"

# enkrpsi
def encrypt_aes_gcm(plaintext, key):
    iv = os.urandom(12) 
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag 
    
    return (
        base64.urlsafe_b64encode(iv + ciphertext + tag).decode('utf-8'),
        base64.urlsafe_b64encode(iv).decode('utf-8'),
        base64.urlsafe_b64encode(tag).decode('utf-8')
    )
    
#dekripsi
def decrypt_aes_gcm(encrypted_data, key):
    try:
        decoded_data = base64.urlsafe_b64decode(encrypted_data)
        
        iv = decoded_data[:12] 
        ciphertext = decoded_data[12:-16]
        tag = decoded_data[-16:] 

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize() 
        return plaintext.decode('utf-8'), None # kalau error
    except (InvalidTag, InvalidSignature):
        return None, "Invalid input"
    except Exception as e:
        return None, f"Format data tidak valid: {e}"

#endpoint
@app.route('/')
def home():
    return "AES-256-GCM."

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Permintaan JSON tidak valid"}), 400

    plaintext = data['text']
    encrypted_data, iv_base64, tag_base64 = encrypt_aes_gcm(plaintext, GLOBAL_ENCRYPTION_KEY)
    encryption_key_hex = GLOBAL_ENCRYPTION_KEY.hex()

    return jsonify({
        "algorithm": "AES-256-GCM",
        "original_text": plaintext,
        "encrypted_data": encrypted_data, 
        "iv": iv_base64,
        "tag": tag_base64,
        "encryption_key_for_decryption": encryption_key_hex #kunci untuk dekrip
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.get_json()
    if not data or 'encrypted_data' not in data or 'key' not in data:
        return jsonify({"error": "Permintaan JSON tidak valid. Harap sertakan 'encrypted_data' dan 'key'."}), 400

    decryption_key_from_client, key_error = validate_key_param(data['key'])
    if key_error:
        return jsonify({"error": key_error}), 400

    encrypted_data = data['encrypted_data']
    decrypted_text, decryption_error = decrypt_aes_gcm(encrypted_data, decryption_key_from_client)
    
    if decryption_error:
        return jsonify({"error": decryption_error}), 401 
    
    return jsonify({
        "algorithm": "AES-256-GCM",
        "encrypted_data": encrypted_data,
        "decrypted_text": decrypted_text
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)