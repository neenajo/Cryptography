import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

class Encryptor:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()  # Generate 256-bit key

    def encrypt_message(self, message):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return {"iv": iv, "ciphertext": ct}

    def decrypt_message(self, iv, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, base64.b64decode(iv))
        decrypted_text = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size).decode()
        return decrypted_text
