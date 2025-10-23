# encryption.py
# (Disederhanakan, karena key handling dipindah ke app.py dan models.py)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import ARC4, DES
import secrets
import time

class EncryptionHandler:
    """Handler untuk operasi enkripsi dan dekripsi"""
    
    @staticmethod
    def encrypt_file(data, algorithm='AES', mode_name='CBC'):
        """
        Enkripsi data.
        Returns: tuple (encrypted_data, key, encryption_time)
        """
        start_time = time.time()
        
        if algorithm == 'AES':
            encrypted_data, key = EncryptionHandler._encrypt_aes(data, mode_name)
        elif algorithm == 'DES':
            encrypted_data, key = EncryptionHandler._encrypt_des(data, mode_name)
        elif algorithm == 'RC4':
            encrypted_data, key = EncryptionHandler._encrypt_rc4(data)
            mode_name = 'Stream' # Pastikan mode RC4 adalah Stream
        else:
            raise ValueError(f"Algoritma tidak didukung: {algorithm}")
        
        encryption_time = (time.time() - start_time) * 1000  # ms
        
        return encrypted_data, key, encryption_time, mode_name
    
    @staticmethod
    def decrypt_file(encrypted_data, key, algorithm='AES', mode_name='CBC'):
        """
        Dekripsi data.
        Returns: tuple (decrypted_data, decryption_time)
        """
        start_time = time.time()
        
        if algorithm == 'AES':
            decrypted_data = EncryptionHandler._decrypt_aes(encrypted_data, key, mode_name)
        elif algorithm == 'DES':
            decrypted_data = EncryptionHandler._decrypt_des(encrypted_data, key, mode_name)
        elif algorithm == 'RC4':
            decrypted_data = EncryptionHandler._decrypt_rc4(encrypted_data, key)
        else:
            raise ValueError(f"Algoritma tidak didukung: {algorithm}")
        
        decryption_time = (time.time() - start_time) * 1000  # ms
        
        return decrypted_data, decryption_time
    
    # ... (Semua fungsi private _encrypt_aes, _decrypt_aes, _encrypt_des, dll.
    #      tetap sama persis seperti di file Anda, jadi tidak saya tulis ulang di sini)
    # ... (Salin-tempel semua fungsi _encrypt_... dan _decrypt_... dari file asli Anda ke sini)

    # ============= AES ENCRYPTION =============
    
    @staticmethod
    def _encrypt_aes(data, mode_name='CBC'):
        """Enkripsi menggunakan AES-256"""
        key = secrets.token_bytes(32)  # AES-256
        
        if mode_name == 'CBC':
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            padding_length = 16 - (len(data) % 16)
            data = data + bytes([padding_length] * padding_length)
            encrypted_data = iv + cipher.encryptor().update(data)
            
        elif mode_name == 'CTR':
            nonce = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            encrypted_data = nonce + cipher.encryptor().update(data)
            
        elif mode_name == 'CFB':
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encrypted_data = iv + cipher.encryptor().update(data)
            
        elif mode_name == 'OFB':
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
            encrypted_data = iv + cipher.encryptor().update(data)
        else:
            raise ValueError(f"Mode tidak didukung untuk AES: {mode_name}")
        
        return encrypted_data, key
    
    @staticmethod
    def _decrypt_aes(encrypted_data, key, mode_name='CBC'):
        """Dekripsi menggunakan AES-256"""
        if mode_name == 'CBC':
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decrypted = cipher.decryptor().update(ciphertext)
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
        elif mode_name == 'CTR':
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            decrypted = cipher.decryptor().update(ciphertext)
            
        elif mode_name == 'CFB':
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decrypted = cipher.decryptor().update(ciphertext)
            
        elif mode_name == 'OFB':
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
            decrypted = cipher.decryptor().update(ciphertext)
        else:
            raise ValueError(f"Mode tidak didukung untuk AES: {mode_name}")
        
        return decrypted
    
    # ============= DES ENCRYPTION =============
    
    @staticmethod
    def _encrypt_des(data, mode_name='CBC'):
        """Enkripsi menggunakan DES"""
        key = secrets.token_bytes(8)
        
        if mode_name == 'CBC':
            iv = secrets.token_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padding_length = 8 - (len(data) % 8)
            data = data + bytes([padding_length] * padding_length)
            encrypted_data = iv + cipher.encrypt(data)
            
        elif mode_name == 'CFB':
            iv = secrets.token_bytes(8)
            cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=64)
            encrypted_data = iv + cipher.encrypt(data)
            
        elif mode_name == 'OFB':
            iv = secrets.token_bytes(8)
            cipher = DES.new(key, DES.MODE_OFB, iv)
            encrypted_data = iv + cipher.encrypt(data)
        else:
            raise ValueError(f"Mode tidak didukung untuk DES: {mode_name}")
        
        return encrypted_data, key
    
    @staticmethod
    def _decrypt_des(encrypted_data, key, mode_name='CBC'):
        """Dekripsi menggunakan DES"""
        if mode_name == 'CBC':
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
        elif mode_name == 'CFB':
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            cipher = DES.new(key, DES.MODE_CFB, iv, segment_size=64)
            decrypted = cipher.decrypt(ciphertext)
            
        elif mode_name == 'OFB':
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            cipher = DES.new(key, DES.MODE_OFB, iv)
            decrypted = cipher.decrypt(ciphertext)
        else:
            raise ValueError(f"Mode tidak didukung untuk DES: {mode_name}")
        
        return decrypted
    
    # ============= RC4 ENCRYPTION =============
    
    @staticmethod
    def _encrypt_rc4(data):
        """Enkripsi menggunakan RC4 (Stream Cipher)"""
        key = secrets.token_bytes(16)
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data, key
    
    @staticmethod
    def _decrypt_rc4(encrypted_data, key):
        """Dekripsi menggunakan RC4"""
        cipher = ARC4.new(key)
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted