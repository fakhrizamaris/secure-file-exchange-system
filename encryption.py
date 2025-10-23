"""
Module untuk enkripsi dan dekripsi file
Mendukung algoritma: AES, DES, RC4
"""

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
        Enkripsi data dengan algoritma dan mode yang dipilih
        
        Args:
            data (bytes): Data yang akan dienkripsi
            algorithm (str): Algoritma enkripsi (AES, DES, RC4)
            mode_name (str): Mode operasi (CBC, CTR, CFB, OFB)
        
        Returns:
            tuple: (encrypted_data, key, encryption_time)
        """
        start_time = time.time()
        
        if algorithm == 'AES':
            encrypted_data, key = EncryptionHandler._encrypt_aes(data, mode_name)
        elif algorithm == 'DES':
            encrypted_data, key = EncryptionHandler._encrypt_des(data, mode_name)
        elif algorithm == 'RC4':
            encrypted_data, key = EncryptionHandler._encrypt_rc4(data)
        else:
            raise ValueError(f"Algoritma tidak didukung: {algorithm}")
        
        encryption_time = (time.time() - start_time) * 1000  # ms
        
        return encrypted_data, key, encryption_time
    
    @staticmethod
    def decrypt_file(encrypted_data, key, algorithm='AES', mode_name='CBC'):
        """
        Dekripsi data dengan algoritma dan mode yang dipilih
        
        Args:
            encrypted_data (bytes): Data terenkripsi
            key (bytes): Kunci enkripsi
            algorithm (str): Algoritma enkripsi
            mode_name (str): Mode operasi
        
        Returns:
            tuple: (decrypted_data, decryption_time)
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
    
    # ============= AES ENCRYPTION =============
    
    @staticmethod
    def _encrypt_aes(data, mode_name='CBC'):
        """Enkripsi menggunakan AES-256"""
        key = secrets.token_bytes(32)  # AES-256
        
        if mode_name == 'CBC':
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            # Padding PKCS7
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
            # Remove PKCS7 padding
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
        key = secrets.token_bytes(8)  # DES key 8 bytes
        
        if mode_name == 'CBC':
            iv = secrets.token_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            # Padding untuk DES (8 bytes block)
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
            # Remove padding
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
        key = secrets.token_bytes(16)  # RC4 key
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data, key
    
    @staticmethod
    def _decrypt_rc4(encrypted_data, key):
        """Dekripsi menggunakan RC4"""
        cipher = ARC4.new(key)
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted


class FileEncryptionUtils:
    """Utility functions untuk file encryption"""
    
    @staticmethod
    def save_encrypted_file(file_path, encrypted_data, key):
        """
        Simpan file terenkripsi dengan format:
        [4 bytes: key_length][key][encrypted_data]
        """
        with open(file_path, 'wb') as f:
            f.write(len(key).to_bytes(4, 'big'))
            f.write(key)
            f.write(encrypted_data)
    
    @staticmethod
    def load_encrypted_file(file_path):
        """
        Baca file terenkripsi dan ekstrak key + data
        
        Returns:
            tuple: (key, encrypted_data)
        """
        with open(file_path, 'rb') as f:
            key_length = int.from_bytes(f.read(4), 'big')
            key = f.read(key_length)
            encrypted_data = f.read()
        return key, encrypted_data
    
    @staticmethod
    def calculate_overhead(original_size, encrypted_size):
        """Hitung overhead enkripsi dalam persen"""
        if original_size == 0:
            return 0
        overhead = ((encrypted_size - original_size) / original_size) * 100
        return round(overhead, 2)
    
    @staticmethod
    def get_encryption_info(algorithm, mode):
        """Dapatkan informasi detail tentang algoritma dan mode"""
        info = {
            'AES': {
                'name': 'Advanced Encryption Standard',
                'key_size': '256-bit',
                'block_size': '128-bit',
                'security': 'Sangat Tinggi',
                'speed': 'Cepat',
                'modes': ['CBC', 'CTR', 'CFB', 'OFB']
            },
            'DES': {
                'name': 'Data Encryption Standard',
                'key_size': '56-bit',
                'block_size': '64-bit',
                'security': 'Rendah (Deprecated)',
                'speed': 'Sedang',
                'modes': ['CBC', 'CFB', 'OFB']
            },
            'RC4': {
                'name': 'Rivest Cipher 4',
                'key_size': '128-bit',
                'block_size': 'Stream',
                'security': 'Rendah (Deprecated)',
                'speed': 'Sangat Cepat',
                'modes': ['Stream']
            }
        }
        
        mode_info = {
            'CBC': 'Cipher Block Chaining - Setiap blok bergantung pada blok sebelumnya',
            'CTR': 'Counter Mode - Mengubah block cipher menjadi stream cipher',
            'CFB': 'Cipher Feedback - Menggunakan feedback dari ciphertext sebelumnya',
            'OFB': 'Output Feedback - Menggunakan feedback dari output cipher',
            'Stream': 'Stream Cipher - Enkripsi byte per byte'
        }
        
        result = info.get(algorithm, {})
        result['mode_description'] = mode_info.get(mode, 'Unknown mode')
        
        return result