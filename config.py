# config.py (Versi Modifikasi untuk Render Disk)

import os
from datetime import timedelta

# Tentukan base directory proyek
basedir = os.path.abspath(os.path.dirname(__file__))

# --- PERUBAHAN DI SINI ---
# Tentukan base path untuk data persisten
# Ini akan membaca Env Var 'DATA_BASE_PATH' di Render (yang akan kita set ke /app/data)
# Jika tidak ada, dia akan membuat folder 'data/' di lokal untuk development
DATA_BASE_PATH = os.environ.get('DATA_BASE_PATH', os.path.join(basedir, 'data'))
# --- AKHIR PERUBAHAN ---

class Config:
    """Konfigurasi aplikasi dasar"""
    
    # Kunci rahasia untuk Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'kunci-rahasia-yang-sangat-sulit-ditebak-ganti-ini'
    
    # --- PERUBAHAN DI SINI ---
    # Konfigurasi Database (sekarang menunjuk ke dalam DATA_BASE_PATH)
    DATABASE_DIR = os.path.join(DATA_BASE_PATH, 'database')
    DATABASE_PATH = os.path.join(DATABASE_DIR, 'secure_files.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Konfigurasi Upload (sekarang menunjuk ke dalam DATA_BASE_PATH)
    UPLOAD_DIR = os.path.join(DATA_BASE_PATH, 'uploads')
    UPLOAD_FOLDER = os.path.join(UPLOAD_DIR, 'encrypted')
    DECRYPTED_FOLDER = os.path.join(UPLOAD_DIR, 'decrypted')
    # --- AKHIR PERUBAHAN ---

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'jpg', 'jpeg', 'png', 'pdf', 'txt', 'doc', 'docx'}
    
    # Konfigurasi Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set True jika menggunakan HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security
    WTF_CSRF_ENABLED = True
    
    # --- PERUBAHAN DI SINI ---
    # Pastikan folder-folder baru ada
    os.makedirs(DATABASE_DIR, exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
    # --- AKHIR PERUBAHAN ---


class DevelopmentConfig(Config):
    """Konfigurasi untuk development"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Konfigurasi untuk production"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True

class TestingConfig(Config):
    """Konfigurasi untuk testing"""
    TESTING = True
    DATABASE_PATH = os.path.join(basedir, 'database', 'test_secure_files.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    WTF_CSRF_ENABLED = False

# Pilih konfigurasi berdasarkan environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}