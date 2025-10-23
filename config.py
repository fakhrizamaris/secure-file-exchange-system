# config.py
# (Nama file diperbaiki dari conifg.py)

import os
from datetime import timedelta

# Tentukan base directory proyek
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Konfigurasi aplikasi dasar"""
    
    # Kunci rahasia untuk Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'kunci-rahasia-yang-sangat-sulit-ditebak-ganti-ini'
    
    # Konfigurasi Database
    DATABASE_PATH = os.path.join(basedir, 'database', 'secure_files.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Konfigurasi Upload
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads', 'encrypted')
    DECRYPTED_FOLDER = os.path.join(basedir, 'uploads', 'decrypted')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'jpg', 'jpeg', 'png', 'pdf', 'txt', 'doc', 'docx'}
    
    # Konfigurasi Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set True jika menggunakan HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security
    WTF_CSRF_ENABLED = True
    
    # Pastikan folder-folder ada
    os.makedirs(os.path.join(basedir, 'database'), exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(DECRYPTED_FOLDER, exist_ok=True)


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