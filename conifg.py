import os
from datetime import timedelta

class Config:
    """Konfigurasi aplikasi"""
    
    # Flask Config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'kunci-rahasia-ganti-dengan-random-string-panjang'
    
    # Database
    DATABASE_PATH = 'database/secure_files.db'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload Config
    UPLOAD_FOLDER = 'uploads/encrypted'
    DECRYPTED_FOLDER = 'uploads/decrypted'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'jpg', 'jpeg', 'png', 'pdf', 'txt', 'doc', 'docx'}
    
    # Session Config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set True jika menggunakan HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    
    # Encryption Config
    AES_KEY_SIZE = 32  # 256 bits
    DES_KEY_SIZE = 8   # 64 bits
    RC4_KEY_SIZE = 16  # 128 bits
    
    # Logging
    LOG_FILE = 'logs/app.log'
    LOG_LEVEL = 'INFO'

class DevelopmentConfig(Config):
    """Konfigurasi untuk development"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Konfigurasi untuk production"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    """Konfigurasi untuk testing"""
    TESTING = True
    DATABASE_PATH = 'database/test_secure_files.db'
    WTF_CSRF_ENABLED = False

# Pilih konfigurasi berdasarkan environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}