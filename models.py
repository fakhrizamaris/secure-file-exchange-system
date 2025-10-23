"""
Database models untuk Secure File Exchange System
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Model untuk tabel users"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    logs = db.relationship('Log', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash password sebelum disimpan"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verifikasi password"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update waktu login terakhir"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def get_file_count(self):
        """Dapatkan jumlah file user"""
        return self.files.count()
    
    def get_total_storage(self):
        """Dapatkan total ukuran storage yang digunakan (dalam bytes)"""
        total = db.session.query(db.func.sum(File.encrypted_size)).filter_by(user_id=self.id).scalar()
        return total or 0
    
    def __repr__(self):
        return f'<User {self.username}>'


class File(db.Model):
    """Model untuk tabel files"""
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # File info
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_type = db.Column(db.String(50))  # xlsx, jpg, pdf, etc
    
    # Encryption info
    algorithm = db.Column(db.String(20), nullable=False)  # AES, DES, RC4
    mode = db.Column(db.String(20), nullable=False)  # CBC, CTR, CFB, OFB, Stream
    
    # Size info
    original_size = db.Column(db.Integer)  # bytes
    encrypted_size = db.Column(db.Integer)  # bytes
    
    # Performance metrics
    encryption_time = db.Column(db.Float)  # milliseconds
    decryption_time = db.Column(db.Float)  # milliseconds
    download_count = db.Column(db.Integer, default=0)
    
    # Timestamps
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_accessed = db.Column(db.DateTime)
    
    # Optional: File description
    description = db.Column(db.Text)
    
    def get_size_mb(self, size_type='original'):
        """Dapatkan ukuran file dalam MB"""
        size = self.original_size if size_type == 'original' else self.encrypted_size
        return round(size / (1024 * 1024), 2) if size else 0
    
    def get_size_kb(self, size_type='original'):
        """Dapatkan ukuran file dalam KB"""
        size = self.original_size if size_type == 'original' else self.encrypted_size
        return round(size / 1024, 2) if size else 0
    
    def get_overhead_percentage(self):
        """Hitung overhead enkripsi dalam persen"""
        if not self.original_size or self.original_size == 0:
            return 0
        overhead = ((self.encrypted_size - self.original_size) / self.original_size) * 100
        return round(overhead, 2)
    
    def increment_download(self):
        """Increment jumlah download"""
        self.download_count += 1
        self.last_accessed = datetime.utcnow()
        db.session.commit()
    
    def update_decryption_time(self, time_ms):
        """Update waktu dekripsi"""
        self.decryption_time = time_ms
        self.last_accessed = datetime.utcnow()
        db.session.commit()
    
    def get_age_days(self):
        """Dapatkan umur file dalam hari"""
        if self.upload_date:
            delta = datetime.utcnow() - self.upload_date
            return delta.days
        return 0
    
    def __repr__(self):
        return f'<File {self.original_filename} ({self.algorithm}-{self.mode})>'


class Log(db.Model):
    """Model untuk tabel logs (audit trail)"""
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    
    # Log info
    action = db.Column(db.String(50), nullable=False)  # LOGIN, UPLOAD, DOWNLOAD, DELETE, etc
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    
    # Status
    status = db.Column(db.String(20), default='SUCCESS')  # SUCCESS, FAILED, ERROR
    error_message = db.Column(db.Text)
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    @staticmethod
    def log_action(user_id, action, details=None, status='SUCCESS', ip_address=None, user_agent=None, error_message=None):
        """Helper method untuk membuat log entry"""
        log = Log(
            user_id=user_id,
            action=action,
            details=details,
            status=status,
            ip_address=ip_address,
            user_agent=user_agent,
            error_message=error_message
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def __repr__(self):
        return f'<Log {self.action} by User {self.user_id} at {self.timestamp}>'


class PerformanceMetric(db.Model):
    """Model untuk menyimpan metrik performa agregat"""
    __tablename__ = 'performance_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Algorithm and mode
    algorithm = db.Column(db.String(20), nullable=False, index=True)
    mode = db.Column(db.String(20), nullable=False)
    file_type = db.Column(db.String(50))
    
    # Aggregated metrics
    total_files = db.Column(db.Integer, default=0)
    avg_encryption_time = db.Column(db.Float)  # ms
    avg_decryption_time = db.Column(db.Float)  # ms
    avg_file_size = db.Column(db.Float)  # bytes
    avg_overhead = db.Column(db.Float)  # percentage
    
    # Date
    date_recorded = db.Column(db.Date, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<PerformanceMetric {self.algorithm}-{self.mode}>'


# Helper functions untuk database initialization

def init_db(app):
    """Initialize database"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")


def create_admin_user(username='admin', password='admin123', email='admin@example.com'):
    """Create default admin user"""
    try:
        admin = User.query.filter_by(username=username).first()
        if not admin:
            admin = User(username=username, email=email)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"Admin user '{username}' created successfully!")
            return admin
        else:
            print(f"Admin user '{username}' already exists!")
            return admin
    except Exception as e:
        print(f"Error creating admin user: {e}")
        db.session.rollback()
        return None


def get_database_stats():
    """Dapatkan statistik database"""
    stats = {
        'total_users': User.query.count(),
        'total_files': File.query.count(),
        'total_logs': Log.query.count(),
        'total_storage_gb': db.session.query(db.func.sum(File.encrypted_size)).scalar() or 0,
    }
    stats['total_storage_gb'] = round(stats['total_storage_gb'] / (1024**3), 2)
    return stats