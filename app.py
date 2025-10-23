# app.py
# (VERSI REFACTORING - Bersih, Aman, dan Menggunakan Modul)

from flask import (
    Flask, render_template, request, redirect, url_for, flash, 
    send_file, jsonify
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, 
    login_required, current_user
)
from werkzeug.utils import secure_filename
import os
import secrets
import io
from sqlalchemy import func

# Impor dari file proyek Anda
from config import config
from models import db, User, File, Log
from encryption import EncryptionHandler

# Tentukan environment (default 'development')
env = os.environ.get('FLASK_ENV', 'default')

# Inisialisasi Aplikasi
app = Flask(__name__)
app.config.from_object(config[env])

# Inisialisasi Database & Login Manager
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Silakan login untuk mengakses halaman ini.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    # Menggunakan SQLAlchemy (models.py)
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if len(username) < 3:
            flash('Username minimal 3 karakter', 'danger')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password minimal 6 karakter', 'danger')
            return redirect(url_for('register'))
        
        # Cek jika user sudah ada (menggunakan SQLAlchemy)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username sudah digunakan', 'danger')
            return redirect(url_for('register'))
        
        # Buat user baru (menggunakan models.py)
        new_user = User(username=username)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Log registrasi
            Log.log_action(
                user_id=new_user.id, 
                action='REGISTER', 
                details=f'User {username} registered.',
                ip_address=request.remote_addr
            )
            
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {e}', 'danger')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Cek user (menggunakan SQLAlchemy)
        user = User.query.filter_by(username=username).first()
        
        # Cek password (menggunakan models.py)
        if user and user.check_password(password):
            login_user(user)
            
            # Log login
            Log.log_action(
                user_id=user.id, 
                action='LOGIN', 
                details=f'User {username} logged in.',
                ip_address=request.remote_addr
            )
            
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Log logout
    Log.log_action(
        user_id=current_user.id, 
        action='LOGOUT', 
        details=f'User {current_user.username} logged out.',
        ip_address=request.remote_addr
    )
    
    logout_user()
    flash('Logout berhasil', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Mengambil data file milik user (menggunakan SQLAlchemy)
    files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).all()
    
    # Konversi ke format list tuple agar kompatibel dengan template Anda
    file_list = [
        (
            f.id, f.original_filename, f.algorithm, f.mode, 
            f.original_size, f.encrypted_size, f.encryption_time, 
            f.upload_date.strftime('%Y-%m-%d %H:%M')
        ) for f in files
    ]
    return render_template('dashboard.html', files=file_list)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Tidak ada file yang dipilih', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        algorithm = request.form.get('algorithm', 'AES')
        mode = request.form.get('mode', 'CBC')
        
        if file.filename == '':
            flash('Tidak ada file yang dipilih', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            file_data = file.read()
            original_size = len(file_data)
            
            try:
                # Enkripsi file (menggunakan encryption.py)
                encrypted_data, key, enc_time, mode = EncryptionHandler.encrypt_file(
                    file_data, algorithm, mode
                )
                
                encrypted_size = len(encrypted_data)
                
                # Simpan file terenkripsi
                encrypted_filename = f"{secrets.token_hex(8)}_{original_filename}.enc"
                encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
                
                with open(encrypted_path, 'wb') as f:
                    f.write(encrypted_data) # Hanya simpan data, kunci disimpan di DB
                
                # Simpan metadata ke database (menggunakan SQLAlchemy)
                new_file = File(
                    user_id=current_user.id,
                    original_filename=original_filename,
                    encrypted_filename=encrypted_filename,
                    algorithm=algorithm,
                    mode=mode,
                    key=key,  # Simpan kunci di database
                    original_size=original_size,
                    encrypted_size=encrypted_size,
                    encryption_time=enc_time
                )
                
                db.session.add(new_file)
                db.session.commit()
                
                # Log upload
                Log.log_action(
                    user_id=current_user.id, 
                    action='UPLOAD', 
                    details=f'File {original_filename} uploaded with {algorithm}-{mode}.',
                    ip_address=request.remote_addr
                )
                
                flash(f'File berhasil dienkripsi dengan {algorithm} ({mode})! Waktu: {enc_time:.2f}ms', 'success')
                return redirect(url_for('dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'Terjadi kesalahan saat enkripsi: {e}', 'danger')
        
        else:
            flash('Format file tidak diizinkan', 'danger')
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    # Ambil info file dari DB (menggunakan SQLAlchemy)
    file_info = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    
    if not file_info:
        flash('File tidak ditemukan', 'danger')
        return redirect(url_for('dashboard'))
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info.encrypted_filename)
    
    try:
        # Baca file terenkripsi
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Ambil kunci dari database
        key = file_info.key
        
        # Dekripsi file (menggunakan encryption.py)
        decrypted_data, dec_time = EncryptionHandler.decrypt_file(
            encrypted_data, key, file_info.algorithm, file_info.mode
        )
        
        # Update waktu dekripsi di database
        file_info.decryption_time = dec_time
        db.session.commit()
        
        # Log download
        Log.log_action(
            user_id=current_user.id, 
            action='DOWNLOAD', 
            details=f'File {file_info.original_filename} downloaded.',
            ip_address=request.remote_addr
        )
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file_info.original_filename
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal mendekripsi file: {e}', 'danger')
        Log.log_action(
            user_id=current_user.id, 
            action='DOWNLOAD', 
            details=f'Failed to download {file_info.original_filename}. Error: {e}',
            ip_address=request.remote_addr,
            status='FAILED'
        )
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_info = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    
    if file_info:
        try:
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info.encrypted_filename)
            
            # Hapus file fisik
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            
            # Hapus entry dari database
            db.session.delete(file_info)
            db.session.commit()
            
            # Log penghapusan
            Log.log_action(
                user_id=current_user.id, 
                action='DELETE', 
                details=f'File {file_info.original_filename} deleted.',
                ip_address=request.remote_addr
            )
            flash('File berhasil dihapus', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Gagal menghapus file: {e}', 'danger')
    else:
        flash('File tidak ditemukan', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/analytics')
@login_required
def analytics():
    # Query analisis (menggunakan SQLAlchemy)
    stats = db.session.query(
        File.algorithm,
        File.mode,
        func.avg(File.encryption_time),
        func.avg(File.decryption_time),
        func.avg(File.encrypted_size),
        func.count(File.id)
    ).filter_by(user_id=current_user.id).group_by(File.algorithm, File.mode).all()
    
    return render_template('analytics.html', stats=stats)


# Perintah untuk inisialisasi database
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'File': File, 'Log': Log}

if __name__ == '__main__':
    # Pastikan database dibuat jika belum ada
    with app.app_context():
        db.create_all()
    app.run(debug=app.config['DEBUG'])