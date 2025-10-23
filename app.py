from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import ARC4, DES
import secrets
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kunci-rahasia-anda-ganti-ini'
app.config['UPLOAD_FOLDER'] = 'uploads/encrypted'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'jpg', 'jpeg', 'png', 'pdf'}

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Buat folder jika belum ada
os.makedirs('uploads/encrypted', exist_ok=True)
os.makedirs('uploads/decrypted', exist_ok=True)
os.makedirs('database', exist_ok=True)

# Database Setup
def init_db():
    conn = sqlite3.connect('database/secure_files.db')
    c = conn.cursor()
    
    # Tabel Users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Tabel Files
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        original_filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        mode TEXT NOT NULL,
        original_size INTEGER,
        encrypted_size INTEGER,
        encryption_time REAL,
        decryption_time REAL,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Tabel Logs
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

# User Class untuk Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database/secure_files.db')
    c = conn.cursor()
    c.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Fungsi Enkripsi
def encrypt_file_aes(data, mode_name='CBC'):
    key = secrets.token_bytes(32)  # AES-256
    
    if mode_name == 'CBC':
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        # Padding untuk CBC
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
    else:  # OFB
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        encrypted_data = iv + cipher.encryptor().update(data)
    
    return encrypted_data, key

def decrypt_file_aes(encrypted_data, key, mode_name='CBC'):
    if mode_name == 'CBC':
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decrypted = cipher.decryptor().update(ciphertext)
        # Remove padding
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
    else:  # OFB
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        decrypted = cipher.decryptor().update(ciphertext)
    
    return decrypted

def encrypt_file_des(data, mode_name='CBC'):
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
        cipher = DES.new(key, DES.MODE_CFB, iv)
        encrypted_data = iv + cipher.encrypt(data)
    else:  # OFB
        iv = secrets.token_bytes(8)
        cipher = DES.new(key, DES.MODE_OFB, iv)
        encrypted_data = iv + cipher.encrypt(data)
    
    return encrypted_data, key

def decrypt_file_des(encrypted_data, key, mode_name='CBC'):
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
        cipher = DES.new(key, DES.MODE_CFB, iv)
        decrypted = cipher.decrypt(ciphertext)
    else:  # OFB
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = DES.new(key, DES.MODE_OFB, iv)
        decrypted = cipher.decrypt(ciphertext)
    
    return decrypted

def encrypt_file_rc4(data):
    key = secrets.token_bytes(16)  # RC4 key
    cipher = ARC4.new(key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data, key

def decrypt_file_rc4(encrypted_data, key):
    cipher = ARC4.new(key)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if len(username) < 3:
            flash('Username minimal 3 karakter', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password minimal 6 karakter', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('database/secure_files.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                     (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username sudah digunakan', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database/secure_files.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1])
            login_user(user_obj)
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout berhasil', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('database/secure_files.db')
    c = conn.cursor()
    c.execute('''SELECT id, original_filename, algorithm, mode, original_size, 
                 encrypted_size, encryption_time, upload_date 
                 FROM files WHERE user_id = ? ORDER BY upload_date DESC''', 
              (current_user.id,))
    files = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', files=files)

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
            
            # Enkripsi file
            start_time = time.time()
            
            if algorithm == 'AES':
                encrypted_data, key = encrypt_file_aes(file_data, mode)
            elif algorithm == 'DES':
                encrypted_data, key = encrypt_file_des(file_data, mode)
            else:  # RC4
                encrypted_data, key = encrypt_file_rc4(file_data)
                mode = 'Stream'
            
            encryption_time = (time.time() - start_time) * 1000  # ms
            
            # Simpan file terenkripsi
            encrypted_filename = f"{secrets.token_hex(8)}_{original_filename}.enc"
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            # Simpan encrypted data dan key dalam satu file
            with open(encrypted_path, 'wb') as f:
                f.write(len(key).to_bytes(4, 'big'))  # simpan panjang key
                f.write(key)  # simpan key
                f.write(encrypted_data)  # simpan data terenkripsi
            
            encrypted_size = len(encrypted_data)
            
            # Simpan metadata ke database
            conn = sqlite3.connect('database/secure_files.db')
            c = conn.cursor()
            c.execute('''INSERT INTO files (user_id, original_filename, encrypted_filename,
                        algorithm, mode, original_size, encrypted_size, encryption_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (current_user.id, original_filename, encrypted_filename, 
                      algorithm, mode, original_size, encrypted_size, encryption_time))
            conn.commit()
            conn.close()
            
            flash(f'File berhasil dienkripsi dengan {algorithm} ({mode})! Waktu: {encryption_time:.2f}ms', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Format file tidak diizinkan', 'danger')
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    conn = sqlite3.connect('database/secure_files.db')
    c = conn.cursor()
    c.execute('''SELECT original_filename, encrypted_filename, algorithm, mode 
                 FROM files WHERE id = ? AND user_id = ?''', (file_id, current_user.id))
    file_info = c.fetchone()
    
    if not file_info:
        flash('File tidak ditemukan', 'danger')
        return redirect(url_for('dashboard'))
    
    original_filename, encrypted_filename, algorithm, mode = file_info
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    
    # Baca file terenkripsi dan key
    with open(encrypted_path, 'rb') as f:
        key_length = int.from_bytes(f.read(4), 'big')
        key = f.read(key_length)
        encrypted_data = f.read()
    
    # Dekripsi file
    start_time = time.time()
    
    if algorithm == 'AES':
        decrypted_data = decrypt_file_aes(encrypted_data, key, mode)
    elif algorithm == 'DES':
        decrypted_data = decrypt_file_des(encrypted_data, key, mode)
    else:  # RC4
        decrypted_data = decrypt_file_rc4(encrypted_data, key)
    
    decryption_time = (time.time() - start_time) * 1000  # ms
    
    # Update waktu dekripsi di database
    c.execute('UPDATE files SET decryption_time = ? WHERE id = ?', 
             (decryption_time, file_id))
    conn.commit()
    conn.close()
    
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_filename
    )

@app.route('/analytics')
@login_required
def analytics():
    conn = sqlite3.connect('database/secure_files.db')
    c = conn.cursor()
    c.execute('''SELECT algorithm, mode, AVG(encryption_time) as avg_enc, 
                 AVG(decryption_time) as avg_dec, AVG(encrypted_size) as avg_size,
                 COUNT(*) as count
                 FROM files WHERE user_id = ?
                 GROUP BY algorithm, mode''', (current_user.id,))
    stats = c.fetchall()
    conn.close()
    
    return render_template('analytics.html', stats=stats)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    conn = sqlite3.connect('database/secure_files.db')
    c = conn.cursor()
    c.execute('SELECT encrypted_filename FROM files WHERE id = ? AND user_id = ?', 
             (file_id, current_user.id))
    file_info = c.fetchone()
    
    if file_info:
        encrypted_filename = file_info[0]
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File berhasil dihapus', 'success')
    else:
        flash('File tidak ditemukan', 'danger')
    
    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)