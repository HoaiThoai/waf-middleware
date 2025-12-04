import os
from datetime import datetime
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, func
from functools import wraps # QUAN TRỌNG: Import thêm cái này
from waf_middleware.firewall import Firewall

# --- CẤU HÌNH ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'YOUR_SECRET_KEY_HERE')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)

class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    ip_address = db.Column(db.String(50), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    rule_id = db.Column(db.String(20))
    description = db.Column(db.String(200))
    payload = db.Column(db.Text)

# --- WAF CALLBACK ---
def log_attack_to_db(ip, attack_type, rule_id, description, payload):
    try:
        with app.app_context():
            new_log = AttackLog(ip_address=ip, attack_type=attack_type, rule_id=str(rule_id), description=description, payload=str(payload))
            db.session.add(new_log)
            db.session.commit()
            print(f"⛔ [DB LOG] Saved attack from {ip}: {attack_type}")
    except Exception as e: print(f"⚠️ Error saving log: {e}")

firewall = Firewall(app, db_callback=log_attack_to_db)

# --- AUTH DECORATOR (SỬA LỖI NAME ERROR TẠI ĐÂY) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Vui lòng đăng nhập quyền Admin!', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- HELPER ---
def check_admin():
    return session.get('admin_logged_in')

# --- ROUTES NGƯỜI DÙNG ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
        try:
            result = db.session.execute(text(query))
            if result.fetchone():
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
            else: error = 'Invalid credentials.'
        except Exception as e: error = f"Database error: {e}"
    return render_template('login.html', error=error)

@app.route('/search', methods=['GET', 'POST'])
def search():
    query = request.args.get('query', '')
    return render_template('search.html', query=query)

@app.route('/guestbook', methods=['GET', 'POST'])
def guestbook():
    if request.method == 'POST':
        content = request.form['comment']
        db.session.add(Comment(content=content))
        db.session.commit()
        flash('Comment posted!', 'success')
        return redirect(url_for('guestbook'))
    return render_template('guestbook.html', comments=Comment.query.all())

# --- FILE UPLOAD ---
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files: return redirect(request.url)
        file = request.files['file']
        if file.filename == '': return redirect(request.url)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        flash(f'File {file.filename} uploaded successfully!', 'success')
    return render_template('upload.html')

# --- ADMIN SYSTEM ---
ADMIN_USER = "admin"
ADMIN_PASS = "YOUR_ADMIN_PASSWORD"

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['admin_logged_in'] = True
            return redirect(url_for('waf_dashboard'))
        return render_template('admin_login.html', error="Sai tài khoản hoặc mật khẩu!")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/waf-dashboard')
@login_required
def waf_dashboard():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(100).all()
    return render_template('dashboard.html', logs=logs)

@app.route('/attack-hub')
@login_required
def attack_hub():
    return render_template('attack_hub.html')

@app.route('/api/stats')
@login_required
def api_stats():
    type_counts = db.session.query(AttackLog.attack_type, func.count(AttackLog.id)).group_by(AttackLog.attack_type).all()
    stats_by_type = {t[0]: t[1] for t in type_counts}
    
    ip_counts = db.session.query(AttackLog.ip_address, func.count(AttackLog.id)).group_by(AttackLog.ip_address).order_by(func.count(AttackLog.id).desc()).limit(5).all()
    stats_by_ip = {t[0]: t[1] for t in ip_counts}

    return jsonify({
        'type_labels': list(stats_by_type.keys()), 'type_data': list(stats_by_type.values()),
        'ip_labels': list(stats_by_ip.keys()), 'ip_data': list(stats_by_ip.values())
    })

# --- RUN ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password='password123'))
            db.session.commit()
    app.run(host='0.0.0.0', debug=True)