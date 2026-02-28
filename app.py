import os
import re
import math
import secrets
import json
import csv
import io
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, session, make_response, send_file)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         login_required, logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, or_
import qrcode
import qrcode.image.svg
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────────────
# APP CONFIG
# ─────────────────────────────────────────────

app = Flask(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'attendr-super-secret-2024-xyz')
_db_url = os.environ.get('DATABASE_URL', 'sqlite:///smart_attendance.db')
# Supabase/Heroku give 'postgres://' but SQLAlchemy 2.x requires 'postgresql://'
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 5,
    'max_overflow': 10,
    'connect_args': {'sslmode': 'require'} if os.environ.get('DATABASE_URL') else {},
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = ''

# ─────────────────────────────────────────────
# CAMPUS CONFIG
# ─────────────────────────────────────────────

CAMPUS_LAT = 18.6851959
CAMPUS_LON = 78.1132355
ALLOWED_RADIUS = 80          # metres
QR_ROTATE_SECONDS = 15       # QR token lifespan
SUSPENSION_THRESHOLD = 3     # suspicious attempts before flag

# ─────────────────────────────────────────────
# EMAIL CONFIG (Gmail SMTP)
# ─────────────────────────────────────────────
ADMIN_EMAIL     = 'sandulapremkumar455@gmail.com'
GMAIL_SENDER    = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASSWORD  = os.environ.get('GMAIL_APP_PASSWORD', '')   # Gmail App Password
OTP_EXPIRY_MINS = 5   # OTP valid for 5 minutes

# In-memory OTP store  {pin: {otp, expires_at}}
otp_store = {}

def send_otp_email(otp_code, purpose='login'):
    """Send OTP to admin email via Gmail SMTP."""
    if not GMAIL_SENDER or not GMAIL_PASSWORD:
        app.logger.warning('Gmail not configured — OTP: %s', otp_code)
        return True   # dev mode: skip actual send

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Smart Attendance System — OTP: {otp_code}'
        msg['From']    = GMAIL_SENDER
        msg['To']      = ADMIN_EMAIL

        body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#070709;color:#fff;padding:32px">
        <div style="max-width:480px;margin:0 auto;background:#111;border-radius:16px;padding:32px;border:1px solid #333">
          <div style="font-size:28px;font-weight:900;letter-spacing:4px;background:linear-gradient(135deg,#6c63ff,#00d4aa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px">Smart Attendance</div>
          <div style="color:#aaa;font-size:14px;margin-bottom:24px">Admin {'Login' if purpose=='login' else 'Action'} OTP</div>
          <div style="font-family:monospace;font-size:48px;font-weight:900;letter-spacing:12px;color:#6c63ff;text-align:center;padding:24px;background:#0d0d0d;border-radius:12px;margin-bottom:20px">{otp_code}</div>
          <div style="color:#aaa;font-size:13px;text-align:center">This OTP expires in <b style="color:#fff">{OTP_EXPIRY_MINS} minutes</b>.</div>
          <div style="color:#555;font-size:11px;text-align:center;margin-top:16px">If you did not request this, ignore this email.</div>
        </div></body></html>
        """
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_SENDER, GMAIL_PASSWORD)
            server.sendmail(GMAIL_SENDER, ADMIN_EMAIL, msg.as_string())
        return True
    except Exception as e:
        app.logger.error('Email send failed: %s', e)
        return False


def generate_otp():
    return str(random.randint(100000, 999999))

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id           = db.Column(db.Integer, primary_key=True)
    pin          = db.Column(db.String(30), unique=True, nullable=False, index=True)
    name         = db.Column(db.String(120), nullable=False)
    password     = db.Column(db.String(256), nullable=False)
    role         = db.Column(db.String(10), default='student', nullable=False)
    year         = db.Column(db.String(10), nullable=True)
    branch       = db.Column(db.String(20), nullable=True)
    is_active    = db.Column(db.Boolean, default=True)
    is_suspended     = db.Column(db.Boolean, default=False)
    face_descriptor  = db.Column(db.Text, nullable=True)   # JSON array from face-api.js
    face_image       = db.Column(db.Text, nullable=True)   # Base64 JPEG for server-side compare
    plain_password   = db.Column(db.String(256), nullable=True)  # stored plain for admin view
    last_login        = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    attendances      = db.relationship('Attendance', backref='student', lazy='dynamic',
                                       foreign_keys='Attendance.student_id')
    suspicious_logs  = db.relationship('SuspiciousLog', backref='user', lazy='dynamic')

    @property
    def branch_upper(self):
        return (self.branch or '').upper()

    def suspicious_count(self):
        return SuspiciousLog.query.filter_by(user_id=self.id).count()


class Subject(db.Model):
    __tablename__ = 'subject'

    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(120), nullable=False)
    branch   = db.Column(db.String(20), nullable=True)
    year     = db.Column(db.String(10), nullable=True)
    sessions = db.relationship('ClassSession', backref='subject', lazy='dynamic')

    __table_args__ = (db.UniqueConstraint('name', 'branch', 'year', name='uq_subject_batch'),)


class ClassSession(db.Model):
    __tablename__ = 'class_session'

    id                 = db.Column(db.Integer, primary_key=True)
    subject_id         = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    created_by_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year               = db.Column(db.String(10), nullable=False)
    branch             = db.Column(db.String(20), nullable=False)
    duration           = db.Column(db.Integer, nullable=False)   # minutes
    qr_token           = db.Column(db.String(64), nullable=False)
    token_generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at         = db.Column(db.DateTime, nullable=False)
    is_active          = db.Column(db.Boolean, default=True)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)

    attendances  = db.relationship('Attendance', backref='session', lazy='dynamic')
    created_by   = db.relationship('User', foreign_keys=[created_by_id])

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def seconds_remaining(self):
        delta = self.expires_at - datetime.utcnow()
        return max(0, int(delta.total_seconds()))

    def token_age_seconds(self):
        if not self.token_generated_at:
            return QR_ROTATE_SECONDS + 1
        delta = datetime.utcnow() - self.token_generated_at
        return delta.total_seconds()

    def qr_seconds_remaining(self):
        age = self.token_age_seconds()
        remaining = QR_ROTATE_SECONDS - age
        return max(0, int(remaining))


class Attendance(db.Model):
    __tablename__ = 'attendance'

    id            = db.Column(db.Integer, primary_key=True)
    student_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id    = db.Column(db.Integer, db.ForeignKey('class_session.id'), nullable=False)
    ip_address    = db.Column(db.String(64), nullable=True)
    device_fingerprint = db.Column(db.String(128), nullable=True)
    latitude      = db.Column(db.String(30), nullable=True)
    longitude     = db.Column(db.String(30), nullable=True)
    is_manual     = db.Column(db.Boolean, default=False)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('student_id', 'session_id', name='uq_student_session'),)


class SuspiciousLog(db.Model):
    __tablename__ = 'suspicious_log'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    reason     = db.Column(db.String(256), nullable=False)
    detail     = db.Column(db.String(512), nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)


class OtpVerification(db.Model):
    """Stores OTP tokens for admin login and password reset."""
    __tablename__ = 'otp_verification'

    id         = db.Column(db.Integer, primary_key=True)
    pin        = db.Column(db.String(30), nullable=False, index=True)
    otp        = db.Column(db.String(6), nullable=False)
    purpose    = db.Column(db.String(20), default='login')   # 'login' or 'reset'
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempt'

    id         = db.Column(db.Integer, primary_key=True)
    pin        = db.Column(db.String(30), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    success    = db.Column(db.Boolean, default=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# LOGIN LOADER
# ─────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─────────────────────────────────────────────
# DECORATORS
# ─────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated


def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'student':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi   = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    a = min(1.0, max(0.0, a))
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def log_suspicious(reason, detail=None, user_id=None, ip=None):
    entry = SuspiciousLog(
        user_id=user_id,
        ip_address=ip or request.remote_addr,
        reason=reason,
        detail=detail
    )
    db.session.add(entry)
    # Auto-suspend after threshold
    if user_id:
        count = SuspiciousLog.query.filter_by(user_id=user_id).count()
        if count >= SUSPENSION_THRESHOLD:
            u = User.query.get(user_id)
            if u:
                u.is_suspended = True
    db.session.commit()


def rotate_qr_if_needed(sess):
    """Rotate token if older than QR_ROTATE_SECONDS. Returns True if rotated."""
    if sess.token_age_seconds() >= QR_ROTATE_SECONDS:
        sess.qr_token = secrets.token_hex(24)
        sess.token_generated_at = datetime.utcnow()
        db.session.commit()
        return True
    return False


def get_or_create_subject(name, year, branch):
    name = name.strip().lower()
    subj = Subject.query.filter_by(name=name, year=year, branch=branch).first()
    if not subj:
        subj = Subject(name=name, year=year, branch=branch)
        db.session.add(subj)
        db.session.commit()
    return subj



def generate_qr_image(data: str, session_id: int) -> str:
    os.makedirs('static/qr', exist_ok=True)
    path = f'static/qr/qr_{session_id}.png'
    img = qrcode.make(data)
    img.save(path)
    return f'qr/qr_{session_id}.png'


def student_stats(student):
    """Strict year+branch filtering — a 1st year CS student ONLY sees
    sessions where year='1st Year' AND branch='CS'. Never cross-batch."""
    sy = (student.year   or '').strip()
    sb = (student.branch or '').strip().upper()

    # Total sessions for THIS EXACT batch only
    total_sessions = (ClassSession.query
                      .filter(ClassSession.year == sy,
                              func.upper(ClassSession.branch) == sb)
                      .count())

    # Only count attendance records linked to sessions of this batch
    attended = (Attendance.query
                .join(ClassSession, Attendance.session_id == ClassSession.id)
                .filter(Attendance.student_id == student.id,
                        ClassSession.year == sy,
                        func.upper(ClassSession.branch) == sb)
                .count())

    overall_pct = round((attended / total_sessions * 100), 1) if total_sessions else 0

    # Subjects belonging to this exact batch
    subjects = (Subject.query
                .filter(Subject.year == sy,
                        func.upper(Subject.branch) == sb)
                .all())

    breakdown = []
    for subj in subjects:
        # Sessions for this subject AND this batch — not all sessions for the subject
        conducted = (ClassSession.query
                     .filter(ClassSession.subject_id == subj.id,
                             ClassSession.year == sy,
                             func.upper(ClassSession.branch) == sb)
                     .count())
        att = (Attendance.query
               .join(ClassSession, Attendance.session_id == ClassSession.id)
               .filter(Attendance.student_id == student.id,
                       ClassSession.subject_id == subj.id,
                       ClassSession.year == sy,
                       func.upper(ClassSession.branch) == sb)
               .count())
        pct = round((att / conducted * 100), 1) if conducted else 0
        breakdown.append({
            'subject':    subj.name.title(),
            'conducted':  conducted,
            'attended':   att,
            'percentage': pct,
            'warning':    pct < 75
        })

    return {
        'total_sessions': total_sessions,
        'attended':       attended,
        'overall_pct':    overall_pct,
        'breakdown':      breakdown,
        'warning':        overall_pct < 75
    }


# ─────────────────────────────────────────────
# ROUTES — AUTH
# ─────────────────────────────────────────────

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'lecturer': return redirect(url_for('lecturer_dashboard'))
        else: return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        pin      = request.form.get('pin', '').strip()
        password = request.form.get('password', '').strip()
        ip       = request.remote_addr

        # Log attempt
        attempt = LoginAttempt(pin=pin, ip_address=ip)

        if not pin or not password:
            flash('PIN and password are required.', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(pin=pin).first()

        if not user:
            attempt.success = False
            db.session.add(attempt)
            db.session.commit()
            log_suspicious('INVALID_PIN', f'PIN: {pin}', ip=ip)
            flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))

        if user.is_suspended:
            flash('Account suspended due to suspicious activity. Contact admin.', 'error')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            attempt.success = False
            db.session.add(attempt)
            db.session.commit()
            log_suspicious('WRONG_PASSWORD', f'PIN: {pin}', user_id=user.id, ip=ip)
            flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))

        # Admin login requires OTP verification
        if user.role == 'admin':
            otp_code = generate_otp()
            expires  = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINS)
            # Delete old OTPs for this pin
            OtpVerification.query.filter_by(pin=pin, purpose='login').delete()
            otp_rec = OtpVerification(pin=pin, otp=otp_code,
                                      purpose='login', expires_at=expires)
            db.session.add(otp_rec)
            db.session.commit()
            sent = send_otp_email(otp_code, purpose='login')
            # Store pending admin pin in session for OTP verification
            session['pending_admin_pin'] = pin
            if not sent:
                flash(f'OTP generated (email failed): {otp_code}', 'warning')
            else:
                flash(f'OTP sent to {ADMIN_EMAIL}', 'success')
            return redirect(url_for('admin_otp'))

        attempt.success = True
        db.session.add(attempt)
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user)
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        if user.role == 'admin': return redirect(url_for('admin_dashboard'))
        elif user.role == 'lecturer': return redirect(url_for('lecturer_dashboard'))
        else: return redirect(url_for('student_dashboard'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        pin    = request.form.get('pin', '').strip()
        name   = request.form.get('name', '').strip()
        pw     = request.form.get('password', '').strip()
        year   = request.form.get('year', '').strip()
        branch = request.form.get('branch', '').strip().upper()

        if not all([pin, name, pw, year, branch]):
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(pin=pin).first():
            flash('PIN already registered.', 'error')
            return redirect(url_for('register'))

        user = User(
            pin=pin, name=name,
            password=generate_password_hash(pw),
            year=year, branch=branch, role='student'
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─────────────────────────────────────────────
# ROUTES — STUDENT
# ─────────────────────────────────────────────

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))

    stats = student_stats(current_user)

    # Active session for this student's batch
    active = ClassSession.query.filter_by(
        year=current_user.year,
        branch=current_user.branch_upper,
        is_active=True
    ).filter(ClassSession.expires_at > datetime.utcnow()).first()

    # Recent class sessions (last 10)
    recent_sessions = (ClassSession.query
                       .filter_by(year=current_user.year, branch=current_user.branch_upper)
                       .order_by(ClassSession.created_at.desc())
                       .limit(10).all())

    # Mark which ones student attended
    attended_ids = {
        a.session_id for a in
        Attendance.query.filter_by(student_id=current_user.id).all()
    }

    return render_template('student_dashboard.html',
                           stats=stats,
                           active_session=active,
                           recent_sessions=recent_sessions,
                           attended_ids=attended_ids)


@app.route('/student/scan', methods=['GET'])
@login_required
def scan_qr():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))
    return render_template('scan_qr.html')


@app.route('/api/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    if current_user.role != 'student':
        return jsonify({'success': False, 'message': 'Forbidden'}), 403

    if current_user.is_suspended:
        return jsonify({'success': False, 'message': 'Account suspended.'})

    data = request.get_json(silent=True) or {}

    qr_raw = data.get('qr', '').strip()
    lat    = data.get('lat')
    lon    = data.get('lon')

    # ── Parse QR ──
    if ':' not in qr_raw:
        return jsonify({'success': False, 'message': 'Invalid QR format.'})

    try:
        session_id_str, token = qr_raw.split(':', 1)
        session_id = int(session_id_str)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Malformed QR data.'})

    sess = ClassSession.query.get(session_id)

    if not sess:
        return jsonify({'success': False, 'message': 'Session not found.'})

    # ── Session active? ──
    if not sess.is_active:
        return jsonify({'success': False, 'message': 'Session is no longer active.'})

    # ── Session expired? ──
    if sess.is_expired():
        sess.is_active = False
        db.session.commit()
        return jsonify({'success': False, 'message': 'Class session has ended.'})

    # ── Token valid & not stale? ──
    if sess.qr_token != token:
        log_suspicious('TOKEN_MISMATCH', f'session={session_id}',
                       user_id=current_user.id, ip=request.remote_addr)
        return jsonify({'success': False, 'message': 'QR expired — get latest QR.'})

    if sess.token_age_seconds() > QR_ROTATE_SECONDS + 2:   # 2s grace
        return jsonify({'success': False, 'message': 'QR token expired. Scan fresh QR.'})

    # ── Batch match ──
    if (sess.year != current_user.year or
            sess.branch.upper() != current_user.branch_upper):
        log_suspicious('BATCH_MISMATCH',
                       f'Student batch {current_user.year}/{current_user.branch_upper} '
                       f'vs session {sess.year}/{sess.branch}',
                       user_id=current_user.id, ip=request.remote_addr)
        return jsonify({'success': False,
                        'message': 'This session is not for your batch.'})

    # ── Duplicate check (same student) ──
    if Attendance.query.filter_by(student_id=current_user.id,
                                  session_id=sess.id).first():
        return jsonify({'success': False, 'message': 'Attendance already marked for this session.'})

    # ── Face auth already verified at login — no IP/device lock needed ──
    ip = request.remote_addr

    # ── Geolocation ──
    if lat is None or lon is None:
        return jsonify({'success': False, 'message': 'Location required. Enable GPS and try again.'})

    try:
        lat, lon = float(lat), float(lon)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid location data.'})

    dist = haversine(lat, lon, CAMPUS_LAT, CAMPUS_LON)
    if dist > ALLOWED_RADIUS:
        log_suspicious('OUTSIDE_CAMPUS',
                       f'Distance: {dist:.1f}m, lat={lat}, lon={lon}',
                       user_id=current_user.id, ip=ip)
        return jsonify({'success': False,
                        'message': f'You are {dist:.0f}m from campus. Must be within {ALLOWED_RADIUS}m.'})

    # ── Record attendance ──
    rec = Attendance(
        student_id=current_user.id,
        session_id=sess.id,
        ip_address=ip,
        latitude=str(lat),
        longitude=str(lon),
        is_manual=False
    )
    db.session.add(rec)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Attendance marked for {sess.subject.name.title()}!'
    })


# ─────────────────────────────────────────────
# ROUTES — ADMIN
# ─────────────────────────────────────────────

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    # Summary cards
    total_students = User.query.filter_by(role='student', is_active=True).count()
    total_sessions = ClassSession.query.count()
    total_att      = Attendance.query.count()
    active_sessions = ClassSession.query.filter_by(is_active=True)\
                      .filter(ClassSession.expires_at > datetime.utcnow()).count()

    # Suspicious logs today
    today = datetime.utcnow().date()
    suspicious_today = SuspiciousLog.query.filter(
        func.date(SuspiciousLog.timestamp) == today
    ).count()

    # Recent sessions (last 8) with lecturer info
    recent = (ClassSession.query
              .order_by(ClassSession.created_at.desc())
              .limit(8).all())

    # Chart data — attendance last 7 days
    chart_data = []
    for i in range(6, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        cnt = Attendance.query.filter(func.date(Attendance.timestamp) == day).count()
        chart_data.append({'day': day.strftime('%a'), 'count': cnt})

    # Batch analytics — per year+branch combo
    BATCHES = [
        ('1st Year', 'CS'), ('1st Year', 'IT'), ('1st Year', 'EC'),
        ('2nd Year', 'CS'), ('2nd Year', 'IT'), ('2nd Year', 'EC'),
        ('3rd Year', 'CS'), ('3rd Year', 'IT'), ('3rd Year', 'EC'),
        ('4th Year', 'CS'), ('4th Year', 'IT'),
    ]
    batch_analytics = []
    for yr, br in BATCHES:
        total_sess = ClassSession.query.filter(
            ClassSession.year == yr, func.upper(ClassSession.branch) == br).count()
        if total_sess == 0:
            continue
        student_count = User.query.filter_by(role='student', year=yr).filter(
            func.upper(User.branch) == br).count()
        if student_count == 0:
            continue
        total_att_batch = (Attendance.query
            .join(ClassSession, Attendance.session_id == ClassSession.id)
            .filter(ClassSession.year == yr, func.upper(ClassSession.branch) == br).count())
        possible = total_sess * student_count
        avg_pct = round(total_att_batch / possible * 100, 1) if possible else 0
        below75 = 0
        students = User.query.filter_by(role='student', year=yr).filter(
            func.upper(User.branch) == br).all()
        for s in students:
            att = (Attendance.query.join(ClassSession, Attendance.session_id == ClassSession.id)
                   .filter(Attendance.student_id == s.id, ClassSession.year == yr,
                           func.upper(ClassSession.branch) == br).count())
            pct = att / total_sess * 100 if total_sess else 100
            if pct < 75:
                below75 += 1
        batch_analytics.append({
            'year': yr, 'branch': br,
            'students': student_count,
            'sessions': total_sess,
            'avg_pct': avg_pct,
            'below75': below75,
        })

    # Count total students below 75%
    total_below75 = 0
    all_students = User.query.filter_by(role='student', is_active=True).all()
    for s in all_students:
        sy, sb = (s.year or '').strip(), (s.branch or '').strip().upper()
        ts = ClassSession.query.filter(ClassSession.year == sy,
                                       func.upper(ClassSession.branch) == sb).count()
        if ts == 0: continue
        att = (Attendance.query.join(ClassSession, Attendance.session_id == ClassSession.id)
               .filter(Attendance.student_id == s.id, ClassSession.year == sy,
                       func.upper(ClassSession.branch) == sb).count())
        if (att / ts * 100) < 75:
            total_below75 += 1

    # Subject list for management
    all_subjects = Subject.query.order_by(Subject.name).all()

    return render_template('admin_dashboard.html',
                           total_students=total_students,
                           total_sessions=total_sessions,
                           total_att=total_att,
                           active_sessions=active_sessions,
                           suspicious_today=suspicious_today,
                           recent=recent,
                           chart_data=json.dumps(chart_data),
                           batch_analytics=batch_analytics,
                           total_below75=total_below75,
                           all_subjects=all_subjects)


@app.route('/admin/start_class', methods=['GET', 'POST'])
@login_required
def start_class():
    if current_user.role not in ('admin', 'lecturer'):
        return redirect(url_for('student_dashboard'))

    subjects = Subject.query.order_by(Subject.name).all()

    if request.method == 'POST':
        subject_name = request.form.get('subject_name', '').strip().lower()
        year         = request.form.get('year', '').strip()
        branch       = request.form.get('branch', '').strip().upper()
        duration     = request.form.get('duration', '').strip()

        if not all([subject_name, year, branch, duration]):
            flash('All fields are required.', 'error')
            return redirect(url_for('start_class'))

        try:
            duration = int(duration)
            assert 5 <= duration <= 300
        except (ValueError, AssertionError):
            flash('Duration must be between 5 and 300 minutes.', 'error')
            return redirect(url_for('start_class'))

        # Prevent duplicate active session for same batch+subject today
        subj = get_or_create_subject(subject_name, year, branch)

        conflict = (ClassSession.query
                    .filter_by(subject_id=subj.id, year=year, branch=branch, is_active=True)
                    .filter(ClassSession.expires_at > datetime.utcnow())
                    .first())
        if conflict:
            flash('An active session already exists for this batch & subject.', 'error')
            return redirect(url_for('start_class'))

        token = secrets.token_hex(24)
        expires = datetime.utcnow() + timedelta(minutes=duration)

        sess = ClassSession(
            subject_id=subj.id,
            created_by_id=current_user.id,
            year=year, branch=branch,
            duration=duration,
            qr_token=token,
            token_generated_at=datetime.utcnow(),
            expires_at=expires,
            is_active=True,
        )
        db.session.add(sess)
        db.session.commit()

        return redirect(url_for('session_live', session_id=sess.id))

    return render_template('start_class.html', subjects=subjects)


@app.route('/admin/session/<int:session_id>/live')
@login_required
def session_live(session_id):
    if current_user.role not in ('admin', 'lecturer'):
        return redirect(url_for('student_dashboard'))

    sess = ClassSession.query.get_or_404(session_id)
    return render_template('session_live.html', sess=sess,
                           qr_rotate=QR_ROTATE_SECONDS)


@app.route('/api/session/<int:session_id>/status')
@login_required
def session_status(session_id):
    """Polling endpoint for live QR & session status."""
    sess = ClassSession.query.get_or_404(session_id)

    rotate_qr_if_needed(sess)

    # Auto-close if expired
    if sess.is_expired() and sess.is_active:
        sess.is_active = False
        db.session.commit()

    qr_data = f'{sess.id}:{sess.qr_token}'
    attend_count = sess.attendances.count()

    # Attendees list for live display
    att_records = (db.session.query(Attendance, User)
                   .join(User, Attendance.student_id == User.id)
                   .filter(Attendance.session_id == sess.id)
                   .order_by(Attendance.timestamp)
                   .all())

    attendances = [{
        'name': u.name,
        'pin':  u.pin,
        'time': a.timestamp.strftime('%H:%M:%S'),
        'is_manual': a.is_manual
    } for a, u in att_records]

    return jsonify({
        'session_id': sess.id,
        'is_active':  sess.is_active,
        'qr_data':    qr_data,
        'qr_seconds_remaining':   sess.qr_seconds_remaining(),
        'session_seconds_remaining': sess.seconds_remaining(),
        'attend_count': attend_count,
        'token':      sess.qr_token,
        'attendances': attendances,
    })


@app.route('/api/session/<int:session_id>/stop', methods=['POST'])
@login_required
def stop_session(session_id):
    if current_user.role not in ('admin', 'lecturer'):
        return jsonify({'error': 'Forbidden'}), 403
    sess = ClassSession.query.get_or_404(session_id)
    sess.is_active = False
    sess.expires_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/students')
@login_required
def student_info():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    year   = request.args.get('year', '')
    branch = request.args.get('branch', '').upper()
    search = request.args.get('search', '').strip()

    q = User.query.filter_by(role='student')
    if year:
        q = q.filter(User.year == year)
    if branch:
        q = q.filter(func.upper(User.branch) == branch)
    if search:
        q = q.filter(or_(User.name.ilike(f'%{search}%'),
                         User.pin.ilike(f'%{search}%')))

    students = q.order_by(User.name).all()

    # Attach quick stats
    enriched = []
    for s in students:
        sy = (s.year   or '').strip()
        sb = (s.branch or '').strip().upper()
        # Strict: only sessions for this student's exact year + branch
        total = (ClassSession.query
                 .filter(ClassSession.year == sy,
                         func.upper(ClassSession.branch) == sb)
                 .count())
        # Only attendance linked to sessions of this batch
        att = (Attendance.query
               .join(ClassSession, Attendance.session_id == ClassSession.id)
               .filter(Attendance.student_id == s.id,
                       ClassSession.year == sy,
                       func.upper(ClassSession.branch) == sb)
               .count())
        pct = round(att / total * 100, 1) if total else 0
        enriched.append({'user': s, 'total': total, 'attended': att, 'pct': pct})

    # Batch summary for the filtered view
    batch_summary = {}
    for item in enriched:
        key = f"{item['user'].year} · {item['user'].branch_upper}"
        if key not in batch_summary:
            batch_summary[key] = {'count': 0, 'total_pct': 0, 'below75': 0}
        batch_summary[key]['count'] += 1
        batch_summary[key]['total_pct'] += item['pct']
        if item['pct'] < 75:
            batch_summary[key]['below75'] += 1
    for k in batch_summary:
        c = batch_summary[k]['count']
        batch_summary[k]['avg_pct'] = round(batch_summary[k]['total_pct'] / c, 1) if c else 0

    return render_template('student_info.html', students=enriched,
                           year=year, branch=branch, search=search,
                           batch_summary=batch_summary)


@app.route('/admin/student/<int:uid>/delete', methods=['POST'])
@login_required
def delete_student(uid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get_or_404(uid)
    if user.role == 'admin':
        return jsonify({'error': 'Cannot delete admin'}), 400
    # Cascade delete attendance
    Attendance.query.filter_by(student_id=uid).delete()
    SuspiciousLog.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'Student {user.name} deleted.', 'success')
    return redirect(url_for('student_info'))


@app.route('/admin/student/<int:uid>/toggle_suspend', methods=['POST'])
@login_required
def toggle_suspend(uid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get_or_404(uid)
    user.is_suspended = not user.is_suspended
    db.session.commit()
    status = 'suspended' if user.is_suspended else 'unsuspended'
    flash(f'Student {user.name} {status}.', 'success')
    return redirect(url_for('student_info'))


@app.route('/admin/attendance', methods=['GET', 'POST'])
@login_required
def attendance_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    year       = request.args.get('year', '')
    branch     = request.args.get('branch', '').upper()
    subject_id = request.args.get('subject_id', '')
    date_str   = request.args.get('date', '')
    page       = request.args.get('page', 1, type=int)
    per_page   = 50

    q = (db.session.query(Attendance, User, ClassSession, Subject)
         .join(User,         Attendance.student_id  == User.id)
         .join(ClassSession, Attendance.session_id  == ClassSession.id)
         .join(Subject,      ClassSession.subject_id == Subject.id))

    if year:
        q = q.filter(ClassSession.year == year)
    if branch:
        q = q.filter(func.upper(ClassSession.branch) == branch)
    if subject_id:
        q = q.filter(ClassSession.subject_id == int(subject_id))
    if date_str:
        try:
            d = datetime.strptime(date_str, '%Y-%m-%d').date()
            q = q.filter(func.date(Attendance.timestamp) == d)
        except ValueError:
            pass

    total_count     = q.count()
    unique_students = len({r[1].id for r in q.all()})
    records = q.order_by(Attendance.timestamp.desc()).offset((page-1)*per_page).limit(per_page).all()
    total_pages = max(1, (total_count + per_page - 1) // per_page)

    subjects_list = Subject.query.order_by(Subject.name).all()

    return render_template('attendance_dashboard.html',
                           records=records,
                           unique_students=unique_students,
                           total_count=total_count,
                           subjects=subjects_list,
                           year=year, branch=branch,
                           subject_id=subject_id, date_str=date_str,
                           page=page, total_pages=total_pages, per_page=per_page)


@app.route('/admin/recent_class', methods=['GET', 'POST'])
@login_required
def recent_class():
    if current_user.role not in ('admin', 'lecturer'):
        return redirect(url_for('student_dashboard'))

    # Optionally filter by year/branch
    year   = request.args.get('year', '')
    branch = request.args.get('branch', '').upper()
    selected_session_id = request.args.get('session')

    q = ClassSession.query
    # Lecturers only see their own classes
    if current_user.role == 'lecturer':
        q = q.filter(ClassSession.created_by_id == current_user.id)
    if year:
        q = q.filter(ClassSession.year == year)
    if branch:
        q = q.filter(func.upper(ClassSession.branch) == branch)

    if selected_session_id:
        recent_session = q.filter(ClassSession.id == int(selected_session_id)).first()
        if not recent_session:
            recent_session = q.order_by(ClassSession.created_at.desc()).first()
    else:
        recent_session = q.order_by(ClassSession.created_at.desc()).first()

    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        sid = int(request.form.get('session_id', 0))
        target_session = ClassSession.query.get_or_404(sid)
        student = User.query.filter_by(pin=pin, role='student').first()

        if not student:
            flash('Student not found with that PIN.', 'error')
            return redirect(url_for('recent_class', year=year, branch=branch))

        if Attendance.query.filter_by(student_id=student.id,
                                      session_id=target_session.id).first():
            flash('Attendance already marked for this student.', 'warning')
            return redirect(url_for('recent_class', year=year, branch=branch))

        rec = Attendance(
            student_id=student.id,
            session_id=target_session.id,
            ip_address='Manual Entry',
            latitude='Manual', longitude='Manual',
            is_manual=True
        )
        db.session.add(rec)
        db.session.commit()
        flash(f'Attendance added for {student.name} ({student.pin}).', 'success')
        return redirect(url_for('recent_class', year=year, branch=branch))

    attendance_list = []
    if recent_session:
        attendance_list = (db.session.query(Attendance, User)
                           .join(User, Attendance.student_id == User.id)
                           .filter(Attendance.session_id == recent_session.id)
                           .order_by(Attendance.timestamp)
                           .all())

    # All sessions for the selector (filtered by lecturer if needed)
    q2 = ClassSession.query
    if current_user.role == 'lecturer':
        q2 = q2.filter(ClassSession.created_by_id == current_user.id)
    all_sessions = q2.order_by(ClassSession.created_at.desc()).limit(20).all()

    return render_template('recent_class.html',
                           recent_session=recent_session,
                           attendance_list=attendance_list,
                           all_sessions=all_sessions,
                           year=year, branch=branch,
                           is_admin=(current_user.role == 'admin'))


@app.route('/admin/suspicious')
@login_required
def suspicious_panel():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    logs = (SuspiciousLog.query
            .order_by(SuspiciousLog.timestamp.desc())
            .limit(200).all())

    suspended = User.query.filter_by(is_suspended=True).all()

    return render_template('suspicious_panel.html',
                           logs=logs, suspended=suspended)


@app.route('/admin/add_student', methods=['POST'])
@login_required
def admin_add_student():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    pin    = request.form.get('pin', '').strip()
    name   = request.form.get('name', '').strip()
    pw     = request.form.get('password', '').strip()
    year   = request.form.get('year', '').strip()
    branch = request.form.get('branch', '').strip().upper()

    if not all([pin, name, pw, year, branch]):
        flash('All fields required.', 'error')
        return redirect(url_for('student_info'))

    if User.query.filter_by(pin=pin).first():
        flash('PIN already exists.', 'error')
        return redirect(url_for('student_info'))

    user = User(pin=pin, name=name,
                password=generate_password_hash(pw),
                plain_password=pw,
                year=year, branch=branch, role='student')
    db.session.add(user)
    db.session.commit()
    flash(f'Student {name} added successfully.', 'success')
    return redirect(url_for('student_info'))


# ─────────────────────────────────────────────
# EXPORT
@app.route('/admin/student/<int:uid>/attendance')
@login_required
def student_attendance_detail(uid):
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    student = User.query.get_or_404(uid)
    if student.role != 'student':
        return redirect(url_for('student_info'))
    stats = student_stats(student)

    # Full attendance history with session info
    history = (db.session.query(Attendance, ClassSession, Subject)
               .join(ClassSession, Attendance.session_id == ClassSession.id)
               .join(Subject, ClassSession.subject_id == Subject.id)
               .filter(Attendance.student_id == uid)
               .order_by(Attendance.timestamp.desc())
               .all())

    return render_template('student_attendance_detail.html',
                           student=student, stats=stats, history=history)


@app.route('/api/admin/student_face/<int:uid>')
@login_required
def admin_student_face(uid):
    """Return student's stored face image for admin view."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    user = User.query.get_or_404(uid)
    if user.face_image:
        return jsonify({'success': True, 'image': user.face_image})
    return jsonify({'success': False, 'message': 'No photo stored.'})


# ─────────────────────────────────────────────

@app.route('/admin/export/csv')
@login_required
def export_csv():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    records = (db.session.query(Attendance, User, ClassSession, Subject)
               .join(User,         Attendance.student_id  == User.id)
               .join(ClassSession, Attendance.session_id  == ClassSession.id)
               .join(Subject,      ClassSession.subject_id == Subject.id)
               .order_by(Attendance.timestamp.desc()).all())

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Student Name', 'PIN', 'Year', 'Branch', 'Subject',
                     'Session Date', 'Timestamp', 'IP Address', 'Manual'])
    for att, user, sess, subj in records:
        writer.writerow([
            user.name, user.pin, sess.year, sess.branch,
            subj.name.title(), sess.created_at.strftime('%Y-%m-%d'),
            att.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            att.ip_address or '', 'Yes' if att.is_manual else 'No'
        ])

    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = 'attachment; filename=attendance_export.csv'
    output.headers['Content-type'] = 'text/csv'
    return output


# ─────────────────────────────────────────────
# API — STATS
# ─────────────────────────────────────────────

@app.route('/api/admin/stats')
@login_required
def api_admin_stats():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    year   = request.args.get('year', '')
    branch = request.args.get('branch', '').upper()

    q_students = User.query.filter_by(role='student')
    q_sessions = ClassSession.query
    q_att      = Attendance.query.join(ClassSession, Attendance.session_id == ClassSession.id)

    if year:
        q_students = q_students.filter(User.year == year)
        q_sessions = q_sessions.filter(ClassSession.year == year)
        q_att      = q_att.filter(ClassSession.year == year)
    if branch:
        q_students = q_students.filter(func.upper(User.branch) == branch)
        q_sessions = q_sessions.filter(func.upper(ClassSession.branch) == branch)
        q_att      = q_att.filter(func.upper(ClassSession.branch) == branch)

    return jsonify({
        'total_students': q_students.count(),
        'total_sessions': q_sessions.count(),
        'total_att':      q_att.count(),
        'active_sessions': ClassSession.query.filter_by(is_active=True)
                           .filter(ClassSession.expires_at > datetime.utcnow()).count(),
    })


@app.route('/api/student/stats')
@login_required
def api_student_stats():
    if current_user.role != 'student':
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(student_stats(current_user))





@app.route('/api/check_credentials', methods=['POST'])
def check_credentials():
    """Step 1 of student login — verify PIN+password before face scan."""
    data = request.get_json(silent=True) or {}
    pin  = data.get('pin','').strip()
    pw   = data.get('password','')
    user = User.query.filter_by(pin=pin).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid PIN or account not found.'})
    if user.is_suspended:
        return jsonify({'success': False, 'message': 'Account suspended. Contact admin.'})
    if not check_password_hash(user.password, pw):
        return jsonify({'success': False, 'message': 'Wrong password.'})
    # Admin: no face needed — signal client to submit directly
    if user.role == 'admin':
        return jsonify({'success': True, 'role': 'admin', 'skip_face': True, 'message': 'Admin verified.'})
    if not user.face_descriptor:
        return jsonify({'success': False, 'message': 'No face registered. Contact admin.'})
    return jsonify({'success': True, 'role': user.role, 'skip_face': False,
                    'has_face_image': bool(user.face_image),
                    'message': 'Credentials verified.'})


@app.route('/api/register', methods=['POST'])
def api_register():
    """JSON register endpoint called from registration page."""
    data   = request.get_json(silent=True) or {}
    pin    = data.get('pin','').strip()
    name   = data.get('name','').strip()
    pw     = data.get('password','')
    year   = data.get('year','').strip()
    branch = data.get('branch','').strip().upper()

    if not all([pin, name, pw, year, branch]):
        return jsonify({'success': False, 'message': 'All fields are required.'})
    if User.query.filter_by(pin=pin).first():
        return jsonify({'success': False, 'message': 'PIN already registered.'})

    user = User(pin=pin, name=name,
                password=generate_password_hash(pw),
                plain_password=pw,
                year=year, branch=branch, role='student')
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Account created.'})


# ─────────────────────────────────────────────
# ROUTES — ADMIN OTP LOGIN
# ─────────────────────────────────────────────

@app.route('/admin/otp', methods=['GET', 'POST'])
def admin_otp():
    """Admin OTP verification page after credentials check."""
    pin = session.get('pending_admin_pin')
    if not pin:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        rec = (OtpVerification.query
               .filter_by(pin=pin, purpose='login', used=False)
               .order_by(OtpVerification.created_at.desc())
               .first())

        if not rec:
            flash('No OTP found. Please login again.', 'error')
            return redirect(url_for('login'))

        if datetime.utcnow() > rec.expires_at:
            flash('OTP expired. Please login again.', 'error')
            return redirect(url_for('login'))

        if rec.otp != entered_otp:
            flash('Wrong OTP. Try again.', 'error')
            return render_template('admin_otp.html')

        # OTP correct — mark used, login
        rec.used = True
        user = User.query.filter_by(pin=pin).first()
        user.last_login = datetime.utcnow()
        db.session.commit()
        session.pop('pending_admin_pin', None)
        login_user(user)
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_otp.html')


@app.route('/admin/otp/resend', methods=['POST'])
def resend_otp():
    pin = session.get('pending_admin_pin')
    if not pin:
        return jsonify({'success': False, 'message': 'Session expired.'})

    otp_code = generate_otp()
    expires  = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINS)
    OtpVerification.query.filter_by(pin=pin, purpose='login').delete()
    otp_rec = OtpVerification(pin=pin, otp=otp_code,
                              purpose='login', expires_at=expires)
    db.session.add(otp_rec)
    db.session.commit()
    sent = send_otp_email(otp_code, purpose='login')
    if sent:
        return jsonify({'success': True, 'message': f'New OTP sent to {ADMIN_EMAIL}'})
    else:
        return jsonify({'success': False, 'message': f'Email failed. OTP: {otp_code}'})


# ─────────────────────────────────────────────
# ROUTES — FORGOT PASSWORD
# ─────────────────────────────────────────────

@app.route('/forgot-password', methods=['GET'])
def forgot_password():
    return render_template('forgot_password.html')


@app.route('/api/forgot/send-otp', methods=['POST'])
def forgot_send_otp():
    """Step 1: Verify PIN exists, send OTP for password reset (students/lecturers use face instead)."""
    data = request.get_json(silent=True) or {}
    pin  = data.get('pin','').strip()
    user = User.query.filter_by(pin=pin).first()

    if not user:
        return jsonify({'success': False, 'message': 'PIN not found.'})

    # Students & lecturers use face to reset — no OTP needed
    # This route is for verifying PIN exists before face step
    if user.role in ('student', 'lecturer'):
        if not user.face_descriptor:
            return jsonify({'success': False,
                            'message': 'No face registered. Contact admin.'})
        return jsonify({'success': True, 'role': user.role,
                        'message': 'PIN verified. Scan your face to continue.'})

    return jsonify({'success': False, 'message': 'Use admin reset for admin accounts.'})


@app.route('/api/forgot/verify-face', methods=['POST'])
def forgot_verify_face():
    """Step 2: Verify face for password reset (student/lecturer)."""
    data       = request.get_json(silent=True) or {}
    pin        = data.get('pin','').strip()
    descriptor = data.get('descriptor')

    if not pin or not descriptor:
        return jsonify({'success': False, 'message': 'Missing data.'})

    user = User.query.filter_by(pin=pin).first()
    if not user or user.role not in ('student', 'lecturer'):
        return jsonify({'success': False, 'message': 'User not found.'})

    if not user.face_descriptor:
        return jsonify({'success': False, 'message': 'No face registered.'})

    stored = json.loads(user.face_descriptor)
    dist   = math.sqrt(sum((a-b)**2 for a,b in zip(stored, descriptor)))

    if dist < 0.5:
        # Generate reset token stored in session
        reset_token = secrets.token_hex(32)
        session['reset_pin']   = pin
        session['reset_token'] = reset_token
        session['reset_expires'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        return jsonify({'success': True, 'token': reset_token,
                        'message': 'Face verified! Set your new password.'})
    else:
        return jsonify({'success': False, 'message': 'Face does not match.'})


@app.route('/api/forgot/reset-password', methods=['POST'])
def forgot_reset_password():
    """Step 3: Set new password after face verification."""
    data        = request.get_json(silent=True) or {}
    pin         = data.get('pin','').strip()
    token       = data.get('token','').strip()
    new_password = data.get('password','').strip()

    if not all([pin, token, new_password]):
        return jsonify({'success': False, 'message': 'Missing data.'})

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters.'})

    # Validate session token
    sess_pin   = session.get('reset_pin')
    sess_token = session.get('reset_token')
    sess_exp   = session.get('reset_expires')

    if sess_pin != pin or sess_token != token:
        return jsonify({'success': False, 'message': 'Invalid reset session. Start over.'})

    if sess_exp and datetime.utcnow() > datetime.fromisoformat(sess_exp):
        return jsonify({'success': False, 'message': 'Reset session expired. Start over.'})

    user = User.query.filter_by(pin=pin).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'})

    user.password       = generate_password_hash(new_password)
    user.plain_password = new_password
    db.session.commit()

    # Clear reset session
    session.pop('reset_pin', None)
    session.pop('reset_token', None)
    session.pop('reset_expires', None)

    return jsonify({'success': True, 'message': 'Password changed successfully! Please login.'})

# ─────────────────────────────────────────────
# FACE AUTHENTICATION ROUTES
# ─────────────────────────────────────────────

@app.route('/api/save_face', methods=['POST'])
@login_required
def save_face():
    """Save face descriptor during registration or profile update."""
    data = request.get_json(silent=True) or {}
    descriptor = data.get('descriptor')   # 128-float array from face-api.js
    if not descriptor or not isinstance(descriptor, list) or len(descriptor) != 128:
        return jsonify({'success': False, 'message': 'Invalid face data.'})
    current_user.face_descriptor = json.dumps(descriptor)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Face saved successfully.'})


@app.route('/api/verify_face', methods=['POST'])
def verify_face():
    """Called during login — verify face descriptor matches stored one for a PIN."""
    data = request.get_json(silent=True) or {}
    pin        = data.get('pin', '').strip()
    descriptor = data.get('descriptor')   # 128-float array from client

    if not pin or not descriptor:
        return jsonify({'success': False, 'message': 'Missing data.'})

    user = User.query.filter_by(pin=pin).first()
    if not user or user.role not in ('student', 'lecturer'):
        return jsonify({'success': False, 'message': 'User not found.'})

    if not user.face_descriptor:
        return jsonify({'success': False, 'message': 'No face registered. Contact admin.'})

    # Compare descriptors using Euclidean distance (same as face-api.js)
    import math as _math
    stored = json.loads(user.face_descriptor)
    if len(stored) != 128 or len(descriptor) != 128:
        return jsonify({'success': False, 'message': 'Face data corrupted.'})

    dist = _math.sqrt(sum((a - b) ** 2 for a, b in zip(stored, descriptor)))
    # 75% match threshold: distance < 0.55 (more permissive, no need for 100% match)
    THRESHOLD = 0.55
    if dist < THRESHOLD:
        return jsonify({'success': True, 'distance': round(dist, 4),
                        'message': 'Face verified!'})
    else:
        log_suspicious('FACE_MISMATCH',
                       f'Distance={dist:.3f} threshold={THRESHOLD} for PIN={pin}',
                       ip=request.remote_addr)
        return jsonify({'success': False, 'distance': round(dist, 4),
                        'message': 'Face does not match. Are you the registered student?'})


@app.route('/api/register_face_data', methods=['POST'])
def register_face_data():
    """Save face during registration (before login — user not authenticated yet).
    Accepts descriptor (128-float array) AND/OR image (base64 JPEG)."""
    data = request.get_json(silent=True) or {}
    pin        = data.get('pin', '').strip()
    descriptor = data.get('descriptor')
    image_b64  = data.get('image')   # base64 JPEG from canvas

    if not pin:
        return jsonify({'success': False, 'message': 'PIN required.'})

    user = User.query.filter_by(pin=pin).first()
    if not user:
        return jsonify({'success': False, 'message': 'Register your account first.'})

    saved = False
    if descriptor and isinstance(descriptor, list) and len(descriptor) == 128:
        user.face_descriptor = json.dumps(descriptor)
        saved = True
    if image_b64:
        user.face_image = image_b64
        saved = True
    if not saved:
        return jsonify({'success': False, 'message': 'Invalid face data.'})

    db.session.commit()
    return jsonify({'success': True, 'message': 'Face registered!'})


@app.route('/api/verify_face_image', methods=['POST'])
def verify_face_image():
    """Verify face using descriptor from client-side face-api.js.
    Compares only with THIS user's stored descriptor (not all students).
    Requires liveness proof (blink/movement detected client-side).
    75% match threshold (distance < 0.55)."""
    data = request.get_json(silent=True) or {}
    pin        = data.get('pin', '').strip()
    descriptor = data.get('descriptor')   # 128-float extracted client-side
    liveness   = data.get('liveness_ok', False)

    if not pin or not descriptor:
        return jsonify({'success': False, 'message': 'Missing data.'})

    user = User.query.filter_by(pin=pin).first()
    if not user or user.role not in ('student', 'lecturer'):
        return jsonify({'success': False, 'message': 'User not found.'})

    if not user.face_descriptor:
        return jsonify({'success': False, 'message': 'No face registered. Contact admin.'})

    stored = json.loads(user.face_descriptor)
    if len(stored) != 128 or len(descriptor) != 128:
        return jsonify({'success': False, 'message': 'Face data corrupted.'})

    dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(stored, descriptor)))
    # 75% match = threshold 0.55 (lower dist = more similar, 0=same, 1=diff)
    THRESHOLD = 0.55
    match_pct  = max(0, min(100, round((1.0 - dist / 1.0) * 100, 1)))

    if dist < THRESHOLD:
        if not liveness:
            return jsonify({'success': False, 'liveness_required': True,
                            'message': 'Face matched! Now prove you\'re live — blink or nod your head.'})
        return jsonify({'success': True, 'distance': round(dist, 4),
                        'match_pct': match_pct, 'message': 'Face verified!'})
    else:
        log_suspicious('FACE_MISMATCH',
                       f'Distance={dist:.3f} threshold={THRESHOLD} PIN={pin}',
                       ip=request.remote_addr)
        return jsonify({'success': False, 'distance': round(dist, 4),
                        'match_pct': match_pct,
                        'message': f'Face does not match ({match_pct:.0f}% similarity). Try better lighting or angle.'})


# ─────────────────────────────────────────────
# ROUTES — LECTURER
# ─────────────────────────────────────────────

@app.route('/lecturer/dashboard')
@login_required
def lecturer_dashboard():
    if current_user.role != 'lecturer':
        return redirect(url_for('home'))

    # Only sessions created by this lecturer
    my_sessions = (ClassSession.query
                   .filter_by(created_by_id=current_user.id)
                   .order_by(ClassSession.created_at.desc())
                   .all())

    total_classes   = len(my_sessions)
    total_students  = sum(s.attendances.count() for s in my_sessions)
    active_session  = next((s for s in my_sessions
                            if s.is_active and not s.is_expired()), None)

    # Enrich sessions with attendance count
    enriched = []
    for s in my_sessions:
        enriched.append({
            'session': s,
            'count':   s.attendances.count(),
        })

    return render_template('lecturer_dashboard.html',
                           enriched=enriched,
                           total_classes=total_classes,
                           total_students=total_students,
                           active_session=active_session)


# ─────────────────────────────────────────────
# ROUTES — ADMIN: MANAGE LECTURERS
# ─────────────────────────────────────────────

@app.route('/admin/lecturers')
@login_required
def admin_lecturers():
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    lecturers = (User.query.filter_by(role='lecturer')
                 .order_by(User.name).all())

    # Enrich each lecturer with their class stats
    enriched = []
    for lec in lecturers:
        sessions = ClassSession.query.filter_by(created_by_id=lec.id).all()
        total_classes   = len(sessions)
        total_students  = sum(s.attendances.count() for s in sessions)
        enriched.append({
            'user':           lec,
            'total_classes':  total_classes,
            'total_students': total_students,
            'last_class':     sessions[0].created_at if sessions else None,
        })

    return render_template('admin_lecturers.html', lecturers=enriched)


@app.route('/admin/lecturer/<int:uid>')
@login_required
def admin_lecturer_detail(uid):
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    lecturer = User.query.get_or_404(uid)
    if lecturer.role != 'lecturer':
        return redirect(url_for('admin_lecturers'))

    year    = request.args.get('year', '')
    branch  = request.args.get('branch', '').upper()
    subject = request.args.get('subject', '')

    q = ClassSession.query.filter_by(created_by_id=uid)
    if year:   q = q.filter(ClassSession.year == year)
    if branch: q = q.filter(func.upper(ClassSession.branch) == branch)

    sessions = q.order_by(ClassSession.created_at.desc()).all()

    # Filter by subject name if given
    if subject:
        sessions = [s for s in sessions
                    if subject.lower() in s.subject.name.lower()]

    enriched = []
    for s in sessions:
        enriched.append({
            'session': s,
            'count':   s.attendances.count(),
        })

    total_classes   = len(sessions)
    total_students  = sum(e['count'] for e in enriched)

    return render_template('admin_lecturer_detail.html',
                           lecturer=lecturer,
                           enriched=enriched,
                           total_classes=total_classes,
                           total_students=total_students,
                           year=year, branch=branch, subject=subject)


@app.route('/admin/add_lecturer', methods=['POST'])
@login_required
def admin_add_lecturer():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    pin         = request.form.get('pin', '').strip()
    name        = request.form.get('name', '').strip()
    pw          = request.form.get('password', '').strip()
    descriptor  = request.form.get('descriptor', '').strip()  # JSON from face capture
    face_image  = request.form.get('face_image', '').strip()  # base64 JPEG

    if not all([pin, name, pw]):
        flash('Name, PIN and password are required.', 'error')
        return redirect(url_for('admin_lecturers'))

    if User.query.filter_by(pin=pin).first():
        flash('PIN already exists.', 'error')
        return redirect(url_for('admin_lecturers'))

    lec = User(pin=pin, name=name,
               password=generate_password_hash(pw),
               plain_password=pw,
               role='lecturer',
               face_descriptor=descriptor if descriptor else None,
               face_image=face_image if face_image else None)
    db.session.add(lec)
    db.session.commit()
    flash(f'Lecturer {name} added successfully.', 'success')
    return redirect(url_for('admin_lecturers'))


@app.route('/admin/lecturer/<int:uid>/delete', methods=['POST'])
@login_required
def delete_lecturer(uid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    lec = User.query.get_or_404(uid)
    if lec.role != 'lecturer':
        return jsonify({'error': 'Not a lecturer'}), 400
    db.session.delete(lec)
    db.session.commit()
    flash(f'Lecturer {lec.name} deleted.', 'success')
    return redirect(url_for('admin_lecturers'))


@app.route('/admin/subjects')
@login_required
def admin_subjects():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    subjects = (Subject.query.order_by(Subject.name).all())
    enriched = []
    for s in subjects:
        sc = ClassSession.query.filter_by(subject_id=s.id).count()
        enriched.append({'subject': s, 'sessions': sc})
    return render_template('admin_subjects.html', subjects=enriched)


@app.route('/admin/subject/<int:sid>/rename', methods=['POST'])
@login_required
def rename_subject(sid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    subj = Subject.query.get_or_404(sid)
    new_name = request.form.get('name', '').strip().lower()
    if not new_name:
        flash('Subject name cannot be empty.', 'error')
        return redirect(url_for('admin_subjects'))
    # Check for duplicate
    existing = Subject.query.filter_by(name=new_name, year=subj.year, branch=subj.branch).first()
    if existing and existing.id != sid:
        flash(f'Subject "{new_name}" already exists for this batch. Merge instead.', 'error')
        return redirect(url_for('admin_subjects'))
    subj.name = new_name
    db.session.commit()
    flash(f'Subject renamed to "{new_name}".', 'success')
    return redirect(url_for('admin_subjects'))


@app.route('/admin/subject/<int:sid>/merge', methods=['POST'])
@login_required
def merge_subject(sid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    subj = Subject.query.get_or_404(sid)
    target_id = request.form.get('target_id', type=int)
    if not target_id or target_id == sid:
        flash('Invalid merge target.', 'error')
        return redirect(url_for('admin_subjects'))
    target = Subject.query.get_or_404(target_id)
    # Move all sessions from subj to target
    ClassSession.query.filter_by(subject_id=sid).update({'subject_id': target_id})
    db.session.delete(subj)
    db.session.commit()
    flash(f'Merged into "{target.name}".', 'success')
    return redirect(url_for('admin_subjects'))


@app.route('/admin/subject/<int:sid>/delete', methods=['POST'])
@login_required
def delete_subject(sid):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    subj = Subject.query.get_or_404(sid)
    force = request.form.get('force', '0') == '1'
    sessions = ClassSession.query.filter_by(subject_id=sid).all()
    if sessions and not force:
        flash(f'Subject "{subj.name}" has {len(sessions)} session(s). Use Force Delete to remove everything.', 'error')
        return redirect(url_for('admin_subjects'))
    # Cascade delete: attendance records -> sessions -> subject
    for sess in sessions:
        Attendance.query.filter_by(session_id=sess.id).delete()
        db.session.delete(sess)
    db.session.delete(subj)
    db.session.commit()
    n = len(sessions)
    flash(f'Subject "{subj.name}" deleted{f" along with {n} session(s) and their records" if n else ""}.', 'success')
    return redirect(url_for('admin_subjects'))


@app.route('/api/admin/session/<int:session_id>/absent')
@login_required
def session_absent_students(session_id):
    """Return students who haven't attended a given session."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    sess = ClassSession.query.get_or_404(session_id)
    attended_ids = {a.student_id for a in Attendance.query.filter_by(session_id=session_id).all()}
    absent = (User.query.filter_by(role='student', year=sess.year)
              .filter(func.upper(User.branch) == sess.branch.upper())
              .filter(~User.id.in_(attended_ids) if attended_ids else True)
              .order_by(User.name).all())
    return jsonify([{'id': s.id, 'name': s.name, 'pin': s.pin} for s in absent])


@app.route('/api/admin/bulk_attendance', methods=['POST'])
@login_required
def bulk_attendance():
    """Mark attendance for multiple students at once (manual)."""
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    student_ids = data.get('student_ids', [])
    if not session_id or not student_ids:
        return jsonify({'success': False, 'message': 'Missing data.'})
    sess = ClassSession.query.get(session_id)
    if not sess:
        return jsonify({'success': False, 'message': 'Session not found.'})
    added = 0
    for sid in student_ids:
        if not Attendance.query.filter_by(student_id=sid, session_id=session_id).first():
            rec = Attendance(student_id=sid, session_id=session_id,
                             ip_address='Bulk Manual', latitude='Manual', longitude='Manual',
                             is_manual=True)
            db.session.add(rec)
            added += 1
    db.session.commit()
    return jsonify({'success': True, 'added': added,
                    'message': f'{added} attendance record(s) added.'})


@app.route('/admin/suspicious/clear/<int:log_id>', methods=['POST'])
@login_required
def clear_suspicious_log(log_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    log = SuspiciousLog.query.get_or_404(log_id)
    db.session.delete(log)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/suspicious/clear_all', methods=['POST'])
@login_required
def clear_all_suspicious():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    SuspiciousLog.query.delete()
    db.session.commit()
    flash('All suspicious logs cleared.', 'success')
    return redirect(url_for('suspicious_panel'))


@app.route('/admin/export/filtered')
@login_required
def export_filtered_csv():
    """Export CSV with optional filters: year, branch, subject_id, student_id, date_from, date_to."""
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))

    year       = request.args.get('year', '')
    branch     = request.args.get('branch', '').upper()
    subject_id = request.args.get('subject_id', '')
    student_id = request.args.get('student_id', '')
    date_from  = request.args.get('date_from', '')
    date_to    = request.args.get('date_to', '')

    q = (db.session.query(Attendance, User, ClassSession, Subject)
         .join(User,         Attendance.student_id  == User.id)
         .join(ClassSession, Attendance.session_id  == ClassSession.id)
         .join(Subject,      ClassSession.subject_id == Subject.id))

    if year:       q = q.filter(ClassSession.year == year)
    if branch:     q = q.filter(func.upper(ClassSession.branch) == branch)
    if subject_id: q = q.filter(ClassSession.subject_id == int(subject_id))
    if student_id: q = q.filter(Attendance.student_id == int(student_id))
    if date_from:
        try:
            df = datetime.strptime(date_from, '%Y-%m-%d')
            q = q.filter(Attendance.timestamp >= df)
        except ValueError: pass
    if date_to:
        try:
            dt = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            q = q.filter(Attendance.timestamp < dt)
        except ValueError: pass

    records = q.order_by(Attendance.timestamp.desc()).all()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['Student Name', 'PIN', 'Year', 'Branch', 'Subject',
                     'Session Date', 'Timestamp', 'IP Address', 'Manual'])
    for att, user, sess, subj in records:
        writer.writerow([user.name, user.pin, sess.year, sess.branch,
                         subj.name.title(), sess.created_at.strftime('%Y-%m-%d'),
                         att.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                         att.ip_address or '', 'Yes' if att.is_manual else 'No'])
    output = make_response(si.getvalue())
    fname = f'attendance_{year or "all"}_{branch or "all"}.csv'
    output.headers['Content-Disposition'] = f'attachment; filename={fname}'
    output.headers['Content-type'] = 'text/csv'
    return output


@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw     = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        if not check_password_hash(current_user.password, current_pw):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('admin_profile'))
        if len(new_pw) < 6:
            flash('New password must be at least 6 characters.', 'error')
            return redirect(url_for('admin_profile'))
        if new_pw != confirm_pw:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('admin_profile'))
        current_user.password = generate_password_hash(new_pw)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_profile'))
    return render_template('admin_profile.html')


@app.route('/api/admin/notifications')
@login_required
def admin_notifications():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    today = datetime.utcnow().date()
    sus_today = SuspiciousLog.query.filter(
        func.date(SuspiciousLog.timestamp) == today).count()
    active = ClassSession.query.filter_by(is_active=True)\
             .filter(ClassSession.expires_at > datetime.utcnow()).count()
    sus_users = User.query.filter_by(is_suspended=True).count()
    return jsonify({'suspicious_today': sus_today, 'active_sessions': active,
                    'suspended_users': sus_users,
                    'total': sus_today + sus_users})


    """Admin can view all user passwords (plain stored in separate column if set,
    else show hash notice). We store plain_password for display."""
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    students  = User.query.filter_by(role='student').order_by(User.name).all()
    lecturers = User.query.filter_by(role='lecturer').order_by(User.name).all()
    return render_template('admin_passwords.html',
                           students=students, lecturers=lecturers)

# ─────────────────────────────────────────────
# PWA — OFFLINE SYNC
# ─────────────────────────────────────────────

@app.route('/api/sync_offline', methods=['POST'])
@login_required
def sync_offline():
    """Accepts queued offline scans from the PWA service worker."""
    if current_user.role != 'student':
        return jsonify({'success': False, 'message': 'Forbidden'}), 403

    if current_user.is_suspended:
        return jsonify({'success': False, 'message': 'Account suspended.'})

    data = request.get_json(silent=True) or {}
    scans = data.get('scans', [])

    results = []
    for scan in scans:
        qr_raw     = scan.get('qr', '').strip()
        lat        = scan.get('lat')
        lon        = scan.get('lon')
        fingerprint = scan.get('fingerprint', '')
        scanned_at  = scan.get('scanned_at', '')   # ISO timestamp from client

        if ':' not in qr_raw:
            results.append({'qr': qr_raw, 'success': False, 'message': 'Invalid QR format.'})
            continue

        try:
            session_id_str, token = qr_raw.split(':', 1)
            session_id = int(session_id_str)
        except (ValueError, TypeError):
            results.append({'qr': qr_raw, 'success': False, 'message': 'Malformed QR data.'})
            continue

        sess = ClassSession.query.get(session_id)
        if not sess:
            results.append({'qr': qr_raw, 'success': False, 'message': 'Session not found.'})
            continue

        # For offline sync: token match is checked but time grace is extended to 5 min
        # because student may have scanned while offline and synced later
        if sess.qr_token != token:
            results.append({'qr': qr_raw, 'success': False, 'message': 'QR token invalid.'})
            continue

        # Batch match
        if (sess.year != current_user.year or
                sess.branch.upper() != current_user.branch_upper):
            results.append({'qr': qr_raw, 'success': False, 'message': 'Wrong batch.'})
            continue

        # Duplicate check
        if Attendance.query.filter_by(student_id=current_user.id, session_id=sess.id).first():
            results.append({'qr': qr_raw, 'success': True, 'message': 'Already marked (synced).'})
            continue

        # Geolocation (optional for offline — campus check skipped if no location)
        ip = request.remote_addr
        lat_str = str(lat) if lat else 'Offline'
        lon_str = str(lon) if lon else 'Offline'

        if lat and lon:
            try:
                dist = haversine(float(lat), float(lon), CAMPUS_LAT, CAMPUS_LON)
                if dist > ALLOWED_RADIUS:
                    results.append({'qr': qr_raw, 'success': False,
                                    'message': f'You were {dist:.0f}m from campus.'})
                    continue
            except (ValueError, TypeError):
                pass

        rec = Attendance(
            student_id=current_user.id,
            session_id=sess.id,
            ip_address=ip,
            latitude=lat_str,
            longitude=lon_str,
            is_manual=False
        )
        db.session.add(rec)
        db.session.commit()
        results.append({'qr': qr_raw, 'success': True, 'message': f'Synced: {sess.subject.name.title()}!'})

    return jsonify({'results': results})


@app.route('/manifest.json')
def pwa_manifest():
    manifest = {
        "name": "Smart Attendance System",
        "short_name": "SmartAtt",
        "description": "Smart Attendance System",
        "start_url": "/student/scan",
        "display": "standalone",
        "background_color": "#070709",
        "theme_color": "#6c63ff",
        "orientation": "portrait",
        "icons": [
            {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    }
    from flask import Response
    return Response(
        json.dumps(manifest),
        mimetype='application/json'
    )


@app.route('/sw.js')
def service_worker():
    """Service worker — served from root so it has full scope."""
    sw_content = open('static/sw.js').read()
    from flask import Response
    return Response(sw_content, mimetype='application/javascript')

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Seed admin
        if not User.query.filter_by(pin='admin').first():
            admin = User(
                pin='admin', name='Administrator',
                password=generate_password_hash('admin123'),
                role='admin', year=None, branch=None
            )
            db.session.add(admin)
            db.session.commit()
            print('[Smart Attendance System] Default admin created — PIN: admin / Pass: admin123')

    app.run(host='0.0.0.0', port=5000, debug=False)
