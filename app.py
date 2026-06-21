import base64
import io
import os
import re
import secrets
import sqlite3

import pyotp
import qrcode
from flask import (Flask, flash, g, redirect, render_template, request, session,
                   url_for)
from passlib.hash import bcrypt

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'users.db')

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(24)),
    DATABASE=DB_PATH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PASSWORD_MIN_LENGTH = 8


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )
        '''
    )
    db.commit()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def validate_email(email: str) -> bool:
    return bool(EMAIL_PATTERN.match(email.strip()))


def validate_password(password: str) -> bool:
    return len(password) >= PASSWORD_MIN_LENGTH


def get_user_by_email(email: str):
    return query_db('SELECT * FROM users WHERE email = ?', (email.lower().strip(),), one=True)


def get_totp_provisioning_uri(email: str, secret: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email.lower().strip(), issuer_name='SecureLoginApp')


def make_qr_code_base64(data: str) -> str:
    image = qrcode.make(data)
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    return base64.b64encode(buffer.getvalue()).decode('utf-8')


def create_user(email: str, password: str):
    password_hash = bcrypt.hash(password)
    totp_secret = pyotp.random_base32()
    db = get_db()
    db.execute(
        'INSERT INTO users (email, password_hash, totp_secret) VALUES (?, ?, ?)',
        (email.lower().strip(), password_hash, totp_secret),
    )
    db.commit()
    return totp_secret


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = query_db('SELECT id, email FROM users WHERE id = ?', (user_id,), one=True)


@app.route('/')
def index():
    if g.user:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    secret = None
    totp_uri = None
    qr_code = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
        elif not validate_password(password):
            flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif get_user_by_email(email):
            flash('A user with that email already exists.', 'error')
        else:
            secret = create_user(email, password)
            totp_uri = get_totp_provisioning_uri(email, secret)
            qr_code = make_qr_code_base64(totp_uri)
            flash('Registration successful. Scan the 2FA QR code to complete setup.', 'success')
            return render_template('register.html', secret=secret, totp_uri=totp_uri, qr_code=qr_code)

    return render_template('register.html', secret=secret, totp_uri=totp_uri, qr_code=qr_code)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user = get_user_by_email(email)

        if user is None or not bcrypt.verify(password, user['password_hash']):
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

        session.clear()
        session['pending_user_id'] = user['id']
        return redirect(url_for('two_factor'))

    return render_template('login.html')


@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    pending_user_id = session.get('pending_user_id')
    if pending_user_id is None:
        return redirect(url_for('login'))

    user = query_db('SELECT * FROM users WHERE id = ?', (pending_user_id,), one=True)
    if user is None:
        session.clear()
        flash('Invalid authentication session. Please log in again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(token, valid_window=1):
            session.clear()
            session['user_id'] = user['id']
            flash('Two-factor authentication successful.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid authentication code.', 'error')

    return render_template('two_factor.html', email=user['email'])


@app.route('/dashboard')
def dashboard():
    if g.user is None:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=g.user['email'])


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()
    app.run(debug=True)