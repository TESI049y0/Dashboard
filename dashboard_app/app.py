from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import requests
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from datetime import datetime, timedelta
import secrets, uuid, os
import bcrypt
from functools import wraps
from config import Config
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.config.from_object(Config)

# Initialize security extensions
talisman = Talisman(
    app,
    force_https=True,
    session_cookie_secure=True,
    feature_policy={
        'geolocation': '\'none\'',
        'midi': '\'none\'',
        'notifications': '\'none\'',
        'push': '\'none\'',
        'sync-xhr': '\'none\'',
        'microphone': '\'none\'',
        'camera': '\'none\'',
        'magnetometer': '\'none\'',
        'gyroscope': '\'none\'',
        'speaker': '\'none\'',
        'vibrate': '\'none\'',
        'fullscreen': '\'none\'',
        'payment': '\'none\'',
    }
)

csrf = CSRFProtect(app)
mail = Mail(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize connection pool
pool = SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    dbname=app.config['DB_NAME'],
    user=app.config['DB_USER'],
    password=app.config['DB_PASSWORD'],
    host=app.config['DB_HOST']
)

def setup_logging():
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/dashboard.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Dashboard startup')

setup_logging()

def get_db_connection():
    return pool.getconn()

def release_db_connection(conn):
    pool.putconn(conn)

# Database connection context manager
class DatabaseConnection:
    def __enter__(self):
        self.conn = get_db_connection()
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            app.logger.error(f"Database error: {exc_val}")
        release_db_connection(self.conn)

# === DECORATORS ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('U moet eerst inloggen om deze pagina te bekijken.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('U heeft geen toegang tot deze pagina.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# === HULPFUNCTIES ===
def log_activiteit(gebruiker, actie):
    with DatabaseConnection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO gebruikers_log (gebruiker, actie, tijdstip) VALUES (%s, %s, %s)",
                (gebruiker, actie, datetime.now())
            )
            conn.commit()

def is_valid_password(password):
    """Check if password meets security requirements"""
    if len(password) < 12:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*()' for c in password):
        return False
    return True

def send_password_reset_email(user_email, token):
    msg = Message('Password Reset Request',
                  sender='noreply@yourdomain.com',
                  recipients=[user_email])
    msg.body = f'''Om uw wachtwoord te resetten, bezoek de volgende link:
{url_for('reset_token', token=token, _external=True)}

Als u geen wachtwoord reset heeft aangevraagd, negeer dan dit bericht.
'''
    mail.send(msg)

# === ERROR HANDLERS ===
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

# === LOGIN ROUTES ===
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        
        with DatabaseConnection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT wachtwoord, is_admin FROM gebruikers WHERE gebruikersnaam = %s",
                    (username,)
                )
                result = cur.fetchone()
                
                if result and bcrypt.checkpw(password, result[0].encode('utf-8')):
                    session['logged_in'] = True
                    session['username'] = username
                    session['is_admin'] = result[1]
                    session.permanent = True
                    log_activiteit(username, "Ingelogd")
                    return redirect(url_for('index'))
                    
        flash("Ongeldige gebruikersnaam of wachtwoord", "error")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    if username:
        log_activiteit(username, "Uitgelogd")
    session.clear()
    return redirect(url_for('login'))

@app.route('/reset-request', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_request():
    if request.method == 'POST':
        username = request.form['username']
        with DatabaseConnection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM gebruikers WHERE gebruikersnaam = %s", (username,))
                user = cur.fetchone()
                
                if user:
                    token = secrets.token_urlsafe(32)
                    expiry = datetime.now() + timedelta(hours=1)
                    
                    cur.execute(
                        "UPDATE gebruikers SET reset_token = %s, reset_token_expiry = %s WHERE id = %s",
                        (token, expiry, user[0])
                    )
                    conn.commit()
                    
                    send_password_reset_email(username, token)
                    
                flash('Als dit account bestaat, ontvangt u een e-mail met instructies.', 'info')
                return redirect(url_for('login'))
    
    return render_template('reset_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    with DatabaseConnection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM gebruikers WHERE reset_token = %s AND reset_token_expiry > %s",
                (token, datetime.now())
            )
            user = cur.fetchone()
            
            if not user:
                flash('Ongeldige of verlopen reset link.', 'error')
                return redirect(url_for('reset_request'))
            
            if request.method == 'POST':
                password = request.form['password']
                
                if not is_valid_password(password):
                    flash('Wachtwoord voldoet niet aan de veiligheidseisen.', 'error')
                    return render_template('reset_token.html')
                
                hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                
                cur.execute(
                    "UPDATE gebruikers SET wachtwoord = %s, reset_token = NULL, reset_token_expiry = NULL WHERE id = %s",
                    (hashed_pw.decode('utf-8'), user[0])
                )
                conn.commit()
                
                flash('Uw wachtwoord is succesvol gewijzigd.', 'success')
                return redirect(url_for('login'))
    
    return render_template('reset_token.html')

# === MAIN DASHBOARD ===
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/scan-status-label')
@login_required
def scan_status_label():
    try:
        r = requests.get(
            f"{app.config['SCAN_SERVICE_URL']}/scan-status",
            timeout=3,
            verify=True
        )
        r.raise_for_status()
        return r.text
    except requests.Timeout:
        return "Timeout bij verbinden"
    except requests.ConnectionError:
        return "Verbinding mislukt"
    except requests.RequestException as e:
        app.logger.error(f"Error in scan-status-label: {str(e)}")
        return "Service niet beschikbaar"

# Clean up database connections when the application stops
@app.teardown_appcontext
def shutdown_session(exception=None):
    pool.closeall()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc') 
