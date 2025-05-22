from flask import render_template, request, redirect, url_for, session, flash
from app import app, limiter, mail
from datetime import datetime, timedelta
import bcrypt
import secrets
from flask_mail import Message
from app.database import DatabaseConnection
import logging

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

# === ROUTES ===
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
