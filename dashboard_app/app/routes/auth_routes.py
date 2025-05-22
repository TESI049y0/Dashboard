from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import bcrypt, uuid
from ..db import get_conn
from .utils import log_activiteit

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT wachtwoord, is_admin FROM gebruikers WHERE gebruikersnaam = %s", (username,))
                result = cur.fetchone()
        if result and bcrypt.checkpw(password, result[0].encode('utf-8')):
            session.update({'logged_in': True, 'user': username, 'is_admin': result[1]})
            log_activiteit(username, 'Login')
            return redirect(url_for('dashboard.index'))
        flash('Foutieve inloggegevens')
    return render_template('login.html')

@bp.route('/logout')
def logout():
    gebruiker = session.get('user')
    session.clear()
    if gebruiker:
        log_activiteit(gebruiker, 'Logout')
    return redirect(url_for('auth.login'))

@bp.route('/reset-request', methods=['GET', 'POST'])
def reset_request():
    msg, fout = "", ""
    if request.method == 'POST':
        gebruikersnaam = request.form['gebruikersnaam']
        token = str(uuid.uuid4())[:8]
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM gebruikers WHERE gebruikersnaam = %s", (gebruikersnaam,))
                exists = cur.fetchone()[0]
                if exists:
                    cur.execute("UPDATE gebruikers SET reset_token = %s WHERE gebruikersnaam = %s", (token, gebruikersnaam))
                    conn.commit()
                    msg = f"Reset-token aangemaakt: {token}"
                else:
                    fout = "Gebruiker bestaat niet."
    return render_template('reset_request.html', msg=msg, fout=fout)

@bp.route('/reset', methods=['GET', 'POST'])
def reset():
    msg = ""
    if request.method == 'POST':
        gebruikersnaam = request.form['gebruikersnaam']
        token = request.form['token']
        nieuw_wachtwoord = request.form['nieuw_wachtwoord'].encode('utf-8')
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT reset_token FROM gebruikers WHERE gebruikersnaam = %s", (gebruikersnaam,))
                result = cur.fetchone()
                if result and result[0] == token:
                    hashw = bcrypt.hashpw(nieuw_wachtwoord, bcrypt.gensalt()).decode('utf-8')
                    cur.execute("UPDATE gebruikers SET wachtwoord = %s, reset_token = NULL WHERE gebruikersnaam = %s",
                                (hashw, gebruikersnaam))
                    conn.commit()
                    msg = "✅ Wachtwoord succesvol gewijzigd."
                else:
                    msg = "❌ Ongeldige token."
    return render_template('reset.html', msg=msg)
