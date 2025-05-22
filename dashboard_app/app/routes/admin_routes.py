from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from ..db import get_conn
from .utils import admin_only, log_activiteit
import bcrypt

bp = Blueprint('admin', __name__)

@bp.route('/admin')
def admin_dashboard():
    if not admin_only():
        return redirect(url_for('dashboard.index'))
    return render_template('admin/index.html')

@bp.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if not admin_only():
        return redirect(url_for('dashboard.index'))

    msg = ""

    if request.method == 'POST':
        action = request.form.get('action')
        gebruikersnaam = request.form['gebruikersnaam']

        with get_conn() as conn:
            with conn.cursor() as cur:
                if action == 'add':
                    wachtwoord = request.form['wachtwoord'].encode('utf-8')
                    hashed = bcrypt.hashpw(wachtwoord, bcrypt.gensalt()).decode('utf-8')
                    try:
                        cur.execute("INSERT INTO gebruikers (gebruikersnaam, wachtwoord, is_admin) VALUES (%s, %s, %s)",
                                    (gebruikersnaam, hashed, bool(request.form.get('is_admin'))))
                        msg = "✅ Gebruiker toegevoegd!"
                    except Exception as e:
                        msg = f"❌ Fout bij toevoegen: {e}"

                elif action == 'edit':
                    try:
                        if request.form.get('nieuw_wachtwoord'):
                            nieuw_wachtwoord = request.form['nieuw_wachtwoord'].encode('utf-8')
                            hashed = bcrypt.hashpw(nieuw_wachtwoord, bcrypt.gensalt()).decode('utf-8')
                            cur.execute("UPDATE gebruikers SET is_admin = %s, wachtwoord = %s WHERE gebruikersnaam = %s",
                                        (bool(request.form.get('is_admin')), hashed, gebruikersnaam))
                        else:
                            cur.execute("UPDATE gebruikers SET is_admin = %s WHERE gebruikersnaam = %s",
                                        (bool(request.form.get('is_admin')), gebruikersnaam))
                        msg = "🔄 Gebruiker bijgewerkt!"
                    except Exception as e:
                        msg = f"❌ Fout bij bewerken: {e}"

                elif action == 'delete':
                    try:
                        cur.execute("DELETE FROM gebruikers WHERE gebruikersnaam = %s", (gebruikersnaam,))
                        msg = "🗑️ Gebruiker verwijderd!"
                    except Exception as e:
                        msg = f"❌ Fout bij verwijderen: {e}"

                conn.commit()

    zoek = request.args.get('zoek', '')
    with get_conn() as conn:
        with conn.cursor() as cur:
            if zoek:
                cur.execute("SELECT gebruikersnaam, is_admin FROM gebruikers WHERE gebruikersnaam ILIKE %s ORDER BY gebruikersnaam", (f"%{zoek}%",))
            else:
                cur.execute("SELECT gebruikersnaam, is_admin FROM gebruikers ORDER BY gebruikersnaam")
            gebruikers = cur.fetchall()

    return render_template('admin/users.html', gebruikers=gebruikers, msg=msg)

@bp.route('/admin/logs')
def admin_logs():
    if not admin_only():
        return redirect(url_for('dashboard.index'))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT gebruiker, actie, tijdstip FROM gebruikers_log ORDER BY tijdstip DESC LIMIT 100")
            logs = cur.fetchall()

    return render_template('admin/logs.html', logs=logs)
