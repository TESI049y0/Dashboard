from flask import session
from ..db import get_conn
from datetime import datetime

def log_activiteit(gebruiker, actie):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO gebruikers_log (gebruiker, actie, tijdstip) VALUES (%s, %s, %s)",
                (gebruiker, actie, datetime.now())
            )
            conn.commit()

def admin_only():
    return session.get('logged_in') and session.get('is_admin') == True
