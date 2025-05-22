from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file
import requests, io, csv
from ..db import get_conn

bp = Blueprint('dashboard', __name__)

@bp.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))

    service_filter = request.args.get('service', '')
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    ip_filter = request.args.get('ip', '')
    poort_filter = request.args.get('poort', '')

    query = "SELECT ip, poort, status, protocol, service, tijdstip FROM scanresultaten WHERE ip IS NOT NULL AND poort IS NOT NULL AND tijdstip IS NOT NULL"
    params = []

    if service_filter:
        query += " AND service = %s"
        params.append(service_filter)
    if ip_filter:
        query += " AND ip ILIKE %s"
        params.append(f"%{ip_filter}%")
    if poort_filter:
        query += " AND poort::text ILIKE %s"
        params.append(f"%{poort_filter}%")
    if date_from:
        query += " AND tijdstip >= %s"
        params.append(date_from)
    if date_to:
        query += " AND tijdstip <= %s"
        params.append(date_to)

    query += " ORDER BY tijdstip DESC LIMIT 100"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            cur.execute("SELECT DISTINCT service FROM scanresultaten")
            services = [r[0] for r in cur.fetchall()]

    return render_template("index.html", rows=rows, services=services)

@bp.route('/export')
def export():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT ip, poort, status, protocol, service, tijdstip FROM scanresultaten ORDER BY tijdstip DESC")
            rows = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP', 'Poort', 'Status', 'Protocol', 'Service', 'Tijdstip'])
    writer.writerows(rows)
    output.seek(0)
    return send_file(io.BytesIO(output.read().encode()), mimetype='text/csv', as_attachment=True, download_name='scan_export.csv')

@bp.route('/start-scan', methods=['POST'])
def start_scan():
    netwerk = request.form.get('netwerk')
    richtlijn_id = request.form.get('richtlijn')

    try:
        # Geef beide waarden mee aan de scanserver
        requests.post('http://192.168.10.11:5000/trigger-scan', json={
            "netwerk": netwerk,
            "richtlijn_id": richtlijn_id
        }, timeout=5)
        flash(f"✅ Scan gestart voor {netwerk} (Richtlijn {richtlijn_id})")
    except Exception as e:
        flash(f"❌ Scan mislukt: {e}")

    return redirect(url_for('dashboard.index'))

@bp.route('/scan-status-label')
def scan_status_label():
    try:
        r = requests.get("http://192.168.10.11:5000/scan-status", timeout=3)
        return r.text
    except:
        return "niet bereikbaar"

@bp.route('/scan-complete')
def scan_complete():
    return "✅ Scan ontvangen!", 200
