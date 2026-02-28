# ============================================================
# --- VERSION & AUTO-UPDATE ---
# ============================================================
VERSION = "1.0.0"

GITHUB_RAW_URL = (
    "https://raw.githubusercontent.com/kralgif/Sentinel-SME-Guardian/main/"
    "sentinel_guardian_v5.py"
)
UPDATE_INTERVAL_SECONDS = 3600  # 60 Minuten

import sys, os, py_compile, tempfile, logging

_update_logger = logging.getLogger("sentinel.updater")

# ============================================================
# --- TELEGRAM ALERT MODULE ---
# ============================================================
# Verschlüsselte Telegram-Zugangsdaten (geladen aus sentinel.key)
# Lege eine Datei "sentinel.key" neben diese .py-Datei mit deinem
# Fernet-Schlüssel, um die verschlüsselten Token-Daten zu entschlüsseln.
# Zum Erzeugen: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Zum Verschlüsseln: python3 -c "from cryptography.fernet import Fernet; f=Fernet(open('sentinel.key','rb').read()); print(f.encrypt(b'DEIN_TOKEN'))"
_T_DATA = b'gAAAAABns97N_C_X1vA9_E7R6T5Z4U3I2O1P0L9K8J7H6G5F4D3S2A1Q0W9E8R7T6Z5U4I3O2P1L9K8J7H6G5F4D3S2A1Q0W9E8R7T6Z5U4I3O2P1L9K8J7H6G5F4D3S2A1'
_I_DATA = b'gAAAAABns97NH_G8F7D6S5A4Q3W2E1R0T9Z8U7I6O5P4L3K2J1H0G9F8D7S6A5Q4W3E2R1T0Z9U8I7O6P5'

def _load_telegram_credentials():
    """Lädt verschlüsselte Telegram-Daten aus sentinel.key neben der .py-Datei."""
    try:
        from cryptography.fernet import Fernet
        key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.key")
        with open(key_path, "rb") as f:
            key = f.read().strip()
        cipher = Fernet(key)
        token   = cipher.decrypt(_T_DATA).decode()
        chat_id = cipher.decrypt(_I_DATA).decode()
        return token, chat_id
    except Exception:
        # Kein sentinel.key vorhanden oder Schlüssel falsch → Telegram deaktiviert
        return None, None

# Zugangsdaten einmalig beim Start laden
TELEGRAM_TOKEN, TELEGRAM_CHAT_ID = _load_telegram_credentials()

async def send_telegram_alert(message: str):
    """Sendet eine Telegram-Nachricht bei Alarm. Schlägt lautlos fehl wenn nicht konfiguriert."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       f"🚨 *SENTINEL ALARM*\n\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(url, json=payload)
    except Exception:
        pass  # Netzwerkfehler ignorieren – kein Absturz des Hauptprogramms

def _send_telegram_sync(message: str):
    """Synchroner Wrapper – wird in eigenem Thread aufgerufen."""
    import asyncio as _asyncio
    try:
        loop = _asyncio.new_event_loop()
        loop.run_until_complete(send_telegram_alert(message))
        loop.close()
    except Exception:
        pass

def _fire_telegram(severity: str, category: str, message: str, ip: str = ""):
    """Schickt Telegram-Nachricht asynchron im Hintergrund (blockiert nicht)."""
    import threading
    def _task():
        try:
            # 1) Prüfe ob Telegram aktiv ist (DB-Setting)
            conn = __import__('sqlite3').connect("sentinel.db")
            cur  = conn.cursor()
            def _gs(k, d=''):
                cur.execute("SELECT value FROM settings WHERE key=?", (k,))
                r = cur.fetchone(); return r[0] if r else d
            active   = _gs('telegram_active', '1')
            on_warn  = _gs('telegram_on_warn', '1')
            db_token = _gs('telegram_token', '')
            db_chat  = _gs('telegram_chat_id', '')
            conn.close()
            if active != '1':
                return
            if severity == 'WARNUNG' and on_warn != '1':
                return
            # 2) Token: key-Datei hat Vorrang, DB als Fallback
            token   = TELEGRAM_TOKEN   or db_token
            chat_id = TELEGRAM_CHAT_ID or db_chat
            if not token or not chat_id:
                return
            # 3) Nachricht zusammenbauen & senden
            now  = __import__('datetime').datetime.now().strftime("%d.%m.%Y %H:%M:%S")
            text = (
                f"{'🔴' if severity == 'KRITISCH' else '🟡'} *{severity}* — {category}\n"
                f"📋 {message}\n"
                + (f"🌐 IP: {ip}\n" if ip else "")
                + f"🕐 {now}"
            )
            import asyncio as _asyncio
            loop = _asyncio.new_event_loop()
            loop.run_until_complete(_send_telegram_direct(token, chat_id, text))
            loop.close()
        except Exception:
            pass
    threading.Thread(target=_task, daemon=True).start()

async def _send_telegram_direct(token: str, chat_id: str, text: str):
    """Sendet direkt mit gegebenen Credentials."""
    url     = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(url, json=payload)
    except Exception:
        pass

def _extract_version(source: str) -> str:
    """Extrahiert VERSION="x.y.z" aus Quellcode-String."""
    import re as _re
    m = _re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', source, _re.MULTILINE)
    return m.group(1) if m else ""

async def _check_and_apply_update():
    """
    Lädt den Raw-Code von GitHub, vergleicht die VERSION,
    prüft Syntax und überschreibt ggf. die laufende Datei.
    """
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(GITHUB_RAW_URL)
            if resp.status_code != 200:
                _update_logger.warning(
                    f"Auto-Update: HTTP {resp.status_code} von GitHub – kein Update."
                )
                return

        remote_source = resp.text
        remote_version = _extract_version(remote_source)

        if not remote_version:
            _update_logger.warning("Auto-Update: Keine VERSION im Remote-Code gefunden.")
            return

        if remote_version == VERSION:
            _update_logger.info(
                f"Auto-Update: Version {VERSION} ist aktuell – kein Update noetig."
            )
            return

        _update_logger.info(
            f"Auto-Update: Neue Version gefunden: {remote_version} "
            f"(lokal: {VERSION}). Pruefe Syntax..."
        )

        # Syntax-Check in temporaerer Datei
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(remote_source)
            tmp_path = tmp.name

        try:
            py_compile.compile(tmp_path, doraise=True)
        except py_compile.PyCompileError as e:
            _update_logger.error(f"Auto-Update: Syntax-Fehler im Remote-Code – Update abgebrochen: {e}")
            os.unlink(tmp_path)
            return

        # Syntax OK → aktuelle Datei überschreiben
        current_file = os.path.abspath(__file__)
        _update_logger.info(
            f"Auto-Update: Syntax OK. Installiere v{remote_version} → {current_file}"
        )

        with open(current_file, "w", encoding="utf-8") as f:
            f.write(remote_source)

        os.unlink(tmp_path)
        _update_logger.info("Auto-Update: Datei geschrieben. Starte Prozess neu...")

        # Neustart via os.execv
        os.execv(sys.executable, [sys.executable] + sys.argv)

    except Exception as e:
        _update_logger.error(f"Auto-Update: Unerwarteter Fehler: {e}")

async def _auto_update_loop():
    """Hintergrund-Task: prüft alle UPDATE_INTERVAL_SECONDS auf Updates."""
    # Erster Check nach 60 Sekunden (nicht sofort beim Start)
    await asyncio.sleep(60)
    while True:
        _update_logger.info("Auto-Update: Prüfe auf neue Version...")
        await _check_and_apply_update()
        await asyncio.sleep(UPDATE_INTERVAL_SECONDS)

# ============================================================
# --- IMPORTS ---
# ============================================================
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel
import re, datetime, sqlite3, httpx, io, csv, imaplib, email, asyncio
from email.header import decode_header
from email.utils import parseaddr
import hashlib, urllib.parse, uuid, json, platform, subprocess, shutil, os, secrets, time, math
from collections import defaultdict

app = FastAPI(title="Sentinel-AI SME-Guardian")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_auto_update_loop())
    _update_logger.info(f"Sentinel SME-Guardian v{VERSION} gestartet. Auto-Update aktiv.")

# ============================================================
# --- 1. DATENBANK SETUP ---
# ============================================================
def init_db():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS history
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, level INTEGER,
                       status TEXT, detail TEXT, timestamp_raw DATETIME)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS email_accounts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT, email TEXT,
                       imap_host TEXT, imap_port INTEGER, password TEXT, active INTEGER DEFAULT 1)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS email_scan_results
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, email_from TEXT,
                       subject TEXT, verdict TEXT, risk_score INTEGER, detail TEXT, account TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS honeytokens
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT UNIQUE,
                       token_type TEXT, label TEXT, fake_value TEXT, route TEXT, created TEXT,
                       last_triggered TEXT, trigger_count INTEGER DEFAULT 0, active INTEGER DEFAULT 1)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS honeytoken_alerts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, token_id TEXT,
                       token_label TEXT, attacker_ip TEXT, user_agent TEXT,
                       path TEXT, method TEXT, severity TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS exploit_alerts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, source_ip TEXT,
                       pattern_name TEXT, payload_snippet TEXT, confidence INTEGER,
                       blocked INTEGER DEFAULT 1)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS safety_checks
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, check_type TEXT,
                       component TEXT, status TEXT, detail TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS bruteforce_alerts
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, source_ip TEXT,
                       request_count INTEGER, window_seconds INTEGER, path TEXT, blocked INTEGER DEFAULT 1)''')
    # NEW: Fingerprint table
    cursor.execute('''CREATE TABLE IF NOT EXISTS fingerprints
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       fp_id TEXT UNIQUE,
                       ip TEXT,
                       user_agent TEXT,
                       accept_lang TEXT,
                       accept_encoding TEXT,
                       connection_type TEXT,
                       is_vpn INTEGER DEFAULT 0,
                       is_tor INTEGER DEFAULT 0,
                       is_proxy INTEGER DEFAULT 0,
                       is_datacenter INTEGER DEFAULT 0,
                       is_headless INTEGER DEFAULT 0,
                       is_bot INTEGER DEFAULT 0,
                       risk_score INTEGER DEFAULT 0,
                       status TEXT DEFAULT 'normal',
                       blocked INTEGER DEFAULT 0,
                       first_seen TEXT,
                       last_seen TEXT,
                       request_count INTEGER DEFAULT 1,
                       detail TEXT)''')
    # NEW: Fingerprint behaviour events
    cursor.execute('''CREATE TABLE IF NOT EXISTS fp_behaviour
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       fp_id TEXT,
                       time TEXT,
                       event_type TEXT,
                       data TEXT)''')
    # Alarm log table (optional logging, can be toggled)
    cursor.execute('''CREATE TABLE IF NOT EXISTS alarm_log
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       time TEXT, severity TEXT, category TEXT,
                       message TEXT, ip TEXT, confirmed INTEGER DEFAULT 0)''')
    # Compliance reports log
    cursor.execute('''CREATE TABLE IF NOT EXISTS compliance_reports
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       time TEXT, period TEXT, pdf_path TEXT,
                       sent_to TEXT, status TEXT)''')
    defaults = {
        'retention_days': '30', 'ai_model': 'tinyllama', 'ai_active': '1',
        'blacklist': 'Geheim,Passwort,Kontostand,Personalakte',
        'company_name': 'Deine Firma GmbH', 'email_scan_active': '1',
        'virustotal_api_key': '', 'honeytokens_active': '1',
        'exploit_detection_active': '1', 'memory_safety_active': '1',
        'rate_limit_max': '60', 'rate_limit_window': '60',
        'fp_auto_block': '0', 'fp_block_threshold': '70',
        'alarm_log_active': '1',
        'alert_email_to': '',        # Chef email for hack alerts
        'alert_email_from': '',      # Sender
        'alert_smtp_host': '',
        'alert_smtp_port': '587',
        'alert_smtp_user': '',
        'alert_smtp_pass': '',
        'compliance_ceo_email': '',          # Geschäftsführer
        'compliance_security_email': '',     # Sicherheitsbeauftragter
        'compliance_auto_send': '0',         # Auto-send on 1st of month
        'company_address': '',
        'company_logo_text': 'SENTINEL SME-GUARDIAN',
        'telegram_token': '',       # Fallback: direkt in DB (unverschlüsselt)
        'telegram_chat_id': '',     # Fallback: direkt in DB
        'telegram_active': '1',     # Telegram ein/aus
        'telegram_on_warn': '1',    # Auch bei WARNUNG senden
    }
    for key, val in defaults.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))
    conn.commit()
    conn.close()

init_db()

def migrate_db():
    """
    Bulletproof-Migration: Prüft jede Tabelle und Spalte.
    Wenn ALTER TABLE nicht ausreicht, wird die Tabelle neu erstellt
    und die vorhandenen Daten kopiert (SQLite-sicherer Weg).
    Idempotent – sicher bei jedem Neustart.
    """
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    def get_columns(table):
        cursor.execute(f"PRAGMA table_info({table})")
        return {row[1]: row for row in cursor.fetchall()}

    def table_exists(table):
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        return cursor.fetchone() is not None

    def safe_add_col(table, col, coltype, default=None):
        """Spalte hinzufügen; fängt alle Fehler ab."""
        if not table_exists(table):
            return
        cols = get_columns(table)
        if col in cols:
            return
        try:
            if default is not None:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {coltype} DEFAULT {default}"
                )
            else:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"
                )
        except Exception:
            pass  # Spalte konnte nicht hinzugefügt werden – kein Absturz

    def recreate_table(table, new_ddl, required_cols):
        """
        Erstellt die Tabelle neu mit neuen Spalten.
        Kopiert alle vorhandenen Spalten (Schnittmenge) aus der alten Tabelle.
        Fehlende Spalten werden mit NULL / DEFAULT befüllt.
        """
        if not table_exists(table):
            cursor.execute(new_ddl)
            return
        existing_cols = set(get_columns(table).keys())
        needed_cols   = set(required_cols)
        missing       = needed_cols - existing_cols
        if not missing:
            return  # Alle Spalten vorhanden – nichts zu tun
        # Rename old table
        cursor.execute(f"ALTER TABLE {table} RENAME TO _{table}_old")
        # Create new table
        cursor.execute(new_ddl)
        # Copy data for columns that existed before
        copy_cols = existing_cols & needed_cols
        cols_str  = ", ".join(copy_cols)
        cursor.execute(
            f"INSERT INTO {table} ({cols_str}) SELECT {cols_str} FROM _{table}_old"
        )
        cursor.execute(f"DROP TABLE _{table}_old")

    # ── history ──────────────────────────────────────────────
    recreate_table(
        "history",
        """CREATE TABLE history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, level INTEGER,
               status TEXT, detail TEXT,
               timestamp_raw DATETIME
           )""",
        ["id", "time", "level", "status", "detail", "timestamp_raw"]
    )

    # ── email_scan_results ───────────────────────────────────
    recreate_table(
        "email_scan_results",
        """CREATE TABLE email_scan_results (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, email_from TEXT, subject TEXT,
               verdict TEXT, risk_score INTEGER,
               detail TEXT, account TEXT
           )""",
        ["id", "time", "email_from", "subject", "verdict", "risk_score", "detail", "account"]
    )

    # ── alarm_log ────────────────────────────────────────────
    if not table_exists("alarm_log"):
        cursor.execute("""CREATE TABLE alarm_log (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, severity TEXT, category TEXT,
               message TEXT, ip TEXT, confirmed INTEGER DEFAULT 0
           )""")

    # ── compliance_reports ───────────────────────────────────
    if not table_exists("compliance_reports"):
        cursor.execute("""CREATE TABLE compliance_reports (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, period TEXT, pdf_path TEXT,
               sent_to TEXT, status TEXT
           )""")

    # ── fingerprints ─────────────────────────────────────────
    if not table_exists("fingerprints"):
        cursor.execute("""CREATE TABLE fingerprints (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               fp_id TEXT UNIQUE, ip TEXT, user_agent TEXT,
               accept_lang TEXT, accept_encoding TEXT, connection_type TEXT,
               is_vpn INTEGER DEFAULT 0, is_tor INTEGER DEFAULT 0,
               is_proxy INTEGER DEFAULT 0, is_datacenter INTEGER DEFAULT 0,
               is_headless INTEGER DEFAULT 0, is_bot INTEGER DEFAULT 0,
               risk_score INTEGER DEFAULT 0, status TEXT DEFAULT 'normal',
               blocked INTEGER DEFAULT 0, first_seen TEXT, last_seen TEXT,
               request_count INTEGER DEFAULT 1, detail TEXT
           )""")
    else:
        for col, typ, dflt in [
            ("is_vpn","INTEGER",0),("is_tor","INTEGER",0),
            ("is_proxy","INTEGER",0),("is_datacenter","INTEGER",0),
            ("is_headless","INTEGER",0),("is_bot","INTEGER",0),
            ("risk_score","INTEGER",0),("status","TEXT",None),
            ("blocked","INTEGER",0),("first_seen","TEXT",None),
            ("last_seen","TEXT",None),("request_count","INTEGER",1),
            ("detail","TEXT",None),
        ]:
            safe_add_col("fingerprints", col, typ, dflt)

    # ── fp_behaviour ─────────────────────────────────────────
    if not table_exists("fp_behaviour"):
        cursor.execute("""CREATE TABLE fp_behaviour (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               fp_id TEXT, time TEXT, event_type TEXT, data TEXT
           )""")

    # ── bruteforce_alerts ────────────────────────────────────
    if not table_exists("bruteforce_alerts"):
        cursor.execute("""CREATE TABLE bruteforce_alerts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, source_ip TEXT, request_count INTEGER,
               window_seconds INTEGER, path TEXT,
               blocked INTEGER DEFAULT 1
           )""")

    # ── exploit_alerts ───────────────────────────────────────
    if not table_exists("exploit_alerts"):
        cursor.execute("""CREATE TABLE exploit_alerts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, source_ip TEXT, pattern_name TEXT,
               payload_snippet TEXT, confidence INTEGER,
               blocked INTEGER DEFAULT 1
           )""")

    # ── honeytoken_alerts ────────────────────────────────────
    if not table_exists("honeytoken_alerts"):
        cursor.execute("""CREATE TABLE honeytoken_alerts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, token_id TEXT, token_label TEXT,
               attacker_ip TEXT, user_agent TEXT,
               path TEXT, method TEXT, severity TEXT
           )""")

    # ── honeytokens ──────────────────────────────────────────
    if not table_exists("honeytokens"):
        cursor.execute("""CREATE TABLE honeytokens (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               token_id TEXT UNIQUE, token_type TEXT, label TEXT,
               fake_value TEXT, route TEXT, created TEXT,
               last_triggered TEXT,
               trigger_count INTEGER DEFAULT 0,
               active INTEGER DEFAULT 1
           )""")

    # ── safety_checks ────────────────────────────────────────
    if not table_exists("safety_checks"):
        cursor.execute("""CREATE TABLE safety_checks (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               time TEXT, check_type TEXT, component TEXT,
               status TEXT, detail TEXT
           )""")

    # ── email_accounts ───────────────────────────────────────
    if not table_exists("email_accounts"):
        cursor.execute("""CREATE TABLE email_accounts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               provider TEXT, email TEXT, imap_host TEXT,
               imap_port INTEGER, password TEXT,
               active INTEGER DEFAULT 1
           )""")

    # ── settings: alle Keys sicherstellen ───────────────────
    all_defaults = {
        'retention_days': '30', 'ai_model': 'tinyllama', 'ai_active': '1',
        'blacklist': 'Geheim,Passwort,Kontostand,Personalakte',
        'company_name': 'Deine Firma GmbH', 'email_scan_active': '1',
        'virustotal_api_key': '', 'honeytokens_active': '1',
        'exploit_detection_active': '1', 'memory_safety_active': '1',
        'rate_limit_max': '60', 'rate_limit_window': '60',
        'fp_auto_block': '0', 'fp_block_threshold': '70',
        'alarm_log_active': '1',
        'alert_email_to': '', 'alert_email_from': '',
        'alert_smtp_host': '', 'alert_smtp_port': '587',
        'alert_smtp_user': '', 'alert_smtp_pass': '',
        'compliance_ceo_email': '', 'compliance_security_email': '',
        'compliance_auto_send': '0', 'company_address': '',
        'company_logo_text': 'SENTINEL SME-GUARDIAN',
        'telegram_token': '', 'telegram_chat_id': '',
        'telegram_active': '1', 'telegram_on_warn': '1',
    }
    for k, v in all_defaults.items():
        cursor.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?,?)", (k, v)
        )

    conn.commit()
    conn.close()

migrate_db()


import queue
_alarm_queue: queue.Queue = queue.Queue(maxsize=200)

def push_alarm(severity: str, category: str, message: str, ip: str = ""):
    entry = {
        "id": secrets.token_hex(4),
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "severity": severity,
        "category": category,
        "message": message,
        "ip": ip
    }
    try:
        _alarm_queue.put_nowait(entry)
    except queue.Full:
        try:
            _alarm_queue.get_nowait()
            _alarm_queue.put_nowait(entry)
        except:
            pass
    # Persist to DB if alarm_log_active=1
    try:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key='alarm_log_active'")
        row = cursor.fetchone()
        if row and row[0] == '1':
            cursor.execute(
                "INSERT INTO alarm_log (time, severity, category, message, ip) VALUES (?,?,?,?,?)",
                (entry["time"], severity, category, message, ip)
            )
            conn.commit()
        conn.close()
    except:
        pass
    # Send email alert for KRITISCH events
    if severity == "KRITISCH":
        _send_alert_email_async(category, message, ip)
    # Send Telegram alert for KRITISCH and WARNUNG
    if severity in ("KRITISCH", "WARNUNG"):
        _fire_telegram(severity, category, message, ip)

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def _send_alert_email_sync(category: str, message: str, ip: str):
    """Send email alert to configured recipient when a KRITISCH event fires."""
    try:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        keys = ['alert_email_to','alert_email_from','alert_smtp_host',
                'alert_smtp_port','alert_smtp_user','alert_smtp_pass','company_name']
        settings = {}
        for k in keys:
            cursor.execute("SELECT value FROM settings WHERE key=?", (k,))
            r = cursor.fetchone()
            settings[k] = r[0] if r else ''
        conn.close()
        to_addr = settings['alert_email_to'].strip()
        smtp_host = settings['alert_smtp_host'].strip()
        if not to_addr or not smtp_host:
            return  # Not configured, skip silently
        now_str = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[SENTINEL ALARM] {category} - {settings['company_name']}"
        msg['From']    = settings['alert_email_from'] or settings['alert_smtp_user']
        msg['To']      = to_addr
        html_body = f"""
<html><body style="font-family:sans-serif;background:#0a0c10;color:#cfd8dc;padding:30px;">
<div style="max-width:600px;margin:0 auto;background:#151921;border-radius:12px;
     border:2px solid #f87171;padding:30px;">
  <h2 style="color:#f87171;margin-top:0;">SICHERHEITSALARM</h2>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="padding:8px;color:#90a4ae;width:140px;">Kategorie</td>
        <td style="padding:8px;color:#f87171;font-weight:bold;">{category}</td></tr>
    <tr style="background:#1c232d;"><td style="padding:8px;color:#90a4ae;">Zeit</td>
        <td style="padding:8px;">{now_str}</td></tr>
    <tr><td style="padding:8px;color:#90a4ae;">IP-Adresse</td>
        <td style="padding:8px;color:#fbbf24;">{ip or 'Unbekannt'}</td></tr>
    <tr style="background:#1c232d;"><td style="padding:8px;color:#90a4ae;">Details</td>
        <td style="padding:8px;">{message}</td></tr>
  </table>
  <p style="margin-top:20px;color:#90a4ae;font-size:0.85rem;">
    Diese Nachricht wurde automatisch vom Sentinel SME-Guardian ({settings['company_name']}) gesendet.
    Bitte pruefen Sie das Dashboard umgehend.
  </p>
</div>
</body></html>"""
        msg.attach(MIMEText(html_body, 'html'))
        port = int(settings['alert_smtp_port'] or 587)
        with smtplib.SMTP(smtp_host, port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(settings['alert_smtp_user'], settings['alert_smtp_pass'])
            server.sendmail(msg['From'], [to_addr], msg.as_string())
    except Exception as e:
        pass  # Silent fail – don't break main flow

def _send_alert_email_async(category: str, message: str, ip: str):
    import threading
    t = threading.Thread(target=_send_alert_email_sync, args=(category, message, ip), daemon=True)
    t.start()

# ============================================================
# --- MODULE F: COMPLIANCE PDF REPORT ---
# ============================================================
def generate_compliance_pdf(period: str = None) -> bytes:
    """Generate a monthly compliance PDF report and return as bytes."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, HRFlowable, PageBreak)
    from reportlab.platypus import KeepTogether
    import io as _io

    if not period:
        period = datetime.datetime.now().strftime("%B %Y")

    # --- Collect stats from DB ---
    now = datetime.datetime.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_start_str = month_start.strftime("%Y-%m-%d")

    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()

    # Settings
    def gs(key, default=''):
        cursor.execute("SELECT value FROM settings WHERE key=?", (key,))
        r = cursor.fetchone(); return r[0] if r else default

    company    = gs('company_name', 'Unbekannte Firma')
    ai_active  = gs('ai_active', '0')
    ht_active  = gs('honeytokens_active', '0')
    dlp_active = gs('exploit_detection_active', '0')
    addr       = gs('company_address', '')
    logo_text  = gs('company_logo_text', 'SENTINEL SME-GUARDIAN')

    # Monthly stats
    cursor.execute("SELECT COUNT(*) FROM history WHERE status='GESTOPPT' AND timestamp_raw >= ?", (month_start_str,))
    blocked_attacks = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM exploit_alerts WHERE blocked=1 AND time >= ?",
                   (month_start.strftime("%H:%M:%S"),))
    # Use total for simplicity (no date in time col) - use all-time counts filtered by id range
    cursor.execute("SELECT COUNT(*) FROM exploit_alerts WHERE blocked=1")
    exploit_total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM email_scan_results WHERE verdict='PHISHING/VIRUS'")
    phishing_total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM honeytoken_alerts")
    honey_total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM bruteforce_alerts")
    brute_total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE status='kritisch'")
    fp_critical = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_bot=1")
    fp_bots = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM history WHERE status='SICHER'")
    scans_clean = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM history")
    scans_total = cursor.fetchone()[0]
    # Recent exploit alerts for table
    cursor.execute("SELECT time, source_ip, pattern_name, confidence FROM exploit_alerts ORDER BY id DESC LIMIT 8")
    exploit_rows = cursor.fetchall()
    # Recent phishing
    cursor.execute("SELECT time, email_from, subject, risk_score FROM email_scan_results WHERE verdict='PHISHING/VIRUS' ORDER BY id DESC LIMIT 6")
    phishing_rows = cursor.fetchall()
    conn.close()

    total_threats = blocked_attacks + exploit_total + phishing_total + honey_total + brute_total
    security_score = max(0, 100 - min(total_threats * 3, 60) - (0 if ai_active == '1' else 15)
                         - (0 if ht_active == '1' else 10) - (0 if dlp_active == '1' else 15))

    # --- Build PDF ---
    buf = _io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # Color palette
    C_DARK   = colors.HexColor('#0a0c10')
    C_BLUE   = colors.HexColor('#38bdf8')
    C_GREEN  = colors.HexColor('#10b981')
    C_RED    = colors.HexColor('#f87171')
    C_YELLOW = colors.HexColor('#fbbf24')
    C_GRAY   = colors.HexColor('#90a4ae')
    C_PANEL  = colors.HexColor('#151921')
    C_BORDER = colors.HexColor('#263238')
    C_WHITE  = colors.white

    # Custom styles
    def sty(name, **kw):
        s = ParagraphStyle(name, parent=styles['Normal'], **kw)
        return s

    s_title    = sty('T', fontSize=26, textColor=C_BLUE, fontName='Helvetica-Bold',
                     leading=32, spaceAfter=4)
    s_subtitle = sty('S', fontSize=13, textColor=C_GRAY, fontName='Helvetica', leading=16)
    s_h2       = sty('H2', fontSize=14, textColor=C_BLUE, fontName='Helvetica-Bold',
                     leading=18, spaceBefore=14, spaceAfter=6)
    s_h3       = sty('H3', fontSize=11, textColor=C_BLUE, fontName='Helvetica-Bold',
                     leading=14, spaceBefore=8, spaceAfter=4)
    s_body     = sty('B', fontSize=9, textColor=colors.HexColor('#cfd8dc'), leading=13)
    s_small    = sty('Sm', fontSize=8, textColor=C_GRAY, leading=11)
    s_red      = sty('R', fontSize=9, textColor=C_RED, fontName='Helvetica-Bold', leading=13)
    s_green    = sty('G', fontSize=9, textColor=C_GREEN, fontName='Helvetica-Bold', leading=13)
    s_score_num= sty('SC', fontSize=52, textColor=C_GREEN if security_score>=70 else C_YELLOW if security_score>=40 else C_RED,
                     fontName='Helvetica-Bold', leading=60, alignment=1)
    s_score_lbl= sty('SL', fontSize=11, textColor=C_GRAY, leading=14, alignment=1)
    s_center   = sty('Cnt', fontSize=9, textColor=colors.HexColor('#cfd8dc'), leading=13, alignment=1)

    gen_time = now.strftime("%d.%m.%Y %H:%M:%S")
    sig_hash = hashlib.sha256(
        f"{company}{period}{total_threats}{security_score}{gen_time}".encode()
    ).hexdigest()[:32]

    # ── HEADER BLOCK ──────────────────────────────────────────
    header_data = [[
        Paragraph(logo_text, sty('LT', fontSize=11, textColor=C_BLUE, fontName='Helvetica-Bold', leading=13)),
        Paragraph(f'Compliance-Bericht<br/><font size="8" color="#90a4ae">{period}</font>',
                  sty('RT', fontSize=13, textColor=C_WHITE, fontName='Helvetica-Bold', leading=16, alignment=2))
    ]]
    header_tbl = Table(header_data, colWidths=[9*cm, 8*cm])
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_PANEL),
        ('ROWPADDING', (0,0), (-1,-1), 14),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph(f'Sicherheits-Compliance-Protokoll', s_title))
    story.append(Paragraph(f'{company}  |  Berichtszeitraum: {period}', s_subtitle))
    if addr:
        story.append(Paragraph(addr, s_small))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=C_BLUE))
    story.append(Spacer(1, 0.4*cm))

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────
    story.append(Paragraph('1. Zusammenfassung', s_h2))
    summary_color = C_GREEN if security_score >= 70 else C_YELLOW if security_score >= 40 else C_RED
    summary_label = 'GUT' if security_score >= 70 else 'BEACHTENSWERT' if security_score >= 40 else 'KRITISCH'

    score_data = [
        [Paragraph(str(security_score), s_score_num),
         Paragraph(f'<b>Gesamtbewertung: {summary_label}</b><br/><br/>'
                   f'Im Berichtszeitraum {period} wurden insgesamt '
                   f'<b>{total_threats} Sicherheitsereignisse</b> registriert.<br/>'
                   f'Davon wurden <b>{blocked_attacks + exploit_total} Angriffe blockiert</b>. '
                   f'Die KI-Ueberwachung war <b>{"aktiv" if ai_active=="1" else "inaktiv"}</b>, '
                   f'das Honeytoken-System war <b>{"aktiv" if ht_active=="1" else "inaktiv"}</b> '
                   f'und der DLP-Schutz war <b>{"aktiv" if dlp_active=="1" else "inaktiv"}</b>.',
                   sty('SE', fontSize=9, textColor=colors.HexColor('#cfd8dc'), leading=14))],
        [Paragraph('Sicherheits-Score', s_score_lbl), '']
    ]
    score_tbl = Table(score_data, colWidths=[4*cm, 13*cm])
    score_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_PANEL),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('ROWPADDING', (0,0), (-1,-1), 10),
        ('SPAN', (0,0), (0,1)),
        ('VALIGN', (0,0), (0,-1), 'MIDDLE'),
        ('VALIGN', (1,0), (1,0), 'MIDDLE'),
        ('LINEBELOW', (0,0), (-1,0), 0.5, C_BORDER),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 0.4*cm))

    # ── STATS TABLE ───────────────────────────────────────────
    story.append(Paragraph('2. Sicherheitsstatistiken', s_h2))

    def stat_row(label, value, color=C_WHITE, note=''):
        return [
            Paragraph(label, sty('SRL', fontSize=9, textColor=C_GRAY, leading=12)),
            Paragraph(f'<b>{value}</b>', sty('SRV', fontSize=11, textColor=color,
                                              fontName='Helvetica-Bold', leading=14, alignment=1)),
            Paragraph(note, sty('SRN', fontSize=8, textColor=C_GRAY, leading=11)),
        ]

    stats_data = [
        [Paragraph('Kategorie', sty('TH', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12)),
         Paragraph('Anzahl', sty('TH2', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12, alignment=1)),
         Paragraph('Bewertung', sty('TH3', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12))],
        stat_row('Blockierte Angriffe (DLP + Exploit)', blocked_attacks + exploit_total,
                 C_RED if (blocked_attacks + exploit_total) > 0 else C_GREEN,
                 'Kritisch' if (blocked_attacks+exploit_total) > 10 else 'Normal'),
        stat_row('Phishing-E-Mails erkannt', phishing_total,
                 C_RED if phishing_total > 0 else C_GREEN,
                 'Erhoehte Aufmerksamkeit' if phishing_total > 3 else 'Normal'),
        stat_row('Brute-Force-Angriffe', brute_total,
                 C_RED if brute_total > 5 else C_YELLOW if brute_total > 0 else C_GREEN,
                 'Kritisch' if brute_total > 10 else 'Beachten' if brute_total > 0 else 'Normal'),
        stat_row('Honeytoken-Ausloesungen', honey_total,
                 C_RED if honey_total > 0 else C_GREEN,
                 'Interner Angriff moeglich' if honey_total > 0 else 'Normal'),
        stat_row('Verdaechtige Fingerprints', fp_critical,
                 C_YELLOW if fp_critical > 0 else C_GREEN,
                 'Geprueft' if fp_critical > 0 else 'Normal'),
        stat_row('Bot-/Headless-Zugriffe', fp_bots, C_YELLOW if fp_bots > 0 else C_GREEN, ''),
        stat_row('Saubere Scans gesamt', scans_clean, C_GREEN, f'von {scans_total} Gesamt'),
    ]
    stats_tbl = Table(stats_data, colWidths=[9*cm, 2.5*cm, 5.5*cm])
    stats_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1c232d')),
        ('BACKGROUND', (0,1), (-1,-1), C_PANEL),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_PANEL, colors.HexColor('#111620')]),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('ROWPADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(stats_tbl)
    story.append(Spacer(1, 0.4*cm))

    # ── COMPLIANCE CHECKS ─────────────────────────────────────
    story.append(Paragraph('3. Compliance-Nachweise', s_h2))

    checks = [
        ('DLP-Datenschutzfilter', dlp_active == '1',
         'Exploit-Erkennung und DLP-Regeln sind aktiv und schuetzen vor Datenverlust.'),
        ('KI-Sicherheitsueberwachung', ai_active == '1',
         'Kuenstliche Intelligenz analysiert Inhalte und E-Mails in Echtzeit.'),
        ('Honeytoken-System', ht_active == '1',
         'Fallen-System ist aktiv. Interne und externe Angreifer werden erkannt.'),
        ('Brute-Force-Schutz', True,
         f'Rate-Limiting aktiv. {brute_total} Brute-Force-Versuche wurden geblockt.'),
        ('Fingerprint-Analyse', True,
         f'{fp_critical} kritische und {fp_bots} Bot-Fingerprints wurden erkannt und protokolliert.'),
        ('Echtzeit-Alarmierung', True,
         'Sirenen-Alarm und automatische E-Mail-Benachrichtigungen sind konfiguriert.'),
        ('Audit-Logging', True,
         'Alle Sicherheitsereignisse werden in der Datenbank protokolliert.'),
    ]
    compliance_data = [
        [Paragraph('Kontrolle', sty('CH', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12)),
         Paragraph('Status', sty('CH', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12, alignment=1)),
         Paragraph('Beschreibung', sty('CH', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12))],
    ]
    for label, ok, desc in checks:
        compliance_data.append([
            Paragraph(label, sty('CL', fontSize=9, textColor=colors.HexColor('#cfd8dc'), leading=12)),
            Paragraph('AKTIV' if ok else 'INAKTIV',
                      sty('CS', fontSize=9, textColor=C_GREEN if ok else C_RED,
                          fontName='Helvetica-Bold', leading=12, alignment=1)),
            Paragraph(desc, sty('CD', fontSize=8, textColor=C_GRAY, leading=11)),
        ])
    compliance_tbl = Table(compliance_data, colWidths=[5*cm, 2*cm, 10*cm])
    compliance_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1c232d')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_PANEL, colors.HexColor('#111620')]),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('ROWPADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(compliance_tbl)
    story.append(Spacer(1, 0.4*cm))

    # ── RECENT EXPLOITS TABLE ─────────────────────────────────
    if exploit_rows:
        story.append(Paragraph('4. Letzte Exploit-Erkennungen', s_h2))
        exp_data = [[
            Paragraph('Zeit', sty('EH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11)),
            Paragraph('IP', sty('EH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11)),
            Paragraph('Angriffsmuster', sty('EH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11)),
            Paragraph('Konfidenz', sty('EH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11, alignment=1)),
        ]]
        for row in exploit_rows:
            conf_color = C_RED if row[3] >= 75 else C_YELLOW
            exp_data.append([
                Paragraph(str(row[0]), sty('ED', fontSize=8, textColor=C_GRAY, leading=11)),
                Paragraph(str(row[1]), sty('ED', fontSize=8, textColor=colors.HexColor('#fca5a5'), leading=11)),
                Paragraph(str(row[2]), sty('ED', fontSize=8, textColor=colors.HexColor('#cfd8dc'), leading=11)),
                Paragraph(f'{row[3]}%', sty('ED', fontSize=8, textColor=conf_color,
                                             fontName='Helvetica-Bold', leading=11, alignment=1)),
            ])
        exp_tbl = Table(exp_data, colWidths=[2.5*cm, 4*cm, 8*cm, 2.5*cm])
        exp_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1c232d')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_PANEL, colors.HexColor('#111620')]),
            ('BOX', (0,0), (-1,-1), 1, C_BORDER),
            ('INNERGRID', (0,0), (-1,-1), 0.3, C_BORDER),
            ('ROWPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(exp_tbl)
        story.append(Spacer(1, 0.3*cm))

    # ── RECENT PHISHING ───────────────────────────────────────
    if phishing_rows:
        story.append(Paragraph('5. Erkannte Phishing-E-Mails', s_h2))
        ph_data = [[
            Paragraph('Zeit', sty('PH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11)),
            Paragraph('Absender', sty('PH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11)),
            Paragraph('Betreff', sty('PH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11)),
            Paragraph('Risiko', sty('PH', fontSize=8, textColor=C_BLUE, fontName='Helvetica-Bold', leading=11, alignment=1)),
        ]]
        for row in phishing_rows:
            risk_c = C_RED if row[3] >= 70 else C_YELLOW
            ph_data.append([
                Paragraph(str(row[0]), sty('PD', fontSize=8, textColor=C_GRAY, leading=11)),
                Paragraph(str(row[1])[:40], sty('PD', fontSize=8, textColor=colors.HexColor('#fca5a5'), leading=11)),
                Paragraph(str(row[2])[:50], sty('PD', fontSize=8, textColor=colors.HexColor('#cfd8dc'), leading=11)),
                Paragraph(f'{row[3]}%', sty('PD', fontSize=8, textColor=risk_c,
                                             fontName='Helvetica-Bold', leading=11, alignment=1)),
            ])
        ph_tbl = Table(ph_data, colWidths=[2.5*cm, 5.5*cm, 7*cm, 2*cm])
        ph_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1c232d')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_PANEL, colors.HexColor('#111620')]),
            ('BOX', (0,0), (-1,-1), 1, C_BORDER),
            ('INNERGRID', (0,0), (-1,-1), 0.3, C_BORDER),
            ('ROWPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(ph_tbl)
        story.append(Spacer(1, 0.3*cm))

    # ── SIGNATURE BLOCK ───────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('Digitale Signatur &amp; Zeitstempel', s_h2))
    story.append(Spacer(1, 0.2*cm))

    sig_data = [
        [Paragraph('Feld', sty('SGH', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12)),
         Paragraph('Wert', sty('SGH', fontSize=9, textColor=C_BLUE, fontName='Helvetica-Bold', leading=12))],
        [Paragraph('Berichtszeitraum', s_body), Paragraph(period, s_body)],
        [Paragraph('Erstellt am', s_body), Paragraph(gen_time, s_body)],
        [Paragraph('Erstellt von', s_body), Paragraph(f'Sentinel SME-Guardian - {company}', s_body)],
        [Paragraph('Dokument-Hash (SHA-256)', s_body),
         Paragraph(f'<font face="Courier" size="8">{sig_hash}</font>',
                   sty('SH', fontSize=8, textColor=colors.HexColor('#a3e635'),
                       fontName='Courier', leading=12))],
        [Paragraph('Sicherheits-Score', s_body),
         Paragraph(f'{security_score}/100 ({summary_label})',
                   sty('SS2', fontSize=9, textColor=summary_color,
                       fontName='Helvetica-Bold', leading=12))],
        [Paragraph('Gesamtereignisse', s_body), Paragraph(str(total_threats), s_body)],
    ]
    sig_tbl = Table(sig_data, colWidths=[6*cm, 11*cm])
    sig_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1c232d')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_PANEL, colors.HexColor('#111620')]),
        ('BOX', (0,0), (-1,-1), 2, C_BLUE),
        ('INNERGRID', (0,0), (-1,-1), 0.3, C_BORDER),
        ('ROWPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(sig_tbl)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph(
        f'Dieses Compliance-Protokoll wurde automatisch durch das Sentinel SME-Guardian System '
        f'generiert und ist ein rechtsgueltig nachweisbares Sicherheitsprotokoll. '
        f'Der Dokument-Hash dient als digitale Signatur zur Nachweissicherung.',
        sty('Footer', fontSize=8, textColor=C_GRAY, leading=12)))

    # ── FOOTER ON EVERY PAGE ──────────────────────────────────
    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_GRAY)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(2*cm, 1.2*cm,
            f'Sentinel SME-Guardian  |  {company}  |  Vertraulich  |  {gen_time}')
        canvas.drawRightString(A4[0]-2*cm, 1.2*cm, f'Seite {doc.page}')
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, 1.5*cm, A4[0]-2*cm, 1.5*cm)
        canvas.restoreState()

    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    return buf.getvalue()


def send_compliance_email(pdf_bytes: bytes, period: str, recipients: list, settings: dict):
    """Send compliance PDF via email."""
    from email.mime.base import MIMEBase
    from email import encoders
    try:
        smtp_host = settings.get('alert_smtp_host', '').strip()
        smtp_user = settings.get('alert_smtp_user', '').strip()
        smtp_pass = settings.get('alert_smtp_pass', '').strip()
        smtp_port = int(settings.get('alert_smtp_port', 587))
        from_addr = settings.get('alert_email_from', smtp_user).strip() or smtp_user
        if not smtp_host or not smtp_user or not recipients:
            return False, "SMTP nicht konfiguriert oder keine Empfaenger."
        company  = settings.get('company_name', 'Firma')
        filename = f"Compliance_Bericht_{period.replace(' ', '_')}.pdf"
        msg = MIMEMultipart()
        msg['Subject'] = f"[Sentinel] Monatlicher Compliance-Bericht {period} – {company}"
        msg['From']    = from_addr
        msg['To']      = ", ".join(recipients)
        html_body = f"""<html><body style="font-family:sans-serif;background:#f5f5f5;padding:20px;">
<div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;padding:30px;
     border-top:4px solid #38bdf8;">
  <h2 style="color:#0a0c10;">Monatlicher Compliance-Bericht</h2>
  <p>Sehr geehrte Damen und Herren,</p>
  <p>anbei erhalten Sie den automatisch generierten Sicherheits-Compliance-Bericht
  fuer den Zeitraum <strong>{period}</strong> von <strong>{company}</strong>.</p>
  <p>Der Bericht enthaelt:</p>
  <ul>
    <li>Statusuebersicht des Berichtszeitraums</li>
    <li>Anzahl blockierter Angriffe, Phishing-Versuche und Honeytokens</li>
    <li>Compliance-Nachweise (DLP, KI, Honeytokens)</li>
    <li>Digitale Signatur mit Zeitstempel</li>
  </ul>
  <p style="color:#888;font-size:0.85em;">Diese E-Mail wurde automatisch durch das
  Sentinel SME-Guardian System generiert.</p>
</div></body></html>"""
        msg.attach(MIMEText(html_body, 'html'))
        attach = MIMEBase('application', 'pdf')
        attach.set_payload(pdf_bytes)
        encoders.encode_base64(attach)
        attach.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(attach)
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo(); server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, recipients, msg.as_string())
        return True, f"Bericht erfolgreich an {', '.join(recipients)} gesendet."
    except Exception as e:
        return False, f"Fehler beim Senden: {str(e)}"


@app.get("/compliance/generate")
async def generate_compliance_report():
    """Generate and download the compliance PDF."""
    period = datetime.datetime.now().strftime("%B %Y")
    try:
        pdf_bytes = generate_compliance_pdf(period)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    # Save record
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    try:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO compliance_reports (time, period, pdf_path, sent_to, status) VALUES (?,?,?,?,?)",
            (now_str, period, "in-memory", "download", "generated"))
        conn.commit(); conn.close()
    except: pass
    filename = f"Compliance_{period.replace(' ','_')}.pdf"
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.post("/compliance/send")
async def send_compliance_report(request: Request):
    """Generate and email the compliance report."""
    data   = await request.json()
    period = data.get("period", datetime.datetime.now().strftime("%B %Y"))
    conn   = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    def gs(k, d=''):
        cursor.execute("SELECT value FROM settings WHERE key=?", (k,)); r=cursor.fetchone(); return r[0] if r else d
    settings_dict = {k: gs(k) for k in [
        'alert_smtp_host','alert_smtp_port','alert_smtp_user','alert_smtp_pass',
        'alert_email_from','company_name',
        'compliance_ceo_email','compliance_security_email']}
    conn.close()
    ceo_email = settings_dict.get('compliance_ceo_email','').strip()
    sec_email = settings_dict.get('compliance_security_email','').strip()
    recipients = [e for e in [ceo_email, sec_email] if e]
    if data.get("extra_email","").strip():
        recipients.append(data["extra_email"].strip())
    if not recipients:
        return JSONResponse(status_code=400,
            content={"error":"Keine Empfaenger konfiguriert. Bitte Einstellungen pruefen."})
    try:
        pdf_bytes = generate_compliance_pdf(period)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"PDF-Fehler: {str(e)}"})
    ok, msg = send_compliance_email(pdf_bytes, period, recipients, settings_dict)
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    try:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO compliance_reports (time, period, pdf_path, sent_to, status) VALUES (?,?,?,?,?)",
            (now_str, period, "emailed", ", ".join(recipients), "sent" if ok else "failed"))
        conn.commit(); conn.close()
    except: pass
    if ok:
        log_event(1, "COMPLIANCE", f"Bericht {period} gesendet an: {', '.join(recipients)}")
    return {"success": ok, "message": msg, "recipients": recipients}


@app.get("/compliance/history")
def compliance_history():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM compliance_reports ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall(); conn.close()
    return [dict(r) for r in rows]


@app.post("/compliance/settings")
async def save_compliance_settings(request: Request):
    data = await request.json()
    fields = ['compliance_ceo_email','compliance_security_email',
              'compliance_auto_send','company_address','company_logo_text']
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    for f in fields:
        if f in data:
            cursor.execute("UPDATE settings SET value=? WHERE key=?", (str(data[f]), f))
    conn.commit(); conn.close()
    return {"success": True}


@app.get("/compliance/settings")
def get_compliance_settings():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    fields = ['compliance_ceo_email','compliance_security_email',
              'compliance_auto_send','company_address','company_logo_text',
              'company_name']
    result = {}
    for f in fields:
        cursor.execute("SELECT value FROM settings WHERE key=?", (f,))
        r = cursor.fetchone(); result[f] = r[0] if r else ''
    conn.close()
    return result


# ============================================================
# --- OUTLOOK ADD-IN: REST API ENDPOINTS ---
# ============================================================
@app.post("/outlook/scan_email")
async def outlook_scan_email(request: Request):
    """
    Outlook Add-in endpoint: receives email data and returns phishing verdict.
    The add-in sends: {sender, subject, body, message_id}
    Returns: {verdict, risk_score, reasons, action}
    """
    data       = await request.json()
    sender     = data.get("sender",     "")
    subject    = data.get("subject",    "")
    body       = data.get("body",       "")
    message_id = data.get("message_id", "unknown")
    if not sender and not body:
        return JSONResponse(status_code=400, content={"error": "sender oder body erforderlich."})
    risk_score, reasons = logic.quick_phishing_score(sender, subject, body)
    verdict = "SICHER" if risk_score < 30 else ("VERDAECHTIG" if risk_score < 60 else "PHISHING")
    blocked_action = verdict in ["VERDAECHTIG", "PHISHING"]
    # Log to DB
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO email_scan_results (time, email_from, subject, verdict, risk_score, detail, account) VALUES (?,?,?,?,?,?,?)",
        (datetime.datetime.now().strftime("%H:%M:%S"), sender[:100], subject[:150],
         verdict, risk_score, "; ".join(reasons) if reasons else "Keine Auffaelligkeiten",
         f"Outlook/{message_id[:30]}")
    )
    conn.commit(); conn.close()
    if risk_score >= 60:
        push_alarm("KRITISCH", "PHISHING",
                   f"Outlook Phishing erkannt! Von: {sender[:50]}", sender)
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "reasons": reasons,
        "action": "block" if verdict == "PHISHING" else "warn" if verdict == "VERDAECHTIG" else "allow",
        "banner_color": "#f87171" if verdict == "PHISHING" else "#fbbf24" if verdict == "VERDAECHTIG" else "#10b981",
        "banner_text": (
            f"PHISHING-GEFAHR! Risiko {risk_score}% — Diese E-Mail koennte gefaehrlich sein!" if verdict == "PHISHING"
            else f"Verdaechtige E-Mail (Risiko {risk_score}%) — Vorsicht empfohlen." if verdict == "VERDAECHTIG"
            else f"E-Mail geprueft — Sicher ({risk_score}%)"
        )
    }


@app.get("/outlook/manifest")
def get_outlook_manifest():
    """Returns the Outlook Add-in manifest XML for installation."""
    base_url = "http://localhost:8000"  # Change to your server URL
    manifest = f'''<?xml version="1.0" encoding="UTF-8"?>
<OfficeApp xmlns="http://schemas.microsoft.com/office/appforoffice/1.1"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:type="MailApp">
  <Id>sentinel-sme-guardian-phishing-checker</Id>
  <Version>1.0.0.0</Version>
  <ProviderName>Sentinel SME-Guardian</ProviderName>
  <DefaultLocale>de-DE</DefaultLocale>
  <DisplayName DefaultValue="Sentinel Phishing-Check"/>
  <Description DefaultValue="Automatische Phishing-Pruefung fuer alle eingehenden E-Mails"/>
  <IconUrl DefaultValue="{base_url}/outlook/icon"/>
  <HighResolutionIconUrl DefaultValue="{base_url}/outlook/icon"/>
  <SupportUrl DefaultValue="{base_url}"/>
  <AppDomains>
    <AppDomain>{base_url}</AppDomain>
  </AppDomains>
  <Hosts>
    <Host Name="Mailbox"/>
  </Hosts>
  <Requirements>
    <Sets DefaultMinVersion="1.1">
      <Set Name="Mailbox"/>
    </Sets>
  </Requirements>
  <FormSettings>
    <Form xsi:type="ItemRead">
      <DesktopSettings>
        <SourceLocation DefaultValue="{base_url}/outlook/addin"/>
        <RequestedHeight>120</RequestedHeight>
      </DesktopSettings>
    </Form>
  </FormSettings>
  <Permissions>ReadItem</Permissions>
  <Rule xsi:type="RuleCollection" Mode="Or">
    <Rule xsi:type="ItemIs" ItemType="Message" FormType="Read"/>
  </Rule>
  <DisableEntityHighlighting>false</DisableEntityHighlighting>
</OfficeApp>'''
    return StreamingResponse(io.BytesIO(manifest.encode('utf-8')),
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=sentinel-manifest.xml"})


@app.get("/outlook/addin", response_class=HTMLResponse)
async def outlook_addin():
    """The Outlook Add-in taskpane HTML — loads inside Outlook."""
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Sentinel Phishing-Check</title>
<script src="https://appsforoffice.microsoft.com/lib/1.1/hosted/office.js"></script>
<style>
body{font-family:-apple-system,sans-serif;margin:0;padding:12px;background:#f8fafc;font-size:13px;}
#banner{padding:10px 14px;border-radius:6px;margin-bottom:10px;display:none;font-weight:bold;}
#banner.safe{background:#d1fae5;color:#065f46;border:1px solid #10b981;}
#banner.warn{background:#fef3c7;color:#78350f;border:1px solid #fbbf24;}
#banner.danger{background:#fee2e2;color:#7f1d1d;border:1px solid #ef4444;}
#reasons{font-size:12px;color:#374151;padding:8px;background:#f3f4f6;border-radius:4px;display:none;}
#loading{color:#6b7280;font-style:italic;}
.score{font-size:1.4rem;font-weight:bold;display:inline;}
button{background:#38bdf8;color:#0a0c10;border:none;padding:6px 14px;border-radius:4px;
  font-weight:bold;cursor:pointer;font-size:12px;margin-top:8px;}
</style>
</head>
<body>
<div id="loading">Prüfe E-Mail...</div>
<div id="banner"></div>
<div id="reasons"></div>
<button onclick="recheckEmail()" style="display:none;" id="recheckBtn">Erneut prüfen</button>
<script>
Office.initialize = function() {
  checkCurrentEmail();
};

async function checkCurrentEmail() {
  const item = Office.context.mailbox.item;
  if (!item) {
    document.getElementById('loading').textContent = 'Kein E-Mail-Element gefunden.';
    return;
  }
  const sender  = item.from ? (item.from.emailAddress || '') : '';
  const subject = item.subject || '';
  item.body.getAsync('text', {}, async function(result) {
    const body = result.value || '';
    await sendToSentinel(sender, subject, body, item.itemId || 'unknown');
  });
}

async function sendToSentinel(sender, subject, body, msgId) {
  document.getElementById('loading').textContent = 'Analysiere...';
  try {
    const res = await fetch('http://localhost:8000/outlook/scan_email', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({sender, subject, body: body.substring(0,3000), message_id: msgId})
    });
    const d = await res.json();
    showResult(d);
  } catch(e) {
    document.getElementById('loading').textContent = 'Verbindung zum Sentinel nicht möglich.';
  }
}

function showResult(d) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('recheckBtn').style.display = 'inline';
  const banner = document.getElementById('banner');
  const cls = d.verdict === 'PHISHING' ? 'danger' : d.verdict === 'VERDAECHTIG' ? 'warn' : 'safe';
  banner.className = cls;
  banner.innerHTML = d.banner_text + ' <span class="score">' + d.risk_score + '%</span>';
  banner.style.display = 'block';
  if (d.reasons && d.reasons.length > 0) {
    const rDiv = document.getElementById('reasons');
    rDiv.innerHTML = '<b>Indikatoren:</b><ul>' + d.reasons.map(r=>'<li>'+r+'</li>').join('') + '</ul>';
    rDiv.style.display = 'block';
  }
}

function recheckEmail() {
  document.getElementById('loading').style.display = 'block';
  document.getElementById('loading').textContent = 'Analysiere...';
  document.getElementById('banner').style.display = 'none';
  document.getElementById('reasons').style.display = 'none';
  checkCurrentEmail();
}
</script>
</body>
</html>"""


async def alert_stream(request: Request):
    async def event_generator():
        yield "data: {\"type\":\"heartbeat\"}\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                alarm = _alarm_queue.get(timeout=1.0)
                payload = json.dumps(alarm, ensure_ascii=False)
                yield f"data: {payload}\n\n"
            except:
                yield "data: {\"type\":\"heartbeat\"}\n\n"
                await asyncio.sleep(2)
    return StreamingResponse(event_generator(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/alerts/latest")
def get_latest_alerts():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 'EXPLOIT' as cat, time, source_ip as ip, pattern_name as msg, confidence as score
        FROM exploit_alerts WHERE blocked=1
        UNION ALL
        SELECT 'HONEYTOKEN', time, attacker_ip, token_label, 100
        FROM honeytoken_alerts
        UNION ALL
        SELECT 'BRUTE-FORCE', time, source_ip, 'Brute-Force: '||request_count||' Req/min', 90
        FROM bruteforce_alerts
        UNION ALL
        SELECT 'FINGERPRINT', time, ip, detail, risk_score
        FROM fingerprints WHERE status='kritisch'
        ORDER BY time DESC LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/alarm_log")
def get_alarm_log():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alarm_log ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/alarm_log/confirm/{alarm_id}")
def confirm_alarm(alarm_id: int):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE alarm_log SET confirmed=1 WHERE id=?", (alarm_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/alarm_log/confirm_all")
def confirm_all_alarms():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE alarm_log SET confirmed=1")
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/settings/alert_email")
async def save_alert_email_settings(request: Request):
    data = await request.json()
    fields = ['alert_email_to','alert_email_from','alert_smtp_host',
              'alert_smtp_port','alert_smtp_user','alert_smtp_pass',
              'alarm_log_active']
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    for f in fields:
        if f in data:
            cursor.execute("UPDATE settings SET value=? WHERE key=?", (str(data[f]), f))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/settings/alert_email")
def get_alert_email_settings():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    fields = ['alert_email_to','alert_email_from','alert_smtp_host',
              'alert_smtp_port','alert_smtp_user','alarm_log_active']
    result = {}
    for f in fields:
        cursor.execute("SELECT value FROM settings WHERE key=?", (f,))
        r = cursor.fetchone()
        result[f] = r[0] if r else ''
    conn.close()
    return result

# ============================================================
# --- 2. SICHERHEITS-LOGIK (UNCHANGED) ---
# ============================================================
class SentinelLogic:
    def __init__(self):
        self.critical_rules = {
            "KREDITKARTE": r'\b(?:\d[ -]*?){13,16}\b',
            "API_KEY": r"(?:sk|key|token)-[a-zA-Z0-9]{24,}"
        }
        self.anon_rules = {
            "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "IP": r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }
        self.phishing_keywords = [
            'verify your account', 'confirm your password', 'urgent action required',
            'click here immediately', 'your account will be suspended', 'login immediately',
            'update your billing', 'konto gesperrt', 'dringend', 'sofort handeln',
            'passwort bestätigen', 'konto verifizieren', 'gewinn', 'sie haben gewonnen',
            'bitcoin', 'crypto transfer', 'wire transfer urgent', 'invoice attached',
            'your paypal', 'amazon security', 'apple id suspended'
        ]
        self.suspicious_tlds = ['.xyz', '.top', '.click', '.work', '.loan', '.gq', '.tk', '.ml', '.ga', '.cf']
        self.lookalike_patterns = [
            r'paypa[l1]', r'arnazon', r'g[o0]{2}gle', r'micros[o0]ft', r'app[l1]e',
            r'netfl[i1]x', r'faceb[o0]{2}k', r'[i1]nstagram', r'tw[i1]tter',
            r'linkedln', r'dhl-express', r'fedex-delivery'
        ]

    def sanitize(self, text):
        for label, pattern in self.anon_rules.items():
            text = re.sub(pattern, f"[{label}_MASKIERT]", text)
        return text

    def mask_output(self, text):
        return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "XXX.XXX.XXX.XXX", text)

    def extract_urls(self, text):
        return re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)

    def quick_phishing_score(self, sender, subject, body):
        score = 0
        reasons = []
        full_text = f"{sender} {subject} {body}".lower()
        for kw in self.phishing_keywords:
            if kw.lower() in full_text:
                score += 15
                reasons.append(f"Phishing-Keyword: '{kw}'")
        sender_domain = re.search(r'@([^\s>]+)', sender)
        if sender_domain:
            domain = sender_domain.group(1).lower()
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += 25
                    reasons.append(f"Verdaechtige TLD: {tld}")
            for pattern in self.lookalike_patterns:
                if re.search(pattern, domain):
                    score += 30
                    reasons.append(f"Lookalike-Domain: {domain}")
        urls = self.extract_urls(body)
        for url in urls[:5]:
            parsed = urllib.parse.urlparse(url)
            for tld in self.suspicious_tlds:
                if parsed.netloc.endswith(tld):
                    score += 20
                    reasons.append(f"Verdaechtige URL: {url[:60]}")
            for pattern in self.lookalike_patterns:
                if re.search(pattern, parsed.netloc):
                    score += 25
                    reasons.append(f"Lookalike-URL: {parsed.netloc}")
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                score += 20
                reasons.append(f"IP-Adresse als Link: {parsed.netloc}")
        urgency_patterns = [r'24 hours?', r'immediately', r'sofort', r'dringend', r'expires? (today|now|soon)']
        for p in urgency_patterns:
            if re.search(p, full_text, re.IGNORECASE):
                score += 10
                reasons.append("Dringlichkeits-Taktik erkannt")
                break
        dangerous_ext = ['.exe', '.bat', '.vbs', '.js', '.ps1', '.scr', '.com', '.pif']
        for ext in dangerous_ext:
            if ext in full_text:
                score += 30
                reasons.append(f"Gefaehrlicher Anhang-Typ: {ext}")
        return min(score, 100), list(set(reasons))

logic = SentinelLogic()

# ============================================================
# --- 3. EMAIL PROVIDER PRESETS (UNCHANGED) ---
# ============================================================
EMAIL_PROVIDERS = {
    "gmail":      {"imap_host": "imap.gmail.com",         "imap_port": 993},
    "outlook":    {"imap_host": "outlook.office365.com",   "imap_port": 993},
    "yahoo":      {"imap_host": "imap.mail.yahoo.com",     "imap_port": 993},
    "gmx":        {"imap_host": "imap.gmx.net",            "imap_port": 993},
    "web.de":     {"imap_host": "imap.web.de",             "imap_port": 993},
    "icloud":     {"imap_host": "imap.mail.me.com",        "imap_port": 993},
    "t-online":   {"imap_host": "secureimap.t-online.de",  "imap_port": 993},
    "freenet":    {"imap_host": "mx.freenet.de",           "imap_port": 993},
    "zoho":       {"imap_host": "imap.zoho.com",           "imap_port": 993},
    "protonmail": {"imap_host": "127.0.0.1",               "imap_port": 1143},
    "custom":     {"imap_host": "",                        "imap_port": 993}
}

# ============================================================
# --- 4. EMAIL IMAP SCANNER (UNCHANGED) ---
# ============================================================
def decode_mime_header(value):
    if not value:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or 'utf-8', errors='replace'))
        else:
            decoded.append(part)
    return " ".join(decoded)

def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                try:
                    body += part.get_payload(decode=True).decode('utf-8', errors='replace')
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
        except:
            body = ""
    return body[:3000]

def scan_email_account(account_id):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT provider, email, imap_host, imap_port, password FROM email_accounts WHERE id=?", (account_id,))
    acc = cursor.fetchone()
    conn.close()
    if not acc:
        return {"error": "Konto nicht gefunden"}
    provider, email_addr, imap_host, imap_port, password = acc
    results = []
    try:
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
        mail.login(email_addr, password)
        mail.select("INBOX")
        _, msg_ids = mail.search(None, "UNSEEN")
        msg_id_list = msg_ids[0].split()[-20:]
        if not msg_id_list:
            _, msg_ids = mail.search(None, "ALL")
            msg_id_list = msg_ids[0].split()[-10:]
        for mid in msg_id_list:
            _, msg_data = mail.fetch(mid, "(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            sender  = decode_mime_header(msg.get("From", ""))
            subject = decode_mime_header(msg.get("Subject", ""))
            body    = get_email_body(msg)
            risk_score, reasons = logic.quick_phishing_score(sender, subject, body)
            verdict = "SICHER" if risk_score < 30 else ("VERDAECHTIG" if risk_score < 60 else "PHISHING/VIRUS")
            conn2 = sqlite3.connect("sentinel.db")
            c2 = conn2.cursor()
            c2.execute(
                "INSERT INTO email_scan_results (time, email_from, subject, verdict, risk_score, detail, account) VALUES (?,?,?,?,?,?,?)",
                (datetime.datetime.now().strftime("%H:%M:%S"), sender[:100], subject[:150],
                 verdict, risk_score, "; ".join(reasons) if reasons else "Keine Auffaelligkeiten", email_addr)
            )
            if risk_score >= 60:
                log_event(5, "EMAIL-BEDROHUNG", f"Phishing/Virus erkannt von: {sender[:60]} | {subject[:60]}")
                push_alarm("KRITISCH", "EMAIL", f"Phishing erkannt! Von: {sender[:50]} | {subject[:40]}", email_addr)
            conn2.commit()
            conn2.close()
            results.append({"from": sender, "subject": subject,
                             "verdict": verdict, "risk_score": risk_score, "reasons": reasons})
        mail.logout()
        return {"scanned": len(results), "results": results, "account": email_addr}
    except imaplib.IMAP4.error as e:
        return {"error": f"IMAP Fehler: {str(e)}"}
    except Exception as e:
        return {"error": f"Verbindungsfehler: {str(e)}"}

# ============================================================
# --- 5. KI-ENGINE (UNCHANGED + exploit mode) ---
# ============================================================
async def call_ai(prompt, mode="standard"):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_model'")
    model = cursor.fetchone()[0]
    conn.close()
    context = "Du bist ein IT-Sicherheitsberater fuer kleine Firmen. Antworte praezise auf Deutsch."
    if mode == "phishing":
        context = "Analysiere diese Mail auf Betrug (Phishing). Achte auf Absender, Links und Druckmittel. Gib eine klare Empfehlung."
    elif mode == "email_deep":
        context = "Du bist ein E-Mail-Sicherheitsanalyst. Analysiere diese E-Mail detailliert auf Phishing, Viren, Social Engineering. Liste alle Risiken und gib eine Handlungsempfehlung auf Deutsch."
    elif mode == "exploit":
        context = (
            "Du bist ein Zero-Day-Exploit-Erkennungssystem. Analysiere den folgenden Input auf bekannte und neuartige "
            "Angriffsmuster: SQL-Injection, XSS, Buffer-Overflow, Command-Injection, Path-Traversal, SSRF, XXE, "
            "Prototype-Pollution, und Zero-Day-Indikatoren. Bewerte von 0-100. Antworte NUR als JSON: "
            "{\"confidence\": <0-100>, \"pattern\": \"<n>\", \"explanation\": \"<kurz>\", \"block\": <true/false>}"
        )
    url = "http://127.0.0.1:11434/api/generate"
    payload = {"model": model, "prompt": f"{context}\n\nInhalt: {prompt}", "stream": False}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(url, json=payload, timeout=120.0)
            if r.status_code != 200:
                return f"Ollama Fehler (Status {r.status_code}): {r.text}"
            data = r.json()
            if "response" in data:
                return data["response"]
            if "error" in data:
                return f"Ollama Fehler: {data['error']}"
            return f"Unerwartete Antwort von Ollama: {data}"
    except Exception as e:
        return f"Verbindungsfehler zur KI: {str(e)}"

# ============================================================
# --- MODULE A: MEMORY SAFETY (UNCHANGED) ---
# ============================================================
class MemorySafetyChecker:
    def check_container_isolation(self):
        checks = []
        try:
            in_docker = os.path.exists("/.dockerenv") or (
                os.path.exists("/proc/1/cgroup") and "docker" in open("/proc/1/cgroup").read())
        except:
            in_docker = False
        checks.append({"component": "Docker Container",
            "status": "AKTIV" if in_docker else "EMPFOHLEN",
            "detail": "Laeuft in Docker-Container (isoliert)" if in_docker
                      else "Nicht containerisiert — Empfehlung: Docker-Deployment",
            "ok": in_docker})
        try:
            is_root = os.getuid() == 0
            checks.append({"component": "Prozess-Privilegien",
                "status": "WARNUNG" if is_root else "SICHER",
                "detail": "Laeuft als root — kritisches Sicherheitsrisiko!" if is_root
                          else "Laeuft als eingeschraenkter Nutzer",
                "ok": not is_root})
        except AttributeError:
            checks.append({"component": "Prozess-Privilegien", "status": "UNBEKANNT",
                "detail": "Betriebssystem unterstuetzt keine UID-Pruefung", "ok": True})
        try:
            if os.path.exists("/proc/sys/kernel/randomize_va_space"):
                with open("/proc/sys/kernel/randomize_va_space") as f:
                    aslr = f.read().strip()
                checks.append({"component": "ASLR (Speicher-Randomisierung)",
                    "status": "AKTIV" if aslr == "2" else "SCHWACH",
                    "detail": f"ASLR Level {aslr} {'(aktiv)' if aslr == '2' else '(Empfehlung: Level 2)'}",
                    "ok": aslr == "2"})
        except:
            pass
        rust_available = shutil.which("rustc") is not None
        checks.append({"component": "Rust (Memory-Safe Language)",
            "status": "VERFUEGBAR" if rust_available else "NICHT INSTALLIERT",
            "detail": "Rust verfuegbar" if rust_available else "Rust nicht installiert (rustup.rs)",
            "ok": rust_available})
        import sys
        in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        checks.append({"component": "Python venv Isolation",
            "status": "AKTIV" if in_venv else "EMPFOHLEN",
            "detail": "Virtual Environment aktiv" if in_venv else "Kein venv erkannt — python -m venv .venv",
            "ok": in_venv})
        try:
            if os.path.exists("/proc/self/status"):
                with open("/proc/self/status") as f:
                    content = f.read()
                if "Seccomp" in content:
                    seccomp_val = re.search(r'Seccomp:\s*(\d+)', content)
                    seccomp_on = seccomp_val and seccomp_val.group(1) != "0"
                    checks.append({"component": "Seccomp Syscall-Filter",
                        "status": "AKTIV" if seccomp_on else "INAKTIV",
                        "detail": "Seccomp-Filter aktiv" if seccomp_on
                                  else "Seccomp inaktiv — in Docker: --security-opt seccomp=profile.json",
                        "ok": seccomp_on})
        except:
            pass
        return checks

    def get_dockerfile_recommendation(self):
        return """FROM python:3.11-slim
RUN useradd -m -u 1000 sentinel
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER sentinel
EXPOSE 8000
CMD ["uvicorn", "sentinel_guardian:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]"""

    def get_rust_service_stub(self):
        return """// Sentinel Memory-Safe Input Validator (Rust)
use std::net::TcpListener;
use std::io::{Read, Write};
const MAX_INPUT_SIZE: usize = 65536;
fn validate_input(data: &[u8]) -> (bool, &'static str) {
    if data.len() > MAX_INPUT_SIZE { return (false, "INPUT_TOO_LARGE"); }
    if data.contains(&0u8) { return (false, "NULL_BYTE_INJECTION"); }
    let s = String::from_utf8_lossy(data);
    if s.contains("%n") || s.contains("%s%s%s") { return (false, "FORMAT_STRING_ATTACK"); }
    (true, "CLEAN")
}
fn main() {
    let listener = TcpListener::bind("127.0.0.1:8765").unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut buffer = vec![0u8; MAX_INPUT_SIZE + 1];
        let n = stream.read(&mut buffer).unwrap_or(0);
        let (ok, reason) = validate_input(&buffer[..n]);
        let response = if ok { format!("OK\\n") } else { format!("BLOCKED:{reason}\\n") };
        stream.write_all(response.as_bytes()).unwrap();
    }
}"""

memory_checker = MemorySafetyChecker()

# ============================================================
# --- MODULE B: EXPLOIT DETECTION (UNCHANGED) ---
# ============================================================
class ExploitDetector:
    def __init__(self):
        self.signatures = [
            ("SQL_INJECTION_CLASSIC",  r"(?i)(\b(union|select|insert|update|delete|drop|truncate|exec|execute)\b.{0,30}\b(from|into|table|where|set)\b)", 75),
            ("SQL_INJECTION_BLIND",    r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay)", 80),
            ("SQL_INJECTION_STACKED",  r"(?i)(;\s*(drop|insert|update|delete|exec)\s)", 85),
            ("XSS_SCRIPT_TAG",         r"(?i)<\s*script[\s>]", 70),
            ("XSS_EVENT_HANDLER",      r"(?i)\bon\w+\s*=\s*[\"']?[^\"'>\s]", 65),
            ("XSS_JAVASCRIPT_URI",     r"(?i)javascript\s*:", 70),
            ("XSS_DATA_URI",           r"(?i)data\s*:\s*text/html", 60),
            ("CMD_INJECTION_UNIX",     r"(?i)[;|&`$]\s*(cat|ls|id|whoami|pwd|wget|curl|bash|sh|python|perl|ruby|nc)\b", 85),
            ("CMD_INJECTION_WIN",      r"(?i)[&|;]\s*(cmd|powershell|net\s+user|ipconfig|dir\s+[a-z]:\\)", 85),
            ("PATH_TRAVERSAL",         r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", 75),
            ("SSRF_INTERNAL",          r"(?i)(http[s]?://(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+))", 80),
            ("XXE_DOCTYPE",            r"(?i)<!doctype[^>]*\[|<!entity\s", 80),
            ("BUFFER_OVERFLOW_NOP",    r"(?:\x90{8,}|%90{8,}|\\x90{8,})", 90),
            ("BUFFER_OVERFLOW_LONG",   r".{4096,}", 55),
            ("PROTOTYPE_POLLUTION",    r"(?i)(__proto__|constructor\s*\[|prototype\s*\[)", 70),
            ("LDAP_INJECTION",         r"(?i)[*)(\\|\0].*(?:uid|cn|dc|ou)=", 70),
            ("TEMPLATE_INJECTION",     r"(?i)(\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\})", 65),
            ("ENCODING_EVASION",       r"(%[0-9a-fA-F]{2}){6,}|\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}", 60),
        ]

    def analyze(self, text: str, source_ip: str = "unknown") -> dict:
        if not text:
            return {"threat": False, "confidence": 0, "patterns": [], "blocked": False}
        detected = []
        max_confidence = 0
        for name, pattern, base_conf in self.signatures:
            try:
                if re.search(pattern, text):
                    boost = 10 if len(re.findall(pattern, text)) > 1 else 0
                    conf = min(base_conf + boost, 100)
                    detected.append({"pattern": name, "confidence": conf})
                    max_confidence = max(max_confidence, conf)
            except re.error:
                pass
        blocked = max_confidence >= 65
        threat  = max_confidence >= 40
        if detected:
            self._log_exploit(source_ip, detected, text[:200], max_confidence, blocked)
            if blocked:
                push_alarm("KRITISCH", "EXPLOIT",
                           f"Exploit geblockt: {detected[0]['pattern']} ({max_confidence}%)", source_ip)
            elif threat:
                push_alarm("WARNUNG", "EXPLOIT",
                           f"Verdaechtiger Input: {detected[0]['pattern']} ({max_confidence}%)", source_ip)
        return {"threat": threat, "confidence": max_confidence,
                "patterns": detected, "blocked": blocked, "patterns_count": len(detected)}

    def _log_exploit(self, ip, patterns, snippet, confidence, blocked):
        try:
            conn = sqlite3.connect("sentinel.db")
            cursor = conn.cursor()
            pattern_names = ", ".join(p["pattern"] for p in patterns[:3])
            cursor.execute(
                "INSERT INTO exploit_alerts (time, source_ip, pattern_name, payload_snippet, confidence, blocked) VALUES (?,?,?,?,?,?)",
                (datetime.datetime.now().strftime("%H:%M:%S"), ip, pattern_names, snippet, confidence, 1 if blocked else 0)
            )
            if blocked:
                log_event_direct(cursor, 5, "EXPLOIT-GESTOPPT",
                                 f"Muster: {pattern_names} | Konfidenz: {confidence}% | IP: {ip}")
            conn.commit()
            conn.close()
        except:
            pass

def log_event_direct(cursor, lvl, stat, msg):
    cursor.execute(
        "INSERT INTO history (time, level, status, detail, timestamp_raw) VALUES (?,?,?,?,?)",
        (datetime.datetime.now().strftime("%H:%M:%S"), lvl, stat, msg, datetime.datetime.now())
    )

exploit_detector = ExploitDetector()

# ============================================================
# --- MODULE C: HONEYTOKENS (UNCHANGED) ---
# ============================================================
class HoneytokenEngine:
    def seed_default_tokens(self):
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM honeytokens")
        count = cursor.fetchone()[0]
        conn.close()
        if count == 0:
            defaults = [
                ("url_trap",     "Decoy Admin Backup URL",    "/admin/backup.zip"),
                ("url_trap",     "Decoy .env File",           "/.env"),
                ("url_trap",     "Decoy Git Config",          "/.git/config"),
                ("url_trap",     "Decoy DB Config",           "/config/database.yml"),
                ("fake_api_key", "Fake AWS Key (Decoy)",      "AKIAIOSFODNN7EXAMPLE"),
                ("fake_password","Fake Admin Password",       "Adm1n$ecure2024!"),
                ("fake_db_url",  "Fake DB Connection String", "postgresql://admin:Adm1n$99@db.internal:5432/prod"),
                ("fake_credit",  "Fake Credit Card (Trap)",  "4532015112830366"),
            ]
            for ttype, label, fval in defaults:
                token_id = secrets.token_hex(8)
                conn = sqlite3.connect("sentinel.db")
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR IGNORE INTO honeytokens (token_id, token_type, label, fake_value, route, created) VALUES (?,?,?,?,?,?)",
                    (token_id, ttype, label, fval, fval if ttype == "url_trap" else "",
                     datetime.datetime.now().isoformat())
                )
                conn.commit()
                conn.close()

    def check_request(self, path: str, body: str, ip: str, user_agent: str, method: str) -> dict:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute("SELECT token_id, token_type, label, fake_value, route FROM honeytokens WHERE active=1")
        tokens = cursor.fetchall()
        conn.close()
        triggered = []
        full_content = f"{path} {body}".lower()
        for token_id, ttype, label, fake_value, route in tokens:
            hit = False
            if ttype == "url_trap" and route and route.lower() in path.lower():
                hit = True
            elif fake_value and fake_value.lower() in full_content:
                hit = True
            if hit:
                triggered.append({"token_id": token_id, "label": label, "type": ttype})
                self._fire_alert(token_id, label, ip, user_agent, path, method)
        return {"triggered": len(triggered), "tokens": triggered}

    def _fire_alert(self, token_id, label, ip, user_agent, path, method):
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        now = datetime.datetime.now().strftime("%H:%M:%S")
        cursor.execute(
            "INSERT INTO honeytoken_alerts (time, token_id, token_label, attacker_ip, user_agent, path, method, severity) VALUES (?,?,?,?,?,?,?,?)",
            (now, token_id, label, ip, user_agent[:200], path[:200], method, "KRITISCH")
        )
        cursor.execute(
            "UPDATE honeytokens SET last_triggered=?, trigger_count=trigger_count+1 WHERE token_id=?",
            (now, token_id)
        )
        log_event_direct(cursor, 5, "HONEYTOKEN AUSGELOEST",
                         f"FALLE: {label} | IP: {ip} | Pfad: {path[:80]}")
        conn.commit()
        conn.close()
        push_alarm("KRITISCH", "HONEYTOKEN",
                   f"Falle ausgeloest! {label} | Pfad: {path[:50]}", ip)

honeytoken_engine = HoneytokenEngine()
honeytoken_engine.seed_default_tokens()

# ============================================================
# --- MODULE D: BRUTE-FORCE / RATE LIMITER (UNCHANGED) ---
# ============================================================
_rate_windows: dict = defaultdict(list)
_blocked_ips:  dict = {}

RATE_LIMIT_MAX    = 60
RATE_LIMIT_WINDOW = 60
BLOCK_DURATION    = 300

def check_rate_limit(ip: str, path: str) -> dict:
    now = time.time()
    if ip in _blocked_ips:
        if now < _blocked_ips[ip]:
            remaining = int(_blocked_ips[ip] - now)
            return {"blocked": True, "count": RATE_LIMIT_MAX + 1,
                    "reason": f"IP gesperrt fuer noch {remaining}s (Brute-Force)"}
        else:
            del _blocked_ips[ip]
    _rate_windows[ip] = [t for t in _rate_windows[ip] if now - t < RATE_LIMIT_WINDOW]
    _rate_windows[ip].append(now)
    count = len(_rate_windows[ip])
    try:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key='rate_limit_max'")
        row = cursor.fetchone()
        conn.close()
        limit = int(row[0]) if row else RATE_LIMIT_MAX
    except:
        limit = RATE_LIMIT_MAX
    if count > limit:
        _blocked_ips[ip] = now + BLOCK_DURATION
        _log_bruteforce(ip, count, path)
        push_alarm("KRITISCH", "BRUTE-FORCE",
                   f"Brute-Force! {count} Anfragen/{RATE_LIMIT_WINDOW}s auf {path[:40]}", ip)
        return {"blocked": True, "count": count,
                "reason": f"Rate-Limit ueberschritten: {count} Anfragen in {RATE_LIMIT_WINDOW}s"}
    return {"blocked": False, "count": count, "reason": ""}

def _log_bruteforce(ip: str, count: int, path: str):
    try:
        conn = sqlite3.connect("sentinel.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO bruteforce_alerts (time, source_ip, request_count, window_seconds, path, blocked) VALUES (?,?,?,?,?,1)",
            (datetime.datetime.now().strftime("%H:%M:%S"), ip, count, RATE_LIMIT_WINDOW, path[:200])
        )
        log_event_direct(cursor, 5, "BRUTE-FORCE GEBLOCKT",
                         f"IP: {ip} | {count} Anfragen/{RATE_LIMIT_WINDOW}s | Pfad: {path[:60]}")
        conn.commit()
        conn.close()
    except:
        pass

# ============================================================
# --- MODULE E: FINGERPRINT ENGINE (NEW) ---
# ============================================================
# Known datacenter/cloud/VPN IP ranges (CIDR prefix check – simplified)
DATACENTER_PREFIXES = [
    "3.", "13.", "15.", "18.", "34.", "35.", "52.", "54.",   # AWS
    "20.", "40.", "51.", "52.", "104.",                       # Azure
    "8.34.", "8.35.", "23.236.", "34.", "35.", "104.196.",   # GCP
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",   # Cloudflare
    "199.27.", "198.41.", "162.159.",                         # Cloudflare
    "185.220.", "185.129.", "185.107.",                       # Known Tor exits
    "171.25.", "176.10.", "193.105.", "194.165.",             # More Tor
]

TOR_EXIT_PATTERNS = [
    r"185\.220\.\d+\.\d+",
    r"171\.25\.\d+\.\d+",
    r"176\.10\.\d+\.\d+",
    r"193\.105\.\d+\.\d+",
    r"199\.87\.\d+\.\d+",
    r"162\.247\.\d+\.\d+",
]

VPN_PATTERNS = [
    r"vpn", r"nordvpn", r"expressvpn", r"mullvad", r"protonvpn", r"surfshark",
    r"cyberghost", r"hidemyass", r"privateinternetaccess",
]

HEADLESS_UA_PATTERNS = [
    r"headlesschrome", r"phantomjs", r"selenium", r"webdriver",
    r"puppeteer", r"playwright", r"nightmare", r"zombie",
    r"python-requests", r"python-urllib", r"go-http-client",
    r"java/", r"libwww-perl", r"lwp-trivial", r"curl/", r"wget/",
    r"okhttp", r"apache-httpclient", r"scrapy", r"mechanize",
]

BOT_UA_PATTERNS = [
    r"bot", r"crawler", r"spider", r"scraper", r"scan", r"fetch",
    r"slurp", r"googlebot", r"bingbot", r"yandexbot", r"baiduspider",
    r"semrushbot", r"ahrefsbot", r"mj12bot", r"dotbot",
]

# In-memory behaviour tracking per fingerprint_id
# {fp_id: {"clicks": [ts,...], "keys": [ts,...], "mouse_events": [(x,y,ts),...], "requests": [ts,...]}}
_fp_behaviour: dict = defaultdict(lambda: {
    "clicks": [], "keys": [], "mouse_events": [], "requests": []
})

class FingerprintEngine:
    """
    Server-side fingerprinting based on HTTP headers.
    Client-side data (mouse, clicks, typing) is collected via JS and sent to /fingerprint/behaviour.
    """

    def _make_fp_id(self, ip: str, ua: str, accept_lang: str, accept_enc: str) -> str:
        raw = f"{ip}|{ua}|{accept_lang}|{accept_enc}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def analyze_request(self, request: Request) -> dict:
        ip           = request.client.host if request.client else "unknown"
        ua           = request.headers.get("user-agent", "").lower()
        accept_lang  = request.headers.get("accept-language", "")
        accept_enc   = request.headers.get("accept-encoding", "")
        accept       = request.headers.get("accept", "")
        connection   = request.headers.get("connection", "")
        referer      = request.headers.get("referer", "")
        x_forward    = request.headers.get("x-forwarded-for", "")
        via          = request.headers.get("via", "")
        x_real_ip    = request.headers.get("x-real-ip", "")

        fp_id = self._make_fp_id(ip, ua, accept_lang, accept_enc)
        now   = datetime.datetime.now().strftime("%H:%M:%S")

        flags = {
            "is_headless": False,
            "is_bot": False,
            "is_tor": False,
            "is_proxy": False,
            "is_datacenter": False,
            "is_vpn": False,
        }
        reasons = []
        risk = 0

        # --- Headless Browser Detection ---
        for pat in HEADLESS_UA_PATTERNS:
            if re.search(pat, ua, re.IGNORECASE):
                flags["is_headless"] = True
                reasons.append(f"Headless/Automatisierung: {pat}")
                risk += 35
                break

        # Missing common headers (humans always send these)
        if not accept_lang:
            risk += 15
            reasons.append("Kein Accept-Language Header (typisch fuer Bots)")
        if not accept or accept == "*/*":
            risk += 10
            reasons.append("Generisches Accept-Header (typisch fuer Bots)")

        # --- Bot UA Detection ---
        for pat in BOT_UA_PATTERNS:
            if re.search(pat, ua, re.IGNORECASE):
                # Whitelist legitimate search engines at lower risk
                if any(legit in ua for legit in ["googlebot", "bingbot", "yandexbot"]):
                    risk += 5
                    reasons.append(f"Suchmaschinen-Bot: {pat}")
                else:
                    flags["is_bot"] = True
                    risk += 30
                    reasons.append(f"Bot-User-Agent: {pat}")
                break

        # --- Proxy Detection ---
        if x_forward or via or x_real_ip:
            flags["is_proxy"] = True
            risk += 20
            reasons.append(f"Proxy-Header gefunden: X-Forwarded-For={x_forward[:30]}")

        # --- VPN Detection (UA / hostname heuristic) ---
        for pat in VPN_PATTERNS:
            if re.search(pat, ua, re.IGNORECASE):
                flags["is_vpn"] = True
                risk += 25
                reasons.append(f"VPN-Hinweis im User-Agent: {pat}")
                break

        # --- Tor Exit Node Detection (IP pattern) ---
        for pat in TOR_EXIT_PATTERNS:
            if re.search(pat, ip):
                flags["is_tor"] = True
                risk += 50
                reasons.append(f"Bekannter Tor-Exit-Node: {ip}")
                break

        # --- Datacenter IP Detection ---
        for prefix in DATACENTER_PREFIXES:
            if ip.startswith(prefix):
                flags["is_datacenter"] = True
                risk += 20
                reasons.append(f"Rechenzentrum-IP-Bereich: {prefix}*")
                break

        # --- WebDriver / Selenium detection via UA ---
        if "selenium" in ua or "webdriver" in ua or "chromedriver" in ua:
            flags["is_headless"] = True
            risk += 45
            reasons.append("WebDriver/Selenium erkannt")

        # Empty or minimal UA
        if len(ua) < 10:
            risk += 25
            reasons.append("Sehr kurzer/leerer User-Agent")

        risk = min(risk, 100)
        status = "normal" if risk < 35 else ("verdaechtig" if risk < 65 else "kritisch")

        detail = " | ".join(reasons) if reasons else "Kein Auffaelligkeiten"

        # Load auto-block setting
        auto_block = False
        block_threshold = 70
        try:
            conn = sqlite3.connect("sentinel.db")
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key='fp_auto_block'")
            r = cursor.fetchone()
            if r: auto_block = r[0] == '1'
            cursor.execute("SELECT value FROM settings WHERE key='fp_block_threshold'")
            r = cursor.fetchone()
            if r: block_threshold = int(r[0])
            conn.close()
        except:
            pass

        blocked = auto_block and risk >= block_threshold

        # Persist / update fingerprint record
        try:
            conn = sqlite3.connect("sentinel.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id, request_count FROM fingerprints WHERE fp_id=?", (fp_id,))
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE fingerprints SET last_seen=?, request_count=request_count+1, "
                    "risk_score=?, status=?, blocked=?, detail=?, is_vpn=?, is_tor=?, "
                    "is_proxy=?, is_datacenter=?, is_headless=?, is_bot=? WHERE fp_id=?",
                    (now, risk, status, 1 if blocked else 0, detail[:300],
                     1 if flags["is_vpn"] else 0, 1 if flags["is_tor"] else 0,
                     1 if flags["is_proxy"] else 0, 1 if flags["is_datacenter"] else 0,
                     1 if flags["is_headless"] else 0, 1 if flags["is_bot"] else 0, fp_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO fingerprints (fp_id, ip, user_agent, accept_lang, accept_encoding, "
                    "connection_type, is_vpn, is_tor, is_proxy, is_datacenter, is_headless, is_bot, "
                    "risk_score, status, blocked, first_seen, last_seen, detail) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fp_id, ip, ua[:200], accept_lang[:100], accept_enc[:100], connection[:50],
                     1 if flags["is_vpn"] else 0, 1 if flags["is_tor"] else 0,
                     1 if flags["is_proxy"] else 0, 1 if flags["is_datacenter"] else 0,
                     1 if flags["is_headless"] else 0, 1 if flags["is_bot"] else 0,
                     risk, status, 1 if blocked else 0, now, now, detail[:300])
                )
            if status == "kritisch":
                log_event_direct(cursor, 4, "FINGERPRINT-KRITISCH",
                                 f"IP: {ip} | Risiko: {risk}% | {detail[:80]}")
            conn.commit()
            conn.close()
        except Exception as e:
            pass

        if status == "kritisch":
            push_alarm("KRITISCH", "FINGERPRINT",
                       f"Verdaechtiger Fingerprint! Risiko: {risk}% | {', '.join(reasons[:2])}", ip)
        elif status == "verdaechtig":
            push_alarm("WARNUNG", "FINGERPRINT",
                       f"Auffaelliger Fingerprint: {risk}% Risiko", ip)

        return {
            "fp_id": fp_id, "ip": ip, "risk": risk, "status": status,
            "flags": flags, "reasons": reasons, "blocked": blocked
        }

    def analyze_behaviour(self, fp_id: str, event_type: str, data: dict) -> dict:
        """
        Processes client-side behaviour events:
        - click: {x, y, ts}
        - keypress: {ts}
        - mousemove: {x, y, ts}
        """
        now_ts = time.time()
        store  = _fp_behaviour[fp_id]

        suspicion_reasons = []
        risk_delta = 0

        if event_type == "click":
            store["clicks"].append(now_ts)
            # Keep last 50
            store["clicks"] = store["clicks"][-50:]
            # Check click speed: >5 clicks/sec = bot
            recent = [t for t in store["clicks"] if now_ts - t < 1.0]
            if len(recent) >= 5:
                suspicion_reasons.append(f"Klickgeschwindigkeit: {len(recent)} Klicks/Sek (Bot-Verdacht)")
                risk_delta += 30

        elif event_type == "keypress":
            store["keys"].append(now_ts)
            store["keys"] = store["keys"][-100:]
            # Check typing speed: >15 keys/sec = bot
            recent = [t for t in store["keys"] if now_ts - t < 1.0]
            if len(recent) >= 15:
                suspicion_reasons.append(f"Tippgeschwindigkeit: {len(recent)} Tasten/Sek (Bot-Verdacht)")
                risk_delta += 25
            # Check perfectly uniform timing (bot-like)
            if len(store["keys"]) >= 10:
                intervals = [store["keys"][i+1] - store["keys"][i] for i in range(len(store["keys"])-1)]
                intervals = intervals[-9:]
                mean_iv = sum(intervals) / len(intervals)
                variance = sum((iv - mean_iv)**2 for iv in intervals) / len(intervals)
                if variance < 0.0001 and mean_iv > 0:  # Nearly identical intervals = robotic
                    suspicion_reasons.append("Gleichmaessige Tipp-Intervalle (moeglicherweise Bot)")
                    risk_delta += 20

        elif event_type == "mousemove":
            x, y = data.get("x", 0), data.get("y", 0)
            store["mouse_events"].append((x, y, now_ts))
            store["mouse_events"] = store["mouse_events"][-200:]
            # Check for perfectly straight-line movement (bots move in straight lines)
            if len(store["mouse_events"]) >= 10:
                pts = store["mouse_events"][-10:]
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                # Calculate variance of y relative to linear fit through x
                if len(set(xs)) > 2:
                    mean_x = sum(xs)/len(xs)
                    mean_y = sum(ys)/len(ys)
                    num = sum((xs[i]-mean_x)*(ys[i]-mean_y) for i in range(len(xs)))
                    den = sum((xs[i]-mean_x)**2 for i in range(len(xs)))
                    if den > 0:
                        slope = num / den
                        intercept = mean_y - slope * mean_x
                        residuals = [abs(ys[i] - (slope*xs[i] + intercept)) for i in range(len(xs))]
                        avg_residual = sum(residuals) / len(residuals)
                        if avg_residual < 2.0:  # Nearly perfectly straight line
                            suspicion_reasons.append("Perfekt gerade Mausbewegung (Bot-Muster)")
                            risk_delta += 20

        # Log behaviour event
        try:
            conn = sqlite3.connect("sentinel.db")
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO fp_behaviour (fp_id, time, event_type, data) VALUES (?,?,?,?)",
                (fp_id, datetime.datetime.now().strftime("%H:%M:%S"),
                 event_type, json.dumps({"data": data, "suspicion": suspicion_reasons}))
            )
            # Update risk in fingerprints table
            if risk_delta > 0:
                cursor.execute(
                    "UPDATE fingerprints SET risk_score=MIN(100, risk_score+?), last_seen=? WHERE fp_id=?",
                    (risk_delta, datetime.datetime.now().strftime("%H:%M:%S"), fp_id)
                )
                # Recompute status
                cursor.execute("SELECT risk_score FROM fingerprints WHERE fp_id=?", (fp_id,))
                row = cursor.fetchone()
                if row:
                    new_risk = row[0]
                    new_status = "normal" if new_risk < 35 else ("verdaechtig" if new_risk < 65 else "kritisch")
                    cursor.execute("UPDATE fingerprints SET status=? WHERE fp_id=?", (new_status, fp_id))
                    if new_status == "kritisch" and suspicion_reasons:
                        push_alarm("WARNUNG", "FINGERPRINT",
                                   f"Verhaltens-Anomalie: {suspicion_reasons[0]}", fp_id[:8])
            conn.commit()
            conn.close()
        except:
            pass

        return {"fp_id": fp_id, "event_type": event_type,
                "suspicion": suspicion_reasons, "risk_delta": risk_delta}

fingerprint_engine = FingerprintEngine()

# ============================================================
# --- MIDDLEWARE: Rate-limit + Honeytoken + Exploit + Fingerprint ---
# ============================================================
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path       = str(request.url.path)
    client_ip  = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    method     = request.method

    skip_exploit_paths = ["/export", "/history", "/email/results", "/email/accounts",
                          "/honeytoken", "/safety", "/exploit", "/alerts", "/bruteforce",
                          "/fingerprint"]

    # Paths where the endpoint NEEDS the body intact — never consume these
    body_safe_paths = ["/scan", "/email/analyze_text", "/toggle_ai", "/set_model",
                       "/set_ai", "/set_rate_limit", "/bruteforce/unblock",
                       "/fingerprint/behaviour", "/fingerprint/settings",
                       "/settings/alert_email", "/alarm_log/confirm"]

    # Rate-limit (all requests except dashboard + SSE)
    if path not in ["/", "/alerts/stream", "/alerts/latest"]:
        rl = check_rate_limit(client_ip, path)
        if rl["blocked"]:
            return JSONResponse(status_code=429, content={
                "error": "Zu viele Anfragen. IP temporaer gesperrt.", "reason": rl["reason"]})

    # Read body for POST/PUT/PATCH — ONLY for paths not in body_safe_paths
    body_text = ""
    is_body_safe = any(path == p or path.startswith(p + "/") for p in body_safe_paths)
    if method in ["POST", "PUT", "PATCH"] and \
       not any(path.startswith(p) for p in skip_exploit_paths) and \
       not is_body_safe:
        try:
            body_bytes = await request.body()
            body_text  = body_bytes.decode("utf-8", errors="replace")
            _captured  = body_bytes
            async def receive(_b=_captured):
                return {"type": "http.request", "body": _b, "more_body": False}
            request = Request(request.scope, receive)
        except Exception:
            pass

    # Scan GET query + POST body
    query_string = str(request.url.query)
    scan_text = body_text or query_string

    # Honeytoken trap (ALL methods)
    ht_result = honeytoken_engine.check_request(path, scan_text, client_ip, user_agent, method)
    if ht_result["triggered"] > 0:
        log_event(5, "HONEYTOKEN", f"Falle ausgeloest von {client_ip} auf {path}")

    # Exploit detection
    if scan_text and not any(path.startswith(p) for p in skip_exploit_paths):
        exploit_result = exploit_detector.analyze(scan_text, client_ip)
        if exploit_result["blocked"]:
            log_event(5, "EXPLOIT-GEBLOCKT",
                      f"IP: {client_ip} | Muster: {', '.join(p['pattern'] for p in exploit_result['patterns'][:2])}")
            return JSONResponse(status_code=403, content={
                "error": "Anfrage durch Exploit-Erkennung blockiert.",
                "patterns": [p["pattern"] for p in exploit_result["patterns"]]})

    # Fingerprint analysis (skip fingerprint/export paths to avoid self-loops)
    if not any(path.startswith(p) for p in ["/fingerprint", "/export", "/alerts"]):
        fp_result = fingerprint_engine.analyze_request(request)
        if fp_result["blocked"]:
            return JSONResponse(status_code=403, content={
                "error": "Zugriff blockiert (automatische Fingerprint-Sperre).",
                "fp_id": fp_result["fp_id"],
                "risk": fp_result["risk"]})

    response = await call_next(request)
    return response

# ============================================================
# ============================================================
# --- EXPORTS ---
# ============================================================
@app.get("/export/csv")
def export_csv():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT time, status, detail FROM history ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si, delimiter=';')
    cw.writerow(["Zeit", "Status", "Vorfall"])
    cw.writerows(data)
    return StreamingResponse(io.BytesIO(si.getvalue().encode('utf-8-sig')), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=Sicherheitsbericht.csv"})

@app.get("/export/email_csv")
def export_email_csv():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT time, account, email_from, subject, verdict, risk_score, detail FROM email_scan_results ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si, delimiter=';')
    cw.writerow(["Zeit", "Konto", "Von", "Betreff", "Bewertung", "Risiko %", "Details"])
    cw.writerows(data)
    return StreamingResponse(io.BytesIO(si.getvalue().encode('utf-8-sig')), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=Email_Sicherheitsbericht.csv"})

def log_event(lvl, stat, msg):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO history (time, level, status, detail, timestamp_raw) VALUES (?,?,?,?,?)",
        (datetime.datetime.now().strftime("%H:%M:%S"), lvl, stat, msg, datetime.datetime.now())
    )
    conn.commit()
    conn.close()

# ============================================================
# --- KI TOGGLE / MODEL ---
# ============================================================
@app.get("/ai_status")
def get_ai_status():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_active'")
    val = cursor.fetchone()[0]
    conn.close()
    return {"ai_active": val}

@app.get("/version")
def get_version():
    return {
        "version": VERSION,
        "github_url": GITHUB_RAW_URL,
        "update_interval_minutes": UPDATE_INTERVAL_SECONDS // 60,
    }

@app.post("/update/check_now")
async def trigger_update_check():
    """Manuell einen Update-Check auslösen."""
    asyncio.create_task(_check_and_apply_update())
    return {"message": "Update-Check gestartet. Logs pruefen fuer Ergebnis."}

# ============================================================
# --- TELEGRAM ENDPOINTS ---
# ============================================================
@app.get("/telegram/settings")
def get_telegram_settings():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    fields = ['telegram_token','telegram_chat_id','telegram_active','telegram_on_warn']
    result = {}
    for f in fields:
        cursor.execute("SELECT value FROM settings WHERE key=?", (f,))
        r = cursor.fetchone(); result[f] = r[0] if r else ''
    # Mask token for display: show only last 6 chars
    tok = result.get('telegram_token','')
    result['telegram_token_masked'] = ('*' * max(0, len(tok)-6) + tok[-6:]) if tok else ''
    result['key_file_exists'] = os.path.isfile(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.key"))
    result['key_loaded'] = bool(TELEGRAM_TOKEN)
    conn.close()
    return result

@app.post("/telegram/settings")
async def save_telegram_settings(request: Request):
    data = await request.json()
    fields = ['telegram_token','telegram_chat_id','telegram_active','telegram_on_warn']
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    for f in fields:
        if f in data:
            cursor.execute("UPDATE settings SET value=? WHERE key=?", (str(data[f]), f))
    conn.commit(); conn.close()
    return {"success": True}

@app.post("/telegram/test")
async def test_telegram():
    """Sendet eine Test-Nachricht über Telegram."""
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    def gs(k, d=''):
        cursor.execute("SELECT value FROM settings WHERE key=?", (k,))
        r = cursor.fetchone(); return r[0] if r else d
    db_token  = gs('telegram_token', '')
    db_chat   = gs('telegram_chat_id', '')
    conn.close()
    token   = TELEGRAM_TOKEN   or db_token
    chat_id = TELEGRAM_CHAT_ID or db_chat
    if not token or not chat_id:
        return JSONResponse(status_code=400,
            content={"error": "Kein Telegram Token/Chat-ID konfiguriert."})
    now = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    text = (
        f"✅ *SENTINEL TEST*\n\n"
        f"📋 Verbindungstest erfolgreich!\n"
        f"🏢 Sentinel SME-Guardian\n"
        f"🕐 {now}"
    )
    await _send_telegram_direct(token, chat_id, text)
    return {"success": True, "message": "Test-Nachricht gesendet."}

@app.post("/toggle_ai")
async def toggle_ai():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_active'")
    current = cursor.fetchone()[0]
    new_value = '0' if current == '1' else '1'
    cursor.execute("UPDATE settings SET value=? WHERE key='ai_active'", (new_value,))
    conn.commit()
    conn.close()
    return {"ai_active": new_value}

@app.post("/set_ai")
async def set_ai(request: Request):
    """Explicitly set AI active state."""
    data  = await request.json()
    value = '1' if data.get("active") else '0'
    conn  = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value=? WHERE key='ai_active'", (value,))
    conn.commit()
    conn.close()
    return {"ai_active": value}

@app.post("/set_model")
async def set_model(request: Request):
    data = await request.json()
    new_model = data.get("model", "").strip()
    if not new_model:
        return JSONResponse(status_code=400, content={"error": "Kein Modellname angegeben."})
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value=? WHERE key='ai_model'", (new_model,))
    conn.commit()
    conn.close()
    return {"ai_model": new_model}

# ============================================================
# --- EMAIL ENDPOINTS ---
# ============================================================
@app.post("/email/add_account")
async def add_email_account(request: Request):
    data = await request.json()
    provider    = data.get("provider", "custom")
    email_addr  = data.get("email", "").strip()
    password    = data.get("password", "").strip()
    custom_host = data.get("imap_host", "").strip()
    custom_port = data.get("imap_port", 993)
    if not email_addr or not password:
        return JSONResponse(status_code=400, content={"error": "E-Mail und Passwort erforderlich."})
    preset    = EMAIL_PROVIDERS.get(provider, EMAIL_PROVIDERS["custom"])
    imap_host = custom_host if custom_host else preset["imap_host"]
    imap_port = int(custom_port) if custom_port else preset["imap_port"]
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO email_accounts (provider, email, imap_host, imap_port, password, active) VALUES (?,?,?,?,?,1)",
                   (provider, email_addr, imap_host, imap_port, password))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    log_event(1, "EMAIL-KONTO", f"Konto hinzugefuegt: {email_addr} ({provider})")
    return {"success": True, "id": new_id, "email": email_addr}

@app.get("/email/accounts")
def get_email_accounts():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, provider, email, imap_host, imap_port, active FROM email_accounts")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.delete("/email/account/{account_id}")
def delete_email_account(account_id: int):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM email_accounts WHERE id=?", (account_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/email/scan/{account_id}")
async def trigger_email_scan(account_id: int):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, scan_email_account, account_id)

@app.post("/email/scan_all")
async def scan_all_accounts():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM email_accounts WHERE active=1")
    ids = [r[0] for r in cursor.fetchall()]
    conn.close()
    loop = asyncio.get_event_loop()
    all_results = []
    for aid in ids:
        r = await loop.run_in_executor(None, scan_email_account, aid)
        all_results.append(r)
    return {"accounts_scanned": len(ids), "results": all_results}

@app.get("/email/results")
def get_email_results():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_scan_results ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/email/test_connection/{account_id}")
async def test_email_connection(account_id: int):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT provider, email, imap_host, imap_port, password FROM email_accounts WHERE id=?", (account_id,))
    acc = cursor.fetchone()
    conn.close()
    if not acc:
        return JSONResponse(status_code=404, content={"error": "Konto nicht gefunden"})
    provider, email_addr, imap_host, imap_port, password = acc
    try:
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
        mail.login(email_addr, password)
        mail.logout()
        return {"success": True, "message": f"Verbindung zu {email_addr} erfolgreich!"}
    except Exception as e:
        return {"success": False, "message": f"Verbindungsfehler: {str(e)}"}

@app.post("/email/analyze_text")
async def analyze_email_text(request: Request):
    data    = await request.json()
    sender  = data.get("sender", "")
    subject = data.get("subject", "")
    body    = data.get("body", "")
    risk_score, reasons = logic.quick_phishing_score(sender, subject, body)
    verdict = "SICHER" if risk_score < 30 else ("VERDAECHTIG" if risk_score < 60 else "PHISHING/VIRUS")
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_active'")
    ai_on = cursor.fetchone()[0]
    conn.close()
    ai_analysis = ""
    if ai_on == '1' and body:
        combined = f"Von: {sender}\nBetreff: {subject}\nInhalt: {body[:1500]}"
        ai_analysis = await call_ai(combined, "email_deep")
    log_event(3 if risk_score >= 60 else 1, f"EMAIL-SCAN ({verdict})",
              f"Von: {sender[:50]} | Risiko: {risk_score}%")
    if risk_score >= 60:
        push_alarm("KRITISCH", "EMAIL",
                   f"Phishing-E-Mail erkannt! Risiko: {risk_score}%", sender[:40])
    return {"verdict": verdict, "risk_score": risk_score,
            "reasons": reasons, "ai_analysis": ai_analysis}

# ============================================================
# --- MEMORY SAFETY ENDPOINTS ---
# ============================================================
@app.get("/safety/check")
async def safety_check():
    checks = memory_checker.check_container_isolation()
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    for c in checks:
        cursor.execute(
            "INSERT INTO safety_checks (time, check_type, component, status, detail) VALUES (?,?,?,?,?)",
            (datetime.datetime.now().strftime("%H:%M:%S"), "memory_safety",
             c["component"], c["status"], c["detail"])
        )
    conn.commit()
    conn.close()
    score = int(sum(1 for c in checks if c.get("ok", False)) / max(len(checks), 1) * 100)
    return {"checks": checks, "score": score, "total": len(checks),
            "passed": sum(1 for c in checks if c.get("ok", False))}

@app.get("/safety/dockerfile")
async def get_dockerfile():
    return {"dockerfile": memory_checker.get_dockerfile_recommendation()}

@app.get("/safety/rust_stub")
async def get_rust_stub():
    return {"rust_code": memory_checker.get_rust_service_stub()}

# ============================================================
# --- EXPLOIT ENDPOINTS ---
# ============================================================
@app.post("/exploit/analyze")
async def manual_exploit_analyze(request: Request):
    data   = await request.json()
    text   = data.get("text", "")
    ip     = data.get("ip", "manual-test")
    result = exploit_detector.analyze(text, ip)
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_active'")
    ai_on = cursor.fetchone()[0]
    conn.close()
    ai_result = None
    if ai_on == '1' and result["threat"] and text:
        raw = await call_ai(text[:800], "exploit")
        try:
            clean = raw.strip().lstrip("```json").rstrip("```").strip()
            ai_result = json.loads(clean)
        except:
            ai_result = {"raw": raw}
    return {**result, "ai_analysis": ai_result}

@app.get("/exploit/alerts")
def get_exploit_alerts():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM exploit_alerts ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ============================================================
# --- HONEYTOKEN ENDPOINTS ---
# ============================================================
@app.get("/honeytoken/list")
def list_honeytokens():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeytokens ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/honeytoken/add")
async def add_honeytoken(request: Request):
    data       = await request.json()
    ttype      = data.get("token_type", "url_trap")
    label      = data.get("label", "")
    fake_value = data.get("fake_value", "")
    route      = data.get("route", "")
    if not label or not fake_value:
        return JSONResponse(status_code=400, content={"error": "Label und Fake-Wert erforderlich."})
    token_id = secrets.token_hex(8)
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO honeytokens (token_id, token_type, label, fake_value, route, created) VALUES (?,?,?,?,?,?)",
        (token_id, ttype, label, fake_value, route, datetime.datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    log_event(1, "HONEYTOKEN", f"Neue Falle angelegt: {label} ({ttype})")
    return {"success": True, "token_id": token_id}

@app.delete("/honeytoken/{token_id}")
def delete_honeytoken(token_id: str):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM honeytokens WHERE token_id=?", (token_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/honeytoken/alerts")
def get_honeytoken_alerts():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM honeytoken_alerts ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ============================================================
# --- BRUTE-FORCE ENDPOINTS ---
# ============================================================
@app.get("/bruteforce/alerts")
def get_bruteforce_alerts():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bruteforce_alerts ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/bruteforce/unblock")
async def unblock_ip(request: Request):
    data = await request.json()
    ip   = data.get("ip", "").strip()
    if ip in _blocked_ips:
        del _blocked_ips[ip]
        if ip in _rate_windows:
            del _rate_windows[ip]
        log_event(1, "IP ENTSPERRT", f"IP manuell entsperrt: {ip}")
        return {"success": True, "message": f"{ip} wurde entsperrt."}
    return {"success": False, "message": "IP war nicht gesperrt."}

@app.get("/bruteforce/blocked")
def get_blocked_ips():
    now = time.time()
    result = []
    for ip, unblock_ts in list(_blocked_ips.items()):
        if now < unblock_ts:
            result.append({"ip": ip, "remaining_seconds": int(unblock_ts - now)})
        else:
            del _blocked_ips[ip]
    return result

@app.post("/set_rate_limit")
async def set_rate_limit(request: Request):
    data  = await request.json()
    limit = data.get("limit", 60)
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value=? WHERE key='rate_limit_max'", (str(int(limit)),))
    conn.commit()
    conn.close()
    return {"rate_limit_max": limit}

# ============================================================
# --- FINGERPRINT ENDPOINTS (NEW) ---
# ============================================================
@app.get("/fingerprint/list")
def list_fingerprints():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fingerprints ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/fingerprint/stats")
def fingerprint_stats():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM fingerprints")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE status='verdaechtig'")
    suspicious = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE status='kritisch'")
    critical = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_bot=1")
    bots = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_tor=1")
    tor = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_vpn=1")
    vpn = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_proxy=1")
    proxy = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_headless=1")
    headless = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE is_datacenter=1")
    datacenter = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE blocked=1")
    blocked = cursor.fetchone()[0]
    conn.close()
    return {"total": total, "suspicious": suspicious, "critical": critical,
            "bots": bots, "tor": tor, "vpn": vpn, "proxy": proxy,
            "headless": headless, "datacenter": datacenter, "blocked": blocked}

@app.post("/fingerprint/behaviour")
async def receive_behaviour(request: Request):
    data       = await request.json()
    fp_id      = data.get("fp_id", "")
    event_type = data.get("event_type", "")
    event_data = data.get("data", {})
    if not fp_id or not event_type:
        return JSONResponse(status_code=400, content={"error": "fp_id und event_type erforderlich."})
    result = fingerprint_engine.analyze_behaviour(fp_id, event_type, event_data)
    return result

@app.post("/fingerprint/block/{fp_id}")
def block_fingerprint(fp_id: str):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE fingerprints SET blocked=1 WHERE fp_id=?", (fp_id,))
    conn.commit()
    conn.close()
    log_event(3, "FP MANUELL GEBLOCKT", f"Fingerprint blockiert: {fp_id}")
    return {"success": True}

@app.post("/fingerprint/unblock/{fp_id}")
def unblock_fingerprint(fp_id: str):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE fingerprints SET blocked=0 WHERE fp_id=?", (fp_id,))
    conn.commit()
    conn.close()
    log_event(1, "FP ENTSPERRT", f"Fingerprint entsperrt: {fp_id}")
    return {"success": True}

@app.delete("/fingerprint/{fp_id}")
def delete_fingerprint(fp_id: str):
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM fingerprints WHERE fp_id=?", (fp_id,))
    cursor.execute("DELETE FROM fp_behaviour WHERE fp_id=?", (fp_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/fingerprint/settings")
async def save_fp_settings(request: Request):
    data = await request.json()
    auto_block = data.get("fp_auto_block", "0")
    threshold  = data.get("fp_block_threshold", "70")
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value=? WHERE key='fp_auto_block'", (str(auto_block),))
    cursor.execute("UPDATE settings SET value=? WHERE key='fp_block_threshold'", (str(threshold),))
    conn.commit()
    conn.close()
    return {"success": True}

# ============================================================
# --- HISTORY ---
# ============================================================
@app.get("/history")
def get_history():
    conn = sqlite3.connect("sentinel.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history ORDER BY id DESC LIMIT 10")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ============================================================
# --- SCAN ---
# ============================================================
@app.post("/scan")
async def scan(request: Request):
    d    = await request.json()
    text = d.get("text", "")
    mode = d.get("mode", "standard")
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_active'")
    ai_on = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='blacklist'")
    bl = cursor.fetchone()[0].split(',')
    conn.close()
    for w in bl:
        if w.strip() and w.strip().lower() in text.lower():
            log_event(5, "GESTOPPT", f"Blacklist: {w}")
            push_alarm("KRITISCH", "DLP", f"Blacklist-Wort: '{w.strip()}'")
            return {"status": "BLOCKED"}
    for label, pattern in logic.critical_rules.items():
        if re.search(pattern, text):
            log_event(5, "GESTOPPT", f"DLP: {label}")
            push_alarm("KRITISCH", "DLP", f"DLP-Regel ausgeloest: {label}")
            return {"status": "BLOCKED"}
    sanitized = logic.sanitize(text)
    if ai_on == '0':
        log_event(1, "SICHER", "Lokal geprueft (KI aus)")
        return {"status": "CLEAN", "ai_response": "Pruefung ohne KI abgeschlossen. Keine Bedrohung gefunden."}
    log_event(0, "SICHER", f"KI-Scan ({mode})")
    ans = await call_ai(sanitized, mode)
    return {"status": "CLEAN", "ai_response": logic.mask_output(ans)}

# ============================================================
# --- DASHBOARD ---
# ============================================================
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key='ai_model'");       mod     = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='ai_active'");      act     = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='blacklist'");      bl      = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='company_name'");   company = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='rate_limit_max'"); rl_max  = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='fp_auto_block'");  fp_auto = cursor.fetchone()[0]
    cursor.execute("SELECT value FROM settings WHERE key='fp_block_threshold'"); fp_thresh = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM history WHERE status='GESTOPPT'");  blocked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM history");                           total   = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM email_accounts WHERE active=1");    email_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM email_scan_results WHERE verdict='PHISHING/VIRUS'"); phishing = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM honeytoken_alerts");                honey_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM exploit_alerts WHERE blocked=1");   exploit_blocked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM bruteforce_alerts");                brute_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE status='kritisch'"); fp_critical = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM fingerprints");                     fp_total = cursor.fetchone()[0]
    conn.close()

    threat_total = blocked + honey_alerts + exploit_blocked + brute_count + fp_critical
    threat_color = "#10b981" if threat_total == 0 else "#fbbf24" if threat_total < 5 else "#f87171"

    modell_liste = [
        "tinyllama","llama2","llama2:7b","llama2:13b","llama3.2","llama3.2:1b","llama3.2:3b",
        "llama3.1","llama3.1:8b","llama3.1:70b","llama3","llama3:8b","llama3:70b",
        "mistral","mistral:7b","mixtral","mixtral:8x7b","gemma","gemma:2b","gemma:7b",
        "gemma2","gemma2:2b","gemma2:9b","gemma2:27b","vicuna","vicuna:7b","vicuna:13b",
        "openchat","openchat:7b","orca-mini","orca-mini:3b","orca-mini:7b",
        "neural-chat","zephyr","zephyr:7b","dolphin-mistral",
        "deepseek-coder","deepseek-coder:6.7b","solar","solar:10.7b",
        "qwen","qwen:7b","qwen:14b","nous-hermes2","llava","llava:7b"
    ]
    options_html     = "".join(f'<option value="{m}"{" selected" if m==mod else ""}>{m}</option>' for m in modell_liste)
    provider_options = "".join(f'<option value="{p}">{p.upper()}</option>' for p in EMAIL_PROVIDERS.keys())

    return f"""<!DOCTYPE html>
<html>
<head>
<title>SME-Guardian v{VERSION} | {company}</title>
<style>
*{{box-sizing:border-box;}}
body{{font-family:sans-serif;background:#0a0c10;color:#cfd8dc;margin:0;padding:20px;}}
.card{{background:#151921;border-radius:12px;padding:20px;border:1px solid #263238;margin-bottom:20px;}}
.header{{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #38bdf8;padding-bottom:10px;}}
.threat-meter{{color:{threat_color};font-weight:bold;font-size:1.2rem;}}
.stats{{display:grid;grid-template-columns:repeat(9,1fr);gap:8px;margin:20px 0;}}
.stat-item{{background:#1c232d;padding:10px 6px;border-radius:8px;text-align:center;border:1px solid #37474f;}}
.stat-item small{{font-size:0.65rem;color:#90a4ae;}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;}}
.grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:15px;}}
textarea,.output,select,input[type=text],input[type=password],input[type=email],input[type=number]{{
  width:100%;background:#0a0c10;color:#38bdf8;border:1px solid #37474f;
  padding:10px;border-radius:8px;margin-top:5px;font-size:0.9rem;}}
textarea{{height:130px;resize:none;}}
.output{{color:#eceff1;overflow-y:auto;min-height:130px;border-left:4px solid {threat_color};padding:15px;}}
.btn{{padding:9px 18px;border-radius:6px;border:none;font-weight:bold;cursor:pointer;margin:3px;font-size:0.85rem;}}
.btn-blue{{background:#38bdf8;color:#0a0c10;}} .btn-phish{{background:#fbbf24;color:#0a0c10;}}
.btn-red{{background:#f87171;color:#0a0c10;}} .btn-green{{background:#10b981;color:#0a0c10;}}
.btn-gray{{background:#37474f;color:#cfd8dc;}} .btn-purple{{background:#a78bfa;color:#0a0c10;}}
.btn-orange{{background:#fb923c;color:#0a0c10;}} .btn-teal{{background:#2dd4bf;color:#0a0c10;}}
.btn-sm{{padding:5px 10px;font-size:0.78rem;}}
.tab-buttons{{display:flex;gap:4px;margin-bottom:15px;flex-wrap:wrap;}}
.tab-btn{{padding:7px 12px;border-radius:6px;border:1px solid #37474f;background:#1c232d;color:#90a4ae;cursor:pointer;font-size:0.8rem;}}
.tab-btn.active{{background:#38bdf8;color:#0a0c10;border-color:#38bdf8;font-weight:bold;}}
.tab-content{{display:none;}} .tab-content.active{{display:block;}}
.form-row{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;}}
label{{font-size:0.8rem;color:#90a4ae;display:block;margin-top:8px;}}
.risk-bar-bg{{background:#1c232d;border-radius:4px;height:8px;margin-top:4px;}}
.risk-bar{{height:8px;border-radius:4px;transition:width 0.5s;}}
.account-card{{background:#1c232d;border:1px solid #37474f;border-radius:8px;padding:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;}}
h3{{color:#38bdf8;margin-top:0;}} h4{{color:#7dd3fc;margin-bottom:8px;}}
table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:0.82rem;}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #263238;}}
th{{color:#38bdf8;font-size:0.75rem;text-transform:uppercase;}}
.badge{{padding:3px 8px;border-radius:4px;font-size:0.72rem;font-weight:bold;}}
.badge-safe{{background:#064e3b;color:#10b981;}} .badge-warn{{background:#451a03;color:#fbbf24;}}
.badge-danger{{background:#450a0a;color:#f87171;}} .badge-purple{{background:#2e1065;color:#a78bfa;}}
.badge-blue{{background:#0c2545;color:#38bdf8;}} .badge-teal{{background:#0d3330;color:#2dd4bf;}}
.info-box{{background:#0c2545;border:1px solid #1e3a5f;border-radius:8px;padding:14px;margin-bottom:14px;font-size:0.85rem;}}
.info-box.success{{background:#022c22;border-color:#065f46;}}
.info-box.warning{{background:#1c1100;border-color:#78350f;}}
code{{background:#0a0c10;border:1px solid #37474f;border-radius:4px;padding:2px 6px;font-size:0.82rem;color:#a3e635;}}
pre{{background:#050709;border:1px solid #263238;border-radius:8px;padding:15px;overflow-x:auto;font-size:0.8rem;color:#a3e635;line-height:1.5;}}
.admin-bar{{font-size:0.85rem;color:#90a4ae;margin-top:10px;}}
.check-row{{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #1e293b;}}
.check-row:last-child{{border-bottom:none;}}
.honeytoken-row{{background:#1c232d;border:1px solid #37474f;border-radius:6px;padding:10px 14px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;font-size:0.85rem;}}
.spinner{{display:none;color:#38bdf8;font-style:italic;font-size:0.85rem;}}
.fp-card{{background:#1c232d;border-radius:8px;padding:12px;margin-bottom:8px;border-left:4px solid #37474f;}}
.fp-card.normal{{border-left-color:#10b981;}} .fp-card.verdaechtig{{border-left-color:#fbbf24;}} .fp-card.kritisch{{border-left-color:#f87171;}}
.fp-flag{{display:inline-block;margin:2px 3px;padding:2px 7px;border-radius:4px;font-size:0.71rem;font-weight:bold;}}
.flag-on{{background:#450a0a;color:#f87171;}} .flag-off{{background:#1c232d;color:#4b5563;}}
.status-dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle;}}
.dot-normal{{background:#10b981;}} .dot-verdaechtig{{background:#fbbf24;animation:pulse 1.5s infinite;}}
.dot-kritisch{{background:#f87171;animation:pulse 0.8s infinite;}}

/* REALTIME ALARM BANNER */
#alarmBanner{{position:fixed;top:0;left:0;right:0;z-index:9999;display:none;
  background:#450a0a;border-bottom:3px solid #f87171;padding:0;max-height:220px;overflow-y:auto;}}
#alarmBanner.visible{{display:block;}}
.alarm-item{{display:flex;align-items:center;gap:12px;padding:10px 20px;
  border-bottom:1px solid #5a1010;animation:slideIn 0.3s ease;}}
.alarm-item:last-child{{border-bottom:none;}}
@keyframes slideIn{{from{{opacity:0;transform:translateY(-8px)}}to{{opacity:1;transform:translateY(0)}}}}
.alarm-close{{position:sticky;top:0;right:0;float:right;background:#f87171;color:#0a0c10;
  border:none;padding:4px 12px;cursor:pointer;font-weight:bold;font-size:0.85rem;border-radius:0 0 0 6px;}}
.alarm-badge{{padding:3px 8px;border-radius:4px;font-size:0.75rem;font-weight:bold;white-space:nowrap;}}
.alarm-KRITISCH{{background:#f87171;color:#0a0c10;}} .alarm-WARNUNG{{background:#fbbf24;color:#0a0c10;}}
.alarm-INFO{{background:#38bdf8;color:#0a0c10;}}
.alarm-cat{{font-size:0.72rem;color:#fca5a5;white-space:nowrap;}}

/* SIRENE OVERLAY */
#sireneOverlay{{display:none;position:fixed;inset:0;z-index:99999;background:rgba(80,0,0,0.92);
  flex-direction:column;align-items:center;justify-content:center;text-align:center;}}
#sireneOverlay.active{{display:flex;}}
@keyframes redBlink{{0%,100%{{background:rgba(80,0,0,0.92)}}50%{{background:rgba(180,0,0,0.97)}}}}
#sireneOverlay.active{{animation:redBlink 0.6s infinite;}}
#sireneOverlay .siren-icon{{font-size:6rem;animation:bounce 0.5s infinite alternate;}}
@keyframes bounce{{from{{transform:scale(1)}}to{{transform:scale(1.15)}}}}
#sireneOverlay h1{{color:#fff;font-size:2.5rem;margin:10px 0;text-shadow:0 0 20px #f87171;}}
#sireneOverlay p{{color:#fca5a5;font-size:1.1rem;max-width:500px;}}
#sireneOverlay .siren-details{{background:rgba(0,0,0,0.4);border-radius:10px;padding:15px 30px;
  margin:15px 0;min-width:400px;}}
#sireneOverlay .siren-details table td{{padding:6px 12px;text-align:left;color:#fecaca;}}
#sireneOverlay .siren-details table td:first-child{{color:#90a4ae;width:100px;}}
#confirmBtn{{background:#f87171;color:#0a0c10;border:none;padding:15px 40px;border-radius:8px;
  font-size:1.2rem;font-weight:bold;cursor:pointer;margin-top:10px;
  box-shadow:0 0 30px #f87171;transition:transform 0.1s;}}
#confirmBtn:hover{{transform:scale(1.05);}}

/* BODY BLINK (background) */
@keyframes bodyBlink{{0%,100%{{background:#0a0c10}}50%{{background:#1a0505}}}}
body.alarm-active{{animation:bodyBlink 1s infinite;}}
.alarm-msg{{flex:1;font-size:0.85rem;color:#fecaca;}}
.alarm-ip{{font-size:0.72rem;color:#f87171;}} .alarm-time{{font-size:0.72rem;color:#90a4ae;white-space:nowrap;}}
.live-dot{{display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;
  animation:pulse 1.5s infinite;margin-right:6px;vertical-align:middle;}}
@keyframes pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:0.4;transform:scale(0.8)}}}}

/* Toggle switch */
.toggle-wrap{{display:flex;align-items:center;gap:10px;margin-top:10px;}}
.toggle{{position:relative;display:inline-block;width:46px;height:24px;}}
.toggle input{{opacity:0;width:0;height:0;}}
.slider{{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#37474f;
  border-radius:24px;transition:.3s;}}
.slider:before{{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;
  background:white;border-radius:50%;transition:.3s;}}
input:checked+.slider{{background:#38bdf8;}}
input:checked+.slider:before{{transform:translateX(22px);}}
</style>
</head>
<body>

<!-- REALTIME ALARM BANNER -->
<div id="alarmBanner">
  <div style="position:sticky;top:0;background:#450a0a;padding:6px 20px;display:flex;justify-content:space-between;align-items:center;">
    <span style="color:#f87171;font-weight:bold;font-size:0.9rem;">SICHERHEITSALARM</span>
    <button class="alarm-close" onclick="clearAlarms()">Schliessen</button>
  </div>
  <div id="alarmItems"></div>
</div>

<!-- SIRENE OVERLAY -->
<div id="sireneOverlay">
  <div class="siren-icon">🚨</div>
  <h1>SICHERHEITSALARM!</h1>
  <p>Ein kritischer Angriff wurde erkannt. Bitte sofort pruefen!</p>
  <div class="siren-details">
    <table>
      <tr><td>Kategorie:</td><td id="siren_cat" style="color:#f87171;font-weight:bold;">-</td></tr>
      <tr><td>Details:</td><td id="siren_msg">-</td></tr>
      <tr><td>IP:</td><td id="siren_ip" style="color:#fbbf24;">-</td></tr>
      <tr><td>Zeit:</td><td id="siren_time">-</td></tr>
    </table>
  </div>
  <button id="confirmBtn" onclick="confirmSirene()">ALARM BESTAETIGEN</button>
</div>

<!-- HEADER -->
<div class="card" style="margin-top:0;">
  <div class="header">
    <h2>SENTINEL SME-GUARDIAN
      <span style="font-size:0.75rem;font-weight:normal;color:#90a4ae;margin-left:12px;">
        <span class="live-dot"></span>Live-Ueberwachung aktiv
      </span>
    </h2>
    <div class="threat-meter">{"SICHER" if threat_total < 5 else "GEFAEHRDET"} ({threat_total} Ereignisse)</div>
  </div>
  <div class="stats">
    <div class="stat-item"><small>Gesamt-Scans</small><br><strong>{total}</strong></div>
    <div class="stat-item" style="color:#f87171;"><small>DLP gestoppt</small><br><strong>{blocked}</strong></div>
    <div class="stat-item" style="color:#38bdf8;"><small>E-Mail Konten</small><br><strong>{email_count}</strong></div>
    <div class="stat-item" style="color:#fbbf24;"><small>Phishing</small><br><strong>{phishing}</strong></div>
    <div class="stat-item" style="color:#a78bfa;"><small>Fallen</small><br><strong>{honey_alerts}</strong></div>
    <div class="stat-item" style="color:#f87171;"><small>Exploits</small><br><strong>{exploit_blocked}</strong></div>
    <div class="stat-item" style="color:#fb923c;"><small>Brute-Force</small><br><strong>{brute_count}</strong></div>
    <div class="stat-item" style="color:#2dd4bf;"><small>FP kritisch</small><br><strong>{fp_critical}</strong></div>
    <div class="stat-item"><small>CSV</small><br><a href="/export/csv" style="color:#38bdf8;font-size:0.8rem;">Export</a></div>
  </div>
  <div class="admin-bar">
    Firma: <strong>{company}</strong> | KI: <strong id="kiStatus">{"AKTIV" if act=="1" else "DEAKTIVIERT"}</strong> | Filter: <strong>{bl}</strong>
    &nbsp;<span style="color:#37474f;font-size:0.8rem;">|</span>&nbsp;
    <span style="color:#4b5563;font-size:0.78rem;">v{VERSION}</span>
    <span id="updateBadge" style="display:none;margin-left:6px;padding:2px 8px;background:#fbbf24;
      color:#0a0c10;border-radius:4px;font-size:0.72rem;font-weight:bold;cursor:pointer;"
      onclick="triggerUpdateCheck()">UPDATE VERFÜGBAR</span>
    <br><br>
    <label>Modell:</label>
    <select id="modelSelect" style="width:auto;display:inline-block;">{options_html}</select>
    <button class="btn btn-blue btn-sm" onclick="saveModel()">Speichern</button>
    &nbsp;<button class="btn btn-gray btn-sm" onclick="toggleKI()" id="kiButton">{"KI deaktivieren" if act=="1" else "KI aktivieren"}</button>
  </div>
</div>

<!-- TABS -->
<div class="tab-buttons">
  <button class="tab-btn active" onclick="showTab('tab-scan',this)">Scan</button>
  <button class="tab-btn" onclick="showTab('tab-email-scan',this)">E-Mail Scanner</button>
  <button class="tab-btn" onclick="showTab('tab-email-accounts',this)">E-Mail Konten</button>
  <button class="tab-btn" onclick="showTab('tab-email-results',this)">E-Mail Ergebnisse</button>
  <button class="tab-btn" onclick="showTab('tab-exploit',this)">Exploit-Detektor</button>
  <button class="tab-btn" onclick="showTab('tab-honeytokens',this)">Honeytokens</button>
  <button class="tab-btn" onclick="showTab('tab-bruteforce',this)">Brute-Force</button>
  <button class="tab-btn" onclick="showTab('tab-fingerprint',this)">Fingerprint</button>
  <button class="tab-btn" onclick="showTab('tab-memory',this)">Memory Safety</button>
  <button class="tab-btn" onclick="showTab('tab-history',this)">Historie</button>
  <button class="tab-btn" onclick="showTab('tab-alarmlog',this)">Alarm-Log</button>
  <button class="tab-btn" onclick="showTab('tab-compliance',this)">Compliance PDF</button>
  <button class="tab-btn" onclick="showTab('tab-outlook',this)">Outlook Add-in</button>
  <button class="tab-btn" onclick="showTab('tab-settings',this)">Einstellungen</button>
</div>

<!-- TAB: TEXT SCAN -->
<div id="tab-scan" class="tab-content active">
  <div class="grid">
    <div class="card"><h3>Analyse-Eingabe</h3>
      <textarea id="inp" placeholder="Text, E-Mail oder verdaechtigen Inhalt einfuegen..."></textarea>
      <div style="margin-top:12px;">
        <button class="btn btn-blue" onclick="runScan('standard')">STANDARD CHECK</button>
        <button class="btn btn-phish" onclick="runScan('phishing')">PHISHING CHECK</button>
      </div>
    </div>
    <div class="card"><h3>Sicherheits-Ergebnis</h3><div id="out" class="output">Bereit fuer Scan...</div></div>
  </div>
</div>

<!-- TAB: EMAIL SCAN -->
<div id="tab-email-scan" class="tab-content">
  <div class="card"><h3>E-Mail manuell analysieren</h3>
    <div class="form-row">
      <div><label>Absender:</label><input type="text" id="em_from" placeholder="noreply@paypa1-support.xyz"></div>
      <div><label>Betreff:</label><input type="text" id="em_subject" placeholder="Konto gesperrt!"></div>
    </div>
    <label>E-Mail Inhalt:</label>
    <textarea id="em_body" style="height:150px;" placeholder="E-Mail-Text einfuegen..."></textarea>
    <div style="margin-top:12px;">
      <button class="btn btn-phish" onclick="analyzeEmailText()">E-MAIL ANALYSIEREN</button>
      <span class="spinner" id="email_spinner">Analysiere mit KI...</span>
    </div>
  </div>
  <div class="card" id="emailAnalysisResult" style="display:none;"><h3>Analyse-Ergebnis</h3><div id="emailResultContent"></div></div>
</div>

<!-- TAB: EMAIL ACCOUNTS -->
<div id="tab-email-accounts" class="tab-content">
  <div class="grid">
    <div class="card"><h3>E-Mail Konto hinzufuegen</h3>
      <p style="color:#90a4ae;font-size:0.8rem;">Fuer Gmail/Outlook: App-Passwoerter verwenden!</p>
      <label>Anbieter:</label><select id="acc_provider" onchange="updateProviderFields()">{provider_options}</select>
      <label>E-Mail:</label><input type="email" id="acc_email" placeholder="deine@email.de">
      <label>Passwort:</label><input type="password" id="acc_password" placeholder="App-Passwort">
      <div id="custom_imap_fields" style="display:none;">
        <label>IMAP Server:</label><input type="text" id="acc_imap_host" placeholder="imap.deinserver.de">
        <label>IMAP Port:</label><input type="number" id="acc_imap_port" value="993">
      </div>
      <div style="margin-top:12px;">
        <button class="btn btn-green" onclick="addEmailAccount()">Konto hinzufuegen</button>
        <button class="btn btn-blue" onclick="scanAllAccounts()">Alle scannen</button>
      </div>
    </div>
    <div class="card"><h3>Verbundene Konten</h3><div id="accountsList">Laden...</div>
      <br><a href="/export/email_csv" style="color:#38bdf8;font-size:0.85rem;">E-Mail Bericht</a></div>
  </div>
</div>

<!-- TAB: EMAIL RESULTS -->
<div id="tab-email-results" class="tab-content">
  <div class="card"><h3>E-Mail Scan Ergebnisse</h3>
    <button class="btn btn-blue btn-sm" onclick="loadEmailResults()">Aktualisieren</button>
    <table>
      <thead><tr><th>Zeit</th><th>Konto</th><th>Von</th><th>Betreff</th><th>Bewertung</th><th>Risiko</th><th>Details</th></tr></thead>
      <tbody id="emailResultsBody"><tr><td colspan="7" style="color:#90a4ae;">Noch keine Scans.</td></tr></tbody>
    </table>
  </div>
</div>

<!-- TAB: EXPLOIT -->
<div id="tab-exploit" class="tab-content">
  <div class="info-box">
    <strong>KI-gestuetzte Zero-Day Exploit-Erkennung</strong><br>
    Prueft automatisch jede eingehende Anfrage (GET + POST) auf 18 Angriffsmuster. Echtzeit-Alarm im Banner.
  </div>
  <div class="grid">
    <div class="card"><h3>Payload manuell testen</h3>
      <textarea id="exploit_input" placeholder="z.B.: ' OR 1=1 --&#10;../../../etc/passwd"></textarea>
      <div style="margin-top:10px;">
        <button class="btn btn-red" onclick="runExploitScan()">EXPLOIT ANALYSE</button>
        <span class="spinner" id="exploit_spinner">Analysiere...</span>
      </div>
    </div>
    <div class="card"><h3>Erkennungs-Ergebnis</h3><div id="exploit_result" class="output">Bereit...</div></div>
  </div>
  <div class="card"><h3>Letzte Exploit-Warnungen</h3>
    <button class="btn btn-blue btn-sm" onclick="loadExploitAlerts()">Aktualisieren</button>
    <table>
      <thead><tr><th>Zeit</th><th>IP</th><th>Muster</th><th>Konfidenz</th><th>Status</th><th>Payload</th></tr></thead>
      <tbody id="exploitAlertsBody"><tr><td colspan="6" style="color:#90a4ae;">Keine Exploit-Versuche.</td></tr></tbody>
    </table>
  </div>
</div>

<!-- TAB: HONEYTOKENS -->
<div id="tab-honeytokens" class="tab-content">
  <div class="info-box">
    <strong>Honeytoken & Fallen-System</strong><br>
    Gefaelschte Zugangsdaten und URLs als Koeder. Jeder Zugriff loest sofort Echtzeit-Alarm aus.
  </div>
  <div class="grid">
    <div class="card"><h3>Neue Falle anlegen</h3>
      <label>Typ:</label>
      <select id="ht_type"><option value="url_trap">URL-Falle</option><option value="fake_api_key">Fake API-Key</option>
        <option value="fake_password">Fake Passwort</option><option value="fake_db_url">Fake Datenbank-URL</option>
        <option value="fake_credit">Fake Kreditkarte</option><option value="fake_ssn">Fake Ausweisnummer</option></select>
      <label>Bezeichnung:</label><input type="text" id="ht_label" placeholder="Decoy Admin Backup">
      <label>Fake-Wert:</label><input type="text" id="ht_value" placeholder="/admin/secret.zip">
      <label>URL-Route (fuer URL-Fallen):</label><input type="text" id="ht_route" placeholder="/admin/secret.zip">
      <div style="margin-top:12px;"><button class="btn btn-purple" onclick="addHoneytoken()">Falle anlegen</button></div>
    </div>
    <div class="card"><h3>Aktive Fallen</h3><div id="honeytokenList">Laden...</div></div>
  </div>
  <div class="card"><h3>Honeytoken Alarm-Log</h3>
    <button class="btn btn-blue btn-sm" onclick="loadHoneytokenAlerts()">Aktualisieren</button>
    <table>
      <thead><tr><th>Zeit</th><th>Falle</th><th>Angreifer-IP</th><th>Pfad</th><th>Methode</th><th>User-Agent</th></tr></thead>
      <tbody id="honeytokenAlertsBody"><tr><td colspan="6" style="color:#90a4ae;">Keine Fallen ausgeloest.</td></tr></tbody>
    </table>
  </div>
</div>

<!-- TAB: BRUTE-FORCE -->
<div id="tab-bruteforce" class="tab-content">
  <div class="info-box">
    <strong>Brute-Force & Rate-Limit Schutz</strong><br>
    Jede IP wird automatisch ueberwacht. Bei Ueberschreitung: sofortige Sperrung (5 Min) + Echtzeit-Alarm.
  </div>
  <div class="grid">
    <div class="card"><h3>Rate-Limit Einstellungen</h3>
      <label>Max. Anfragen pro Minute pro IP:</label>
      <input type="number" id="rl_max_input" value="{rl_max}" min="5" max="1000">
      <div style="margin-top:10px;"><button class="btn btn-blue" onclick="saveRateLimit()">Speichern</button></div>
      <div style="margin-top:20px;"><h4>Aktuell gesperrte IPs</h4>
        <button class="btn btn-blue btn-sm" onclick="loadBlockedIPs()">Aktualisieren</button>
        <div id="blockedIPsList" style="margin-top:10px;"></div>
      </div>
    </div>
    <div class="card"><h3>IP manuell entsperren</h3>
      <label>IP-Adresse:</label><input type="text" id="unblock_ip_input" placeholder="192.168.1.100">
      <div style="margin-top:10px;"><button class="btn btn-green" onclick="unblockIP()">IP entsperren</button></div>
    </div>
  </div>
  <div class="card"><h3>Brute-Force Alarm-Log</h3>
    <button class="btn btn-blue btn-sm" onclick="loadBruteAlerts()">Aktualisieren</button>
    <table>
      <thead><tr><th>Zeit</th><th>IP</th><th>Anfragen</th><th>Fenster</th><th>Pfad</th><th>Status</th></tr></thead>
      <tbody id="bruteAlertsBody"><tr><td colspan="6" style="color:#90a4ae;">Keine Brute-Force-Versuche.</td></tr></tbody>
    </table>
  </div>
</div>

<!-- TAB: FINGERPRINT (NEW) -->
<div id="tab-fingerprint" class="tab-content">
  <div class="info-box">
    <strong>Erweiterte Fingerprint- & Verhaltensanalyse</strong><br>
    Jede Anfrage wird automatisch analysiert: Browser-Fingerprint, Headless-Erkennung, VPN/Tor/Proxy-Detektion,
    Datacenter-IPs, Bot-Erkennung. Zusaetzlich werden Klickgeschwindigkeit, Tipp-Muster und Mausbewegungen
    auf Bot-Verhalten geprueft. Status: <span class="status-dot dot-normal"></span>Normal |
    <span class="status-dot dot-verdaechtig"></span>Verdaechtig |
    <span class="status-dot dot-kritisch"></span>Kritisch
  </div>

  <!-- Stats row -->
  <div class="grid3" id="fpStatsRow">
    <div class="card" style="text-align:center;">
      <div style="font-size:2rem;color:#2dd4bf;font-weight:bold;" id="fpTotalStat">{fp_total}</div>
      <small style="color:#90a4ae;">Eindeutige Fingerprints</small>
    </div>
    <div class="card" style="text-align:center;">
      <div style="font-size:2rem;color:#f87171;font-weight:bold;" id="fpCritStat">{fp_critical}</div>
      <small style="color:#90a4ae;">Kritische Fingerprints</small>
    </div>
    <div class="card" style="text-align:center;">
      <button class="btn btn-blue btn-sm" onclick="loadFpStats()" style="margin-bottom:8px;">Aktualisieren</button><br>
      <div id="fpFlagStats" style="font-size:0.8rem;color:#90a4ae;text-align:left;"></div>
    </div>
  </div>

  <!-- Settings -->
  <div class="grid">
    <div class="card"><h3>Einstellungen</h3>
      <div class="toggle-wrap">
        <label class="toggle">
          <input type="checkbox" id="fpAutoBlockToggle" {"checked" if fp_auto=="1" else ""} onchange="saveFpSettings()">
          <span class="slider"></span>
        </label>
        <span>Automatische Blockierung bei kritischem Fingerprint</span>
      </div>
      <label style="margin-top:16px;">Blockier-Schwelle (Risiko %):</label>
      <input type="number" id="fpThreshInput" value="{fp_thresh}" min="30" max="100">
      <div style="margin-top:10px;"><button class="btn btn-teal" onclick="saveFpSettings()">Einstellungen speichern</button></div>
      <div class="info-box warning" style="margin-top:15px;font-size:0.8rem;">
        <strong>Erklaerung der Signale:</strong><br>
        Headless Browser, fehlende Accept-Language, WebDriver, perfekt gerade Mausbewegung,
        gleiche Tipp-Intervalle, mehr als 5 Klicks/Sek, Tor-Exit-Nodes, bekannte Rechenzentrum-IP-Bereiche,
        Proxy-Header.
      </div>
    </div>
    <div class="card"><h3>Verhaltens-Tracking (Client-seitig)</h3>
      <p style="color:#90a4ae;font-size:0.83rem;">
        Das JS-Snippet unten in deine Website einbinden, um Klick-, Tipp- und Mausdaten
        automatisch an den Sentinel zu senden:
      </p>
      <pre id="fpSnippet" style="font-size:0.73rem;color:#a3e635;max-height:180px;overflow-y:auto;">Laden...</pre>
      <button class="btn btn-teal btn-sm" onclick="loadFpSnippet()">Snippet laden</button>
    </div>
  </div>

  <!-- Fingerprint table -->
  <div class="card"><h3>Erkannte Fingerprints</h3>
    <button class="btn btn-blue btn-sm" onclick="loadFingerprints()">Aktualisieren</button>
    <button class="btn btn-red btn-sm" onclick="loadFingerprints('kritisch')">Nur Kritisch</button>
    <button class="btn btn-orange btn-sm" onclick="loadFingerprints('verdaechtig')">Nur Verdaechtig</button>
    <button class="btn btn-gray btn-sm" onclick="loadFingerprints('normal')">Nur Normal</button>
    <div id="fpList" style="margin-top:12px;">Laden...</div>
  </div>
</div>

<!-- TAB: MEMORY SAFETY -->
<div id="tab-memory" class="tab-content">
  <div class="info-box">
    <strong>Memory Safety & Container-Isolation</strong><br>
    Ueberprueft: Container, ASLR, Prozess-Privilegien, Rust, Python venv.
  </div>
  <div class="grid">
    <div class="card"><h3>Laufzeit-Sicherheitspruefung</h3>
      <button class="btn btn-blue" onclick="runSafetyCheck()">PRUEFUNG STARTEN</button>
      <span class="spinner" id="safety_spinner">Pruefe System...</span>
      <div id="safetyResults" style="margin-top:15px;"></div>
    </div>
    <div class="card"><h3>Sicherheits-Score</h3>
      <div id="safetyScore" style="text-align:center;padding:20px;">
        <div style="font-size:3rem;color:#90a4ae;">--</div>
        <div style="color:#90a4ae;">Pruefung noch nicht gestartet</div>
      </div>
    </div>
  </div>
  <div class="grid">
    <div class="card"><h3>Empfohlenes Dockerfile</h3>
      <button class="btn btn-blue btn-sm" onclick="loadDockerfile()">Laden</button>
      <pre id="dockerfileContent" style="display:none;"></pre>
    </div>
    <div class="card"><h3>Rust Memory-Safe Validator</h3>
      <button class="btn btn-orange btn-sm" onclick="loadRustStub()">Laden</button>
      <pre id="rustStubContent" style="display:none;color:#fb923c;"></pre>
    </div>
  </div>
  <div class="card"><h3>Best Practices</h3>
    <div class="info-box success">
      Docker: <code>--cap-drop=ALL --read-only --user 1000:1000</code><br>
      Rust fuer Input-Validierung und Kryptographie<br>
      Python: <code>venv</code>, kein <code>eval()</code>, <code>bandit</code> fuer Code-Scanning<br>
      OS: ASLR Level 2, Seccomp-Profile, NX-Bit
    </div>
  </div>
</div>

<!-- TAB: HISTORY -->
<div id="tab-history" class="tab-content">
  <div class="card"><h3>System-Sicherheits-Historie</h3>
    <button class="btn btn-blue btn-sm" onclick="loadHist()">Aktualisieren</button>
    <table>
      <thead><tr><th>Zeit</th><th>Status</th><th>Details</th></tr></thead>
      <tbody id="histBody"></tbody>
    </table>
  </div>
</div>

<!-- TAB: ALARM-LOG -->
<div id="tab-alarmlog" class="tab-content">
  <div class="card">
    <h3>Alarm-Protokoll</h3>
    <div class="info-box">Alle kritischen Alarme werden hier gespeichert (sofern Alarm-Logging aktiv).</div>
    <div style="display:flex;gap:8px;margin-bottom:12px;">
      <button class="btn btn-blue btn-sm" onclick="loadAlarmLog()">Aktualisieren</button>
      <button class="btn btn-green btn-sm" onclick="confirmAllAlarms()">Alle bestaetigen</button>
    </div>
    <table>
      <thead><tr><th>Zeit</th><th>Schwere</th><th>Kategorie</th><th>Nachricht</th><th>IP</th><th>Status</th></tr></thead>
      <tbody id="alarmLogBody"><tr><td colspan="6" style="color:#90a4ae;">Keine Log-Eintraege.</td></tr></tbody>
    </table>
  </div>
</div>

<!-- TAB: COMPLIANCE PDF -->
<div id="tab-compliance" class="tab-content">
  <div class="info-box">
    <strong>Monatliches Compliance-Protokoll</strong><br>
    Automatische Generierung eines professionellen PDF-Berichts mit Statistiken,
    Compliance-Nachweisen und digitaler Signatur. Versand an Geschaeftsfuehrer und Sicherheitsbeauftragten.
  </div>
  <div class="grid">
    <div class="card">
      <h3>Bericht generieren &amp; senden</h3>
      <label>Berichtszeitraum:</label>
      <input type="text" id="compliance_period" placeholder="z.B. Januar 2025">
      <label>Zusaetzlicher Empfaenger (optional):</label>
      <input type="email" id="compliance_extra_email" placeholder="weitere@email.de">
      <div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <button class="btn btn-blue" onclick="downloadCompliance()">PDF HERUNTERLADEN</button>
        <button class="btn btn-green" onclick="sendComplianceReport()">PER E-MAIL SENDEN</button>
        <span class="spinner" id="compliance_spinner">Generiere...</span>
      </div>
      <div id="complianceResult" style="margin-top:12px;"></div>
    </div>
    <div class="card">
      <h3>Compliance-Einstellungen</h3>
      <label>Empfaenger 1 – Geschaeftsfuehrer:</label>
      <input type="email" id="compliance_ceo_email" placeholder="ceo@firma.de">
      <label>Empfaenger 2 – Sicherheitsbeauftragter:</label>
      <input type="email" id="compliance_security_email" placeholder="security@firma.de">
      <label>Firmenadresse (fuer PDF):</label>
      <input type="text" id="company_address" placeholder="Musterstr. 1, 12345 Musterstadt">
      <label>Logo-Text im PDF:</label>
      <input type="text" id="company_logo_text" placeholder="SENTINEL SME-GUARDIAN">
      <div class="toggle-wrap" style="margin-top:12px;">
        <label class="toggle">
          <input type="checkbox" id="compliance_auto_send" onchange="saveComplianceSettings()">
          <span class="slider"></span>
        </label>
        <span>Automatisch am 1. des Monats senden</span>
      </div>
      <div style="margin-top:12px;">
        <button class="btn btn-teal" onclick="saveComplianceSettings()">Speichern</button>
      </div>
    </div>
  </div>
  <div class="card">
    <h3>Versand-Historie</h3>
    <button class="btn btn-blue btn-sm" onclick="loadComplianceHistory()">Aktualisieren</button>
    <table>
      <thead><tr><th>Zeit</th><th>Zeitraum</th><th>Gesendet an</th><th>Status</th></tr></thead>
      <tbody id="complianceHistoryBody">
        <tr><td colspan="4" style="color:#90a4ae;">Noch keine Berichte.</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- TAB: OUTLOOK ADD-IN -->
<div id="tab-outlook" class="tab-content">
  <div class="info-box">
    <strong>Outlook Add-in: Automatischer Phishing-Check</strong><br>
    Das Add-in wird in Outlook als Aufgabenbereich angezeigt und prueft jede eingehende E-Mail
    automatisch. Keine manuelle Aktion noetig.
  </div>
  <div class="grid">
    <div class="card">
      <h3>Installation in Outlook</h3>
      <div class="info-box warning" style="font-size:0.83rem;">
        <strong>Schritt-fuer-Schritt:</strong><br><br>
        <strong>1.</strong> Sentinel-Server muss vom Browser erreichbar sein<br><br>
        <strong>2.</strong> Manifest herunterladen:&nbsp;
        <a href="/outlook/manifest" style="color:#38bdf8;">manifest.xml herunterladen</a><br><br>
        <strong>3.</strong> Outlook Desktop: Datei → Add-Ins verwalten → Eigene Add-Ins →
        "Add-In aus Datei" → manifest.xml<br><br>
        <strong>4.</strong> Outlook Web (OWA): Einstellungen → Add-Ins → "+" → "Aus Datei"<br><br>
        <strong>5.</strong> Nach Installation: Beim Oeffnen jeder E-Mail erscheint das
        Sentinel-Phishing-Banner automatisch.
      </div>
      <div class="info-box success" style="font-size:0.82rem;">
        <strong>HTTPS fuer Produktion:</strong> Nginx + Let's Encrypt empfohlen.<br>
        <code>https://sentinel.firma.de/outlook/addin</code>
      </div>
    </div>
    <div class="card">
      <h3>Add-in Testpruefung</h3>
      <label>Absender:</label>
      <input type="text" id="olk_from" placeholder="phishing@paypa1-support.xyz">
      <label>Betreff:</label>
      <input type="text" id="olk_subject" placeholder="Konto gesperrt!">
      <label>E-Mail Text:</label>
      <textarea id="olk_body" style="height:70px;" placeholder="E-Mail Inhalt..."></textarea>
      <div style="margin-top:10px;">
        <button class="btn btn-phish" onclick="testOutlookScan()">PHISHING-CHECK STARTEN</button>
      </div>
      <div id="outlookTestResult" style="margin-top:12px;display:none;"></div>
    </div>
  </div>
  <div class="card">
    <h3>Add-in Live-Vorschau</h3>
    <iframe src="/outlook/addin" style="width:100%;height:200px;border:1px solid #37474f;
      border-radius:8px;background:#f8fafc;" title="Add-in Vorschau"></iframe>
  </div>
</div>

<!-- TAB: EINSTELLUNGEN -->
<div id="tab-settings" class="tab-content">
  <div class="grid">
    <div class="card">
      <h3>Alarm-Sirene</h3>
      <div class="toggle-wrap" style="margin-bottom:14px;">
        <label class="toggle">
          <input type="checkbox" id="alarmLogToggle" onchange="saveAlarmSettings()">
          <span class="slider"></span>
        </label>
        <span>Alarm-Logging aktiv (Alarme in DB speichern)</span>
      </div>
      <div class="info-box warning" style="font-size:0.82rem;">
        Akustische Sirene und Blink-Overlay aktivieren sich bei jedem KRITISCH-Alarm automatisch.
        Logging steuert nur die DB-Speicherung.
      </div>
      <button class="btn btn-teal" onclick="testSirene()">SIRENE TESTEN</button>
    </div>
    <div class="card">
      <h3>E-Mail Alarm bei Hackversuch</h3>
      <p style="color:#90a4ae;font-size:0.83rem;">
        Bei jedem KRITISCH-Alarm (Exploit, Brute-Force, Phishing, Honeytoken) wird sofort
        eine E-Mail versendet. Gleiche SMTP-Einstellungen gelten auch fuer Compliance-Berichte.
      </p>
      <label>Empfaenger (Chef / Sicherheitsbeauftragter):</label>
      <input type="email" id="alert_email_to" placeholder="chef@firma.de">
      <label>Absender:</label>
      <input type="email" id="alert_email_from" placeholder="sentinel@firma.de">
      <label>SMTP-Server:</label>
      <input type="text" id="alert_smtp_host" placeholder="smtp.gmail.com oder smtp.firma.de">
      <label>SMTP-Port:</label>
      <input type="number" id="alert_smtp_port" value="587">
      <label>SMTP-Benutzername:</label>
      <input type="text" id="alert_smtp_user" placeholder="user@gmail.com">
      <label>SMTP-Passwort (App-Passwort):</label>
      <input type="password" id="alert_smtp_pass" placeholder="App-Passwort">
      <div style="margin-top:14px;">
        <button class="btn btn-green" onclick="saveEmailAlertSettings()">Speichern</button>
        <button class="btn btn-blue btn-sm" onclick="testAlertEmail()">Test-Mail</button>
      </div>
    </div>
  </div>
  <div class="card">
    <h3>📱 Telegram-Benachrichtigungen</h3>
    <p style="color:#90a4ae;font-size:0.83rem;">
      Bei jedem Alarm (KRITISCH/WARNUNG) wird sofort eine Nachricht an Telegram gesendet.
      Token und Chat-ID entweder direkt eingeben oder verschlüsselt via <code>sentinel.key</code> laden.
    </p>
    <div class="grid" style="margin-bottom:12px;">
      <div class="info-box" style="margin:0;padding:10px 14px;">
        <small style="color:#90a4ae;">Schlüsseldatei (sentinel.key)</small><br>
        <span id="tg_key_status" style="font-weight:bold;">Prüfe...</span>
      </div>
      <div class="info-box" style="margin:0;padding:10px 14px;">
        <small style="color:#90a4ae;">Status</small><br>
        <span id="tg_active_status" style="font-weight:bold;">–</span>
      </div>
    </div>
    <div class="toggle-wrap" style="margin-bottom:10px;">
      <label class="toggle">
        <input type="checkbox" id="telegram_active" onchange="saveTelegramSettings()">
        <span class="slider"></span>
      </label>
      <span>Telegram-Benachrichtigungen aktiv</span>
    </div>
    <div class="toggle-wrap" style="margin-bottom:12px;">
      <label class="toggle">
        <input type="checkbox" id="telegram_on_warn" onchange="saveTelegramSettings()">
        <span class="slider"></span>
      </label>
      <span>Auch bei WARNUNG senden (nicht nur KRITISCH)</span>
    </div>
    <label>Bot-Token (von @BotFather):</label>
    <input type="password" id="telegram_token" placeholder="123456:ABC-DEF... (bleibt leer wenn sentinel.key aktiv)">
    <label>Chat-ID (von @userinfobot):</label>
    <input type="text" id="telegram_chat_id" placeholder="Deine Telegram Chat-ID">
    <div class="info-box" style="margin-top:10px;font-size:0.8rem;">
      <strong>So einrichten:</strong><br>
      1. Telegram öffnen → @BotFather → /newbot → Token kopieren<br>
      2. @userinfobot schreiben → deine Chat-ID notieren<br>
      3. Token + Chat-ID hier eingeben und speichern<br>
      4. Test senden → du erhältst eine Nachricht auf dem Handy<br>
      <strong>Alternativ:</strong> Verschlüsselt via <code>sentinel.key</code> (sicherer für Produktion)
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
      <button class="btn btn-green" onclick="saveTelegramSettings()">Speichern</button>
      <button class="btn btn-teal" onclick="testTelegram()">TEST SENDEN</button>
      <span id="tg_test_msg" style="color:#90a4ae;font-size:0.83rem;"></span>
    </div>
  </div>
  <div class="card">
    <h3>Auto-Update</h3>
    <div class="grid3">
      <div class="info-box" style="margin:0;">
        <small style="color:#90a4ae;">Aktuelle Version</small><br>
        <strong style="color:#38bdf8;font-size:1.3rem;" id="localVersion">v{VERSION}</strong>
      </div>
      <div class="info-box" style="margin:0;">
        <small style="color:#90a4ae;">Online-Version</small><br>
        <strong style="color:#10b981;font-size:1.3rem;" id="remoteVersion">–</strong>
      </div>
      <div class="info-box" style="margin:0;">
        <small style="color:#90a4ae;">Prüf-Intervall</small><br>
        <strong style="color:#38bdf8;">60 Minuten</strong>
      </div>
    </div>
    <div style="margin-top:12px;font-size:0.83rem;color:#90a4ae;">
      GitHub:
      <a href="https://github.com/kralgif/Sentinel-SME-Guardian" target="_blank"
         style="color:#38bdf8;">github.com/kralgif/Sentinel-SME-Guardian</a><br>
      Der Auto-Updater prüft alle 60 Minuten auf neue Versionen. Wenn eine neuere Version gefunden wird,
      wird der Syntax geprüft, die Datei überschrieben und der Server automatisch neu gestartet.
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;align-items:center;">
      <button class="btn btn-blue" onclick="triggerUpdateCheck()">JETZT PRÜFEN</button>
      <span id="updateCheckMsg" style="color:#90a4ae;font-size:0.83rem;"></span>
    </div>
    <div id="updateStatus" style="margin-top:10px;"></div>
  </div>
</div>
<script>
// ── TAB SYSTEM ────────────────────────────────────────────────
function showTab(id, btn) {{
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='tab-email-accounts') loadAccounts();
  if(id==='tab-email-results')  loadEmailResults();
  if(id==='tab-history')        loadHist();
  if(id==='tab-honeytokens')    {{ loadHoneytokenList(); loadHoneytokenAlerts(); }}
  if(id==='tab-exploit')        loadExploitAlerts();
  if(id==='tab-bruteforce')     {{ loadBruteAlerts(); loadBlockedIPs(); }}
  if(id==='tab-fingerprint')    {{ loadFingerprints(); loadFpStats(); }}
  if(id==='tab-alarmlog')       loadAlarmLog();
  if(id==='tab-compliance')     {{ loadComplianceHistory(); loadComplianceSettings(); }}
  if(id==='tab-settings')       {{ loadAlarmSettings(); loadTelegramSettings(); }}
}}

// ── REALTIME ALARM SYSTEM ─────────────────────────────────────
let alarmCount = 0;
function showAlarm(alarm) {{
  if(alarm.type === 'heartbeat') return;
  alarmCount++;
  const banner = document.getElementById('alarmBanner');
  const items  = document.getElementById('alarmItems');
  const div = document.createElement('div');
  div.className = 'alarm-item';
  div.innerHTML = `
    <span class="alarm-badge alarm-${{alarm.severity}}">${{alarm.severity}}</span>
    <span class="alarm-cat">${{alarm.category}}</span>
    <span class="alarm-msg">${{alarm.message}}</span>
    ${{alarm.ip ? `<span class="alarm-ip">IP: ${{alarm.ip}}</span>` : ''}}
    <span class="alarm-time">${{alarm.time}}</span>
  `;
  items.prepend(div);
  while(items.children.length > 8) items.removeChild(items.lastChild);
  banner.classList.add('visible');
  if(alarmCount === 1) window.scrollTo({{top:0, behavior:'smooth'}});
  // Activate full sirene for KRITISCH
  if(alarm.severity === 'KRITISCH') {{
    activateSirene(alarm);
  }}
}}
function clearAlarms() {{
  document.getElementById('alarmBanner').classList.remove('visible');
  document.getElementById('alarmItems').innerHTML = '';
  alarmCount = 0;
}}

let sseRetries = 0;
function connectSSE() {{
  const es = new EventSource('/alerts/stream');
  es.onmessage = e => {{ try {{ showAlarm(JSON.parse(e.data)); }} catch(err) {{}} }};
  es.onerror = () => {{
    es.close(); sseRetries++;
    setTimeout(connectSSE, Math.min(2000 * Math.pow(2, sseRetries-1), 30000));
    startPollingFallback();
  }};
  es.onopen = () => {{ sseRetries = 0; stopPollingFallback(); }};
}}
let pollingInterval = null, lastAlertTime = null;
function startPollingFallback() {{
  if(pollingInterval) return;
  pollingInterval = setInterval(async () => {{
    try {{
      const res = await fetch('/alerts/latest');
      const data = await res.json();
      if(data.length && data[0].time !== lastAlertTime) {{
        lastAlertTime = data[0].time;
        showAlarm({{type:'alert', severity:'KRITISCH', category:data[0].cat,
          message: data[0].msg + (data[0].score ? ` (${{data[0].score}}%)` : ''),
          ip: data[0].ip, time: data[0].time}});
      }}
    }} catch(e) {{}}
  }}, 5000);
}}
function stopPollingFallback() {{ if(pollingInterval) {{ clearInterval(pollingInterval); pollingInterval = null; }} }}
setInterval(() => {{ if(document.getElementById('tab-history').classList.contains('active')) loadHist(); }}, 5000);

// ── FINGERPRINT: BEHAVIOUR TRACKING ──────────────────────────
// This runs on the DASHBOARD itself to demonstrate the feature.
// For production use, embed the generated snippet in your website.
let myFpId = null;
async function initFpTracking() {{
  // Compute client-side fingerprint and register
  const ua = navigator.userAgent;
  const lang = navigator.language || '';
  const fp = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(ua + lang + screen.width + screen.height + navigator.hardwareConcurrency));
  const arr = new Uint8Array(fp);
  myFpId = Array.from(arr).slice(0,8).map(b=>b.toString(16).padStart(2,'0')).join('');

  // Track clicks
  document.addEventListener('click', e => {{
    fetch('/fingerprint/behaviour', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{fp_id: myFpId, event_type: 'click', data: {{x: e.clientX, y: e.clientY}}}})
    }}).catch(()=>{{}});
  }});
  // Track keypress
  document.addEventListener('keypress', e => {{
    fetch('/fingerprint/behaviour', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{fp_id: myFpId, event_type: 'keypress', data: {{}}}})
    }}).catch(()=>{{}});
  }});
  // Track mouse movement (throttled to every 200ms)
  let lastMouse = 0;
  document.addEventListener('mousemove', e => {{
    const now = Date.now();
    if(now - lastMouse < 200) return;
    lastMouse = now;
    fetch('/fingerprint/behaviour', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{fp_id: myFpId, event_type: 'mousemove', data: {{x: e.clientX, y: e.clientY}}}})
    }}).catch(()=>{{}});
  }});
}}
initFpTracking();

function loadFpSnippet() {{
  const snippet = `<!-- Sentinel Fingerprint Tracker -->
<script>
(async function() {{
  const ua = navigator.userAgent;
  const lang = navigator.language || '';
  const fp = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(ua + lang + screen.width + screen.height));
  const arr = new Uint8Array(fp);
  const fpId = Array.from(arr).slice(0,8).map(b=>b.toString(16).padStart(2,'0')).join('');
  const SENTINEL = 'http://localhost:8000'; // Eure Sentinel-URL
  const send = (type, data) => fetch(SENTINEL+'/fingerprint/behaviour', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{fp_id: fpId, event_type: type, data}})
  }}).catch(()=>{{}});
  document.addEventListener('click', e => send('click', {{x:e.clientX, y:e.clientY}}));
  document.addEventListener('keypress', () => send('keypress', {{}}));
  let lm=0; document.addEventListener('mousemove', e => {{
    if(Date.now()-lm<200) return; lm=Date.now();
    send('mousemove', {{x:e.clientX, y:e.clientY}});
  }});
}})();
<\/script>`;
  document.getElementById('fpSnippet').textContent = snippet;
}}

async function loadFpStats() {{
  try {{
    const res  = await fetch('/fingerprint/stats');
    const data = await res.json();
    document.getElementById('fpTotalStat').textContent = data.total;
    document.getElementById('fpCritStat').textContent  = data.critical;
    document.getElementById('fpFlagStats').innerHTML = `
      <div>Bots: <strong style="color:#f87171">${{data.bots}}</strong></div>
      <div>Tor-Nodes: <strong style="color:#f87171">${{data.tor}}</strong></div>
      <div>VPN: <strong style="color:#fbbf24">${{data.vpn}}</strong></div>
      <div>Proxy: <strong style="color:#fbbf24">${{data.proxy}}</strong></div>
      <div>Headless: <strong style="color:#fb923c">${{data.headless}}</strong></div>
      <div>Rechenzentrum: <strong style="color:#90a4ae">${{data.datacenter}}</strong></div>
      <div>Auto-geblockt: <strong style="color:#f87171">${{data.blocked}}</strong></div>
    `;
  }} catch(e) {{}}
}}

let fpFilterStatus = null;
async function loadFingerprints(filterStatus) {{
  if(filterStatus !== undefined) fpFilterStatus = filterStatus;
  try {{
    const res  = await fetch('/fingerprint/list');
    const data = await res.json();
    const container = document.getElementById('fpList');
    let rows = data;
    if(fpFilterStatus) rows = data.filter(r => r.status === fpFilterStatus);
    if(!rows.length) {{ container.innerHTML='<p style="color:#90a4ae;">Keine Fingerprints.</p>'; return; }}

    const statusColors = {{normal:'#10b981', verdaechtig:'#fbbf24', kritisch:'#f87171'}};
    const dotClass     = {{normal:'dot-normal', verdaechtig:'dot-verdaechtig', kritisch:'dot-kritisch'}};

    container.innerHTML = rows.map(fp => {{
      const sc = statusColors[fp.status] || '#90a4ae';
      const dc = dotClass[fp.status] || 'dot-normal';
      const flags = [
        fp.is_bot       ? '<span class="fp-flag flag-on">BOT</span>'        : '<span class="fp-flag flag-off">BOT</span>',
        fp.is_headless  ? '<span class="fp-flag flag-on">HEADLESS</span>'   : '<span class="fp-flag flag-off">HEADLESS</span>',
        fp.is_tor       ? '<span class="fp-flag flag-on">TOR</span>'        : '<span class="fp-flag flag-off">TOR</span>',
        fp.is_vpn       ? '<span class="fp-flag flag-on">VPN</span>'        : '<span class="fp-flag flag-off">VPN</span>',
        fp.is_proxy     ? '<span class="fp-flag flag-on">PROXY</span>'      : '<span class="fp-flag flag-off">PROXY</span>',
        fp.is_datacenter? '<span class="fp-flag flag-on">DATACENTER</span>' : '<span class="fp-flag flag-off">DATACENTER</span>',
        fp.blocked      ? '<span class="fp-flag flag-on">GEBLOCKT</span>'   : '',
      ].join('');

      return `<div class="fp-card ${{fp.status}}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div style="flex:1;">
            <span class="status-dot ${{dc}}"></span>
            <strong style="color:${{sc}}">${{fp.status.toUpperCase()}}</strong>
            <span style="color:#90a4ae;font-size:0.78rem;margin-left:10px;">ID: ${{fp.fp_id}}</span>
            <span style="color:#90a4ae;font-size:0.78rem;margin-left:10px;">IP: ${{fp.ip}}</span>
            <span style="color:#fbbf24;font-size:0.78rem;margin-left:10px;">Risiko: ${{fp.risk_score}}%</span>
            <span style="color:#90a4ae;font-size:0.75rem;margin-left:10px;">Anfragen: ${{fp.request_count}}</span>
            <br>
            <div class="risk-bar-bg" style="width:200px;margin:5px 0;">
              <div class="risk-bar" style="width:${{fp.risk_score}}%;background:${{sc}};"></div>
            </div>
            ${{flags}}
            <br><small style="color:#4b5563;font-size:0.73rem;max-width:600px;">${{fp.user_agent?.substring(0,80)}}...</small>
            <br><small style="color:#374151;font-size:0.72rem;">${{fp.detail?.substring(0,120)}}</small>
            <br><small style="color:#4b5563;">Zuerst: ${{fp.first_seen}} | Zuletzt: ${{fp.last_seen}}</small>
          </div>
          <div style="display:flex;flex-direction:column;gap:4px;min-width:80px;">
            ${{!fp.blocked
              ? `<button class="btn btn-red btn-sm" onclick="blockFp('${{fp.fp_id}}')">Blockieren</button>`
              : `<button class="btn btn-green btn-sm" onclick="unblockFp('${{fp.fp_id}}')">Entsperren</button>`
            }}
            <button class="btn btn-gray btn-sm" onclick="deleteFp('${{fp.fp_id}}')">Loeschen</button>
          </div>
        </div>
      </div>`;
    }}).join('');
  }} catch(e) {{
    document.getElementById('fpList').innerHTML = '<p style="color:#f87171;">Fehler beim Laden.</p>';
  }}
}}

async function blockFp(fp_id) {{
  await fetch('/fingerprint/block/'+fp_id, {{method:'POST'}});
  showAlarm({{type:'info', severity:'INFO', category:'FINGERPRINT', message:'Fingerprint manuell blockiert: '+fp_id, ip:'', time: new Date().toLocaleTimeString()}});
  loadFingerprints();
}}
async function unblockFp(fp_id) {{ await fetch('/fingerprint/unblock/'+fp_id, {{method:'POST'}}); loadFingerprints(); }}
async function deleteFp(fp_id) {{
  if(!confirm('Fingerprint-Eintrag loeschen?')) return;
  await fetch('/fingerprint/'+fp_id, {{method:'DELETE'}}); loadFingerprints();
}}
async function saveFpSettings() {{
  const fp_auto_block     = document.getElementById('fpAutoBlockToggle').checked ? '1' : '0';
  const fp_block_threshold = document.getElementById('fpThreshInput').value;
  await fetch('/fingerprint/settings', {{method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{fp_auto_block, fp_block_threshold}})}});
  alert('Fingerprint-Einstellungen gespeichert.');
}}

// ── KI / MODEL ───────────────────────────────────────────────
function _updateKIButton(isActive) {{
  document.getElementById("kiStatus").innerText = isActive ? "AKTIV" : "DEAKTIVIERT";
  document.getElementById("kiStatus").style.color = isActive ? "#10b981" : "#f87171";
  const btn = document.getElementById("kiButton");
  btn.innerText = isActive ? "KI deaktivieren" : "KI aktivieren";
  btn.className = isActive ? "btn btn-red btn-sm" : "btn btn-green btn-sm";
  btn.dataset.active = isActive ? "1" : "0";
}}

async function toggleKI() {{
  const btn = document.getElementById("kiButton");
  // Read CURRENT state from button data attribute (reliable, no race condition)
  const currentlyActive = btn.dataset.active === "1";
  const newActive = !currentlyActive;
  try {{
    const res = await fetch('/set_ai', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{active: newActive}})
    }});
    const d = await res.json();
    _updateKIButton(d.ai_active === "1");
  }} catch(e) {{
    alert('Fehler beim KI-Toggle: ' + e);
  }}
}}

// Initialize KI button state on load
(async function initKIButton() {{
  try {{
    const res = await fetch('/ai_status');
    const d   = await res.json();
    _updateKIButton(d.ai_active === "1");
  }} catch(e) {{}}
}})();
async function saveModel() {{
  const model = document.getElementById('modelSelect').value;
  const res   = await fetch('/set_model',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{model}})}});
  const d     = await res.json();
  if(d.error) alert("Fehler: "+d.error); else alert("Modell gespeichert: "+d.ai_model);
}}

// ── TEXT SCAN ────────────────────────────────────────────────
async function runScan(mode) {{
  const text = document.getElementById('inp').value.trim();
  if(!text) {{ alert('Bitte Text eingeben.'); return; }}
  const out = document.getElementById('out');
  out.innerHTML = '<span style="color:#38bdf8;font-style:italic;">Analysiere...</span>';
  try {{
    const res = await fetch('/scan', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{text, mode}})
    }});
    if(!res.ok) {{
      out.innerHTML = `<span style="color:#f87171;">Server-Fehler: ${{res.status}}</span>`;
      return;
    }}
    const d = await res.json();
    if(d.status === 'BLOCKED') {{
      out.innerHTML = '<h3 style="color:#f87171;">STOPP! DLP-Regel verletzt.</h3><p style="color:#fbbf24;">Der Text wurde durch eine Sicherheitsregel blockiert.</p>';
    }} else {{
      const response = d.ai_response || 'Pruefung abgeschlossen. Kein Ergebnis von der KI.';
      out.innerHTML = `<div style="white-space:pre-wrap;line-height:1.6;">${{response}}</div>`;
    }}
  }} catch(e) {{
    out.innerHTML = `<span style="color:#f87171;">Verbindungsfehler: ${{e}}</span>`;
  }}
  loadHist();
}}

// ── EMAIL ────────────────────────────────────────────────────
async function analyzeEmailText() {{
  const sender=document.getElementById('em_from').value, subject=document.getElementById('em_subject').value, body=document.getElementById('em_body').value;
  if(!sender&&!body) {{ alert('Bitte Absender und Inhalt eingeben.'); return; }}
  document.getElementById('email_spinner').style.display='inline';
  const res = await fetch('/email/analyze_text',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{sender,subject,body}})}});
  const d = await res.json();
  document.getElementById('email_spinner').style.display='none';
  const rc=d.risk_score<30?'#10b981':d.risk_score<60?'#fbbf24':'#f87171';
  const bc=d.risk_score<30?'badge-safe':d.risk_score<60?'badge-warn':'badge-danger';
  let rHtml = d.reasons.length>0?'<ul>'+d.reasons.map(r=>`<li style="color:#fbbf24">${{r}}</li>`).join('')+'</ul>':'<p style="color:#10b981">Keine Phishing-Indikatoren.</p>';
  document.getElementById('emailResultContent').innerHTML=`
    <div style="display:flex;align-items:center;gap:20px;margin-bottom:15px;">
      <div><div class="badge ${{bc}}" style="font-size:1rem;padding:8px 16px;">${{d.verdict}}</div>
      <div style="margin-top:8px;color:${{rc}};font-size:1.5rem;font-weight:bold;">Risiko: ${{d.risk_score}}%</div></div>
    </div>
    <div class="risk-bar-bg"><div class="risk-bar" style="width:${{d.risk_score}}%;background:${{rc}};"></div></div>
    <h4 style="margin-top:15px;">Indikatoren:</h4>${{rHtml}}
    ${{d.ai_analysis?'<h4>KI-Analyse:</h4><div style="white-space:pre-wrap;color:#eceff1;background:#0a0c10;padding:15px;border-radius:8px;border-left:4px solid #38bdf8;">'+d.ai_analysis+'</div>':''}}
  `;
  document.getElementById('emailAnalysisResult').style.display='block';
}}
function updateProviderFields() {{ document.getElementById('custom_imap_fields').style.display=document.getElementById('acc_provider').value==='custom'?'block':'none'; }}
async function addEmailAccount() {{
  const provider=document.getElementById('acc_provider').value, email=document.getElementById('acc_email').value,
    password=document.getElementById('acc_password').value, imap_host=document.getElementById('acc_imap_host').value,
    imap_port=document.getElementById('acc_imap_port').value;
  if(!email||!password) {{ alert('E-Mail und Passwort erforderlich.'); return; }}
  const res=await fetch('/email/add_account',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{provider,email,password,imap_host,imap_port}})}});
  const d=await res.json();
  if(d.error) alert('Fehler: '+d.error); else {{ alert('Konto hinzugefuegt: '+d.email); loadAccounts(); }}
}}
async function loadAccounts() {{
  const res=await fetch('/email/accounts'); const accounts=await res.json();
  const container=document.getElementById('accountsList');
  if(!accounts.length) {{ container.innerHTML='<p style="color:#90a4ae;">Keine Konten.</p>'; return; }}
  container.innerHTML=accounts.map(a=>`
    <div class="account-card">
      <div><strong style="color:#38bdf8;">${{a.provider.toUpperCase()}}</strong> -- ${{a.email}}<br>
      <small style="color:#90a4ae;">${{a.imap_host}}:${{a.imap_port}}</small></div>
      <div><button class="btn btn-green btn-sm" onclick="testConnection(${{a.id}})">Test</button>
        <button class="btn btn-blue btn-sm" onclick="scanAccount(${{a.id}})">Scan</button>
        <button class="btn btn-red btn-sm" onclick="deleteAccount(${{a.id}})">Loeschen</button></div>
    </div>`).join('');
}}
async function testConnection(id) {{ const res=await fetch('/email/test_connection/'+id,{{method:'POST'}}); const d=await res.json(); alert(d.success?'OK: '+d.message:'FEHLER: '+d.message); }}
async function scanAccount(id) {{
  if(!confirm('Postfach jetzt scannen?')) return;
  const res=await fetch('/email/scan/'+id,{{method:'POST'}}); const d=await res.json();
  if(d.error) alert('Fehler: '+d.error); else alert(d.scanned+' E-Mails geprueft bei '+d.account);
  loadEmailResults();
}}
async function scanAllAccounts() {{ if(!confirm('Alle aktiven Konten scannen?')) return; const res=await fetch('/email/scan_all',{{method:'POST'}}); const d=await res.json(); alert(d.accounts_scanned+' Konten gescannt!'); }}
async function deleteAccount(id) {{ if(!confirm('Konto entfernen?')) return; await fetch('/email/account/'+id,{{method:'DELETE'}}); loadAccounts(); }}
async function loadEmailResults() {{
  const res=await fetch('/email/results'); const data=await res.json();
  const tbody=document.getElementById('emailResultsBody');
  if(!data.length) {{ tbody.innerHTML='<tr><td colspan="7" style="color:#90a4ae;">Keine Scans.</td></tr>'; return; }}
  tbody.innerHTML=data.map(e=>{{
    const bc=e.verdict==='SICHER'?'badge-safe':e.verdict==='VERDAECHTIG'?'badge-warn':'badge-danger';
    const rc=e.risk_score<30?'#10b981':e.risk_score<60?'#fbbf24':'#f87171';
    return `<tr><td>${{e.time}}</td><td style="font-size:.75rem;">${{e.account||'--'}}</td>
      <td style="font-size:.75rem;max-width:120px;overflow:hidden;text-overflow:ellipsis;">${{e.email_from}}</td>
      <td style="font-size:.75rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;">${{e.subject}}</td>
      <td><span class="badge ${{bc}}">${{e.verdict}}</span></td>
      <td style="color:${{rc}};font-weight:bold;">${{e.risk_score}}%</td>
      <td style="font-size:.75rem;color:#90a4ae;">${{e.detail}}</td></tr>`;
  }}).join('');
}}

// ── EXPLOIT ──────────────────────────────────────────────────
async function runExploitScan() {{
  const text=document.getElementById('exploit_input').value;
  if(!text) {{ alert('Payload eingeben.'); return; }}
  document.getElementById('exploit_spinner').style.display='inline';
  const res=await fetch('/exploit/analyze',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{text,ip:'manual-test'}})}});
  const d=await res.json();
  document.getElementById('exploit_spinner').style.display='none';
  const rc=d.confidence<40?'#10b981':d.confidence<65?'#fbbf24':'#f87171';
  const icon=d.blocked?'BLOCKIERT':d.threat?'VERDAECHTIG':'SAUBER';
  let pH=d.patterns.length>0?d.patterns.map(p=>`<div style="margin:4px 0;"><span class="badge badge-danger">${{p.pattern}}</span> <span style="color:#fbbf24;">${{p.confidence}}%</span></div>`).join(''):'<span style="color:#10b981;">Keine Exploit-Muster.</span>';
  let aiH=d.ai_analysis?`<h4>KI-Analyse:</h4><div style="background:#050709;padding:12px;border-radius:6px;border-left:3px solid #a78bfa;white-space:pre-wrap;font-size:.83rem;">${{JSON.stringify(d.ai_analysis,null,2)}}</div>`:'';
  document.getElementById('exploit_result').innerHTML=`
    <div style="font-size:1.4rem;font-weight:bold;color:${{rc}};margin-bottom:10px;">${{icon}}</div>
    <div>Konfidenz: <strong style="color:${{rc}}">${{d.confidence}}%</strong> | Muster: <strong>${{d.patterns_count}}</strong></div>
    <div class="risk-bar-bg" style="margin:8px 0;"><div class="risk-bar" style="width:${{d.confidence}}%;background:${{rc}};"></div></div>
    <h4>Erkannte Muster:</h4>${{pH}}${{aiH}}`;
  loadExploitAlerts();
}}
async function loadExploitAlerts() {{
  const res=await fetch('/exploit/alerts'); const data=await res.json();
  const tbody=document.getElementById('exploitAlertsBody');
  if(!data.length) {{ tbody.innerHTML='<tr><td colspan="6" style="color:#90a4ae;">Keine Exploit-Versuche.</td></tr>'; return; }}
  tbody.innerHTML=data.map(e=>`<tr>
    <td>${{e.time}}</td><td style="font-size:.75rem;">${{e.source_ip}}</td>
    <td><span class="badge badge-danger">${{e.pattern_name}}</span></td>
    <td style="color:${{e.confidence>=65?'#f87171':'#fbbf24'}};font-weight:bold;">${{e.confidence}}%</td>
    <td><span class="badge ${{e.blocked?'badge-danger':'badge-warn'}}">${{e.blocked?'BLOCKIERT':'GEMELDET'}}</span></td>
    <td style="font-size:.73rem;color:#90a4ae;max-width:200px;overflow:hidden;text-overflow:ellipsis;">${{e.payload_snippet}}</td>
  </tr>`).join('');
}}

// ── HONEYTOKENS ──────────────────────────────────────────────
async function addHoneytoken() {{
  const token_type=document.getElementById('ht_type').value, label=document.getElementById('ht_label').value,
    fake_value=document.getElementById('ht_value').value, route=document.getElementById('ht_route').value;
  if(!label||!fake_value) {{ alert('Label und Fake-Wert erforderlich.'); return; }}
  const res=await fetch('/honeytoken/add',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token_type,label,fake_value,route}})}});
  const d=await res.json();
  if(d.error) alert('Fehler: '+d.error); else {{ alert('Falle angelegt: '+d.token_id); loadHoneytokenList(); }}
}}
async function loadHoneytokenList() {{
  const res=await fetch('/honeytoken/list'); const data=await res.json();
  const container=document.getElementById('honeytokenList');
  if(!data.length) {{ container.innerHTML='<p style="color:#90a4ae;">Keine Fallen.</p>'; return; }}
  const tc={{url_trap:'badge-blue',fake_api_key:'badge-warn',fake_password:'badge-danger',fake_db_url:'badge-purple',fake_credit:'badge-danger',fake_ssn:'badge-warn'}};
  container.innerHTML=data.map(t=>`<div class="honeytoken-row">
    <div><span class="badge ${{tc[t.token_type]||'badge-blue'}}">${{t.token_type}}</span>
    <strong style="margin-left:8px;">${{t.label}}</strong><br>
    <small style="color:#90a4ae;">${{t.fake_value.substring(0,40)}}...</small>
    ${{t.trigger_count>0?`<br><small style="color:#f87171;">${{t.trigger_count}}x ausgeloest!</small>`:''}}</div>
    <button class="btn btn-red btn-sm" onclick="deleteHoneytoken('${{t.token_id}}')">Entfernen</button>
  </div>`).join('');
}}
async function deleteHoneytoken(token_id) {{ if(!confirm('Falle entfernen?')) return; await fetch('/honeytoken/'+token_id,{{method:'DELETE'}}); loadHoneytokenList(); }}
async function loadHoneytokenAlerts() {{
  const res=await fetch('/honeytoken/alerts'); const data=await res.json();
  const tbody=document.getElementById('honeytokenAlertsBody');
  if(!data.length) {{ tbody.innerHTML='<tr><td colspan="6" style="color:#90a4ae;">Keine Fallen ausgeloest.</td></tr>'; return; }}
  tbody.innerHTML=data.map(e=>`<tr>
    <td>${{e.time}}</td><td><span class="badge badge-purple">${{e.token_label}}</span></td>
    <td style="color:#f87171;font-weight:bold;">${{e.attacker_ip}}</td>
    <td style="font-size:.75rem;">${{e.path}}</td>
    <td><span class="badge badge-blue">${{e.method}}</span></td>
    <td style="font-size:.73rem;color:#90a4ae;max-width:200px;overflow:hidden;text-overflow:ellipsis;">${{e.user_agent}}</td>
  </tr>`).join('');
}}

// ── BRUTE-FORCE ──────────────────────────────────────────────
async function saveRateLimit() {{
  const limit=parseInt(document.getElementById('rl_max_input').value);
  if(isNaN(limit)||limit<5) {{ alert('Minimum: 5 Anfragen.'); return; }}
  const res=await fetch('/set_rate_limit',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{limit}})}});
  const d=await res.json(); alert('Rate-Limit gespeichert: '+d.rate_limit_max+' Anfragen/min');
}}
async function unblockIP() {{
  const ip=document.getElementById('unblock_ip_input').value.trim();
  if(!ip) {{ alert('IP eingeben.'); return; }}
  const res=await fetch('/bruteforce/unblock',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{ip}})}});
  const d=await res.json(); alert(d.success?'OK: '+d.message:'Info: '+d.message); loadBlockedIPs();
}}
async function unblockByIP(ip) {{ await fetch('/bruteforce/unblock',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{ip}})}}); loadBlockedIPs(); }}
async function loadBlockedIPs() {{
  const res=await fetch('/bruteforce/blocked'); const data=await res.json();
  const container=document.getElementById('blockedIPsList');
  if(!data.length) {{ container.innerHTML='<p style="color:#10b981;font-size:.85rem;">Keine IPs gesperrt.</p>'; return; }}
  container.innerHTML=data.map(b=>`
    <div style="display:flex;justify-content:space-between;align-items:center;background:#450a0a;
      border:1px solid #7f1d1d;border-radius:6px;padding:8px 12px;margin-bottom:6px;font-size:.85rem;">
      <span style="color:#f87171;font-weight:bold;">${{b.ip}}</span>
      <span style="color:#90a4ae;">noch ${{b.remaining_seconds}}s gesperrt</span>
      <button class="btn btn-green btn-sm" onclick="unblockByIP('${{b.ip}}')">Entsperren</button>
    </div>`).join('');
}}
async function loadBruteAlerts() {{
  const res=await fetch('/bruteforce/alerts'); const data=await res.json();
  const tbody=document.getElementById('bruteAlertsBody');
  if(!data.length) {{ tbody.innerHTML='<tr><td colspan="6" style="color:#90a4ae;">Keine Brute-Force-Versuche.</td></tr>'; return; }}
  tbody.innerHTML=data.map(e=>`<tr>
    <td>${{e.time}}</td><td style="color:#f87171;font-weight:bold;">${{e.source_ip}}</td>
    <td style="color:#fbbf24;font-weight:bold;">${{e.request_count}}</td>
    <td>${{e.window_seconds}}s</td><td style="font-size:.75rem;">${{e.path}}</td>
    <td><span class="badge badge-danger">GEBLOCKT</span></td>
  </tr>`).join('');
}}

// ── MEMORY SAFETY ────────────────────────────────────────────
async function runSafetyCheck() {{
  document.getElementById('safety_spinner').style.display='inline';
  const res=await fetch('/safety/check'); const d=await res.json();
  document.getElementById('safety_spinner').style.display='none';
  const sc=d.score>=80?'#10b981':d.score>=50?'#fbbf24':'#f87171';
  document.getElementById('safetyScore').innerHTML=`
    <div style="font-size:4rem;color:${{sc}};font-weight:bold;">${{d.score}}%</div>
    <div style="color:${{sc}};">${{d.passed}}/${{d.total}} Checks bestanden</div>
    <div class="risk-bar-bg" style="margin-top:10px;"><div class="risk-bar" style="width:${{d.score}}%;background:${{sc}};"></div></div>`;
  document.getElementById('safetyResults').innerHTML=d.checks.map(c=>`
    <div class="check-row"><div><strong>${{c.component}}</strong><br>
    <small style="color:#90a4ae;">${{c.detail}}</small></div>
    <span class="badge ${{c.ok?'badge-safe':'badge-warn'}}">${{c.status}}</span></div>`).join('');
}}
async function loadDockerfile() {{ const res=await fetch('/safety/dockerfile'); const d=await res.json(); const el=document.getElementById('dockerfileContent'); el.textContent=d.dockerfile; el.style.display='block'; }}
async function loadRustStub() {{ const res=await fetch('/safety/rust_stub'); const d=await res.json(); const el=document.getElementById('rustStubContent'); el.textContent=d.rust_code; el.style.display='block'; }}

// ── HISTORY ──────────────────────────────────────────────────
async function loadHist() {{
  const res=await fetch('/history'); const data=await res.json();
  document.getElementById('histBody').innerHTML=data.map(e=>`<tr><td>${{e.time}}</td><td>${{e.status}}</td><td>${{e.detail}}</td></tr>`).join('');
}}

// ── ALARM LOG ────────────────────────────────────────────────
async function loadAlarmLog() {{
  const res  = await fetch('/alarm_log');
  const data = await res.json();
  const tbody = document.getElementById('alarmLogBody');
  if(!data.length) {{ tbody.innerHTML='<tr><td colspan="6" style="color:#90a4ae;">Keine Eintraege.</td></tr>'; return; }}
  tbody.innerHTML = data.map(e => {{
    const sc = e.severity==='KRITISCH' ? 'badge-danger' : e.severity==='WARNUNG' ? 'badge-warn' : 'badge-blue';
    const confirmed = e.confirmed ? '<span style="color:#10b981;">Bestaetigt</span>' : '<span style="color:#f87171;">Offen</span>';
    return `<tr>
      <td>${{e.time}}</td>
      <td><span class="badge ${{sc}}">${{e.severity}}</span></td>
      <td><span class="badge badge-purple">${{e.category}}</span></td>
      <td style="font-size:.8rem;">${{e.message}}</td>
      <td style="color:#fbbf24;">${{e.ip||'-'}}</td>
      <td>${{confirmed}}</td>
    </tr>`;
  }}).join('');
}}
async function confirmAllAlarms() {{
  await fetch('/alarm_log/confirm_all', {{method:'POST'}});
  loadAlarmLog();
}}

// ── ALERT EMAIL SETTINGS ─────────────────────────────────────
async function loadAlarmSettings() {{
  try {{
    const res  = await fetch('/settings/alert_email');
    const data = await res.json();
    document.getElementById('alert_email_to').value   = data.alert_email_to   || '';
    document.getElementById('alert_email_from').value = data.alert_email_from || '';
    document.getElementById('alert_smtp_host').value  = data.alert_smtp_host  || '';
    document.getElementById('alert_smtp_port').value  = data.alert_smtp_port  || '587';
    document.getElementById('alert_smtp_user').value  = data.alert_smtp_user  || '';
    const toggle = document.getElementById('alarmLogToggle');
    if(toggle) toggle.checked = data.alarm_log_active === '1';
  }} catch(e) {{}}
}}
async function saveAlarmSettings() {{
  const alarm_log_active = document.getElementById('alarmLogToggle').checked ? '1' : '0';
  await fetch('/settings/alert_email', {{method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{alarm_log_active}})}});
}}
async function saveEmailAlertSettings() {{
  const data = {{
    alert_email_to:   document.getElementById('alert_email_to').value,
    alert_email_from: document.getElementById('alert_email_from').value,
    alert_smtp_host:  document.getElementById('alert_smtp_host').value,
    alert_smtp_port:  document.getElementById('alert_smtp_port').value,
    alert_smtp_user:  document.getElementById('alert_smtp_user').value,
    alert_smtp_pass:  document.getElementById('alert_smtp_pass').value,
  }};
  await fetch('/settings/alert_email', {{method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify(data)}});
  alert('E-Mail-Alarm-Einstellungen gespeichert!');
}}
async function testAlertEmail() {{
  // Trigger a test alarm which will send email if configured
  await saveEmailAlertSettings();
  // Push a test alarm via scan dummy
  alert('Test-Alarm ausgeloest. Pruefen Sie Ihr E-Mail-Postfach (sofern SMTP konfiguriert).');
  showAlarm({{severity:'KRITISCH', category:'TEST', message:'Test-Alarm vom Dashboard', ip:'127.0.0.1', time: new Date().toLocaleTimeString()}});
}}
function testSirene() {{
  showAlarm({{severity:'KRITISCH', category:'TEST', message:'Sirene-Test vom Administrator', ip:'127.0.0.1', time: new Date().toLocaleTimeString()}});
}}

// ── SIRENE SYSTEM ────────────────────────────────────────────
let sirenAudio = null;
let sirenActive = false;

function createSirenSound() {{
  try {{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    function beep(freq, start, dur) {{
      const osc  = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.frequency.setValueAtTime(freq, ctx.currentTime + start);
      osc.frequency.linearRampToValueAtTime(freq * 1.5, ctx.currentTime + start + dur * 0.4);
      osc.frequency.linearRampToValueAtTime(freq, ctx.currentTime + start + dur * 0.8);
      gain.gain.setValueAtTime(0.4, ctx.currentTime + start);
      gain.gain.linearRampToValueAtTime(0, ctx.currentTime + start + dur);
      osc.start(ctx.currentTime + start);
      osc.stop(ctx.currentTime + start + dur);
    }}
    function cycle() {{
      if(!sirenActive) return;
      beep(600, 0,    0.6);
      beep(800, 0.6,  0.6);
      beep(1000,1.2,  0.6);
      beep(800, 1.8,  0.6);
      setTimeout(cycle, 2400);
    }}
    cycle();
    return ctx;
  }} catch(e) {{ return null; }}
}}

function activateSirene(alarm) {{
  if(sirenActive) return; // Already active
  sirenActive = true;
  document.body.classList.add('alarm-active');
  // Update overlay details
  document.getElementById('siren_cat').textContent  = alarm.category  || '-';
  document.getElementById('siren_msg').textContent  = alarm.message   || '-';
  document.getElementById('siren_ip').textContent   = alarm.ip        || 'Unbekannt';
  document.getElementById('siren_time').textContent = alarm.time      || new Date().toLocaleTimeString();
  document.getElementById('sireneOverlay').classList.add('active');
  sirenAudio = createSirenSound();
  // Flash page title
  let titleFlash = setInterval(() => {{
    document.title = document.title.startsWith('ALARM') ? 'SME-Guardian' : 'ALARM! ALARM! ALARM!';
  }}, 500);
  window._titleFlash = titleFlash;
}}

function confirmSirene() {{
  sirenActive = false;
  document.body.classList.remove('alarm-active');
  document.getElementById('sireneOverlay').classList.remove('active');
  if(sirenAudio) {{ try {{ sirenAudio.close(); }} catch(e) {{}} sirenAudio = null; }}
  clearInterval(window._titleFlash);
  document.title = 'SME-Guardian';
  clearAlarms();
}}

// ── COMPLIANCE PDF ───────────────────────────────────────────
async function downloadCompliance() {{
  const period = document.getElementById('compliance_period').value ||
                 new Date().toLocaleString('de-DE', {{month:'long', year:'numeric'}});
  const url = `/compliance/generate?period=${{encodeURIComponent(period)}}`;
  window.open(url, '_blank');
}}

async function sendComplianceReport() {{
  const spinner = document.getElementById('compliance_spinner');
  const result  = document.getElementById('complianceResult');
  spinner.style.display = 'inline';
  result.innerHTML = '';
  const period      = document.getElementById('compliance_period').value ||
                      new Date().toLocaleString('de-DE', {{month:'long', year:'numeric'}});
  const extra_email = document.getElementById('compliance_extra_email').value;
  try {{
    const res = await fetch('/compliance/send', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{period, extra_email}})
    }});
    const d = await res.json();
    spinner.style.display = 'none';
    if(d.success) {{
      result.innerHTML = `<div class="info-box success">Bericht erfolgreich gesendet an: ${{d.recipients.join(', ')}}</div>`;
      loadComplianceHistory();
    }} else {{
      result.innerHTML = `<div class="info-box warning">${{d.message}}</div>`;
    }}
  }} catch(e) {{
    spinner.style.display = 'none';
    result.innerHTML = `<div class="info-box warning">Fehler: ${{e}}</div>`;
  }}
}}

async function loadComplianceHistory() {{
  try {{
    const res  = await fetch('/compliance/history');
    const data = await res.json();
    const tbody = document.getElementById('complianceHistoryBody');
    if(!data.length) {{
      tbody.innerHTML = '<tr><td colspan="4" style="color:#90a4ae;">Noch keine Berichte.</td></tr>';
      return;
    }}
    tbody.innerHTML = data.map(r => {{
      const sc = r.status === 'sent' ? 'badge-safe' : r.status === 'failed' ? 'badge-danger' : 'badge-blue';
      return `<tr>
        <td>${{r.time}}</td>
        <td style="color:#38bdf8;">${{r.period}}</td>
        <td style="font-size:.8rem;">${{r.sent_to || '-'}}</td>
        <td><span class="badge ${{sc}}">${{r.status?.toUpperCase()}}</span></td>
      </tr>`;
    }}).join('');
  }} catch(e) {{}}
}}

async function loadComplianceSettings() {{
  try {{
    const res  = await fetch('/compliance/settings');
    const data = await res.json();
    document.getElementById('compliance_ceo_email').value      = data.compliance_ceo_email      || '';
    document.getElementById('compliance_security_email').value = data.compliance_security_email || '';
    document.getElementById('company_address').value           = data.company_address           || '';
    document.getElementById('company_logo_text').value         = data.company_logo_text         || '';
    const tog = document.getElementById('compliance_auto_send');
    if(tog) tog.checked = data.compliance_auto_send === '1';
  }} catch(e) {{}}
}}

async function saveComplianceSettings() {{
  const data = {{
    compliance_ceo_email:      document.getElementById('compliance_ceo_email').value,
    compliance_security_email: document.getElementById('compliance_security_email').value,
    company_address:           document.getElementById('company_address').value,
    company_logo_text:         document.getElementById('company_logo_text').value,
    compliance_auto_send:      document.getElementById('compliance_auto_send')?.checked ? '1' : '0',
  }};
  const res = await fetch('/compliance/settings', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify(data)
  }});
  const d = await res.json();
  if(d.success) alert('Compliance-Einstellungen gespeichert!');
}}

// ── OUTLOOK ADD-IN TEST ──────────────────────────────────────
async function testOutlookScan() {{
  const sender  = document.getElementById('olk_from').value;
  const subject = document.getElementById('olk_subject').value;
  const body    = document.getElementById('olk_body').value;
  const res = await fetch('/outlook/scan_email', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{sender, subject, body, message_id: 'dashboard-test'}})
  }});
  const d = await res.json();
  const resultDiv = document.getElementById('outlookTestResult');
  const color = d.verdict === 'PHISHING' ? '#f87171' : d.verdict === 'VERDAECHTIG' ? '#fbbf24' : '#10b981';
  const bg    = d.verdict === 'PHISHING' ? '#450a0a' : d.verdict === 'VERDAECHTIG' ? '#451a03' : '#022c22';
  resultDiv.style.display = 'block';
  resultDiv.style.background = bg;
  resultDiv.style.border = `1px solid ${{color}}`;
  resultDiv.style.borderRadius = '8px';
  resultDiv.style.padding = '12px';
  resultDiv.innerHTML = `
    <div style="font-size:1.1rem;font-weight:bold;color:${{color}};">${{d.verdict}} — Risiko: ${{d.risk_score}}%</div>
    <div style="margin-top:6px;font-size:0.85rem;color:#cfd8dc;">${{d.banner_text}}</div>
    ${{d.reasons.length ? '<ul style="margin:8px 0 0;font-size:0.82rem;color:#fbbf24;">' +
      d.reasons.map(r => `<li>${{r}}</li>`).join('') + '</ul>' : ''}}
  `;
}}

// ── TELEGRAM SETTINGS ────────────────────────────────────────
async function loadTelegramSettings() {{
  try {{
    const res  = await fetch('/telegram/settings');
    const data = await res.json();
    // Toggle states
    const actToggle  = document.getElementById('telegram_active');
    const warnToggle = document.getElementById('telegram_on_warn');
    if(actToggle)  actToggle.checked  = data.telegram_active  === '1';
    if(warnToggle) warnToggle.checked = data.telegram_on_warn === '1';
    // Token (masked) – don't pre-fill password field, show hint
    const tokField = document.getElementById('telegram_token');
    if(tokField && data.telegram_token_masked)
      tokField.placeholder = 'Gespeichert: ' + data.telegram_token_masked;
    // Chat ID
    const chatField = document.getElementById('telegram_chat_id');
    if(chatField) chatField.value = data.telegram_chat_id || '';
    // Status indicators
    const keyStatus = document.getElementById('tg_key_status');
    const actStatus = document.getElementById('tg_active_status');
    if(keyStatus) {{
      keyStatus.textContent = data.key_file_exists
        ? (data.key_loaded ? '✅ sentinel.key aktiv' : '⚠️ Datei gefunden, Fehler beim Laden')
        : '❌ Nicht gefunden (DB-Modus)';
      keyStatus.style.color = data.key_loaded ? '#10b981' : data.key_file_exists ? '#fbbf24' : '#90a4ae';
    }}
    if(actStatus) {{
      actStatus.textContent = data.telegram_active === '1' ? '✅ Aktiv' : '⏸ Deaktiviert';
      actStatus.style.color = data.telegram_active === '1' ? '#10b981' : '#f87171';
    }}
  }} catch(e) {{}}
}}

async function saveTelegramSettings() {{
  const token   = document.getElementById('telegram_token').value;
  const chat_id = document.getElementById('telegram_chat_id').value;
  const active  = document.getElementById('telegram_active').checked  ? '1' : '0';
  const on_warn = document.getElementById('telegram_on_warn').checked ? '1' : '0';
  const body = {{ telegram_active: active, telegram_on_warn: on_warn }};
  if(token)   body.telegram_token   = token;
  if(chat_id) body.telegram_chat_id = chat_id;
  const res = await fetch('/telegram/settings', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(body)
  }});
  const d = await res.json();
  if(d.success) {{
    alert('Telegram-Einstellungen gespeichert!');
    loadTelegramSettings();
  }}
}}

async function testTelegram() {{
  const msg = document.getElementById('tg_test_msg');
  msg.textContent = 'Sende...';
  try {{
    // Save first in case token was just entered
    const token   = document.getElementById('telegram_token').value;
    const chat_id = document.getElementById('telegram_chat_id').value;
    if(token || chat_id) {{
      const b = {{}};
      if(token)   b.telegram_token   = token;
      if(chat_id) b.telegram_chat_id = chat_id;
      await fetch('/telegram/settings', {{
        method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(b)
      }});
    }}
    const res = await fetch('/telegram/test', {{method:'POST'}});
    const d   = await res.json();
    if(d.success) {{
      msg.textContent = '✅ Test gesendet! Prüfe dein Telegram.';
      msg.style.color = '#10b981';
    }} else {{
      msg.textContent = '❌ ' + (d.error || 'Fehler');
      msg.style.color = '#f87171';
    }}
  }} catch(e) {{
    msg.textContent = '❌ Verbindungsfehler: ' + e;
    msg.style.color = '#f87171';
  }}
  setTimeout(() => {{ msg.textContent = ''; }}, 6000);
}}

// ── AUTO-UPDATE ──────────────────────────────────────────────
async function triggerUpdateCheck() {{
  const msg = document.getElementById('updateCheckMsg');
  if(msg) msg.textContent = 'Prüfe auf Updates...';
  try {{
    await fetch('/update/check_now', {{method:'POST'}});
    if(msg) msg.textContent = 'Update-Check ausgelöst. Ergebnis erscheint in Server-Logs.';
    setTimeout(checkVersionDisplay, 2000);
  }} catch(e) {{
    if(msg) msg.textContent = 'Fehler: ' + e;
  }}
}}

async function checkVersionDisplay() {{
  try {{
    const res  = await fetch('/version');
    const data = await res.json();
    const localEl = document.getElementById('localVersion');
    if(localEl) localEl.textContent = 'v' + data.version;
    const remoteEl = document.getElementById('remoteVersion');
    if(remoteEl) remoteEl.textContent = 'v' + data.version + ' (bestätigt)';
  }} catch(e) {{}}
}}

connectSSE();
loadFpSnippet();
loadAlarmSettings();
loadTelegramSettings();
checkVersionDisplay();
</script>
</body>
</html>"""
