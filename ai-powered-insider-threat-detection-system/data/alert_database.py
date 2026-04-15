"""
Alert History Database

Stores and manages security alerts with status tracking, analyst notes, and audit logging.
"""

import sqlite3
import os
from datetime import datetime
import uuid
import json

DATA_DIR = 'data'
DB_PATH = os.path.join(DATA_DIR, 'alerts.db')

def init_database():
    """Initialize the SQLite database with required tables."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            threat_type TEXT,
            analyst_notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            resolved_by TEXT,
            investigation_summary TEXT
        )
    ''')

    # Alert indicators table (detailed evidence)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            severity TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
        )
    ''')

    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user TEXT,
            action TEXT NOT NULL,
            alert_id TEXT,
            details TEXT
        )
    ''')

    # User credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Sessions table for tracking active sessions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_valid INTEGER DEFAULT 1
        )
    ''')

    conn.commit()
    conn.close()

    # Insert default admin user if not exists
    insert_default_admin()

    print(f"Database initialized at {DB_PATH}")

def insert_default_admin():
    """Insert default admin user (admin:admin)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin', 'admin', datetime.now().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # User already exists
    finally:
        conn.close()

def create_alert(user, risk_score, risk_level, threat_type=None, indicators=None):
    """Create a new alert."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()

        alert_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO alerts (alert_id, user, timestamp, risk_score, risk_level,
                               status, threat_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?)
        ''', (alert_id, user, now, risk_score, risk_level, threat_type, now, now))

        # Add indicators if provided
        if indicators:
            for indicator in indicators:
                cursor.execute('''
                    INSERT INTO alert_indicators (alert_id, indicator_type, indicator_value, severity)
                    VALUES (?, ?, ?, ?)
                ''', (alert_id, indicator.get('type', 'behavior'),
                      indicator.get('value', ''), indicator.get('severity', 'medium')))

        conn.commit()
        conn.close()

        # Log the action (separate connection to avoid lock)
        try:
            log_audit('system', 'alert_created', alert_id, f"Alert created for {user}")
        except:
            pass

        return alert_id
    except sqlite3.OperationalError as e:
        print(f"Warning: Could not create alert: {e}")
        return None

def get_alerts(status=None, limit=100):
    """Get alerts with optional status filter."""
    conn = sqlite3.connect(DB_PATH)

    if status:
        df = pd.read_sql_query('''
            SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?
        ''', conn, params=(status, limit))
    else:
        df = pd.read_sql_query('''
            SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?
        ''', conn, params=(limit,))

    conn.close()
    return df

def update_alert_status(alert_id, status, analyst_notes=None, resolved_by=None):
    """Update alert status."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    now = datetime.now().isoformat()
    resolved_at = now if status in ['dismissed', 'resolved'] else None

    cursor.execute('''
        UPDATE alerts
        SET status = ?, analyst_notes = ?, updated_at = ?, resolved_at = ?, resolved_by = ?
        WHERE alert_id = ?
    ''', (status, analyst_notes, now, resolved_at, resolved_by, alert_id))

    log_audit(resolved_by or 'system', 'alert_updated', alert_id,
              f"Status changed to {status}")

    conn.commit()
    conn.close()

def get_alert_by_id(alert_id):
    """Get a specific alert by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM alerts WHERE alert_id = ?', (alert_id,))
    alert = cursor.fetchone()

    # Get indicators
    cursor.execute('SELECT * FROM alert_indicators WHERE alert_id = ?', (alert_id,))
    indicators = cursor.fetchall()

    conn.close()

    if alert:
        return {'alert': alert, 'indicators': indicators}
    return None

def log_audit(user, action, alert_id=None, details=None):
    """Log an audit event."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (timestamp, user, action, alert_id, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), user, action, alert_id,
              json.dumps(details) if details else None))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        pass  # Silently ignore audit log failures

def get_audit_log(limit=100):
    """Get audit log entries."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('''
        SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?
    ''', conn, params=(limit,))
    conn.close()
    return df

def verify_user(username, password):
    """Verify user credentials."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM users WHERE username = ? AND password = ? AND is_active = 1
    ''', (username, password))

    user = cursor.fetchone()
    conn.close()

    return user is not None

def create_session(username):
    """Create a new session for a user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    session_id = str(uuid.uuid4())
    now = datetime.now()
    expires = now + timedelta(hours=8)  # 8 hour session

    cursor.execute('''
        INSERT INTO sessions (session_id, username, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (session_id, username, now.isoformat(), expires.isoformat()))

    # Update last login
    cursor.execute('''
        UPDATE users SET last_login = ? WHERE username = ?
    ''', (now.isoformat(), username))

    conn.commit()
    conn.close()

    return session_id

def validate_session(session_id):
    """Check if a session is valid."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM sessions
        WHERE session_id = ? AND is_valid = 1 AND expires_at > ?
    ''', (session_id, datetime.now().isoformat()))

    session = cursor.fetchone()
    conn.close()

    return session is not None

def change_password(username, old_password, new_password):
    """Change user password."""
    if verify_user(username, old_password):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE users SET password = ? WHERE username = ?
        ''', (new_password, username))

        log_audit(username, 'password_changed')

        conn.commit()
        conn.close()
        return True
    return False

def get_alert_statistics():
    """Get alert statistics for dashboard."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Status counts
    cursor.execute('''
        SELECT status, COUNT(*) as count
        FROM alerts
        GROUP BY status
    ''')
    status_counts = {row[0]: row[1] for row in cursor.fetchall()}

    # Total alerts
    cursor.execute('SELECT COUNT(*) FROM alerts')
    total = cursor.fetchone()[0]

    # Recent alerts (last 24 hours)
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    cursor.execute('''
        SELECT COUNT(*) FROM alerts WHERE created_at > ?
    ''', (yesterday,))
    recent = cursor.fetchone()[0]

    conn.close()

    return {
        'total': total,
        'open': status_counts.get('open', 0),
        'investigating': status_counts.get('investigating', 0),
        'dismissed': status_counts.get('dismissed', 0),
        'resolved': status_counts.get('resolved', 0),
        'recent_24h': recent
    }

# Import required modules
import pandas as pd
from datetime import timedelta

if __name__ == '__main__':
    print("Initializing alert database...")
    init_database()
    print("Done!")

    # Test
    print("\nCreating test alert...")
    alert_id = create_alert(
        user='user42',
        risk_score=2.47,
        risk_level='CRITICAL',
        threat_type='data_exfiltration',
        indicators=[
            {'type': 'after_hours_access', 'value': '2:00 AM', 'severity': 'high'},
            {'type': 'mass_download', 'value': '50+ files', 'severity': 'critical'},
            {'type': 'usb_transfer', 'value': '2.5 GB', 'severity': 'critical'}
        ]
    )
    print(f"Created alert: {alert_id}")

    print("\nAlert statistics:")
    stats = get_alert_statistics()
    print(stats)
