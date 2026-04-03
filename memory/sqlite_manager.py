import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any, List

DB_PATH = os.path.join(os.path.dirname(__file__), "zylar_memory.db")

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    """Initializes the SQLite database with required tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            timestamp TEXT,
            attack_classification TEXT,
            risk_score INTEGER,
            risk_category TEXT,
            mitigation_plan TEXT,
            threat_intel TEXT,
            anomalous_events_count INTEGER
        )
    ''')
    
    # IP History table for tracking recurring bad actors
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_history (
            ip_address TEXT PRIMARY KEY,
            offense_count INTEGER DEFAULT 0,
            last_seen TEXT,
            last_risk_score INTEGER
        )
    ''')
    
    # User History table for tracking compromised/malicious users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_history (
            username TEXT PRIMARY KEY,
            offense_count INTEGER DEFAULT 0,
            last_seen TEXT,
            last_risk_score INTEGER
        )
    ''')
    
    # Risk History table for tracking overall system risk over time
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            incident_id TEXT,
            risk_score INTEGER
        )
    ''')
    
    # Processed Events table to prevent log reprocessing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processed_events (
            event_id TEXT PRIMARY KEY,
            processed_at TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def log_incident(incident_data: Dict[str, Any]):
    """Stores the generated incident report into memory."""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO incidents (incident_id, timestamp, attack_classification, risk_score, risk_category, mitigation_plan, threat_intel, anomalous_events_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_data.get("incident_id"),
            incident_data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            incident_data.get("attack_classification"),
            incident_data.get("risk_score"),
            incident_data.get("risk_category"),
            json.dumps(incident_data.get("mitigation_plan", [])),
            json.dumps(incident_data.get("threat_intel", {})),
            incident_data.get("anomalous_events_count", 0)
        ))
        
        # Log to risk history
        cursor.execute('''
            INSERT INTO risk_history (timestamp, incident_id, risk_score)
            VALUES (?, ?, ?)
        ''', (
            incident_data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            incident_data.get("incident_id"),
            incident_data.get("risk_score")
        ))
        
        conn.commit()
    except sqlite3.IntegrityError:
        # Incident already exists
        pass
    finally:
        conn.close()

def update_entity_history(ips: List[str], users: List[str], risk_score: int):
    """Updates the offense count and last seen time for IPs and Users."""
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().isoformat() + "Z"
    
    for ip in ips:
        cursor.execute("SELECT offense_count FROM ip_history WHERE ip_address=?", (ip,))
        result = cursor.fetchone()
        if result:
            new_count = result[0] + 1
            cursor.execute('''
                UPDATE ip_history 
                SET offense_count=?, last_seen=?, last_risk_score=? 
                WHERE ip_address=?
            ''', (new_count, now_str, risk_score, ip))
        else:
            cursor.execute('''
                INSERT INTO ip_history (ip_address, offense_count, last_seen, last_risk_score)
                VALUES (?, ?, ?, ?)
            ''', (ip, 1, now_str, risk_score))
            
    for user in users:
        cursor.execute("SELECT offense_count FROM user_history WHERE username=?", (user,))
        result = cursor.fetchone()
        if result:
            new_count = result[0] + 1
            cursor.execute('''
                UPDATE user_history 
                SET offense_count=?, last_seen=?, last_risk_score=? 
                WHERE username=?
            ''', (new_count, now_str, risk_score, user))
        else:
            cursor.execute('''
                INSERT INTO user_history (username, offense_count, last_seen, last_risk_score)
                VALUES (?, ?, ?, ?)
            ''', (user, 1, now_str, risk_score))

    conn.commit()
    conn.close()

def get_historical_recurrence_factor(ips: List[str], users: List[str]) -> int:
    """Calculates a heuristic recurrence factor based on past offenses (0-100)."""
    conn = get_connection()
    cursor = conn.cursor()
    
    total_offenses = 0
    
    for ip in ips:
        cursor.execute("SELECT offense_count FROM ip_history WHERE ip_address=?", (ip,))
        res = cursor.fetchone()
        if res:
            total_offenses += res[0]
            
    for user in users:
        cursor.execute("SELECT offense_count FROM user_history WHERE username=?", (user,))
        res = cursor.fetchone()
        if res:
            total_offenses += res[0]
            
    conn.close()
    
    # 5 points per past offense, max 100
    return min(100, total_offenses * 5)

def get_top_offenders(limit: int = 5) -> Dict[str, List[Dict]]:
    """Retrieves top recurring anomalous IPs and users for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT ip_address, offense_count, last_seen FROM ip_history ORDER BY offense_count DESC LIMIT ?", (limit,))
    ips = [{"ip": row[0], "count": row[1], "last_seen": row[2]} for row in cursor.fetchall()]
    
    cursor.execute("SELECT username, offense_count, last_seen FROM user_history ORDER BY offense_count DESC LIMIT ?", (limit,))
    users = [{"user": row[0], "count": row[1], "last_seen": row[2]} for row in cursor.fetchall()]
    
    conn.close()
    return {"top_ips": ips, "top_users": users}

def is_event_processed(event_id: str) -> bool:
    """Checks if an event_id was already processed through the pipeline."""
    if not event_id:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM processed_events WHERE event_id=?", (event_id,))
    res = cursor.fetchone()
    conn.close()
    return res is not None

def mark_event_processed(event_id: str):
    """Marks an event_id as processed."""
    if not event_id:
        return
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO processed_events (event_id, processed_at) VALUES (?, ?)", 
                       (event_id, datetime.utcnow().isoformat() + "Z"))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

# Initialize DB on load
if not os.path.exists(DB_PATH):
    init_db()
else:
    # Ensure tables exist even if file exists
    init_db()
