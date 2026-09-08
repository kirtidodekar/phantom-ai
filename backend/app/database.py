import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "sentinel.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Telemetry events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT,
        layer TEXT,
        entity_id TEXT,
        action TEXT,
        detail_json TEXT,
        source_confidence TEXT,
        attack_type TEXT,
        confidence_score REAL,
        is_simulated INTEGER
    );
    """)

    # Incidents table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        title TEXT,
        status TEXT,
        primary_entity TEXT,
        threat_score REAL,
        risk_level TEXT,
        data_json TEXT,
        updated_at TEXT
    );
    """)

    # Analyst Feedback table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyst_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT,
        event_id TEXT,
        feedback_type TEXT,
        notes TEXT,
        created_at TEXT
    );
    """)

    # Sandboxed Actions Audit table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sandboxed_actions (
        action_id TEXT PRIMARY KEY,
        action_type TEXT,
        target_id TEXT,
        incident_id TEXT,
        status TEXT,
        message TEXT,
        timestamp TEXT
    );
    """)

    conn.commit()
    conn.close()

def save_feedback(feedback_type: str, incident_id: str, event_id: Optional[str], notes: str, created_at: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analyst_feedback (incident_id, event_id, feedback_type, notes, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (incident_id, event_id, feedback_type, notes, created_at))
    conn.commit()
    conn.close()

def log_sandboxed_action(action_id: str, action_type: str, target_id: str, incident_id: str, status: str, message: str, timestamp: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sandboxed_actions (action_id, action_type, target_id, incident_id, status, message, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (action_id, action_type, target_id, incident_id, status, message, timestamp))
    conn.commit()
    conn.close()

def get_sandboxed_actions() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sandboxed_actions ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
