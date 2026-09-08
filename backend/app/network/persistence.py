"""
Persistence for network telemetry.

Extends the existing storage layer additively: four new tables with indexes,
batched writes, and configurable retention. Raw payloads are never stored and
packet metadata is bounded by PACKET_RETENTION_MINUTES.

Reuses the provider-neutral connection helpers already in app.database so the
subsystem works on both the SQLite fallback and PostgreSQL.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .. import database as db

_SQLITE_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        packet_size INTEGER,
        tcp_flags TEXT,
        interface TEXT,
        direction TEXT,
        connection_id TEXT,
        is_simulated INTEGER DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS network_connections (
        connection_id TEXT PRIMARY KEY,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        packet_count INTEGER,
        byte_count INTEGER,
        duration_seconds REAL,
        failed INTEGER DEFAULT 0,
        first_seen TEXT,
        last_seen TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS network_ip_stats (
        ip TEXT PRIMARY KEY,
        role TEXT,
        packet_count INTEGER,
        byte_count INTEGER,
        connection_count INTEGER,
        unique_destinations INTEGER,
        unique_destination_ports INTEGER,
        protocols TEXT,
        traffic_rate REAL,
        threat_score REAL,
        risk_level TEXT,
        first_seen TEXT,
        last_seen TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS network_threats (
        threat_id TEXT PRIMARY KEY,
        detected_at TEXT NOT NULL,
        threat_type TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        confidence REAL,
        anomaly_score REAL,
        threat_score REAL,
        risk_level TEXT,
        mitre_id TEXT,
        mitre_technique TEXT,
        mitre_tactic TEXT,
        description TEXT,
        incident_id TEXT,
        detection_source TEXT,
        recommended_action TEXT,
        evidence_json TEXT,
        is_simulated INTEGER DEFAULT 0
    );
    """,
)

_INDEXES = (
    ("idx_network_events_timestamp", "network_events", "timestamp"),
    ("idx_network_events_source_ip", "network_events", "source_ip"),
    ("idx_network_events_destination_ip", "network_events", "destination_ip"),
    ("idx_network_threats_detected_at", "network_threats", "detected_at"),
    ("idx_network_threats_source_ip", "network_threats", "source_ip"),
    ("idx_network_threats_threat_type", "network_threats", "threat_type"),
    ("idx_network_threats_risk_level", "network_threats", "risk_level"),
    ("idx_network_conn_source_ip", "network_connections", "source_ip"),
    ("idx_network_ip_stats_risk", "network_ip_stats", "risk_level"),
)

_PG_TYPE_FIXES = (
    ("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"),
)

_initialized = False
_last_error: Optional[str] = None


def _is_postgres() -> bool:
    return db._database_backend() == "postgresql"


def _pg_schema() -> str:
    return db._postgresql_schema()


def _translate_for_pg(statement: str, schema: str) -> str:
    out = statement
    for old, new in _PG_TYPE_FIXES:
        out = out.replace(old, new)
    for table in ("network_events", "network_connections", "network_ip_stats", "network_threats"):
        out = out.replace(f"IF NOT EXISTS {table}", f'IF NOT EXISTS {schema}."{table}"')
    return out


def init_network_tables() -> Dict[str, Any]:
    """Creates tables and indexes. Never drops or rewrites existing data."""
    global _initialized, _last_error
    try:
        if _is_postgres():
            schema = _pg_schema()
            with db._postgresql_connection() as conn:
                with conn.cursor() as cur:
                    for statement in _SQLITE_SCHEMA:
                        cur.execute(_translate_for_pg(statement, schema))
                    for name, table, column in _INDEXES:
                        cur.execute(
                            f'CREATE INDEX IF NOT EXISTS {name} ON {schema}."{table}" ("{column}")'
                        )
        else:
            with db._sqlite_connection() as conn:
                cur = conn.cursor()
                for statement in _SQLITE_SCHEMA:
                    cur.execute(statement)
                for name, table, column in _INDEXES:
                    cur.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({column})")
        _initialized = True
        _last_error = None
        return {"initialized": True, "backend": db._database_backend(), "error": None}
    except Exception as error:
        _initialized = False
        _last_error = db._safe_error(error)
        return {"initialized": False, "backend": db._database_backend(), "error": _last_error}


def status() -> Dict[str, Any]:
    return {"initialized": _initialized, "backend": db._database_backend(), "error": _last_error}


def _q(table: str) -> str:
    """Returns a properly qualified/quoted table reference for the backend."""
    return f'{_pg_schema()}."{table}"' if _is_postgres() else table


def _ph(count: int) -> str:
    """Parameter placeholders for the active driver."""
    token = "%s" if _is_postgres() else "?"
    return ", ".join([token] * count)


def save_packet_batch(packets: List[Any]) -> int:
    """Batched insert of packet metadata. Returns rows written."""
    if not packets or not _initialized:
        return 0

    rows = [
        (
            p.timestamp, p.source_ip, p.destination_ip, p.source_port, p.destination_port,
            p.protocol, p.packet_size, p.tcp_flags, p.interface, p.direction,
            p.connection_id, 1 if p.is_simulated else 0,
        )
        for p in packets
    ]
    sql = (
        f"INSERT INTO {_q('network_events')} "
        "(timestamp, source_ip, destination_ip, source_port, destination_port, protocol, "
        "packet_size, tcp_flags, interface, direction, connection_id, is_simulated) "
        f"VALUES ({_ph(12)})"
    )
    try:
        if _is_postgres():
            with db._postgresql_connection() as conn:
                with conn.cursor() as cur:
                    cur.executemany(sql, rows)
        else:
            with db._sqlite_connection() as conn:
                conn.cursor().executemany(sql, rows)
        return len(rows)
    except Exception:
        return 0


def save_threat(threat: Any) -> bool:
    """Persists one network detection (idempotent on threat_id)."""
    if not _initialized:
        return False

    conflict = "ON CONFLICT (threat_id) DO NOTHING" if _is_postgres() else "OR IGNORE"
    sql = (
        f"INSERT {'' if _is_postgres() else conflict} INTO {_q('network_threats')} "
        "(threat_id, detected_at, threat_type, source_ip, destination_ip, confidence, "
        "anomaly_score, threat_score, risk_level, mitre_id, mitre_technique, mitre_tactic, "
        "description, incident_id, detection_source, recommended_action, evidence_json, is_simulated) "
        f"VALUES ({_ph(18)}) {conflict if _is_postgres() else ''}"
    )
    row = (
        threat.threat_id, threat.detected_at, threat.threat_type, threat.source_ip,
        threat.destination_ip, threat.confidence, threat.anomaly_score, threat.threat_score,
        threat.risk_level, threat.mitre_id, threat.mitre_technique, threat.mitre_tactic,
        threat.description, threat.incident_id, threat.detection_source,
        threat.recommended_action, json.dumps(threat.evidence, default=str),
        1 if threat.is_simulated else 0,
    )
    try:
        if _is_postgres():
            with db._postgresql_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, row)
        else:
            with db._sqlite_connection() as conn:
                conn.cursor().execute(sql, row)
        return True
    except Exception:
        return False


def recent_threats(limit: int = 50) -> List[Dict[str, Any]]:
    """Reads stored network threats, newest first."""
    if not _initialized:
        return []
    sql = f"SELECT * FROM {_q('network_threats')} ORDER BY detected_at DESC LIMIT {int(limit)}"
    try:
        if _is_postgres():
            with db._postgresql_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    return [dict(r) for r in cur.fetchall()]
        with db._sqlite_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql)
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def enforce_retention(retention_minutes: int) -> int:
    """Deletes packet metadata older than the retention horizon."""
    if not _initialized:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max(1, retention_minutes))).isoformat()
    token = "%s" if _is_postgres() else "?"
    sql = f"DELETE FROM {_q('network_events')} WHERE timestamp < {token}"
    try:
        if _is_postgres():
            with db._postgresql_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (cutoff,))
                    return cur.rowcount or 0
        with db._sqlite_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (cutoff,))
            return cur.rowcount or 0
    except Exception:
        return 0
