import json
import sqlite3
from pathlib import Path

DB_PATH = Path("ioc_lens.db")


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                risk_score INTEGER,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                response_json TEXT NOT NULL,
                analyzed_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_indicator
            ON analyses(indicator_type, indicator, analyzed_at)
        """)


def save(response: dict):
    with connect() as db:
        db.execute(
            """INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                response["analysis_id"], response["indicator"], response["indicator_type"],
                response["risk_score"], response["verdict"], response["confidence"],
                json.dumps(response, default=str), response["analyzed_at"],
            ),
        )


def latest(indicator_type: str, indicator: str):
    with connect() as db:
        row = db.execute(
            """SELECT response_json FROM analyses
               WHERE indicator_type = ? AND indicator = ?
               ORDER BY analyzed_at DESC LIMIT 1""",
            (indicator_type, indicator),
        ).fetchone()
    return json.loads(row["response_json"]) if row else None


def related(indicator: str):
    # Relationship graph is intentionally empty until provider/relationship evidence is added.
    return []
