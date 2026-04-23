import sqlite3
import json
import time
from pathlib import Path

DB_PATH = Path.home() / ".phantomai" / "sessions.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            mode TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            finished_at INTEGER,
            status TEXT DEFAULT 'running'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            module TEXT,
            severity TEXT,
            vuln_type TEXT,
            affected_url TEXT,
            reasoning TEXT,
            raw_output TEXT,
            ai_result TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    """)
    c.execute("PRAGMA table_info(findings)")
    columns = {row[1] for row in c.fetchall()}
    if "confirmed" not in columns:
        c.execute("ALTER TABLE findings ADD COLUMN confirmed INTEGER DEFAULT 0")
    conn.commit()
    conn.close()


class SessionLogger:
    def __init__(self, target: str, mode: str):
        init_db()
        self.conn = sqlite3.connect(DB_PATH)
        self.target = target
        self.session_id = self._create_session(target, mode)

    def _create_session(self, target: str, mode: str) -> int:
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO sessions (target, mode, started_at) VALUES (?, ?, ?)",
            (target, mode, int(time.time())),
        )
        self.conn.commit()
        return c.lastrowid

    def log_finding(self, module: str, raw_output: str, ai_result: dict):
        c = self.conn.cursor()
        c.execute(
            """INSERT INTO findings
               (session_id, timestamp, module, severity, vuln_type, affected_url, reasoning, raw_output, ai_result, confirmed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self.session_id,
                int(time.time()),
                module,
                ai_result.get("severity", "unknown"),
                ai_result.get("vuln_type", "unknown"),
                ai_result.get("affected_url", ""),
                ai_result.get("reasoning", ""),
                raw_output[:4000],
                json.dumps(ai_result),
                1 if ai_result.get("confirmed") else 0,
            ),
        )
        self.conn.commit()

    def get_all_findings(self) -> list:
        c = self.conn.cursor()
        c.execute(
            "SELECT * FROM findings WHERE session_id = ? AND severity != 'none' AND confirmed = 1",
            (self.session_id,),
        )
        rows = c.fetchall()
        findings = []
        for row in rows:
            findings.append({
                "id": row[0],
                "module": row[3],
                "severity": row[4],
                "vuln_type": row[5],
                "affected_url": row[6],
                "reasoning": row[7],
                "ai_result": json.loads(row[9]) if row[9] else {},
            })
        return findings

    def finish_session(self):
        c = self.conn.cursor()
        c.execute(
            "UPDATE sessions SET finished_at = ?, status = 'done' WHERE id = ?",
            (int(time.time()), self.session_id),
        )
        self.conn.commit()
        self.conn.close()

    @staticmethod
    def list_sessions() -> list:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, target, mode, started_at, status FROM sessions ORDER BY started_at DESC LIMIT 20")
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "target": r[1], "mode": r[2], "started_at": r[3], "status": r[4]} for r in rows]

    @staticmethod
    def load_session_findings(session_id: int) -> list:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT * FROM findings WHERE session_id = ? AND severity != 'none' AND confirmed = 1",
            (session_id,),
        )
        rows = c.fetchall()
        conn.close()
        findings = []
        for row in rows:
            findings.append({
                "module": row[3],
                "severity": row[4],
                "vuln_type": row[5],
                "affected_url": row[6],
                "reasoning": row[7],
                "ai_result": json.loads(row[9]) if row[9] else {},
            })
        return findings
