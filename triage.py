"""Local SQLite persistence for analyst decisions, not raw event logs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from soc import Alert

STATUSES = ("Open", "Investigating", "Resolved", "False positive")


def alert_id(alert: Alert, dataset_id: str) -> str:
    """Identify an exact detection within its source dataset."""
    payload = json.dumps(asdict(alert), default=str, sort_keys=True)
    return hashlib.sha256(f"{dataset_id}:{payload}".encode()).hexdigest()


@dataclass(frozen=True)
class TriageRecord:
    status: str = "Open"
    notes: str = ""
    updated_at: str | None = None


class TriageStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS alert_triage (
                    alert_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def records(self) -> dict[str, TriageRecord]:
        with self._connect() as connection:
            rows = connection.execute("SELECT alert_id, status, notes, updated_at FROM alert_triage")
            return {key: TriageRecord(status, notes, updated) for key, status, notes, updated in rows}

    def save(self, key: str, status: str, notes: str) -> None:
        if status not in STATUSES:
            raise ValueError("Invalid triage status")
        if len(notes) > 10000:
            raise ValueError("Notes must be at most 10,000 characters")
        updated = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute("""
                INSERT INTO alert_triage (alert_id, status, notes, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    status = excluded.status, notes = excluded.notes,
                    updated_at = excluded.updated_at
            """, (key, status, notes, updated))
