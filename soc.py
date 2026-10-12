"""Local event parsing and transparent, rule-based SOC detections."""

from __future__ import annotations

import csv
import io
import json
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_type: str
    source_ip: str | None
    username: str | None
    status: str | None
    message: str
    destination_port: int | None = None


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    severity: str
    title: str
    source_ip: str | None
    username: str | None
    event_count: int
    description: str
    rule_id: str


def _timestamp(value: Any) -> datetime:
    if value is None or str(value).strip() == "":
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        result = datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
            try:
                result = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"Unsupported timestamp: {value}")
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _normalize(row: dict[str, Any]) -> Event:
    data = {str(k).strip().lower().replace(" ", "_"): v for k, v in row.items() if k is not None}
    event_type = str(data.get("event_type") or data.get("type") or data.get("action") or "unknown").lower().replace(" ", "_")
    status = str(data.get("status") or data.get("result") or "").lower() or None
    message = str(data.get("message") or data.get("description") or "")
    # Infer common auth outcomes from messages when structured status is absent.
    if not status and re.search(r"failed|invalid password|authentication failure", message, re.I):
        status = "failed"
    if not status and re.search(r"accepted|successful|logged in", message, re.I):
        status = "success"
    if event_type == "unknown" and re.search(r"ssh|login|authentication", message, re.I):
        event_type = "authentication"
    port_value = data.get("destination_port") or data.get("dest_port") or data.get("port")
    try:
        port = int(port_value) if port_value not in (None, "") else None
    except (ValueError, TypeError):
        port = None
    return Event(
        timestamp=_timestamp(data.get("timestamp") or data.get("time") or data.get("datetime")),
        event_type=event_type,
        source_ip=str(data.get("source_ip") or data.get("src_ip") or data.get("ip") or "") or None,
        username=str(data.get("username") or data.get("user") or "") or None,
        status=status,
        message=message,
        destination_port=port,
    )


def load_events(raw: str | None, filename: str | None) -> list[Event]:
    """Parse CSV/JSON/JSONL uploads; no file is persisted."""
    if raw is None:
        return sample_events()
    if not raw.strip():
        return []
    name = (filename or "").lower()
    try:
        if name.endswith(".csv") or (not name.endswith((".json", ".jsonl")) and raw.lstrip()[0] not in "[{" ):
            rows = list(csv.DictReader(io.StringIO(raw)))
        else:
            parsed = json.loads(raw) if not name.endswith(".jsonl") else [json.loads(line) for line in raw.splitlines() if line.strip()]
            rows = parsed if isinstance(parsed, list) else parsed.get("events", [parsed])
        if not isinstance(rows, list):
            raise ValueError("Expected a JSON object, array, or line-delimited JSON records.")
        return [_normalize(row) for row in rows if isinstance(row, dict)]
    except (json.JSONDecodeError, csv.Error, AttributeError) as exc:
        raise ValueError(f"Invalid log format: {exc}") from exc


def _is_auth(event: Event) -> bool:
    return any(token in event.event_type for token in ("auth", "login", "ssh", "sign_in")) or bool(re.search(r"ssh|login|authentication", event.message, re.I))


def _is_failure(event: Event) -> bool:
    return (event.status or "") in {"failed", "failure", "denied", "error", "invalid"} or bool(re.search(r"failed|invalid password|authentication failure", event.message, re.I))


def analyze_events(events: list[Event], threshold: int = 5, window_minutes: int = 10) -> list[Alert]:
    alerts: list[Alert] = []
    auth_events = sorted((e for e in events if _is_auth(e) and e.source_ip), key=lambda e: e.timestamp)
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in auth_events:
        grouped[event.source_ip or ""].append(event)
    window = timedelta(minutes=window_minutes)
    for ip, group in grouped.items():
        failures = [e for e in group if _is_failure(e)]
        for end in failures:
            recent = [e for e in failures if timedelta(0) <= end.timestamp - e.timestamp <= window]
            if len(recent) >= threshold:
                latest = max(recent, key=lambda e: e.timestamp)
                alerts.append(Alert(latest.timestamp, "HIGH", "Repeated failed logins", ip, latest.username, len(recent), f"{len(recent)} failed authentication attempts from {ip} within {window_minutes} minutes.", "AUTH-001"))
                break
        for success in (e for e in group if not _is_failure(e) and (e.status or "") in {"success", "accepted", "ok"}):
            prior = [e for e in failures if timedelta(0) <= success.timestamp - e.timestamp <= window]
            if len(prior) >= threshold:
                alerts.append(Alert(success.timestamp, "HIGH", "Successful login after repeated failures", ip, success.username, len(prior) + 1, f"Successful authentication followed {len(prior)} failures from {ip}; validate the account and source.", "AUTH-002"))
                break
    # Network port events can identify repeated distinct destination ports from one source.
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.source_ip and event.destination_port is not None and any(x in event.event_type for x in ("network", "connection", "firewall", "flow")):
            by_ip[event.source_ip].append(event)
        if event.destination_port in {21, 23, 445, 3389, 5900}:
            alerts.append(Alert(event.timestamp, "MEDIUM", "Connection to sensitive service", event.source_ip, event.username, 1, f"Observed a connection to destination port {event.destination_port}; confirm it is expected.", "NET-002"))
    for ip, group in by_ip.items():
        ports = {e.destination_port for e in group if e.destination_port is not None}
        if len(ports) >= 8:
            last = max(group, key=lambda e: e.timestamp)
            alerts.append(Alert(last.timestamp, "MEDIUM", "Possible port scan", ip, None, len(ports), f"Observed connections to {len(ports)} distinct destination ports from {ip}.", "NET-001"))
    unique = {(a.rule_id, a.source_ip, a.username): a for a in alerts}
    return sorted(unique.values(), key=lambda a: a.timestamp, reverse=True)


def sample_events() -> list[Event]:
    """Reproducible synthetic event dataset for demonstrations."""
    rng = random.Random(31)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    events: list[Event] = []
    actors = [("10.0.2.18", "j.smith"), ("10.0.4.22", "a.patel"), ("172.16.4.9", "svc-backup"), ("203.0.113.77", "admin")]
    for hour in range(24):
        for _ in range(rng.randint(5, 13)):
            ip, user = rng.choice(actors[:3])
            event_type = rng.choice(["authentication", "network_connection", "process", "dns_query"])
            timestamp = now - timedelta(hours=23-hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            if event_type == "authentication":
                status = "failed" if rng.random() < .12 else "success"
                events.append(Event(timestamp, event_type, ip, user, status, f"User {user} {status} login"))
            elif event_type == "network_connection":
                port = rng.choice([443, 80, 53, 22, 8080])
                events.append(Event(timestamp, event_type, ip, user, "allowed", f"Outbound connection to port {port}", port))
            else:
                events.append(Event(timestamp, event_type, ip, user, "observed", f"Observed {event_type.replace('_', ' ')} activity"))
    # A clearly synthetic attack sequence for a useful first-run dashboard.
    attacker = "198.51.100.24"
    attack_start = now - timedelta(minutes=19)
    for i in range(7):
        events.append(Event(attack_start + timedelta(minutes=i), "authentication", attacker, "admin", "failed", "Failed SSH password for admin"))
    events.append(Event(now - timedelta(minutes=10), "authentication", attacker, "admin", "success", "Accepted password for admin"))
    for i in range(9):
        events.append(Event(now - timedelta(minutes=20) + timedelta(seconds=i * 40), "network_connection", "203.0.113.44", None, "denied", f"Connection attempt on port {2000+i}", 2000+i))
    return sorted(events, key=lambda e: e.timestamp)
