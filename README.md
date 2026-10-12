# Sentinel SOC — Mini Security Operations Center Dashboard

A local-first, portfolio-ready SOC dashboard for exploring security events, testing transparent detection rules, and triaging alerts. The first-run dataset is synthetic. Uploaded data is parsed in memory and is not sent to a third party.

> This is a learning and demonstration project, not a production SIEM. Alerts are indicators that require analyst validation. It does not block traffic or perform live scanning.

## Features

- Dashboard metrics for analyzed events and alert severity
- Timeline chart and event-type composition chart
- Rule-based detections for repeated failed authentication, successful login after repeated failures, connections to sensitive services, and possible port scanning
- Adjustable failed-login threshold and time window
- Search, severity and detection filters, newest/oldest sorting
- Export filtered alerts to CSV
- Analyst workspace with Open, Investigating, Resolved, and False positive statuses
- Persistent analyst notes and decisions in local SQLite storage (`data/soc.db`)
- Upload CSV, JSON array/object, or JSON Lines logs
- Local-only processing; no external integrations or automatic response

## Quick start (macOS/Linux)

```bash
cd "Mini Security Operations Center Dashboard"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Streamlit prints a local URL, usually `http://localhost:8501`.

## Public portfolio demo

**Hosted demo:** https://huzaifa-sentinel-soc.streamlit.app/

**Source code:** https://github.com/HuzaifaQuaid/mini-soc-dashboard

The separate `public_app.py` entry point disables log uploads and uses only synthetic events. Analyst statuses and notes live in Streamlit session state, not SQLite, and are separate for each visitor session. They can reset on reload or restart. Do not enter sensitive information; exported CSV files include practice notes.

```bash
python -m streamlit run public_app.py
```

For Streamlit Community Cloud, publish source files to GitHub and select **public_app.py** as the main file (not app.py). Use Python 3.13, the tested version. Do not publish `.venv`, private logs, secrets or `data/soc.db`. The full local entry point remains `app.py` with uploads and persistent triage. A hosted public demo processes synthetic data on the host; it is not live security monitoring.

## Supported upload fields (local version)

The parser accepts common aliases. Recommended columns/keys:

| Field | Common aliases | Example |
| --- | --- | --- |
| `timestamp` | `time`, `datetime` | `2026-10-07T12:30:00Z` |
| `event_type` | `type`, `action` | `authentication` |
| `source_ip` | `src_ip`, `ip` | `198.51.100.24` |
| `username` | `user` | `admin` |
| `status` | `result` | `failed`, `success` |
| `message` | `description` | `Failed SSH password for admin` |
| `destination_port` | `dest_port`, `port` | `22` |

Example CSV:

```csv
timestamp,event_type,source_ip,username,status,message,destination_port
2026-10-07T12:01:00Z,authentication,198.51.100.24,admin,failed,Failed SSH password,22
```

Example JSON:

```json
[
  {"timestamp":"2026-10-07T12:01:00Z","event_type":"authentication","source_ip":"198.51.100.24","username":"admin","status":"failed","message":"Failed SSH password","destination_port":22}
]
```

## Detection logic

- **AUTH-001 — Repeated failed logins:** at least the configured number of failed authentication events from one source IP within the configured sliding time window.
- **AUTH-002 — Successful login after repeated failures:** a successful authentication from the same IP after the configured number of failures within the time window.
- **NET-001 — Possible port scan:** eight or more distinct destination ports observed for one source IP in network/connection/firewall/flow events.
- **NET-002 — Sensitive service connection:** observed destination port is one of 21, 23, 445, 3389, or 5900. This is context-dependent and not inherently malicious.

The detections are intentionally explainable and lightweight. They are not a substitute for correlation with asset context, allowlists, identity provider logs, or a mature SIEM.

## Project structure

```text
app.py          Streamlit dashboard and UI
soc.py          Event normalization and detection logic
triage.py       SQLite-backed alert status and analyst notes
tests/          Unit tests for parser and detections
requirements.txt
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests cover parsing, detections, persistence, and dashboard triage interactions.

## Triage storage

Select an alert in the analyst workspace, choose a status, add notes, and click **Save triage**. Active alerts include Open and Investigating statuses. Use the triage filter to find resolved alerts or false positives; CSV exports include statuses and notes.

Decisions are matched to the exact detection and uploaded file contents. Uploading the same file restores its decisions; changed files or changed detections receive new identities. Demo events stay stable during a browser session, but a fresh demo dataset can generate new alert identities. All local browser sessions share the same database; there is no authentication or per-analyst access control.

Only alert identifiers, statuses, notes, and update timestamps are persisted. Raw uploaded logs remain in memory. Notes may contain sensitive information, so keep `data/soc.db` private. Back up this file to preserve decisions.

## Next improvements

- Add CI checks
- Add Windows Event Log and syslog parsers
- Add configurable rules and allowlists
- Add Docker deployment and a demo screenshot

## Safety and privacy

Use only logs you are authorized to analyze. The app processes uploaded file contents in memory, but Streamlit itself may display data in the local browser session. Analyst notes and statuses are persisted locally. Avoid uploading sensitive production logs to shared or public deployments. The demo IPs use documentation ranges where appropriate.
