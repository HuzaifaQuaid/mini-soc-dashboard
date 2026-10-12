from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from soc import Alert, analyze_events, load_events, sample_events
from triage import STATUSES, TriageRecord, TriageStore, alert_id


st.set_page_config(page_title="Sentinel SOC", page_icon="◈", layout="wide")

ROOT = Path(__file__).parent
DB_PATH = ROOT / "data" / "soc.db"


def inject_styles() -> None:
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
    .stApp { background: #0b0f14; color: #e8edf2; }
    [data-testid="stSidebar"] { background: #10161e; border-right: 1px solid #202a35; }
    [data-testid="stHeader"] { background: rgba(11,15,20,.8); }
    h1,h2,h3 { letter-spacing: -.04em; }
    .eyebrow { color:#7b8a9b; font: 500 11px 'DM Mono',monospace; letter-spacing:.14em; text-transform:uppercase; }
    .subtle { color:#8b98a7; font-size:13px; }
    .metric-card { background:linear-gradient(145deg,#141c25,#10161d); border:1px solid #222e3a; border-radius:10px; padding:18px 20px; min-height:116px; }
    .metric-label { color:#8b98a7; font:500 11px 'DM Mono',monospace; letter-spacing:.1em; text-transform:uppercase; }
    .metric-value { color:#f1f5f9; font-size:30px; line-height:1.35; font-weight:700; }
    .metric-note { color:#6f7f8e; font-size:11px; }
    .section-head { border-bottom:1px solid #202a35; padding: 8px 0 13px; margin-bottom:12px; }
    .stButton>button { border-radius:7px; border:1px solid #2a3948; background:#18222d; color:#e6edf3; }
    .stButton>button:hover { border-color:#30d6a0; color:#30d6a0; }
    div[data-testid="stDataFrame"] { border:1px solid #202a35; border-radius:8px; overflow:hidden; }
    </style>
    """, unsafe_allow_html=True)


def metric(label: str, value: str, note: str, color: str = "#f1f5f9") -> None:
    st.markdown(f'<div class="metric-card"><div class="metric-label">{label}</div><div class="metric-value" style="color:{color}">{value}</div><div class="metric-note">{note}</div></div>', unsafe_allow_html=True)


def alert_frame(alerts: list[Alert]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Time (UTC)": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "Severity": a.severity,
        "Detection": a.title,
        "Source IP": a.source_ip or "—",
        "User": a.username or "—",
        "Events": a.event_count,
        "Description": a.description,
        "Rule ID": a.rule_id,
    } for a in alerts])


def main(public_demo: bool = False) -> None:
    inject_styles()
    st.markdown('<div class="eyebrow">SECURITY OPERATIONS CENTER / COMMUNITY EDITION</div>', unsafe_allow_html=True)
    title, status = st.columns([4, 1])
    with title:
        st.title("Sentinel SOC")
        st.markdown('<div class="subtle">Security event monitoring · detection · triage</div>', unsafe_allow_html=True)
    with status:
        st.markdown('<div style="text-align:right;padding-top:20px;color:#30d6a0;font:12px DM Mono">● SYSTEM ONLINE</div>', unsafe_allow_html=True)

    if public_demo:
        st.info("Public portfolio demo · Synthetic events only. Uploads are disabled. Decisions belong to this browser session and are not saved permanently. Do not enter sensitive information.")

    with st.sidebar:
        st.markdown("### ◈ Sentinel")
        st.markdown('<div class="eyebrow">Workspace</div>', unsafe_allow_html=True)
        source_mode = st.radio("Event source", ["Demo dataset"] if public_demo else ["Demo dataset", "Upload log file"], label_visibility="collapsed")
        uploaded = None
        if source_mode == "Upload log file":
            uploaded = st.file_uploader("Upload JSON or CSV", type=["json", "jsonl", "csv"])
            st.caption("Expected fields: timestamp, event_type, source_ip, username, status, message")
        st.divider()
        st.markdown('<div class="eyebrow">Detection settings</div>', unsafe_allow_html=True)
        threshold = st.slider("Failed logins before alert", 3, 20, 5)
        window_minutes = st.slider("Detection window (minutes)", 1, 30, 10)
        st.divider()
        st.caption("Built for safe analysis of sample or authorized logs. No live blocking or external scanning.")

    try:
        if uploaded:
            content = uploaded.getvalue()
            dataset_id = hashlib.sha256(content).hexdigest()
            raw = content.decode("utf-8-sig")
            events = load_events(raw, uploaded.name)
        elif source_mode == "Upload log file":
            events = []
        else:
            if "demo_events" not in st.session_state:
                st.session_state.demo_events = sample_events()
            events = st.session_state.demo_events
            dataset_id = "demo"
    except (ValueError, UnicodeDecodeError) as exc:
        st.error(f"Could not read this file: {exc}")
        return
    if not events:
        if source_mode == "Upload log file" and not uploaded:
            st.info("Upload a CSV or JSON log file to begin, or select Demo dataset.")
        else:
            st.info("This file contains no events. Upload a non-empty log file.")
        return

    alerts = analyze_events(events, threshold=threshold, window_minutes=window_minutes)
    frame = alert_frame(alerts)
    store = None
    if public_demo:
        if "public_triage" not in st.session_state:
            st.session_state.public_triage = {}
        records = st.session_state.public_triage
    else:
        try:
            store = TriageStore(DB_PATH)
            records = store.records()
        except (sqlite3.Error, OSError) as exc:
            st.error(f"Local triage storage is unavailable: {exc}")
            return
    if alerts:
        frame["Alert ID"] = [alert_id(a, dataset_id) for a in alerts]
        frame["Status"] = [records.get(key, TriageRecord()).status for key in frame["Alert ID"]]
        frame["Analyst notes"] = [records.get(key, TriageRecord()).notes for key in frame["Alert ID"]]
    open_count = sum(records.get(alert_id(a, dataset_id), TriageRecord()).status in ("Open", "Investigating") for a in alerts)
    now = datetime.now(timezone.utc)
    high = sum(a.severity == "HIGH" for a in alerts)
    medium = sum(a.severity == "MEDIUM" for a in alerts)
    events_today = sum(e.timestamp.date() == now.date() for e in events)
    m1, m2, m3, m4 = st.columns(4)
    with m1: metric("Events analyzed", f"{len(events):,}", f"{events_today} observed today", "#dce6f0")
    with m2: metric("Active alerts", f"{open_count:02}", "Open or under investigation", "#30d6a0" if not open_count else "#ffbd5b")
    with m3: metric("High severity", f"{high:02}", "Requires analyst review", "#ff6978" if high else "#dce6f0")
    with m4: metric("Medium severity", f"{medium:02}", "Investigate and validate", "#ffbd5b" if medium else "#dce6f0")

    st.write("")
    left, right = st.columns([1.6, 1])
    with left:
        st.markdown('<div class="section-head"><span class="eyebrow">Alert volume / severity</span></div>', unsafe_allow_html=True)
        if alerts:
            chart_df = frame.copy()
            chart_df["Time"] = pd.to_datetime(chart_df["Time (UTC)"], utc=True).dt.floor("h")
            chart_data = chart_df.groupby(["Time", "Severity"]).size().reset_index(name="Alerts")
            fig = px.bar(chart_data, x="Time", y="Alerts", color="Severity", barmode="stack", color_discrete_map={"HIGH":"#ff6978", "MEDIUM":"#ffbd5b", "LOW":"#30d6a0"})
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=285, margin=dict(l=0,r=0,t=12,b=0), legend_title_text="", font=dict(family="Manrope", color="#9aa8b6"), xaxis_title="", yaxis_title="Alert count")
            fig.update_xaxes(gridcolor="#202a35")
            fig.update_yaxes(gridcolor="#202a35", dtick=1)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
        else:
            st.success("No alerts matched the current detection rules.")
    with right:
        st.markdown('<div class="section-head"><span class="eyebrow">Event composition</span></div>', unsafe_allow_html=True)
        counts = Counter(e.event_type.replace("_", " ").title() for e in events)
        pie = px.pie(names=list(counts.keys()), values=list(counts.values()), hole=.68, color_discrete_sequence=["#30d6a0", "#60a5fa", "#ffbd5b", "#ad8cff", "#ff6978"])
        pie.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=285, margin=dict(l=0,r=0,t=12,b=0), showlegend=True, legend=dict(font=dict(size=10), orientation="h", y=-.12), font=dict(family="Manrope", color="#9aa8b6"))
        pie.update_traces(textinfo="none", marker=dict(line=dict(color="#0b0f14", width=3)))
        st.plotly_chart(pie, use_container_width=True, config={"displayModeBar":False})

    st.markdown('<div class="section-head"><span class="eyebrow">Detection queue</span></div>', unsafe_allow_html=True)
    f1, f2, f3, f4 = st.columns([1.3, 1.3, 1.3, 2.2])
    with f1: sev_filter = st.selectbox("Severity", ["All", "HIGH", "MEDIUM", "LOW"])
    with f2: type_filter = st.selectbox("Detection", ["All"] + sorted(frame["Detection"].unique().tolist()) if not frame.empty else ["All"])
    with f3: sort_order = st.selectbox("Sort", ["Newest", "Oldest"])
    with f4: search = st.text_input("Search", placeholder="IP address, username, detection…")
    status_filter = st.selectbox("Triage status", ["All"] + list(STATUSES))
    shown = frame.copy()
    if not shown.empty:
        if sev_filter != "All": shown = shown[shown["Severity"] == sev_filter]
        if type_filter != "All": shown = shown[shown["Detection"] == type_filter]
        if status_filter != "All": shown = shown[shown["Status"] == status_filter]
        if search:
            matches = shown.drop(columns=["Alert ID"]).astype(str).apply(lambda col: col.str.contains(search, case=False, na=False, regex=False)).any(axis=1)
            shown = shown[matches]
        shown = shown.sort_values("Time (UTC)", ascending=sort_order == "Oldest")
    if shown.empty:
        st.info("No alerts match these filters.")
    else:
        st.dataframe(shown.drop(columns=["Rule ID", "Alert ID"]), use_container_width=True, hide_index=True, height=min(430, 42 + len(shown) * 38), column_config={"Severity": st.column_config.TextColumn(width="small"), "Detection": st.column_config.TextColumn(width="medium"), "Description": st.column_config.TextColumn(width="large")})
        st.download_button("↓ Export filtered alerts as CSV", shown.to_csv(index=False).encode(), "sentinel-alerts.csv", "text/csv")

        st.subheader("Analyst workspace")
        rows = shown.set_index("Alert ID")
        selected = st.selectbox("Alert to investigate", rows.index.tolist(), format_func=lambda key: f"{rows.loc[key, 'Time (UTC)']} · {rows.loc[key, 'Detection']} · {rows.loc[key, 'Source IP']}")
        record = records.get(selected, TriageRecord())
        st.write(rows.loc[selected, "Description"])
        st.caption(f"Rule: {rows.loc[selected, 'Rule ID']} · Last saved: {record.updated_at or 'Not yet reviewed'}")
        with st.form(f"triage-{selected}"):
            decision = st.selectbox("Analyst status", STATUSES, index=STATUSES.index(record.status))
            notes = st.text_area("Investigation notes", value=record.notes, max_chars=10000)
            submitted = st.form_submit_button("Save triage")
        if submitted:
            try:
                if public_demo:
                    records[selected] = TriageRecord(decision, notes, datetime.now(timezone.utc).isoformat())
                else:
                    store.save(selected, decision, notes)
            except (sqlite3.Error, OSError, ValueError) as exc:
                st.error(f"Could not save triage: {exc}")
            else:
                st.session_state.triage_saved = True
                st.rerun()
        if st.session_state.pop("triage_saved", False):
            st.success("Triage updated for this session only." if public_demo else "Triage saved locally.")
        if public_demo:
            st.caption("Practice notes and statuses are temporary, isolated to this session, and may reset on reload or restart. Downloads include your notes. Do not enter sensitive information.")
        else:
            st.caption("Statuses and notes are stored in data/soc.db. Raw uploaded logs are not persisted. Do not include sensitive information in notes on shared deployments.")

    with st.expander("Detection rules & methodology"):
        st.markdown("""
        - **Repeated failed logins** — counts failed authentication events by source IP within the selected time window.
        - **Successful login after failures** — flags a successful login following repeated failures from the same IP.
        - **Suspicious network activity** — flags known high-risk ports and basic port-scan patterns in network events.
        - **Severity** — rules assign severity based on event pattern and volume; alerts are indicators for review, not proof of compromise.

        The included demo data is synthetic. Detection rules execute on the computer hosting this application, not exclusively in your browser.
        """)
        st.caption("Public demo: no log uploads or permanent triage storage." if public_demo else "Local version: uploaded logs are processed in memory and are not sent to an external analysis service.")

    st.markdown('<div style="border-top:1px solid #202a35;margin-top:28px;padding-top:14px;color:#627181;font:10px DM Mono">SENTINEL SOC · LOCAL ANALYSIS · UTC TIMESTAMPS · REVIEW ALERTS BEFORE TAKING ACTION</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
