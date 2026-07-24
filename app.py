import pandas as pd
import plotly.express as px
from reports.report import generate_report
from flask import Flask, render_template, request, send_file
from database.db import Database
from datetime import datetime
import os
import logging

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/app.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

app = Flask(__name__)

db = Database()

# ----------------------------------------------------------------
# Shared chart theming: transparent background + dashboard palette
# so Plotly figures blend into the dark SOC dashboard instead of
# rendering as white boxes.
# ----------------------------------------------------------------

CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#8b98ac", family="Inter, sans-serif", size=12),
    margin=dict(l=10, r=10, t=40, b=10),
    legend=dict(bgcolor="rgba(0,0,0,0)"),
)

ATTACK_COLOR_SEQUENCE = [
    "#34d399", "#f9576a", "#f5b942", "#3fd0c9",
    "#b183f0", "#6d8ee8", "#ff5f5f", "#5a6579"
]


def style_chart(fig):
    fig.update_layout(**CHART_LAYOUT)
    return fig


@app.route("/")
def home():
    logging.info("Dashboard opened")
    rows = db.fetch_all()

    columns = [
        "id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "attack",
        "confidence",
        "anomaly",
        "anomaly_score",
        "duration",
        "total_packets",
        "total_bytes"
    ]

    df = pd.DataFrame(rows, columns=columns)

    # -----------------------------
    # Search & Filters
    # -----------------------------

    ip = request.args.get("ip", "").strip()

    attack = request.args.get("attack", "")

    filtered = rows

    if ip:

        filtered = [
            row for row in filtered
            if ip in row[2] or ip in row[3]
        ]

    if attack:

        filtered = [
            row for row in filtered
            if row[7] == attack
        ]

    # -----------------------------
    # Dashboard Statistics
    # -----------------------------

    total = len(filtered)

    benign = sum(
        1 for r in filtered
        if r[7] == "BENIGN"
    )

    attacks = total - benign

    tcp = sum(
        1 for r in filtered
        if r[6] == 6
    )

    udp = sum(
        1 for r in filtered
        if r[6] == 17
    )

    avg_confidence = 0

    if total:

        avg_confidence = (
            sum(r[8] for r in filtered)
            / total
        ) * 100

    # -----------------------------
    # Analytics
    # -----------------------------

    attack_chart = ""

    protocol_chart = ""

    top_sources = []

    top_destinations = []

    avg_packets = 0

    avg_bytes = 0

    avg_duration = 0

    recent_alerts = []

    timeline_chart = ""

    severity = "LOW"

    if not df.empty:

        # Attack Distribution

        attack_counts = (
            df["attack"]
            .value_counts()
            .reset_index()
        )

        attack_counts.columns = [
            "Attack",
            "Count"
        ]

        fig = px.pie(
            attack_counts,
            names="Attack",
            values="Count",
            hole=0.55,
            color_discrete_sequence=ATTACK_COLOR_SEQUENCE
        )

        style_chart(fig)

        attack_chart = fig.to_html(
            full_html=False,
            include_plotlyjs="cdn",
            config={"displayModeBar": False}
        )

        # Protocol Distribution

        protocol_map = {
            6: "TCP",
            17: "UDP",
            1: "ICMP"
        }

        df["Protocol"] = (
            df["protocol"]
            .map(protocol_map)
            .fillna("Other")
        )

        protocol_counts = (
            df["Protocol"]
            .value_counts()
            .reset_index()
        )

        protocol_counts.columns = [
            "Protocol",
            "Count"
        ]

        fig2 = px.pie(
            protocol_counts,
            names="Protocol",
            values="Count",
            hole=0.55,
            color_discrete_sequence=ATTACK_COLOR_SEQUENCE
        )

        style_chart(fig2)

        protocol_chart = fig2.to_html(
            full_html=False,
            include_plotlyjs=False,
            config={"displayModeBar": False}
        )

        # Top Source IPs

        top_sources = list(
            df["source_ip"]
            .value_counts()
            .head(5)
            .items()
        )

        # Top Destination IPs

        top_destinations = list(
            df["destination_ip"]
            .value_counts()
            .head(5)
            .items()
        )

        # Average Statistics

        avg_packets = round(
            df["total_packets"].mean(),
            2
        )

        avg_bytes = round(
            df["total_bytes"].mean(),
            2
        )

        avg_duration = round(
            df["duration"].mean(),
            2
        )

        # Recent Alerts

        recent_alerts = (
            df[df["attack"] != "BENIGN"]
            .sort_values(
                "timestamp",
                ascending=False
            )
            .head(5)
            .to_dict("records")
        )

        # -----------------------------
        # Attack Timeline
        # -----------------------------

        df["timestamp"] = pd.to_datetime(df["timestamp"])

        timeline = (
            df.groupby(
                df["timestamp"].dt.strftime("%H:%M")
            )
            .size()
            .reset_index(name="Flows")
        )

        fig3 = px.line(
            timeline,
            x="timestamp",
            y="Flows",
            markers=True,
            color_discrete_sequence=["#3fd0c9"]
        )

        fig3.update_traces(
            fill="tozeroy",
            fillcolor="rgba(63, 208, 201, 0.08)"
        )

        fig3.update_xaxes(gridcolor="#263041", title=None)
        fig3.update_yaxes(gridcolor="#263041", title=None)

        style_chart(fig3)

        timeline_chart = fig3.to_html(
            full_html=False,
            include_plotlyjs=False,
            config={"displayModeBar": False}
        )

        # -----------------------------
        # Severity
        # -----------------------------

        if attacks > 50:
            severity = "CRITICAL"

        elif attacks > 20:
            severity = "HIGH"

        elif attacks > 5:
            severity = "MEDIUM"

    # -----------------------------
    # Render Dashboard
    # -----------------------------

    return render_template(

        "index.html",

        rows=filtered,

        total=total,

        benign=benign,

        attacks=attacks,

        tcp=tcp,

        udp=udp,

        avg=round(avg_confidence, 2),

        last_updated=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),

        attack_filter=attack,

        ip_search=ip,

        attack_chart=attack_chart,

        protocol_chart=protocol_chart,

        top_sources=top_sources,

        top_destinations=top_destinations,

        avg_packets=avg_packets,

        avg_bytes=avg_bytes,

        avg_duration=avg_duration,

        recent_alerts=recent_alerts,

        timeline_chart=timeline_chart,

        severity=severity

    )

@app.route("/download")
def download():

    logging.info("CSV Report Downloaded")
    rows = db.fetch_all()

    columns = [
        "ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Attack",
        "Confidence",
        "Anomaly",
        "Anomaly Score",
        "Duration",
        "Packets",
        "Bytes"
    ]

    df = pd.DataFrame(rows, columns=columns)

    path = "detections.csv"

    df.to_csv(path, index=False)

    return send_file(path, as_attachment=True)

@app.route("/report")
def report():

    logging.info("PDF Report Downloaded")
    rows = db.fetch_all()

    total = len(rows)

    benign = sum(
        1 for r in rows
        if r[7] == "BENIGN"
    )

    attacks = total - benign

    tcp = sum(
        1 for r in rows
        if r[6] == 6
    )

    udp = sum(
        1 for r in rows
        if r[6] == 17
    )

    avg = 0

    if total:

        avg = (
            sum(r[8] for r in rows)
            / total
        ) * 100

    severity = "LOW"

    if attacks > 50:
        severity = "CRITICAL"

    elif attacks > 20:
        severity = "HIGH"

    elif attacks > 5:
        severity = "MEDIUM"

    df = pd.DataFrame(rows, columns=[
        "id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "attack",
        "confidence",
        "anomaly",
        "anomaly_score",
        "duration",
        "total_packets",
        "total_bytes"
    ])

    top_sources = list(
        df["source_ip"]
        .value_counts()
        .head(5)
        .items()
    )

    top_destinations = list(
        df["destination_ip"]
        .value_counts()
        .head(5)
        .items()
    )

    recent_alerts = (
        df[df["attack"] != "BENIGN"]
        .sort_values(
            "timestamp",
            ascending=False
        )
        .head(5)
        .to_dict("records")
    )

    filename = "network_ids_report.pdf"

    generate_report(

        filename,

        total,

        benign,

        attacks,

        tcp,

        udp,

        avg,

        severity,

        top_sources,

        top_destinations,

        recent_alerts

    )

    return send_file(
        filename,
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)