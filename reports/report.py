from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch


def generate_report(
        filename,
        total,
        benign,
        attacks,
        tcp,
        udp,
        avg_confidence,
        severity,
        top_sources,
        top_destinations,
        recent_alerts
):

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "<b><font size=18>"
            "AI Network Intrusion Detection Report"
            "</font></b>",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 0.3 * inch))

    summary = [

        ["Metric", "Value"],

        ["Total Flows", total],

        ["Benign", benign],

        ["Attacks", attacks],

        ["TCP", tcp],

        ["UDP", udp],

        ["Average Confidence",
         f"{avg_confidence:.2f}%"],

        ["Risk Level", severity]

    ]

    table = Table(summary)

    table.setStyle(

        TableStyle([

            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("GRID", (0, 0), (-1, -1), 1, colors.black),

            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),

            ("ALIGN", (0, 0), (-1, -1), "CENTER"),

            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0, 0), (-1, 0), 12)

        ])

    )

    story.append(table)

    story.append(Spacer(1, 0.3 * inch))

    story.append(
        Paragraph(
            "<b>Top Source IPs</b>",
            styles["Heading2"]
        )
    )

    for ip, count in top_sources:

        story.append(
            Paragraph(
                f"{ip} ({count})",
                styles["BodyText"]
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    story.append(
        Paragraph(
            "<b>Top Destination IPs</b>",
            styles["Heading2"]
        )
    )

    for ip, count in top_destinations:

        story.append(
            Paragraph(
                f"{ip} ({count})",
                styles["BodyText"]
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    story.append(
        Paragraph(
            "<b>Recent Alerts</b>",
            styles["Heading2"]
        )
    )

    if recent_alerts:

        for alert in recent_alerts:

            story.append(

                Paragraph(

                    f"""
                    {alert['timestamp']}<br/>
                    Attack :
                    {alert['attack']}<br/>
                    Source :
                    {alert['source_ip']}<br/>
                    Confidence :
                    {alert['confidence']:.2f}
                    """,

                    styles["BodyText"]

                )

            )

    else:

        story.append(

            Paragraph(
                "No Active Alerts",
                styles["BodyText"]
            )

        )

    doc.build(story)