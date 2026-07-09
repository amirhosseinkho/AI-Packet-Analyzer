from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.flow import Flow
from app.models.packet import Packet


async def generate_pdf_report(
    db: AsyncSession,
    output_path: Path,
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
) -> dict:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ImportError("reportlab is required: pip install reportlab") from exc

    # Gather stats
    pkt_count = (await db.execute(select(func.count()).select_from(Packet))).scalar_one()
    flow_count = (await db.execute(select(func.count()).select_from(Flow))).scalar_one()
    anomaly_count = (
        await db.execute(select(func.count()).select_from(Anomaly).where(Anomaly.is_anomaly.is_(True)))
    ).scalar_one()

    top_anomalies = (
        await db.execute(
            select(Anomaly)
            .where(Anomaly.is_anomaly.is_(True))
            .order_by(Anomaly.ensemble_score.desc())
            .limit(20)
        )
    ).scalars().all()

    doc = SimpleDocTemplate(str(output_path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("AI Packet Analyzer – Security Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Summary table
    summary_data = [
        ["Metric", "Value"],
        ["Total Packets", str(pkt_count)],
        ["Total Flows", str(flow_count)],
        ["Anomalies Detected", str(anomaly_count)],
        ["Anomaly Rate", f"{(anomaly_count / flow_count * 100):.1f}%" if flow_count else "N/A"],
    ]
    summary_table = Table(summary_data, colWidths=[8 * cm, 6 * cm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    # Anomaly table
    if top_anomalies:
        story.append(Paragraph("Top Anomalies", styles["Heading2"]))
        anomaly_data = [["Flow ID", "Type", "Severity", "Score", "Explanation"]]
        for a in top_anomalies:
            anomaly_data.append(
                [
                    a.flow_id[:20] + "…" if len(a.flow_id) > 20 else a.flow_id,
                    a.anomaly_type or "unknown",
                    a.severity or "",
                    f"{a.ensemble_score:.3f}" if a.ensemble_score else "",
                    (a.explanation or "")[:80] + "…" if a.explanation and len(a.explanation) > 80 else (a.explanation or ""),
                ]
            )
        anomaly_table = Table(anomaly_data, colWidths=[4 * cm, 3 * cm, 2.5 * cm, 2 * cm, 7 * cm])
        anomaly_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e94560")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff0f0")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )
        story.append(anomaly_table)

    doc.build(story)
    return {"packets": pkt_count, "flows": flow_count, "anomalies": anomaly_count}
