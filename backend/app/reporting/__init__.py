from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.report import Report

settings = get_settings()


async def generate_report(
    db: AsyncSession,
    name: str,
    fmt: str,
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
) -> Report:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{name}_{ts}.{fmt}"
    output_path = settings.report_output_dir / filename

    meta: dict = {}

    if fmt == "json":
        from app.reporting.json_report import generate_json_report
        meta = await generate_json_report(db, output_path, period_start, period_end)
    elif fmt == "csv":
        from app.reporting.csv_report import generate_csv_report
        meta = await generate_csv_report(db, output_path, period_start, period_end)
    elif fmt == "pdf":
        from app.reporting.pdf_report import generate_pdf_report
        meta = await generate_pdf_report(db, output_path, period_start, period_end)
    else:
        raise ValueError(f"Unsupported report format: {fmt!r}")

    file_size = output_path.stat().st_size if output_path.exists() else None

    report = Report(
        name=name,
        format=fmt,
        file_path=str(output_path),
        file_size_bytes=file_size,
        packet_count=meta.get("packets", meta.get("summary", {}).get("packet_count", 0)),
        flow_count=meta.get("flows", meta.get("summary", {}).get("flow_count", 0)),
        anomaly_count=meta.get("anomalies", meta.get("summary", {}).get("anomaly_count", 0)),
        period_start=period_start,
        period_end=period_end,
    )
    db.add(report)
    await db.flush()
    return report
