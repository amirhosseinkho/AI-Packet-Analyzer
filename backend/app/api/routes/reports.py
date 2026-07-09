from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import GenerateReportRequest, ReportSchema
from app.database import get_db
from app.models.report import Report
from app.reporting import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportSchema)
async def create_report(
    req: GenerateReportRequest,
    db: AsyncSession = Depends(get_db),
) -> ReportSchema:
    report_row = await generate_report(
        db=db,
        name=req.name,
        fmt=req.format,
        period_start=req.period_start,
        period_end=req.period_end,
    )
    return ReportSchema.model_validate(report_row)


@router.get("", response_model=list[ReportSchema])
async def list_reports(db: AsyncSession = Depends(get_db)) -> list[ReportSchema]:
    result = await db.execute(select(Report).order_by(Report.created_at.desc()).limit(50))
    return [ReportSchema.model_validate(r) for r in result.scalars().all()]


@router.get("/{report_id}/download")
async def download_report(report_id: int, db: AsyncSession = Depends(get_db)) -> FileResponse:
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    from pathlib import Path

    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    media_type = {
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }.get(report.format, "application/octet-stream")

    return FileResponse(path=str(path), media_type=media_type, filename=path.name)
