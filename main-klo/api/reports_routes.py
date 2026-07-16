"""
Docs Hub — /api/reports CRUD (2026-07-09).

Свободные markdown-отчёты пользователей панели. Auth уровня Backend — только
X-Admin-Key (AdminAuthMiddleware в main.py). Author_email/name инъектируются
panel proxy из NextAuth session — backend им доверяет и просто сохраняет.
Проверка «редактировать/удалять может только автор» — на уровне panel UI
(кнопки скрываются) + panel proxy (валидация email match перед PUT/DELETE).
"""
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, desc

from database import async_session
from db_models import Report

router = APIRouter()


class ReportCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    body_md: str = Field(default="", max_length=200_000)
    tags: list[str] = Field(default_factory=list)
    author_email: str = Field(..., min_length=3, max_length=200)
    author_name: str | None = Field(default=None, max_length=200)


class ReportUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    body_md: str | None = Field(default=None, max_length=200_000)
    tags: list[str] | None = None


def _clean_tags(tags: list[str]) -> list[str]:
    out = []
    seen = set()
    for t in tags or []:
        s = str(t).strip().lower()
        if s and s not in seen and len(s) <= 40:
            seen.add(s)
            out.append(s)
    return out[:20]


@router.get("/api/reports")
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Feed отчётов — последние сверху."""
    async with async_session() as session:
        result = await session.execute(
            select(Report).order_by(desc(Report.created_at)).limit(limit).offset(offset)
        )
        rows = result.scalars().all()
        return [r.to_dict() for r in rows]


@router.get("/api/reports/{report_id}")
async def get_report(report_id: str):
    try:
        rid = UUID(report_id)
    except ValueError:
        return JSONResponse({"error": "invalid id"}, status_code=400)
    async with async_session() as session:
        r = await session.get(Report, rid)
        if not r:
            return JSONResponse({"error": "not found"}, status_code=404)
        return r.to_dict()


@router.post("/api/reports")
async def create_report(body: ReportCreate):
    async with async_session() as session:
        r = Report(
            author_email=body.author_email.strip().lower(),
            author_name=body.author_name.strip() if body.author_name else None,
            title=body.title.strip(),
            body_md=body.body_md,
            tags=_clean_tags(body.tags),
        )
        session.add(r)
        await session.commit()
        await session.refresh(r)
        return r.to_dict()


@router.put("/api/reports/{report_id}")
async def update_report(report_id: str, body: ReportUpdate):
    try:
        rid = UUID(report_id)
    except ValueError:
        return JSONResponse({"error": "invalid id"}, status_code=400)
    async with async_session() as session:
        r = await session.get(Report, rid)
        if not r:
            return JSONResponse({"error": "not found"}, status_code=404)
        if body.title is not None:
            r.title = body.title.strip()
        if body.body_md is not None:
            r.body_md = body.body_md
        if body.tags is not None:
            r.tags = _clean_tags(body.tags)
        r.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(r)
        return r.to_dict()


@router.delete("/api/reports/{report_id}")
async def delete_report(report_id: str):
    try:
        rid = UUID(report_id)
    except ValueError:
        return JSONResponse({"error": "invalid id"}, status_code=400)
    async with async_session() as session:
        r = await session.get(Report, rid)
        if not r:
            return JSONResponse({"error": "not found"}, status_code=404)
        await session.delete(r)
        await session.commit()
        return {"success": True, "id": report_id}
