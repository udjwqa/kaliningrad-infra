from typing import Optional
from fastapi import APIRouter, Query
from request_logger import request_logger

router = APIRouter()


@router.get("/api/audit/logs")
async def get_audit_logs(
    search: str = "",
    verdict: str = "all",
    rejectionCode: Optional[str] = None,
    country: Optional[str] = None,
    app: Optional[str] = None,
    dateFrom: Optional[str] = None,
    dateTo: Optional[str] = None,
    anonymousType: Optional[str] = None,
    page: int = Query(1, ge=1),
    pageSize: int = Query(25, ge=1, le=100),
):
    return await request_logger.query_logs(
        search=search,
        verdict=verdict,
        rejection_code=rejectionCode,
        country=country,
        package_name=app,
        date_from=dateFrom,
        date_to=dateTo,
        anonymous_type=anonymousType,
        page=page,
        page_size=pageSize,
    )
