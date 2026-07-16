from typing import Optional
from fastapi import APIRouter, Query
from request_logger import request_logger

router = APIRouter()


@router.get("/api/dashboard/metrics")
async def get_metrics():
    return await request_logger.get_metrics()


@router.get("/api/dashboard/feed")
async def get_feed(
    search: str = "",
    verdict: str = "all",
    rejectionCode: Optional[str] = None,
    country: Optional[str] = None,
    app: Optional[str] = None,
    dateFrom: Optional[str] = None,
    dateTo: Optional[str] = None,
    page: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=200),
):
    """Dashboard feed теперь читает напрямую из DB (2026-06-21), с pagination + filters.
    Раньше был in-memory deque(500) с hard-cap 200. UI hook poll'ит каждые 3 сек для
    real-time эффекта (только когда page=1 и фильтры пустые — иначе auto-refresh off)."""
    return await request_logger.query_logs(
        search=search,
        verdict=verdict,
        rejection_code=rejectionCode,
        country=country,
        package_name=app,
        date_from=dateFrom,
        date_to=dateTo,
        page=page,
        page_size=pageSize,
    )


@router.get("/api/dashboard/traffic")
async def get_traffic():
    return await request_logger.get_traffic_hourly()


@router.get("/api/dashboard/rejections")
async def get_rejections():
    return await request_logger.get_rejections()


@router.get("/api/dashboard/app-stats")
async def get_app_stats():
    return await request_logger.get_app_stats_all()


@router.get("/api/dashboard/app-stats/{package_name:path}")
async def get_app_detail(package_name: str):
    return await request_logger.get_app_detail(package_name)
