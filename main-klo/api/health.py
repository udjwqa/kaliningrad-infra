import time
from fastapi import APIRouter
from lists_manager import lists_manager

router = APIRouter()

_start_time = time.time()


@router.get("/api/health")
async def health():
    return {
        "status": "ok",
        "uptime": round(time.time() - _start_time),
        "lists_loaded": len(lists_manager.get_all()),
    }
