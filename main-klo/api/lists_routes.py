from typing import List
from fastapi import APIRouter, HTTPException
from models import BlockList, BlockListUpdate
from lists_manager import lists_manager

router = APIRouter()


@router.get("/api/lists")
async def get_all_lists() -> List[BlockList]:
    return lists_manager.get_all()


@router.put("/api/lists/{list_id}")
async def update_list(list_id: str, body: BlockListUpdate):
    ok = lists_manager.update_list(list_id, body.items)
    if not ok:
        raise HTTPException(status_code=404, detail=f"List '{list_id}' not found")
    return {"success": True, "id": list_id, "count": len(body.items)}
