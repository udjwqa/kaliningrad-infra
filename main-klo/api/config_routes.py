from fastapi import APIRouter
from pydantic import BaseModel
from models import EngineConfig, OfferConfig
from config import config_store

router = APIRouter()


class DebugAllow(BaseModel):
    ips: list[str] = []
    instances: list[str] = []


@router.get("/api/config")
async def get_config() -> EngineConfig:
    return config_store.engine


@router.put("/api/config")
async def update_config(config: EngineConfig):
    config_store.update_engine(config)
    return {"success": True}


@router.get("/api/offers")
async def get_offers() -> OfferConfig:
    return config_store.offers


@router.put("/api/offers")
async def update_offers(config: OfferConfig):
    config_store.update_offers(config)
    return {"success": True}


@router.get("/api/debug-allow")
async def get_debug_allow() -> DebugAllow:
    return DebugAllow(**config_store.get_debug())


@router.put("/api/debug-allow")
async def set_debug_allow(body: DebugAllow):
    config_store.set_debug(body.ips, body.instances)
    return config_store.get_debug()
