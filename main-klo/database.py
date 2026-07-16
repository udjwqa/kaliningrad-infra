import os
import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger("database")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://panel:panel@localhost:5432/panel"
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,   # пинговать каждое connection перед использованием — лечит «мёртвый пул»
    pool_recycle=1800,    # пересоздавать connections старше 30 минут (idle timeout safety)
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
    # 2026-06-23: явный import всех моделей для Base.metadata.create_all
    from db_models import RequestLog, BannedIP, AutoBannedEntry, Report  # noqa: F401
    from sqlalchemy import text as _sql_text
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # 2026-07-09 Analytics: функциональный индекс для быстрого distinct-count
        # по instance_id — он живёт в raw_payload, distinct без индекса медленный.
        await conn.execute(_sql_text(
            "CREATE INDEX IF NOT EXISTS idx_reqlogs_instance_id "
            "ON request_logs ((raw_payload->'headers'->>'x-instance-id')) "
            "WHERE raw_payload IS NOT NULL"
        ))
    logger.info("Database tables created (+ analytics functional index)")


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
