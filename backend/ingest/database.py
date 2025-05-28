from .models import Base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from typing import AsyncGenerator
import logging

from .config import settings

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=20,
    max_overflow=0,
    pool_pre_ping=True,
    pool_recycle=3600,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=True,
    autocommit=False,
)  # TODO: check if this is correct... i dont think it is

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

async def close_db():
    """Close database connections"""
    await engine.dispose()
    logger.info("Database connections closed")