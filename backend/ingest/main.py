from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import strawberry
from strawberry.fastapi import GraphQLRouter
import uvicorn
import logging
from contextlib import asynccontextmanager
from typing import Optional

from .database import engine, get_db
from .models import Base
from .routers import telemetry, alerts, sensors, nodes
from .graphql_schema import schema
from .config import settings
from .spire_client import SpireClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    logger.info("Starting GPUShield Ingest Service")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app.state.spire_client = SpireClient()
    await app.state.spire_client.initialize()
    logger.info("GPUShield Ingest Service started successfully")
    yield
    logger.info("Shutting down GPUShield Ingest Service")
    if hasattr(app.state, "spire_client"):
        await app.state.spire_client.close()


app = FastAPI(
    title="GPUShield Telemetry Ingest API",
    description="Backend API for GPU runtime security telemetry ingestion and alerting",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify SPIRE SVID token"""
    try:
        # TODO: verify against SPIRE
        # ... for now... simple validation
        if not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

app.include_router(
    telemetry.router,
    prefix="/api/v1/telemetry",
    tags=["telemetry"],
    dependencies=[Depends(verify_token)] if settings.REQUIRE_AUTH else [],
)

app.include_router(
    alerts.router,
    prefix="/api/v1/alerts",
    tags=["alerts"],
    dependencies=[Depends(verify_token)] if settings.REQUIRE_AUTH else [],
)

app.include_router(
    sensors.router,
    prefix="/api/v1/sensors",
    tags=["sensors"],
    dependencies=[Depends(verify_token)] if settings.REQUIRE_AUTH else [],
)

app.include_router(
    nodes.router,
    prefix="/api/v1/nodes",
    tags=["nodes"],
    dependencies=[Depends(verify_token)] if settings.REQUIRE_AUTH else [],
)

graphql_app = GraphQLRouter(schema, context_getter=lambda: {"db": get_db})
app.include_router(graphql_app, prefix="/graphql")


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "GPUShield Telemetry Ingest",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    try:
        async with engine.begin() as conn:
            await conn.execute("SELECT 1")
        return {
            "status": "healthy",
            "database": "connected",
            "spire": (
                "connected" if hasattr(app.state, "spire_client") else "disconnected"
            ),
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )
