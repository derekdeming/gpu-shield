from pydantic import BaseSettings, Field
from typing import List


class Settings(BaseSettings):
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://gpushield:gpushield@localhost:5432/gpushield",
        description="PostgreSQL database URL",
    )
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8000, description="Server port")
    DEBUG: bool = Field(default=False, description="Debug mode")
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="Allowed CORS origins",
    )
    REQUIRE_AUTH: bool = Field(default=False, description="Require authentication")
    SPIRE_SOCKET_PATH: str = Field(
        default="/tmp/spire-agent/public/api.sock",
        description="SPIRE agent socket path",
    )
    ANOMALY_THRESHOLD: float = Field(
        default=0.7, description="Anomaly detection threshold"
    )
    BATCH_SIZE: int = Field(default=1000, description="Batch processing size")
    OTLP_ENDPOINT: str = Field(
        default="http://localhost:4317", description="OTLP gRPC endpoint"
    )

    class Config:
        env_file = ".env"
        case_sensitive = True


# global setting for now
settings = Settings()
