from .routers.telemetry import router as telemetry_router
from .routers.alerts import router as alerts_router
from .routers.sensors import router as sensors_router
from .routers.nodes import router as nodes_router

telemetry = telemetry_router
alerts = alerts_router
sensors = sensors_router
nodes = nodes_router