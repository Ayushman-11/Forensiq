"""
Forensiq FastAPI Main Application Entrypoint.
Configures app lifespan, middleware, routers, and CORS.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.api.v1.router import api_router


from app.database.session import connect_to_mongo, close_mongo_connection

from app.services.poller import AlertPoller
from app.database.session import db_config

poller = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager handling startup and shutdown events."""
    setup_logging()
    logger.info("forensiq_backend_startup", env=settings.ENV, debug=settings.DEBUG)
    await connect_to_mongo()
    
    global poller
    if db_config.client:
        poller = AlertPoller(db_config.client[settings.MONGO_DB_NAME], interval_seconds=30)
        poller.start()
        
    yield
    
    if poller:
        poller.stop()
        
    await close_mongo_connection()
    logger.info("forensiq_backend_shutdown")


app = FastAPI(
    title="Forensiq API",
    description="AI-Agent Driven Security Operations & Investigation Platform API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global unhandled exception handler returning structured JSON response."""
    logger.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred.", "error": str(exc)},
    )


# Include API Routers
app.include_router(api_router)


@app.get("/")
async def root():
    """Root landing endpoint."""
    return {
        "platform": "Forensiq Security Operations Platform",
        "status": "operational",
        "docs": "/docs",
        "api_v1": "/api/v1",
    }
