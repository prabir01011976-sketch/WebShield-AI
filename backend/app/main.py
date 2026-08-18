from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.health import router
from app.scanner.scan import router as scan_router


# ============================================================
# WebShield-AI FastAPI Application
# ============================================================

app = FastAPI(
    title="WebShield AI",
    version="1.0.0",
    description="WebShield-AI Web Security Scanner"
)


# ============================================================
# API Routers
# ============================================================

app.include_router(router)

app.include_router(scan_router)


# ============================================================
# Frontend Directory
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

FRONTEND_DIR = BASE_DIR / "frontend"


# ============================================================
# Serve Frontend
# ============================================================

app.mount(
    "/",
    StaticFiles(
        directory=FRONTEND_DIR,
        html=True
    ),
    name="frontend"
)