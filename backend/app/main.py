from fastapi import FastAPI
from app.api.health import router
from app.scanner.scan import router as scan_router

app = FastAPI(
    title="WebShield AI",
    version="1.0.0"
)

app.include_router(router)
app.include_router(scan_router)