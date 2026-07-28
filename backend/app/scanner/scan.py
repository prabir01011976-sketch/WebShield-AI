from fastapi import APIRouter
from app.models.scan import ScanRequest

router = APIRouter()

@router.post("/scan")
def scan(data: ScanRequest):
    return {
        "message": "Scan Started",
        "url": data.url
    }