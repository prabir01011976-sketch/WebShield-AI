from fastapi import APIRouter
from app.models.scan import ScanRequest
import requests

router = APIRouter()

@router.post("/scan")
def scan(data: ScanRequest):
    try:
        response = requests.get(data.url, timeout=10)

        return {
            "message": "Scan Completed",
            "url": data.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown")
        }

    except requests.exceptions.RequestException as e:
        return {
            "message": "Website Unreachable",
            "url": data.url,
            "error": str(e)
        }