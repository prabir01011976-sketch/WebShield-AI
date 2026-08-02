from fastapi import APIRouter
from app.models.scan import ScanRequest
import requests
import time
router = APIRouter()

@router.post("/scan")
def scan(data: ScanRequest):
    try:
        start = time.time()
        response = requests.get(data.url, timeout=10)
        end = time.time()
        headers = response.headers

        security_headers = {
    "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
    "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
    "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
    "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
}
        

        return {
            "message": "Scan Completed",
            "url": data.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown"),
            "response_time": round(end - start, 2),
            "security_headers": security_headers
        }

    except requests.exceptions.RequestException as e:
        return {
            "message": "Website Unreachable",
            "url": data.url,
            "error": str(e)
        }