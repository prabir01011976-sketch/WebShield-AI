from fastapi import APIRouter
from app.models.scan import ScanRequest
import requests
import time
import ssl
import socket

router = APIRouter()


@router.post("/scan")
def scan(data: ScanRequest):
    try:
        start = time.time()
        response = requests.get(data.url, timeout=10)
        end = time.time()

        headers = response.headers

        # ==========================
        # Robots.txt Check
        # ==========================
        robots = {
            "found": False,
            "url": data.url.rstrip("/") + "/robots.txt"
        }

        try:
            robots_response = requests.get(robots["url"], timeout=5)

            if robots_response.status_code == 200:
                robots["found"] = True

        except Exception:
            pass

        # ==========================
        # SSL Check
        # ==========================
        ssl_info = {
            "https": data.url.startswith("https://"),
            "certificate": "Unknown"
        }

        if data.url.startswith("https://"):
            try:
                hostname = data.url.replace("https://", "").split("/")[0]

                context = ssl.create_default_context()

                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        ssl_info["certificate"] = "Valid"

            except Exception:
                ssl_info["certificate"] = "Invalid"

        # ==========================
        # Technology Detection
        # ==========================
        technologies = {
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Unknown")
        }

        # ==========================
        # Security Headers
        # ==========================
        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
        }

        # ==========================
        # Risk Score
        # ==========================
        score = 100

        for value in security_headers.values():
            if value == "Missing":
                score -= 25

        if score >= 75:
            risk = "Low"
        elif score >= 50:
            risk = "Medium"
        else:
            risk = "High"

        # ==========================
        # Return Response
        # ==========================
        return {
            "message": "Scan Completed",
            "url": data.url,
            "status_code": response.status_code,
            "server": headers.get("Server", "Unknown"),
            "response_time": round(end - start, 2),
            "robots": robots,
            "ssl": ssl_info,
            "security_headers": security_headers,
            "technologies": technologies,
            "risk_score": score,
            "risk_level": risk
        }

    except requests.exceptions.RequestException as e:
        return {
            "message": "Website Unreachable",
            "url": data.url,
            "error": str(e)
        }