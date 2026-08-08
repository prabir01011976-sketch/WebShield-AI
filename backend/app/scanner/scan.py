from fastapi import APIRouter
from app.models.scan import ScanRequest
import requests
import time
import ssl
import socket
from urllib.parse import urlparse

router = APIRouter()


@router.post("/scan")
def scan(data: ScanRequest):
    try:
        # ==========================
        # Website Request
        # ==========================
        start = time.time()
        response = requests.get(data.url, timeout=10)
        end = time.time()

        headers = response.headers

        # ==========================
        # URL and Domain Information
        # ==========================
        parsed_url = urlparse(data.url)

        hostname = parsed_url.hostname

        if hostname is None:
            return {
                "message": "Invalid URL",
                "url": data.url
            }

        # Root URL তৈরি করা হচ্ছে
        base_url = f"{parsed_url.scheme}://{hostname}"

        # ==========================
        # Domain & IP Detection
        # ==========================
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            ip_address = "Unknown"

        domain_info = {
            "domain": hostname,
            "ip_address": ip_address
        }

        # ==========================
        # Robots.txt Check
        # ==========================
        robots = {
            "found": False,
            "url": base_url + "/robots.txt"
        }

        try:
            robots_response = requests.get(
                robots["url"],
                timeout=5
            )

            if robots_response.status_code == 200:
                robots["found"] = True

        except Exception:
            pass

        # ==========================
        # Sitemap.xml Check
        # ==========================
        sitemap = {
            "found": False,
            "url": base_url + "/sitemap.xml"
        }

        try:
            sitemap_response = requests.get(
                sitemap["url"],
                timeout=5
            )

            if sitemap_response.status_code == 200:
                sitemap["found"] = True

        except Exception:
            pass

        # ==========================
        # SSL Check
        # ==========================
        ssl_info = {
            "https": parsed_url.scheme == "https",
            "certificate": "Unknown"
        }

        if parsed_url.scheme == "https":
            try:
                context = ssl.create_default_context()

                with socket.create_connection(
                    (hostname, 443),
                    timeout=5
                ) as sock:

                    with context.wrap_socket(
                        sock,
                        server_hostname=hostname
                    ):
                        ssl_info["certificate"] = "Valid"

            except Exception:
                ssl_info["certificate"] = "Invalid"

        # ==========================
        # Technology Detection
        # ==========================
        technologies = {
            "server": headers.get(
                "Server",
                "Unknown"
            ),
            "powered_by": headers.get(
                "X-Powered-By",
                "Unknown"
            )
        }

        # ==========================
        # Security Headers
        # ==========================
        security_headers = {
            "Content-Security-Policy": headers.get(
                "Content-Security-Policy",
                "Missing"
            ),
            "X-Frame-Options": headers.get(
                "X-Frame-Options",
                "Missing"
            ),
            "X-Content-Type-Options": headers.get(
                "X-Content-Type-Options",
                "Missing"
            ),
            "Strict-Transport-Security": headers.get(
                "Strict-Transport-Security",
                "Missing"
            )
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
        # Return Scan Result
        # ==========================
        return {
            "message": "Scan Completed",
            "url": data.url,
            "status_code": response.status_code,
            "server": headers.get(
                "Server",
                "Unknown"
            ),
            "response_time": round(
                end - start,
                2
            ),

            "robots": robots,
            "sitemap": sitemap,
            "domain_info": domain_info,
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