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

        response = requests.get(
            data.url,
            timeout=10
        )

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

        # Root URL
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
        # Cookie Security Check
        # ==========================
        cookies = []

        set_cookie_headers = response.raw.headers.getlist(
            "Set-Cookie"
        )

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split(
                "=",
                1
            )[0].strip()

            cookie_info = {
                "name": cookie_name,
                "secure": "Secure" in cookie_header,
                "httponly": "HttpOnly" in cookie_header,
                "samesite": "SameSite" in cookie_header
            }

            cookies.append(cookie_info)

        cookie_security = {
            "cookies_found": len(cookies),
            "cookies": cookies
        }

        # ==========================
        # Risk Score
        # ==========================
        score = 100

        # Security Header Penalties
        if security_headers["Content-Security-Policy"] == "Missing":
            score -= 15

        if security_headers["X-Frame-Options"] == "Missing":
            score -= 10

        if security_headers["X-Content-Type-Options"] == "Missing":
            score -= 10

        if security_headers["Strict-Transport-Security"] == "Missing":
            score -= 15

        # Cookie Penalties
        for cookie in cookies:

            if not cookie["secure"]:
                score -= 5

            if not cookie["httponly"]:
                score -= 5

            if not cookie["samesite"]:
                score -= 5

        # Keep score between 0 and 100
        score = max(
            0,
            min(score, 100)
        )

        # ==========================
        # Risk Level
        # ==========================
        if score >= 80:
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
            "cookie_security": cookie_security,

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