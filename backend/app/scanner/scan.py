from fastapi import APIRouter
from app.models.scan import ScanRequest

import requests
import time
import ssl
import socket
from urllib.parse import urlparse


router = APIRouter()


# ============================================================
# Helper: Find Domain and IP
# ============================================================

def get_domain_info(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "domain": "Unknown",
            "ip_address": "Unknown"
        }

    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip_address = "Unknown"

    return {
        "domain": hostname,
        "ip_address": ip_address
    }


# ============================================================
# Helper: SSL Certificate Check
# ============================================================

def check_ssl(url: str):
    ssl_info = {
        "https": url.startswith("https://"),
        "certificate": "Not Applicable"
    }

    if not url.startswith("https://"):
        return ssl_info

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            ssl_info["certificate"] = "Invalid"
            return ssl_info

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

    return ssl_info


# ============================================================
# Helper: Robots.txt Check
# ============================================================

def check_robots(url: str):
    base_url = url.rstrip("/")

    parsed = urlparse(base_url)

    if not parsed.scheme or not parsed.netloc:
        return {
            "found": False,
            "url": "Unknown"
        }

    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    robots = {
        "found": False,
        "url": robots_url
    }

    try:
        response = requests.get(
            robots_url,
            timeout=5
        )

        if response.status_code == 200:
            robots["found"] = True

    except requests.exceptions.RequestException:
        pass

    return robots


# ============================================================
# Helper: Sitemap.xml Check
# ============================================================

def check_sitemap(url: str):
    base_url = url.rstrip("/")

    parsed = urlparse(base_url)

    if not parsed.scheme or not parsed.netloc:
        return {
            "found": False,
            "url": "Unknown"
        }

    sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"

    sitemap = {
        "found": False,
        "url": sitemap_url
    }

    try:
        response = requests.get(
            sitemap_url,
            timeout=5
        )

        if response.status_code == 200:
            sitemap["found"] = True

    except requests.exceptions.RequestException:
        pass

    return sitemap


# ============================================================
# Helper: Cookie Security Analysis
# ============================================================

def analyze_cookies(response):

    cookies = []

    try:
        cookie_jar = response.cookies

        for cookie in cookie_jar:

            rest = getattr(cookie, "_rest", {})

            httponly = False
            samesite = False

            for key, value in rest.items():

                key_lower = str(key).lower()

                if key_lower == "httponly":
                    httponly = True

                if key_lower == "samesite":
                    samesite = True

            cookies.append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": httponly,
                "samesite": samesite
            })

    except Exception:
        pass

    return {
        "cookies_found": len(cookies),
        "cookies": cookies
    }


# ============================================================
# Helper: Security Findings
# ============================================================

def generate_findings(
    security_headers,
    cookie_security,
    ssl_info,
    response,
    redirect_info
):

    findings = []

    # --------------------------------------------------------
    # Content Security Policy
    # --------------------------------------------------------

    if security_headers["Content-Security-Policy"] == "Missing":

        findings.append({
            "type": "Security Header",
            "name": "Content-Security-Policy",
            "severity": "Medium",
            "reason": "Content Security Policy header is missing.",
            "recommendation": (
                "Add a suitable Content-Security-Policy header "
                "to control allowed content sources."
            )
        })

    # --------------------------------------------------------
    # X-Content-Type-Options
    # --------------------------------------------------------

    if security_headers["X-Content-Type-Options"] == "Missing":

        findings.append({
            "type": "Security Header",
            "name": "X-Content-Type-Options",
            "severity": "Low",
            "reason": "X-Content-Type-Options header is missing.",
            "recommendation": (
                "Add X-Content-Type-Options: nosniff "
                "to reduce MIME-type sniffing."
            )
        })

    # --------------------------------------------------------
    # HSTS
    # --------------------------------------------------------

    if (
        security_headers["Strict-Transport-Security"] == "Missing"
        and ssl_info["https"] is True
    ):

        findings.append({
            "type": "Security Header",
            "name": "Strict-Transport-Security",
            "severity": "Medium",
            "reason": "HSTS header is missing.",
            "recommendation": (
                "Configure Strict-Transport-Security "
                "when the website is fully HTTPS."
            )
        })

    # --------------------------------------------------------
    # SSL
    # --------------------------------------------------------

    if ssl_info["https"] is True:

        if ssl_info["certificate"] == "Invalid":

            findings.append({
                "type": "SSL",
                "name": "SSL Certificate",
                "severity": "High",
                "reason": "The SSL certificate could not be validated.",
                "recommendation": (
                    "Install a valid certificate and ensure "
                    "the certificate chain is correctly configured."
                )
            })

    else:

        findings.append({
            "type": "Transport Security",
            "name": "HTTPS",
            "severity": "High",
            "reason": "The scanned URL does not use HTTPS.",
            "recommendation": (
                "Use HTTPS with a valid TLS certificate "
                "to protect data in transit."
            )
        })

    # --------------------------------------------------------
    # Cookie Security
    # --------------------------------------------------------

    for cookie in cookie_security["cookies"]:

        cookie_name = cookie["name"]

        if not cookie["secure"] and ssl_info["https"]:

            findings.append({
                "type": "Cookie Security",
                "name": cookie_name,
                "severity": "Medium",
                "reason": (
                    "Cookie does not have the Secure attribute."
                ),
                "recommendation": (
                    "Use the Secure attribute for cookies "
                    "that should only be transmitted over HTTPS."
                )
            })

        if not cookie["httponly"]:

            findings.append({
                "type": "Cookie Security",
                "name": cookie_name,
                "severity": "Medium",
                "reason": (
                    "Cookie does not have the HttpOnly attribute."
                ),
                "recommendation": (
                    "Use HttpOnly for cookies that do not "
                    "need to be accessed by client-side JavaScript."
                )
            })

        if not cookie["samesite"]:

            findings.append({
                "type": "Cookie Security",
                "name": cookie_name,
                "severity": "Low",
                "reason": (
                    "Cookie does not specify SameSite."
                ),
                "recommendation": (
                    "Consider using an appropriate "
                    "SameSite policy for the cookie."
                )
            })

    # --------------------------------------------------------
    # Redirect Analysis
    # --------------------------------------------------------

    if redirect_info["redirected"]:

        if redirect_info["redirect_count"] > 3:

            findings.append({
                "type": "Configuration",
                "name": "Multiple Redirects",
                "severity": "Low",
                "reason": (
                    "The website uses multiple HTTP redirects."
                ),
                "recommendation": (
                    "Review the redirect chain and remove "
                    "unnecessary redirects."
                )
            })

    # --------------------------------------------------------
    # Server Header Information
    # --------------------------------------------------------

    server_header = response.headers.get(
        "Server",
        ""
    )

    if server_header:

        findings.append({
            "type": "Information Disclosure",
            "name": "Server Header",
            "severity": "Info",
            "reason": (
                "The server response exposes server information."
            ),
            "recommendation": (
                "Consider minimizing unnecessary server "
                "version information in production."
            )
        })

    return findings


# ============================================================
# Helper: Calculate Risk Score
# ============================================================

def calculate_risk_score(findings):

    score = 100

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        if severity == "Critical":
            score -= 35

        elif severity == "High":
            score -= 25

        elif severity == "Medium":
            score -= 15

        elif severity == "Low":
            score -= 5

    score = max(
        0,
        min(100, score)
    )

    if score >= 80:
        risk_level = "Low"

    elif score >= 60:
        risk_level = "Medium"

    elif score >= 40:
        risk_level = "High"

    else:
        risk_level = "Critical"

    return score, risk_level


# ============================================================
# Main Scan API
# ============================================================

@router.post("/scan")
def scan(data: ScanRequest):

    try:

        # ====================================================
        # Validate URL
        # ====================================================

        parsed_url = urlparse(data.url)

        if parsed_url.scheme not in ["http", "https"]:

            return {
                "message": "Invalid URL",
                "scan_status": "Failed",
                "url": data.url,
                "error": (
                    "URL must start with http:// or https://"
                )
            }

        if not parsed_url.netloc:

            return {
                "message": "Invalid URL",
                "scan_status": "Failed",
                "url": data.url,
                "error": "Invalid domain name."
            }

        # ====================================================
        # Main HTTP Request
        # ====================================================

        start = time.time()

        response = requests.get(
            data.url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "WebShield-AI Security Scanner/1.0"
                )
            }
        )

        end = time.time()

        # ====================================================
        # Redirect Information
        # ====================================================

        redirect_history = response.history

        redirect_info = {
            "redirected": len(redirect_history) > 0,
            "redirect_count": len(redirect_history),
            "final_url": response.url
        }

        # ====================================================
        # Response Headers
        # ====================================================

        headers = response.headers

        response_headers = {}

        for key, value in headers.items():
            response_headers[key] = value

        # ====================================================
        # Domain Information
        # ====================================================

        domain_info = get_domain_info(
            data.url
        )

        # ====================================================
        # Robots
        # ====================================================

        robots = check_robots(
            data.url
        )

        # ====================================================
        # Sitemap
        # ====================================================

        sitemap = check_sitemap(
            data.url
        )

        # ====================================================
        # SSL
        # ====================================================

        ssl_info = check_ssl(
            data.url
        )

        # ====================================================
        # Security Headers
        # ====================================================

        security_headers = {

            "Content-Security-Policy":
                headers.get(
                    "Content-Security-Policy",
                    "Missing"
                ),

            "X-Frame-Options":
                headers.get(
                    "X-Frame-Options",
                    "Missing"
                ),

            "X-Content-Type-Options":
                headers.get(
                    "X-Content-Type-Options",
                    "Missing"
                ),

            "Strict-Transport-Security":
                headers.get(
                    "Strict-Transport-Security",
                    "Missing"
                )
        }

        # ====================================================
        # Technology Detection
        # ====================================================

        technologies = {

            "server":
                headers.get(
                    "Server",
                    "Unknown"
                ),

            "powered_by":
                headers.get(
                    "X-Powered-By",
                    "Unknown"
                )
        }

        # ====================================================
        # Cookie Security
        # ====================================================

        cookie_security = analyze_cookies(
            response
        )

        # ====================================================
        # Security Findings
        # ====================================================

        findings = generate_findings(
            security_headers,
            cookie_security,
            ssl_info,
            response,
            redirect_info
        )

        # ====================================================
        # Risk Score
        # ====================================================

        risk_score, risk_level = calculate_risk_score(
            findings
        )

        # ====================================================
        # Warnings
        # ====================================================

        warnings = []

        if response.status_code >= 400:

            warnings.append(
                f"Website returned HTTP "
                f"status code {response.status_code}."
            )

        if redirect_info["redirect_count"] > 3:

            warnings.append(
                "Website has a long redirect chain."
            )

        if (
            ssl_info["https"]
            and ssl_info["certificate"] == "Invalid"
        ):

            warnings.append(
                "SSL certificate validation failed."
            )

        # ====================================================
        # Final Response
        # ====================================================

        return {

            "message": "Scan Completed",

            "scan_status": "Completed",

            "url": data.url,

            "status_code": response.status_code,

            "server": headers.get(
                "Server",
                "Unknown"
            ),

            "response_time":
                round(
                    end - start,
                    2
                ),

            "redirect_info": redirect_info,

            "response_headers": response_headers,

            "robots": robots,

            "sitemap": sitemap,

            "domain_info": domain_info,

            "ssl": ssl_info,

            "security_headers": security_headers,

            "cookie_security": cookie_security,

            "technologies": technologies,

            "findings": findings,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "warnings": warnings
        }

    except requests.exceptions.Timeout:

        return {

            "message": "Scan Timeout",

            "scan_status": "Failed",

            "url": data.url,

            "error": (
                "The website did not respond "
                "within the allowed time."
            )
        }

    except requests.exceptions.SSLError as e:

        return {

            "message": "SSL Error",

            "scan_status": "Failed",

            "url": data.url,

            "error": str(e)
        }

    except requests.exceptions.ConnectionError as e:

        return {

            "message": "Connection Error",

            "scan_status": "Failed",

            "url": data.url,

            "error": str(e)
        }

    except requests.exceptions.RequestException as e:

        return {

            "message": "Website Unreachable",

            "scan_status": "Failed",

            "url": data.url,

            "error": str(e)
        }

    except Exception as e:

        return {

            "message": "Internal Scanner Error",

            "scan_status": "Failed",

            "url": data.url,

            "error": str(e)
        }