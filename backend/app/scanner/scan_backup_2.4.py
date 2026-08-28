from fastapi import APIRouter
from app.models.scan import ScanRequest

import requests
import time
import ssl
import socket

from urllib.parse import urlparse


router = APIRouter()


# ============================================================
# WebShield-AI
# Security Scanner
#
# Scanner Version: 2.4
#
# Current Security Checks:
#
# WS-001  Content-Security-Policy
# WS-002  X-Frame-Options
# WS-003  X-Content-Type-Options
# WS-004  Strict-Transport-Security
# WS-005  Referrer-Policy
# WS-006  Permissions-Policy
# WS-007  Server Information Disclosure
# WS-008  security.txt
# WS-009  Directory Listing
# WS-010  Sensitive File Exposure
#
# NOTE:
# Run scans only against websites that you own
# or have explicit authorization to test.
# ============================================================


SCANNER_NAME = "WebShield-AI"
SCANNER_VERSION = "2.4"


# ============================================================
# HTTP Request Headers
# ============================================================

SCANNER_HEADERS = {
    "User-Agent": (
        "WebShield-AI Security Scanner/2.4"
    )
}


# ============================================================
# Helper: Normalize Base URL
# ============================================================

def get_base_url(url: str):

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return None

    return f"{parsed.scheme}://{parsed.netloc}"


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

        ip_address = socket.gethostbyname(
            hostname
        )

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

        "https": url.startswith(
            "https://"
        ),

        "certificate": "Not Applicable",

        "issuer": "Unknown",

        "subject": "Unknown",

        "expires": "Unknown",

        "days_remaining": None,

        "expired": None
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
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                ssl_info["certificate"] = "Valid"

                subject_parts = []

                for item in certificate.get(
                    "subject",
                    []
                ):

                    for key, value in item:

                        subject_parts.append(
                            f"{key}={value}"
                        )

                if subject_parts:

                    ssl_info["subject"] = ", ".join(
                        subject_parts
                    )

                issuer_parts = []

                for item in certificate.get(
                    "issuer",
                    []
                ):

                    for key, value in item:

                        issuer_parts.append(
                            f"{key}={value}"
                        )

                if issuer_parts:

                    ssl_info["issuer"] = ", ".join(
                        issuer_parts
                    )

                expires = certificate.get(
                    "notAfter"
                )

                if expires:

                    ssl_info["expires"] = expires

                    try:

                        from datetime import datetime

                        expiry_date = datetime.strptime(
                            expires,
                            "%b %d %H:%M:%S %Y %Z"
                        )

                        remaining = (
                            expiry_date - datetime.utcnow()
                        )

                        days_remaining = (
                            remaining.days
                        )

                        ssl_info[
                            "days_remaining"
                        ] = days_remaining

                        ssl_info[
                            "expired"
                        ] = days_remaining < 0

                    except Exception:

                        pass

    except Exception:

        ssl_info["certificate"] = "Invalid"

    return ssl_info


# ============================================================
# Helper: Robots.txt Check
# ============================================================

def check_robots(url: str):

    base_url = get_base_url(url)

    if not base_url:

        return {
            "found": False,
            "url": "Unknown",
            "status_code": None
        }

    robots_url = (
        f"{base_url}/robots.txt"
    )

    robots = {

        "found": False,

        "url": robots_url,

        "status_code": None
    }

    try:

        response = requests.get(
            robots_url,
            timeout=5,
            headers=SCANNER_HEADERS,
            allow_redirects=True
        )

        robots["status_code"] = (
            response.status_code
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

    base_url = get_base_url(url)

    if not base_url:

        return {
            "found": False,
            "url": "Unknown",
            "status_code": None
        }

    sitemap_url = (
        f"{base_url}/sitemap.xml"
    )

    sitemap = {

        "found": False,

        "url": sitemap_url,

        "status_code": None
    }

    try:

        response = requests.get(
            sitemap_url,
            timeout=5,
            headers=SCANNER_HEADERS,
            allow_redirects=True
        )

        sitemap["status_code"] = (
            response.status_code
        )

        if response.status_code == 200:

            sitemap["found"] = True

    except requests.exceptions.RequestException:

        pass

    return sitemap


# ============================================================
# Helper: security.txt Check
# ============================================================

def check_security_txt(url: str):

    base_url = get_base_url(url)

    if not base_url:

        return {
            "found": False,
            "url": "Unknown",
            "status_code": None
        }

    security_url = (
        f"{base_url}/.well-known/security.txt"
    )

    result = {

        "found": False,

        "url": security_url,

        "status_code": None
    }

    try:

        response = requests.get(
            security_url,
            timeout=5,
            headers=SCANNER_HEADERS,
            allow_redirects=True
        )

        result["status_code"] = (
            response.status_code
        )

        if response.status_code == 200:

            result["found"] = True

    except requests.exceptions.RequestException:

        pass

    return result


# ============================================================
# Helper: Cookie Security Analysis
# ============================================================

def analyze_cookies(response):

    cookies = []

    try:

        cookie_jar = response.cookies

        for cookie in cookie_jar:

            rest = getattr(
                cookie,
                "_rest",
                {}
            )

            httponly = False

            samesite = False

            for key, value in rest.items():

                key_lower = str(
                    key
                ).lower()

                if key_lower == "httponly":

                    httponly = True

                if key_lower == "samesite":

                    samesite = True

            cookies.append({

                "name": cookie.name,

                "secure": bool(
                    cookie.secure
                ),

                "httponly": httponly,

                "samesite": samesite
            })

    except Exception:

        pass

    return {

        "cookies_found": len(
            cookies
        ),

        "cookies": cookies
    }


# ============================================================
# Helper: CORS Analysis
# ============================================================

def analyze_cors(response):

    headers = response.headers

    return {

        "allow_origin":
            headers.get(
                "Access-Control-Allow-Origin",
                "Not Present"
            ),

        "allow_credentials":
            headers.get(
                "Access-Control-Allow-Credentials",
                "Not Present"
            ),

        "allow_methods":
            headers.get(
                "Access-Control-Allow-Methods",
                "Not Present"
            ),

        "allow_headers":
            headers.get(
                "Access-Control-Allow-Headers",
                "Not Present"
            )
    }


# ============================================================
# Helper: HTTP Methods
# ============================================================

def check_http_methods(url: str):

    result = {

        "allow_header": "Not Present",

        "methods": []
    }

    try:

        response = requests.options(
            url,
            timeout=5,
            headers=SCANNER_HEADERS,
            allow_redirects=True
        )

        allow_header = response.headers.get(
            "Allow"
        )

        if allow_header:

            result["allow_header"] = (
                allow_header
            )

            result["methods"] = [
                method.strip()
                for method in allow_header.split(",")
                if method.strip()
            ]

    except requests.exceptions.RequestException:

        pass

    return result


# ============================================================
# Helper: Directory Listing Detection
# ============================================================

def check_directory_listing(url: str):

    base_url = get_base_url(url)

    checked_paths = [

        "/uploads/",

        "/images/",

        "/css/",

        "/js/",

        "/assets/",

        "/backup/"
    ]

    result = {

        "detected": False,

        "base_url": base_url
            if base_url
            else "Unknown",

        "checked_paths": [],

        "evidence": []
    }

    if not base_url:

        return result

    for path in checked_paths:

        target_url = (
            f"{base_url}{path}"
        )

        result[
            "checked_paths"
        ].append(
            target_url
        )

        try:

            response = requests.get(
                target_url,
                timeout=5,
                headers=SCANNER_HEADERS,
                allow_redirects=True
            )

            if response.status_code != 200:

                continue

            body = response.text.lower()

            directory_indicators = [

                "index of /",

                "directory listing",

                "<title>index of",

                "parent directory"
            ]

            matched = False

            for indicator in directory_indicators:

                if indicator in body:

                    matched = True

                    break

            if matched:

                result[
                    "detected"
                ] = True

                result[
                    "evidence"
                ].append({

                    "url": target_url,

                    "status_code":
                        response.status_code,

                    "indicator":
                        "Directory listing page detected"
                })

        except requests.exceptions.RequestException:

            continue

    return result


# ============================================================
# Helper: Sensitive File Exposure Detection
# ============================================================

def check_sensitive_file_exposure(url: str):

    base_url = get_base_url(url)

    sensitive_paths = [

        "/.env",

        "/.git/HEAD",

        "/.git/config",

        "/backup.zip",

        "/backup.tar.gz",

        "/database.sql",

        "/db.sql",

        "/config.php.bak",

        "/wp-config.php.bak",

        "/phpinfo.php",

        "/server-status"
    ]

    result = {

        "detected": False,

        "base_url":
            base_url
            if base_url
            else "Unknown",

        "checked_paths": [],

        "evidence": []
    }

    if not base_url:

        return result

    for path in sensitive_paths:

        target_url = (
            f"{base_url}{path}"
        )

        result[
            "checked_paths"
        ].append(
            target_url
        )

        try:

            response = requests.get(
                target_url,
                timeout=5,
                headers=SCANNER_HEADERS,
                allow_redirects=False
            )

            status_code = (
                response.status_code
            )

            # ------------------------------------------------
            # We consider only successful exposure.
            #
            # 404 = Not Found
            # 403 = Forbidden
            # 401 = Unauthorized
            #
            # These are NOT automatically treated as exposure.
            # ------------------------------------------------

            if status_code != 200:

                continue

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            body = response.text[:10000].lower()

            evidence_type = None

            # ------------------------------------------------
            # .env detection
            # ------------------------------------------------

            if path == "/.env":

                env_indicators = [

                    "app_key=",

                    "app_env=",

                    "database_url=",

                    "db_host=",

                    "db_password=",

                    "secret_key="
                ]

                for indicator in env_indicators:

                    if indicator in body:

                        evidence_type = (
                            "Environment configuration "
                            "content detected"
                        )

                        break

            # ------------------------------------------------
            # Git HEAD
            # ------------------------------------------------

            elif path == "/.git/HEAD":

                if (
                    "ref: refs/"
                    in body
                ):

                    evidence_type = (
                        "Git repository HEAD "
                        "information exposed"
                    )

            # ------------------------------------------------
            # Git config
            # ------------------------------------------------

            elif path == "/.git/config":

                if (
                    "[core]"
                    in body
                    or "[remote"
                    in body
                ):

                    evidence_type = (
                        "Git configuration "
                        "content exposed"
                    )

            # ------------------------------------------------
            # Database files
            # ------------------------------------------------

            elif path.endswith(
                ".sql"
            ):

                sql_indicators = [

                    "create table",

                    "insert into",

                    "drop table",

                    "-- mysql dump",

                    "-- phpmyadmin"
                ]

                for indicator in sql_indicators:

                    if indicator in body:

                        evidence_type = (
                            "Database dump content "
                            "detected"
                        )

                        break

            # ------------------------------------------------
            # PHP information
            # ------------------------------------------------

            elif path == "/phpinfo.php":

                phpinfo_indicators = [

                    "php version",

                    "phpinfo()",

                    "configuration"
                ]

                for indicator in phpinfo_indicators:

                    if indicator in body:

                        evidence_type = (
                            "PHP configuration "
                            "information exposed"
                        )

                        break

            # ------------------------------------------------
            # Server status
            # ------------------------------------------------

            elif path == "/server-status":

                server_status_indicators = [

                    "apache server status",

                    "server uptime",

                    "server version"
                ]

                for indicator in server_status_indicators:

                    if indicator in body:

                        evidence_type = (
                            "Server status information "
                            "exposed"
                        )

                        break

            # ------------------------------------------------
            # Backup files
            # ------------------------------------------------

            elif (
                path.endswith(".zip")
                or path.endswith(".tar.gz")
                or path.endswith(".bak")
            ):

                # A 200 response alone is not enough to claim
                # sensitive content was exposed.
                #
                # Content-Type / body evidence is checked.
                #

                if (
                    "text" in content_type
                    or "json" in content_type
                    or "sql" in content_type
                ):

                    evidence_type = (
                        "Potential backup/configuration "
                        "file exposed"
                    )

            # ------------------------------------------------
            # Generic fallback
            # ------------------------------------------------

            if evidence_type:

                result[
                    "detected"
                ] = True

                result[
                    "evidence"
                ].append({

                    "url": target_url,

                    "status_code": status_code,

                    "content_type":
                        content_type,

                    "evidence":
                        evidence_type
                })

        except requests.exceptions.RequestException:

            continue

    return result


# ============================================================
# Helper: Security Findings
# ============================================================

def generate_findings(
    security_headers,
    cookie_security,
    ssl_info,
    response,
    redirect_info,
    security_txt,
    directory_listing,
    sensitive_file_exposure
):

    findings = []


    # ========================================================
    # WS-001
    # Content Security Policy
    # ========================================================

    if (
        security_headers[
            "Content-Security-Policy"
        ] == "Missing"
    ):

        findings.append({

            "id": "WS-001",

            "type": "Security Header",

            "category":
                "Security Configuration",

            "name":
                "Content-Security-Policy",

            "severity": "Medium",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "Content Security Policy header is missing.",

            "evidence":
                "Content-Security-Policy: Missing",

            "recommendation":
                "Add a suitable Content-Security-Policy "
                "header and define trusted content sources.",

            "priority": "Recommended"
        })


    # ========================================================
    # WS-002
    # X-Frame-Options
    # ========================================================

    if (
        security_headers[
            "X-Frame-Options"
        ] == "Missing"
    ):

        findings.append({

            "id": "WS-002",

            "type": "Security Header",

            "category":
                "Security Configuration",

            "name":
                "X-Frame-Options",

            "severity": "Low",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "X-Frame-Options header is missing.",

            "evidence":
                "X-Frame-Options: Missing",

            "recommendation":
                "Add X-Frame-Options: DENY or SAMEORIGIN "
                "where appropriate.",

            "priority": "Recommended"
        })


    # ========================================================
    # WS-003
    # X-Content-Type-Options
    # ========================================================

    if (
        security_headers[
            "X-Content-Type-Options"
        ] == "Missing"
    ):

        findings.append({

            "id": "WS-003",

            "type": "Security Header",

            "category":
                "Security Configuration",

            "name":
                "X-Content-Type-Options",

            "severity": "Low",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "X-Content-Type-Options header is missing.",

            "evidence":
                "X-Content-Type-Options: Missing",

            "recommendation":
                "Add X-Content-Type-Options: nosniff.",

            "priority": "Recommended"
        })


    # ========================================================
    # WS-004
    # HSTS
    # ========================================================

    if (
        security_headers[
            "Strict-Transport-Security"
        ] == "Missing"
        and ssl_info["https"] is True
    ):

        findings.append({

            "id": "WS-004",

            "type": "Security Header",

            "category":
                "Transport Security",

            "name":
                "Strict-Transport-Security",

            "severity": "Medium",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "HSTS header is missing while "
                "the website uses HTTPS.",

            "evidence":
                "Strict-Transport-Security: Missing",

            "recommendation":
                "Configure HSTS after confirming "
                "the website is fully HTTPS.",

            "priority": "Recommended"
        })


    # ========================================================
    # WS-005
    # Referrer Policy
    # ========================================================

    if (
        security_headers[
            "Referrer-Policy"
        ] == "Missing"
    ):

        findings.append({

            "id": "WS-005",

            "type": "Security Header",

            "category":
                "Security Configuration",

            "name":
                "Referrer-Policy",

            "severity": "Low",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "Referrer-Policy header is missing.",

            "evidence":
                "Referrer-Policy: Missing",

            "recommendation":
                "Configure an appropriate "
                "Referrer-Policy.",

            "priority": "Optional"
        })


    # ========================================================
    # WS-006
    # Permissions Policy
    # ========================================================

    if (
        security_headers[
            "Permissions-Policy"
        ] == "Missing"
    ):

        findings.append({

            "id": "WS-006",

            "type": "Security Header",

            "category":
                "Security Configuration",

            "name":
                "Permissions-Policy",

            "severity": "Low",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "Permissions-Policy header is missing.",

            "evidence":
                "Permissions-Policy: Missing",

            "recommendation":
                "Configure Permissions-Policy to "
                "restrict unnecessary browser features.",

            "priority": "Optional"
        })


    # ========================================================
    # WS-007
    # Server Information Disclosure
    # ========================================================

    server_header = response.headers.get(
        "Server",
        ""
    )

    if server_header:

        findings.append({

            "id": "WS-007",

            "type":
                "Information Disclosure",

            "category":
                "Information Exposure",

            "name":
                "Server Header",

            "severity": "Info",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "The HTTP response exposes "
                "server information.",

            "evidence":
                f"Server: {server_header}",

            "recommendation":
                "Consider minimizing unnecessary "
                "server information in production.",

            "priority": "Optional"
        })


    # ========================================================
    # WS-008
    # security.txt
    # ========================================================

    if not security_txt["found"]:

        findings.append({

            "id": "WS-008",

            "type":
                "Security Configuration",

            "category":
                "Vulnerability Disclosure",

            "name":
                "security.txt",

            "severity": "Info",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "A security.txt file was not found "
                "at the standard well-known location.",

            "evidence":
                f"Checked URL: "
                f"{security_txt['url']}",

            "recommendation":
                "Consider publishing security.txt with "
                "security contact and vulnerability "
                "disclosure information.",

            "priority": "Optional"
        })


    # ========================================================
    # WS-009
    # Directory Listing
    # ========================================================

    if directory_listing["detected"]:

        evidence_text = []

        for item in directory_listing[
            "evidence"
        ]:

            evidence_text.append(
                f"{item['url']} - "
                f"{item['indicator']}"
            )

        findings.append({

            "id": "WS-009",

            "type":
                "Directory Listing",

            "category":
                "Security Configuration",

            "name":
                "Directory Listing",

            "severity": "Medium",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "A web directory appears to allow "
                "directory listing.",

            "evidence":
                "; ".join(evidence_text),

            "recommendation":
                "Disable directory indexing and ensure "
                "sensitive directories cannot be browsed.",

            "priority": "Recommended"
        })


    # ========================================================
    # WS-010
    # Sensitive File Exposure
    # ========================================================

    if sensitive_file_exposure["detected"]:

        evidence_text = []

        for item in sensitive_file_exposure[
            "evidence"
        ]:

            evidence_text.append(
                f"{item['url']} - "
                f"{item['evidence']}"
            )

        findings.append({

            "id": "WS-010",

            "type":
                "Sensitive File Exposure",

            "category":
                "Security Configuration",

            "name":
                "Sensitive File Exposure",

            "severity": "High",

            "confidence": "High",

            "owasp":
                "A05: Security Misconfiguration",

            "reason":
                "A potentially sensitive configuration, "
                "backup, repository or diagnostic file "
                "appears to be publicly accessible.",

            "evidence":
                "; ".join(evidence_text),

            "recommendation":
                "Remove sensitive files from the public "
                "web root or restrict access to them. "
                "Do not expose configuration files, "
                "database dumps, repository metadata, "
                "backup archives or diagnostic pages.",

            "priority": "Critical Review"
        })


    # ========================================================
    # SSL Certificate
    # ========================================================

    if ssl_info["https"]:

        if (
            ssl_info["certificate"]
            == "Invalid"
        ):

            findings.append({

                "id": "WS-011",

                "type": "SSL",

                "category":
                    "Transport Security",

                "name":
                    "SSL Certificate",

                "severity": "High",

                "confidence": "High",

                "reason":
                    "The SSL certificate could not "
                    "be validated.",

                "evidence":
                    "Certificate validation failed.",

                "recommendation":
                    "Install a valid TLS certificate and "
                    "ensure the certificate chain is "
                    "correctly configured.",

                "priority": "Recommended"
            })

    else:

        findings.append({

            "id": "WS-011",

            "type":
                "Transport Security",

            "category":
                "Transport Security",

            "name":
                "HTTPS",

            "severity": "High",

            "confidence": "High",

            "reason":
                "The scanned URL does not use HTTPS.",

            "evidence":
                "URL uses HTTP instead of HTTPS.",

            "recommendation":
                "Use HTTPS with a valid TLS certificate "
                "to protect data in transit.",

            "priority": "Recommended"
        })


    # ========================================================
    # Cookie Security
    # ========================================================

    for cookie in cookie_security["cookies"]:

        cookie_name = cookie["name"]


        if (
            not cookie["secure"]
            and ssl_info["https"]
        ):

            findings.append({

                "id": "WS-012",

                "type":
                    "Cookie Security",

                "category":
                    "Session Security",

                "name":
                    cookie_name,

                "severity": "Medium",

                "confidence": "High",

                "reason":
                    "Cookie does not have "
                    "the Secure attribute.",

                "evidence":
                    f"Cookie: {cookie_name}",

                "recommendation":
                    "Use the Secure attribute for cookies "
                    "that should only be transmitted over HTTPS.",

                "priority": "Recommended"
            })


        if not cookie["httponly"]:

            findings.append({

                "id": "WS-013",

                "type":
                    "Cookie Security",

                "category":
                    "Session Security",

                "name":
                    cookie_name,

                "severity": "Medium",

                "confidence": "High",

                "reason":
                    "Cookie does not have "
                    "the HttpOnly attribute.",

                "evidence":
                    f"Cookie: {cookie_name}",

                "recommendation":
                    "Use HttpOnly for cookies that do not "
                    "need to be accessed by client-side JavaScript.",

                "priority": "Recommended"
            })


        if not cookie["samesite"]:

            findings.append({

                "id": "WS-014",

                "type":
                    "Cookie Security",

                "category":
                    "Session Security",

                "name":
                    cookie_name,

                "severity": "Low",

                "confidence": "High",

                "reason":
                    "Cookie does not specify SameSite.",

                "evidence":
                    f"Cookie: {cookie_name}",

                "recommendation":
                    "Consider using an appropriate "
                    "SameSite policy for the cookie.",

                "priority": "Optional"
            })


    # ========================================================
    # Redirect Analysis
    # ========================================================

    if redirect_info["redirected"]:

        if (
            redirect_info["redirect_count"]
            > 3
        ):

            findings.append({

                "id": "WS-015",

                "type":
                    "Configuration",

                "category":
                    "Web Configuration",

                "name":
                    "Multiple Redirects",

                "severity": "Low",

                "confidence": "High",

                "reason":
                    "The website uses multiple "
                    "HTTP redirects.",

                "evidence":
                    f"Redirect count: "
                    f"{redirect_info['redirect_count']}",

                "recommendation":
                    "Review the redirect chain and remove "
                    "unnecessary redirects.",

                "priority": "Optional"
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

        elif severity == "Info":

            score -= 0


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
# Helper: Risk Explanation
# ============================================================

def get_risk_explanation(
    risk_level
):

    explanations = {

        "Low":
            (
                "The website shows a relatively "
                "low level of security risk based "
                "on the checks performed. Only minor "
                "security improvements may be required."
            ),

        "Medium":
            (
                "The website has some security "
                "weaknesses that should be reviewed "
                "and improved to strengthen its "
                "overall security posture."
            ),

        "High":
            (
                "The website has multiple security "
                "weaknesses that should be addressed. "
                "Security improvements are recommended "
                "before considering the website fully protected."
            ),

        "Critical":
            (
                "The scan identified serious security "
                "weaknesses that require immediate attention. "
                "The website should be reviewed and secured "
                "as soon as possible."
            )
    }

    return explanations.get(
        risk_level,
        "Risk level could not be determined."
    )


# ============================================================
# Helper: Risk Score Guide
# ============================================================

def get_risk_score_guide():

    return {

        "80-100": "Low",

        "60-79": "Medium",

        "40-59": "High",

        "0-39": "Critical"
    }


# ============================================================
# Helper: Finding Summary
# ============================================================

def get_finding_summary(
    findings
):

    summary = {

        "critical": 0,

        "high": 0,

        "medium": 0,

        "low": 0,

        "info": 0,

        "total": 0
    }

    for finding in findings:

        severity = (
            finding.get(
                "severity",
                "Info"
            )
            .lower()
        )

        if severity in summary:

            summary[severity] += 1

        summary["total"] += 1

    return summary


# ============================================================
# Main Scan API
# ============================================================

@router.post("/scan")
def scan(
    data: ScanRequest
):

    try:

        # ====================================================
        # URL Validation
        # ====================================================

        parsed_url = urlparse(
            data.url
        )

        if parsed_url.scheme not in [
            "http",
            "https"
        ]:

            return {

                "message":
                    "Invalid URL",

                "scan_status":
                    "Failed",

                "url":
                    data.url,

                "error":
                    "URL must start with "
                    "http:// or https://"
            }


        if not parsed_url.netloc:

            return {

                "message":
                    "Invalid URL",

                "scan_status":
                    "Failed",

                "url":
                    data.url,

                "error":
                    "Invalid domain name."
            }


        # ====================================================
        # Main HTTP Request
        # ====================================================

        start = time.time()

        response = requests.get(

            data.url,

            timeout=10,

            allow_redirects=True,

            headers=SCANNER_HEADERS
        )

        end = time.time()


        # ====================================================
        # Redirect Information
        # ====================================================

        redirect_history = (
            response.history
        )

        redirect_chain = []

        for redirect in redirect_history:

            redirect_chain.append({

                "status_code":
                    redirect.status_code,

                "url":
                    redirect.url,

                "location":
                    redirect.headers.get(
                        "Location",
                        "Unknown"
                    )
            })


        redirect_info = {

            "redirected":
                len(redirect_history) > 0,

            "redirect_count":
                len(redirect_history),

            "chain":
                redirect_chain,

            "final_url":
                response.url
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

        domain_info = (
            get_domain_info(
                data.url
            )
        )


        # ====================================================
        # Robots
        # ====================================================

        robots = (
            check_robots(
                data.url
            )
        )


        # ====================================================
        # Sitemap
        # ====================================================

        sitemap = (
            check_sitemap(
                data.url
            )
        )


        # ====================================================
        # security.txt
        # ====================================================

        security_txt = (
            check_security_txt(
                data.url
            )
        )


        # ====================================================
        # SSL
        # ====================================================

        ssl_info = (
            check_ssl(
                data.url
            )
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
                ),

            "Referrer-Policy":
                headers.get(
                    "Referrer-Policy",
                    "Missing"
                ),

            "Permissions-Policy":
                headers.get(
                    "Permissions-Policy",
                    "Missing"
                )
        }


        # ====================================================
        # Cookie Security
        # ====================================================

        cookie_security = (
            analyze_cookies(
                response
            )
        )


        # ====================================================
        # CORS
        # ====================================================

        cors = (
            analyze_cors(
                response
            )
        )


        # ====================================================
        # HTTP Methods
        # ====================================================

        http_methods = (
            check_http_methods(
                data.url
            )
        )


        # ====================================================
        # Directory Listing
        #
        # WS-009
        # ====================================================

        directory_listing = (
            check_directory_listing(
                data.url
            )
        )


        # ====================================================
        # Sensitive File Exposure
        #
        # WS-010
        # ====================================================

        sensitive_file_exposure = (
            check_sensitive_file_exposure(
                data.url
            )
        )


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
        # Generate Findings
        # ====================================================

        findings = generate_findings(

            security_headers,

            cookie_security,

            ssl_info,

            response,

            redirect_info,

            security_txt,

            directory_listing,

            sensitive_file_exposure
        )


        # ====================================================
        # Finding Summary
        # ====================================================

        finding_summary = (
            get_finding_summary(
                findings
            )
        )


        # ====================================================
        # Risk Score
        # ====================================================

        risk_score, risk_level = (
            calculate_risk_score(
                findings
            )
        )


        # ====================================================
        # Risk Explanation
        # ====================================================

        risk_explanation = (
            get_risk_explanation(
                risk_level
            )
        )


        # ====================================================
        # Risk Guide
        # ====================================================

        risk_score_guide = (
            get_risk_score_guide()
        )


        # ====================================================
        # Warnings
        # ====================================================

        warnings = []


        if response.status_code >= 400:

            warnings.append(

                f"Website returned HTTP "
                f"status code "
                f"{response.status_code}."
            )


        if (
            redirect_info[
                "redirect_count"
            ] > 3
        ):

            warnings.append(
                "Website has a long "
                "redirect chain."
            )


        if (
            ssl_info["https"]
            and ssl_info["certificate"]
            == "Invalid"
        ):

            warnings.append(
                "SSL certificate "
                "validation failed."
            )


        if (
            directory_listing[
                "detected"
            ]
        ):

            warnings.append(
                "Directory listing was "
                "detected on one or more "
                "checked paths."
            )


        if (
            sensitive_file_exposure[
                "detected"
            ]
        ):

            warnings.append(
                "Potential sensitive file "
                "exposure was detected. "
                "Review the affected paths."
            )


        # ====================================================
        # Final Response
        # ====================================================

        return {

            "message":
                "Scan Completed",

            "scan_status":
                "Completed",

            "scanner":
                SCANNER_NAME,

            "scanner_version":
                SCANNER_VERSION,

            "url":
                data.url,

            "status_code":
                response.status_code,

            "server":
                headers.get(
                    "Server",
                    "Unknown"
                ),

            "response_time":
                round(
                    end - start,
                    2
                ),

            "redirect_info":
                redirect_info,

            "response_headers":
                response_headers,

            "robots":
                robots,

            "sitemap":
                sitemap,

            "security_txt":
                security_txt,

            "domain_info":
                domain_info,

            "ssl":
                ssl_info,

            "security_headers":
                security_headers,

            "cookie_security":
                cookie_security,

            "cors":
                cors,

            "http_methods":
                http_methods,

            "directory_listing":
                directory_listing,

            "sensitive_file_exposure":
                sensitive_file_exposure,

            "technologies":
                technologies,

            "findings":
                findings,

            "finding_summary":
                finding_summary,

            "risk_assessment": {

                "score":
                    risk_score,

                "level":
                    risk_level,

                "description":
                    risk_explanation,

                "score_guide":
                    risk_score_guide
            },

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "warnings":
                warnings
        }


    # ========================================================
    # Error Handling
    # ========================================================

    except requests.exceptions.Timeout:

        return {

            "message":
                "Scan Timeout",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                "The website did not respond "
                "within the allowed time."
        }


    except requests.exceptions.SSLError as e:

        return {

            "message":
                "SSL Error",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                str(e)
        }


    except requests.exceptions.ConnectionError as e:

        return {

            "message":
                "Connection Error",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                str(e)
        }


    except requests.exceptions.RequestException as e:

        return {

            "message":
                "Website Unreachable",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                str(e)
        }


    except Exception as e:

        return {

            "message":
                "Internal Scanner Error",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                str(e)
        }