"""
WebShield-AI
Professional Passive / Safe Web Security Scanner

File:
    backend/app/api/scan.py

Purpose:
    Safe, non-destructive web application security analysis.

Important:
    This scanner intentionally does NOT perform:
        - SQL injection exploitation
        - XSS payload injection
        - command execution
        - SSRF exploitation
        - credential brute force
        - malicious file upload
        - destructive testing
        - authentication bypass
        - arbitrary Host-header poisoning

The scanner performs passive analysis and safe GET/HEAD-style
discovery checks only.

Compatible with:
    FastAPI
    Requests
    Python 3.x
"""

# ============================================================
# IMPORTS
# ============================================================

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
import time

from datetime import datetime, timezone
from html import unescape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import (
    parse_qsl,
    quote,
    urljoin,
    urlparse,
    urlunparse,
)

import requests

from fastapi import APIRouter
from pydantic import BaseModel


# ============================================================
# ROUTER
# ============================================================

router = APIRouter()


# ============================================================
# SCANNER CONFIGURATION
# ============================================================

SCANNER_NAME = "WebShield-AI"
SCANNER_VERSION = "3.0.0"

REQUEST_TIMEOUT = 10
SECONDARY_TIMEOUT = 5

MAX_BODY_LENGTH = 500_000
MAX_FINDINGS = 200
MAX_LIST_ITEMS = 100

USER_AGENT = (
    "WebShield-AI/3.0 "
    "(Safe-Non-Destructive-Web-Security-Scanner)"
)

SCANNER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/json;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.8",
    "Connection": "close",
}


# ============================================================
# REQUEST MODEL
# ============================================================

class ScanRequest(BaseModel):
    url: str


# ============================================================
# COMMON HELPERS
# ============================================================

def utc_now() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_url(url: str) -> str:
    """
    Normalize user supplied URL.

    If scheme is missing, HTTPS is preferred.
    """
    value = str(url).strip()

    if not value:
        return value

    parsed = urlparse(value)

    if not parsed.scheme:
        value = "https://" + value

    return value


def validate_scan_url(
    url: str,
) -> Tuple[bool, Optional[str]]:
    """
    Validate target URL.

    This scanner accepts normal public HTTP/HTTPS targets.
    Localhost, loopback and private network targets are blocked
    to reduce accidental internal-network scanning.
    """

    if not url:
        return False, "URL is empty."

    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return False, "Only HTTP and HTTPS URLs are supported."

    if not parsed.hostname:
        return False, "URL hostname is missing."

    hostname = parsed.hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
    }

    if hostname in blocked_names:
        return False, "Localhost targets are not allowed."

    try:
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            return (
                False,
                "Private, loopback or reserved IP targets "
                "are not allowed.",
            )

    except ValueError:
        # Hostname is not an IP address.
        pass

    return True, None


def safe_get(
    url: str,
    timeout: int = SECONDARY_TIMEOUT,
) -> Optional[requests.Response]:
    """Safe GET request helper."""

    try:
        return requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=SCANNER_HEADERS,
        )

    except requests.exceptions.RequestException:
        return None


def safe_head(
    url: str,
    timeout: int = SECONDARY_TIMEOUT,
) -> Optional[requests.Response]:
    """Safe HEAD request helper."""

    try:
        return requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=SCANNER_HEADERS,
        )

    except requests.exceptions.RequestException:
        return None


def get_base_url(url: str) -> str:
    """Return scheme + hostname + optional port."""

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.hostname:
        return ""

    netloc = parsed.netloc

    return f"{parsed.scheme}://{netloc}"


def unique_list(
    values: List[Any],
) -> List[Any]:
    """Preserve order while removing duplicates."""

    result = []
    seen = set()

    for value in values:

        key = str(value)

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def limit_list(
    values: List[Any],
    limit: int = MAX_LIST_ITEMS,
) -> List[Any]:
    """Limit result size."""

    return values[:limit]


def clean_text(
    value: Any,
    max_length: int = 500,
) -> str:
    """Normalize text for JSON output."""

    if value is None:
        return ""

    text = str(value)

    text = re.sub(
        r"\s+",
        " ",
        text,
    ).strip()

    return text[:max_length]


def get_response_body(
    response: requests.Response,
) -> str:
    """Return safely limited response body."""

    try:
        return response.text[:MAX_BODY_LENGTH]

    except Exception:
        return ""


def absolute_url(
    base: str,
    value: str,
) -> str:
    """Convert relative URL to absolute URL."""

    return urljoin(
        base,
        unescape(value.strip()),
    )


def is_http_url(
    value: str,
) -> bool:
    """Check whether URL is HTTP/HTTPS."""

    parsed = urlparse(value)

    return parsed.scheme.lower() in {
        "http",
        "https",
    }


def is_https_url(
    value: str,
) -> bool:
    """Check HTTPS URL."""

    return urlparse(value).scheme.lower() == "https"


def same_hostname(
    first: str,
    second: str,
) -> bool:
    """Compare URL hostnames."""

    first_host = urlparse(first).hostname
    second_host = urlparse(second).hostname

    if not first_host or not second_host:
        return False

    return first_host.lower() == second_host.lower()


# ============================================================
# DOMAIN / NETWORK ANALYSIS
# ============================================================

def get_domain_info(
    url: str,
) -> Dict[str, Any]:

    parsed = urlparse(url)

    hostname = parsed.hostname

    addresses = []

    if hostname:

        try:
            infos = socket.getaddrinfo(
                hostname,
                parsed.port or (
                    443
                    if parsed.scheme == "https"
                    else 80
                ),
                type=socket.SOCK_STREAM,
            )

            for info in infos:

                address = info[4][0]

                if address not in addresses:
                    addresses.append(address)

        except socket.gaierror:
            pass

        except OSError:
            pass

    return {
        "hostname": hostname,
        "scheme": parsed.scheme,
        "port": parsed.port,
        "domain": hostname,
        "ip_addresses": addresses[:20],
        "path": parsed.path or "/",
        "query_present": bool(parsed.query),
    }


# ============================================================
# REDIRECT ANALYSIS
# ============================================================

def analyze_redirects(
    response: requests.Response,
) -> Dict[str, Any]:

    history = response.history

    chain = []

    for item in history:

        chain.append(
            {
                "status_code": item.status_code,
                "url": item.url,
                "location": item.headers.get(
                    "Location",
                    "",
                ),
            }
        )

    count = len(history)

    return {
        "redirect_count": count,
        "final_url": response.url,
        "chain": chain[:20],
        "long_chain": count > 3,
    }


# ============================================================
# TLS / SSL
# ============================================================

def check_ssl(
    url: str,
) -> Dict[str, Any]:

    parsed = urlparse(url)

    result = {
        "https": parsed.scheme.lower() == "https",
        "certificate": "Not Applicable",
        "validation_error": None,
        "days_remaining": None,
        "issuer": {},
        "subject": {},
    }

    if parsed.scheme.lower() != "https":
        return result

    hostname = parsed.hostname

    if not hostname:
        result["certificate"] = "Invalid"
        result["validation_error"] = "Hostname unavailable."
        return result

    port = parsed.port or 443

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=REQUEST_TIMEOUT,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                result["certificate"] = "Valid"

                issuer = {}

                for part in certificate.get(
                    "issuer",
                    [],
                ):
                    for key, value in part:
                        issuer[key] = value

                subject = {}

                for part in certificate.get(
                    "subject",
                    [],
                ):
                    for key, value in part:
                        subject[key] = value

                result["issuer"] = issuer
                result["subject"] = subject

                not_after = certificate.get(
                    "notAfter"
                )

                if not_after:

                    expiry = datetime.strptime(
                        not_after,
                        "%b %d %H:%M:%S %Y %Z",
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    days = (
                        expiry
                        - datetime.now(timezone.utc)
                    ).total_seconds() / 86400

                    result["days_remaining"] = round(
                        days,
                        2,
                    )

    except ssl.SSLCertVerificationError as exc:

        result["certificate"] = "Invalid"
        result["validation_error"] = str(exc)

    except Exception as exc:

        result["certificate"] = "Invalid"
        result["validation_error"] = clean_text(
            exc
        )

    return result


# ============================================================
# SECURITY HEADERS
# ============================================================

SECURITY_HEADER_NAMES = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


def analyze_security_headers(
    headers: requests.structures.CaseInsensitiveDict,
) -> Dict[str, Any]:

    result = {}

    for name in SECURITY_HEADER_NAMES:

        value = headers.get(name)

        if value:
            result[name] = value
        else:
            result[name] = "Missing"

    return result


# ============================================================
# RESPONSE SECURITY
# ============================================================

def analyze_response_security(
    response: requests.Response,
) -> Dict[str, Any]:

    headers = response.headers

    content_length = headers.get(
        "Content-Length"
    )

    try:
        declared_size = (
            int(content_length)
            if content_length
            else None
        )

    except ValueError:
        declared_size = None

    return {
        "status_code": response.status_code,
        "content_type": headers.get(
            "Content-Type",
            "Not Present",
        ),
        "content_encoding": headers.get(
            "Content-Encoding",
            "Not Present",
        ),
        "content_length_header": declared_size,
        "actual_response_size": len(
            response.content
        ),
        "connection": headers.get(
            "Connection",
            "Not Present",
        ),
        "server": headers.get(
            "Server",
            "Not Present",
        ),
        "date": headers.get(
            "Date",
            "Not Present",
        ),
        "cache_control": headers.get(
            "Cache-Control",
            "Not Present",
        ),
        "vary": headers.get(
            "Vary",
            "Not Present",
        ),
    }


# ============================================================
# COOKIE SECURITY
# ============================================================

def analyze_cookies(
    response: requests.Response,
) -> Dict[str, Any]:

    cookies = []

    try:

        for cookie in response.cookies:

            same_site = cookie.get(
                "SameSite"
            )

            cookies.append(
                {
                    "name": cookie.name,
                    "secure": bool(
                        cookie.secure
                    ),
                    "httponly": bool(
                        cookie.has_nonstandard_attr(
                            "HttpOnly"
                        )
                    ),
                    "samesite": same_site
                    if same_site
                    else None,
                    "domain": cookie.domain,
                    "path": cookie.path,
                }
            )

    except Exception:
        pass

    return {
        "count": len(cookies),
        "cookies": cookies,
    }


# ============================================================
# CORS
# ============================================================

def analyze_cors(
    response: requests.Response,
) -> Dict[str, Any]:

    headers = response.headers

    allow_origin = headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = headers.get(
        "Access-Control-Allow-Credentials"
    )

    wildcard = (
        allow_origin == "*"
    )

    credentials_enabled = (
        str(
            allow_credentials
        ).lower()
        == "true"
    )

    return {
        "allow_origin": (
            allow_origin
            if allow_origin
            else "Missing"
        ),
        "allow_credentials": (
            allow_credentials
            if allow_credentials
            else "Missing"
        ),
        "allow_methods": headers.get(
            "Access-Control-Allow-Methods",
            "Missing",
        ),
        "allow_headers": headers.get(
            "Access-Control-Allow-Headers",
            "Missing",
        ),
        "expose_headers": headers.get(
            "Access-Control-Expose-Headers",
            "Missing",
        ),
        "wildcard_origin": wildcard,
        "credentials_enabled": credentials_enabled,
        "wildcard_credentials_risk": (
            wildcard
            and credentials_enabled
        ),
    }


# ============================================================
# HTTP METHODS
# ============================================================

def check_http_methods(
    url: str,
) -> Dict[str, Any]:

    result = {
        "allow_header": "Missing",
        "review_methods": [],
        "options_supported": False,
    }

    try:

        response = requests.options(
            url,
            timeout=SECONDARY_TIMEOUT,
            allow_redirects=True,
            headers=SCANNER_HEADERS,
        )

        allow = response.headers.get(
            "Allow"
        )

        if allow:

            result["allow_header"] = allow

            methods = [
                item.strip().upper()
                for item in allow.split(",")
                if item.strip()
            ]

            result["review_methods"] = [
                method
                for method in methods
                if method in {
                    "TRACE",
                    "PUT",
                    "DELETE",
                    "CONNECT",
                }
            ]

        result["options_supported"] = (
            response.status_code < 500
        )

    except requests.exceptions.RequestException:
        pass

    return result


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def detect_technologies(
    response: requests.Response,
) -> Dict[str, Any]:

    headers = response.headers
    body = get_response_body(response).lower()

    detected = []

    server = headers.get(
        "Server",
        "Unknown",
    )

    x_powered = headers.get(
        "X-Powered-By"
    )

    if "wordpress" in body:
        detected.append("WordPress")

    if "wp-content" in body:
        detected.append("WordPress")

    if "wp-includes" in body:
        detected.append("WordPress")

    if "jquery" in body:
        detected.append("jQuery")

    if "bootstrap" in body:
        detected.append("Bootstrap")

    if "react" in body:
        detected.append("React")

    if "vue" in body:
        detected.append("Vue.js")

    if "angular" in body:
        detected.append("Angular")

    if "next.js" in body:
        detected.append("Next.js")

    if "laravel" in body:
        detected.append("Laravel")

    if "django" in body:
        detected.append("Django")

    if "fastapi" in body:
        detected.append("FastAPI")

    if server != "Unknown":
        detected.append(
            f"Server: {server}"
        )

    return {
        "detected": unique_list(
            detected
        ),
        "server": server,
        "x_powered_by": (
            x_powered
            if x_powered
            else "Not Present"
        ),
    }


# ============================================================
# WORDPRESS DETECTION
# ============================================================

def analyze_wordpress(
    response: requests.Response,
) -> Dict[str, Any]:

    body = get_response_body(response)

    indicators = []

    generator = None

    generator_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        body,
        re.IGNORECASE,
    )

    if generator_match:

        generator = clean_text(
            generator_match.group(1),
            200,
        )

        if "wordpress" in generator.lower():
            indicators.append(
                "generator_meta"
            )

    if re.search(
        r"/wp-content/",
        body,
        re.IGNORECASE,
    ):
        indicators.append(
            "wp-content"
        )

    if re.search(
        r"/wp-includes/",
        body,
        re.IGNORECASE,
    ):
        indicators.append(
            "wp-includes"
        )

    if re.search(
        r"wp-json",
        body,
        re.IGNORECASE,
    ):
        indicators.append(
            "wp-json"
        )

    detected = bool(indicators)

    return {
        "detected": detected,
        "confidence": (
            "High"
            if len(indicators) >= 2
            else "Medium"
            if indicators
            else "Low"
        ),
        "indicators": unique_list(
            indicators
        ),
        "generator": generator,
    }


# ============================================================
# WORDPRESS REST API
# ============================================================

def analyze_wordpress_rest_api(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(url)

    endpoint = (
        f"{base_url}/wp-json/"
        if base_url
        else ""
    )

    result = {
        "detected": False,
        "url": endpoint,
        "status_code": None,
        "content_type": None,
        "indicators": [],
    }

    if not endpoint:
        return result

    response = safe_get(
        endpoint,
        timeout=SECONDARY_TIMEOUT,
    )

    if response is None:
        return result

    result["status_code"] = (
        response.status_code
    )

    result["content_type"] = (
        response.headers.get(
            "Content-Type"
        )
    )

    body = get_response_body(
        response
    ).lower()

    if response.status_code == 200:

        markers = [
            "namespaces",
            "routes",
            "wp/v2",
            "wordpress",
        ]

        for marker in markers:

            if marker in body:
                result["indicators"].append(
                    marker
                )

        if result["indicators"]:
            result["detected"] = True

    return result


# ============================================================
# CONTENT TYPE
# ============================================================

def analyze_content_type(
    response: requests.Response,
) -> Dict[str, Any]:

    content_type = response.headers.get(
        "Content-Type",
        "",
    )

    body = get_response_body(
        response
    ).lstrip().lower()

    appears_html = (
        body.startswith("<!doctype html")
        or body.startswith("<html")
        or "<html" in body[:5000]
    )

    declared_html = (
        "text/html" in content_type.lower()
    )

    html_mismatch = (
        appears_html
        and content_type
        and not declared_html
    )

    return {
        "content_type": (
            content_type
            if content_type
            else "Not Present"
        ),
        "appears_html": appears_html,
        "declared_html": declared_html,
        "html_mismatch": html_mismatch,
    }


# ============================================================
# FORMS ANALYSIS
# ============================================================

def extract_forms(
    response: requests.Response,
) -> List[Dict[str, Any]]:

    body = get_response_body(
        response
    )

    forms = []

    form_matches = re.findall(
        r"<form\b([^>]*)>(.*?)</form>",
        body,
        re.IGNORECASE | re.DOTALL,
    )

    for attributes, content in form_matches:

        action_match = re.search(
            r'\baction\s*=\s*["\']([^"\']*)',
            attributes,
            re.IGNORECASE,
        )

        method_match = re.search(
            r'\bmethod\s*=\s*["\']([^"\']*)',
            attributes,
            re.IGNORECASE,
        )

        action_value = (
            action_match.group(1)
            if action_match
            else response.url
        )

        action = absolute_url(
            response.url,
            action_value,
        )

        method = (
            method_match.group(1).upper()
            if method_match
            else "GET"
        )

        inputs = []

        for input_match in re.finditer(
            r"<input\b([^>]*)>",
            content,
            re.IGNORECASE,
        ):

            attrs = input_match.group(1)

            type_match = re.search(
                r'\btype\s*=\s*["\']([^"\']+)',
                attrs,
                re.IGNORECASE,
            )

            name_match = re.search(
                r'\bname\s*=\s*["\']([^"\']+)',
                attrs,
                re.IGNORECASE,
            )

            inputs.append(
                {
                    "type": (
                        type_match.group(1)
                        if type_match
                        else "text"
                    ),
                    "name": (
                        name_match.group(1)
                        if name_match
                        else None
                    ),
                }
            )

        forms.append(
            {
                "action": action,
                "method": method,
                "inputs": inputs,
            }
        )

    return forms[:100]


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(
    response: requests.Response,
    forms: List[Dict[str, Any]],
    cookie_security: Dict[str, Any],
) -> Dict[str, Any]:

    body = get_response_body(
        response
    ).lower()

    login_words = [
        "login",
        "log in",
        "sign in",
        "signin",
        "authentication",
        "username",
        "password",
    ]

    mfa_words = [
        "two-factor",
        "two factor",
        "2fa",
        "mfa",
        "verification code",
        "authenticator",
        "one-time password",
        "otp",
    ]

    password_form_count = 0
    authentication_forms = []

    for form in forms:

        password_fields = [
            field
            for field in form["inputs"]
            if field["type"].lower()
            == "password"
        ]

        if password_fields:

            password_form_count += 1

            authentication_forms.append(
                {
                    "action": form["action"],
                    "method": form["method"],
                }
            )

    login_indicator = (
        password_form_count > 0
        or any(
            word in body
            for word in login_words
        )
    )

    mfa_indicator = any(
        word in body
        for word in mfa_words
    )

    return {
        "authentication_forms": (
            authentication_forms
        ),
        "indicators": {
            "login_indicator": login_indicator,
            "mfa_indicator": mfa_indicator,
            "password_form_count": (
                password_form_count
            ),
        },
        "session_cookie_count": (
            cookie_security.get(
                "count",
                0,
            )
        ),
    }


# ============================================================
# AUTHORIZATION / IDOR INDICATORS
# ============================================================

def analyze_authorization(
    response: requests.Response,
) -> Dict[str, Any]:

    parsed = urlparse(
        response.url
    )

    params = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    identifier_names = {
        "id",
        "uid",
        "user",
        "userid",
        "user_id",
        "account",
        "account_id",
        "profile",
        "profile_id",
        "order",
        "order_id",
        "document",
        "document_id",
        "file",
        "file_id",
        "record",
        "record_id",
    }

    identifiers = []

    for name, value in params:

        if name.lower() in identifier_names:

            identifiers.append(
                {
                    "parameter": name,
                    "value_present": bool(value),
                }
            )

    return {
        "potential_indicator": bool(
            identifiers
        ),
        "identifier_parameters": identifiers,
        "active_authorization_testing": False,
    }


# ============================================================
# SQL INJECTION PASSIVE ANALYSIS
# ============================================================

def analyze_sql_injection(
    response: requests.Response,
) -> Dict[str, Any]:

    body = get_response_body(
        response
    ).lower()

    database_errors = [
        "sql syntax",
        "mysql_fetch",
        "mysql error",
        "mysqli",
        "postgresql",
        "pg_query",
        "sqlite error",
        "ora-",
        "oracle error",
        "microsoft sql server",
        "odbc sql server",
        "syntax error at or near",
        "unclosed quotation mark",
        "jdbc",
    ]

    indicators = [
        marker
        for marker in database_errors
        if marker in body
    ]

    parsed = urlparse(
        response.url
    )

    params = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    interesting_names = {
        "id",
        "uid",
        "user_id",
        "item",
        "item_id",
        "product",
        "product_id",
        "category",
        "search",
        "query",
        "q",
        "page",
        "sort",
        "order",
        "filter",
    }

    interesting_parameters = [
        name
        for name, _ in params
        if name.lower()
        in interesting_names
    ]

    return {
        "database_error_indicators": unique_list(
            indicators
        ),
        "interesting_parameters": unique_list(
            interesting_parameters
        ),
        "passive_only": True,
    }


# ============================================================
# XSS PASSIVE ANALYSIS
# ============================================================

def analyze_xss(
    response: requests.Response,
) -> Dict[str, Any]:

    body = get_response_body(
        response
    )

    parsed = urlparse(
        response.url
    )

    params = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    reflected = []

    for name, value in params:

        if not value:
            continue

        decoded_value = unescape(
            value
        )

        if decoded_value in body:

            reflected.append(
                {
                    "parameter": name,
                    "value_reflected": True,
                }
            )

    return {
        "reflected_parameters": reflected,
        "passive_only": True,
    }


# ============================================================
# CSRF
# ============================================================

def analyze_csrf(
    response: requests.Response,
    forms: List[Dict[str, Any]],
    cookie_security: Dict[str, Any],
) -> Dict[str, Any]:

    body = get_response_body(
        response
    ).lower()

    potential_missing = []

    csrf_names = [
        "csrf",
        "xsrf",
        "csrfmiddlewaretoken",
        "authenticity_token",
        "_token",
    ]

    for form in forms:

        if form["method"] != "POST":
            continue

        form_token_present = False

        # This scanner uses page-wide evidence as a safe heuristic.
        for name in csrf_names:

            if name in body:
                form_token_present = True
                break

        if not form_token_present:

            potential_missing.append(
                {
                    "action": form["action"],
                    "method": form["method"],
                }
            )

    return {
        "potential_missing_token_forms": (
            potential_missing
        ),
        "cookie_count": cookie_security.get(
            "count",
            0,
        ),
        "passive_only": True,
    }


# ============================================================
# SSRF INDICATORS
# ============================================================

def analyze_ssrf(
    response: requests.Response,
    forms: List[Dict[str, Any]],
) -> Dict[str, Any]:

    candidates = []

    url_names = {
        "url",
        "uri",
        "link",
        "target",
        "redirect",
        "callback",
        "webhook",
        "endpoint",
        "feed",
        "source",
        "image_url",
        "remote_url",
    }

    parsed = urlparse(
        response.url
    )

    for name, _ in parse_qsl(
        parsed.query,
        keep_blank_values=True,
    ):

        if name.lower() in url_names:
            candidates.append(name)

    for form in forms:

        for field in form["inputs"]:

            name = field.get(
                "name"
            )

            if (
                name
                and name.lower()
                in url_names
            ):
                candidates.append(name)

    return {
        "potential_indicator": bool(
            candidates
        ),
        "url_parameter_candidates": unique_list(
            candidates
        ),
        "active_exploitation": False,
    }


# ============================================================
# COMMAND INJECTION INDICATORS
# ============================================================

def analyze_command_injection(
    response: requests.Response,
) -> Dict[str, Any]:

    parsed = urlparse(
        response.url
    )

    names = {
        "cmd",
        "command",
        "exec",
        "execute",
        "ping",
        "host",
        "shell",
        "process",
        "run",
    }

    parameters = [
        name
        for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if name.lower() in names
    ]

    body = get_response_body(
        response
    ).lower()

    response_markers = [
        "command not found",
        "sh:",
        "bash:",
        "cmd.exe",
        "powershell",
        "permission denied",
    ]

    observed = [
        marker
        for marker in response_markers
        if marker in body
    ]

    return {
        "potential_indicator": bool(
            parameters
            or observed
        ),
        "parameters": parameters,
        "response_indicators": observed,
        "active_execution": False,
    }


# ============================================================
# PATH TRAVERSAL INDICATORS
# ============================================================

def analyze_path_traversal(
    response: requests.Response,
) -> Dict[str, Any]:

    parsed = urlparse(
        response.url
    )

    names = {
        "file",
        "path",
        "filename",
        "filepath",
        "document",
        "template",
        "include",
        "page",
        "resource",
    }

    parameters = [
        name
        for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if name.lower() in names
    ]

    body = get_response_body(
        response
    ).lower()

    disclosure_markers = [
        "root:x:",
        "[boot loader]",
        "windows directory",
        "/etc/passwd",
        "system32",
    ]

    observed = [
        marker
        for marker in disclosure_markers
        if marker in body
    ]

    return {
        "potential_indicator": bool(
            parameters
            or observed
        ),
        "parameters": parameters,
        "response_indicators": observed,
        "active_payload_testing": False,
    }


# ============================================================
# FILE UPLOAD
# ============================================================

def analyze_file_upload(
    forms: List[Dict[str, Any]],
) -> Dict[str, Any]:

    upload_forms = []

    for form in forms:

        has_file = any(
            field["type"].lower()
            == "file"
            for field in form["inputs"]
        )

        if has_file:

            upload_forms.append(
                {
                    "action": form["action"],
                    "method": form["method"],
                }
            )

    return {
        "upload_forms_detected": bool(
            upload_forms
        ),
        "forms": upload_forms,
        "malicious_upload": False,
    }


# ============================================================
# API SECURITY
# ============================================================

def analyze_api_security(
    response: requests.Response,
) -> Dict[str, Any]:

    body = get_response_body(
        response
    ).lower()

    indicators = []

    api_patterns = [
        "/api/",
        "/api.",
        "application/json",
        "graphql",
        "wp-json",
        "rest api",
    ]

    for marker in api_patterns:

        if marker in body:
            indicators.append(marker)

    return {
        "api_detected": bool(
            indicators
        ),
        "indicators": unique_list(
            indicators
        ),
    }


# ============================================================
# OPEN REDIRECT
# ============================================================

def analyze_open_redirect(
    response: requests.Response,
) -> Dict[str, Any]:

    parsed = urlparse(
        response.url
    )

    redirect_names = {
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_url",
        "next",
        "continue",
        "destination",
        "target",
    }

    parameters = [
        name
        for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if name.lower() in redirect_names
    ]

    return {
        "redirect_parameters": unique_list(
            parameters
        ),
        "active_redirect_testing": False,
    }


# ============================================================
# CLICKJACKING
# ============================================================

def analyze_clickjacking(
    security_headers: Dict[str, Any],
) -> Dict[str, Any]:

    x_frame = security_headers.get(
        "X-Frame-Options"
    )

    csp = security_headers.get(
        "Content-Security-Policy"
    )

    csp_frame_ancestors = False

    if (
        csp
        and csp != "Missing"
        and "frame-ancestors" in csp.lower()
    ):
        csp_frame_ancestors = True

    frame_protection = (
        x_frame != "Missing"
        or csp_frame_ancestors
    )

    return {
        "frame_protection_present": (
            frame_protection
        ),
        "x_frame_options": (
            x_frame
        ),
        "csp_frame_ancestors": (
            csp_frame_ancestors
        ),
    }


# ============================================================
# CACHE SECURITY
# ============================================================

def analyze_cache_security(
    response: requests.Response,
) -> Dict[str, Any]:

    headers = response.headers

    cache_control = headers.get(
        "Cache-Control",
        "Not Present",
    )

    pragma = headers.get(
        "Pragma",
        "Not Present",
    )

    expires = headers.get(
        "Expires",
        "Not Present",
    )

    content = get_response_body(
        response
    ).lower()

    sensitive_terms = [
        "password",
        "session",
        "authorization",
        "account",
        "private",
        "token",
        "secret",
    ]

    sensitive_indicator = any(
        term in content
        for term in sensitive_terms
    )

    public_cache = (
        "public"
        in cache_control.lower()
    )

    no_store = (
        "no-store"
        in cache_control.lower()
    )

    warning = (
        sensitive_indicator
        and public_cache
        and not no_store
    )

    return {
        "cache_control": cache_control,
        "pragma": pragma,
        "expires": expires,
        "sensitive_content_indicator": (
            sensitive_indicator
        ),
        "public_cache_indicator": (
            public_cache
        ),
        "no_store": no_store,
        "sensitive_content_cache_indicator": (
            warning
        ),
    }


# ============================================================
# HOST HEADER
# ============================================================

def analyze_host_header(
    url: str,
) -> Dict[str, Any]:

    parsed = urlparse(url)

    hostname = parsed.hostname

    return {
        "hostname": hostname,
        "host_header_observed": parsed.netloc,
        "suspicious_host_behavior": False,
        "tested_with_alternate_host": False,
        "safe_mode": True,
    }


# ============================================================
# SUBRESOURCE INTEGRITY
# ============================================================

def analyze_sri(
    response: requests.Response,
) -> Dict[str, Any]:

    body = get_response_body(
        response
    )

    scripts = re.findall(
        r"<script\b([^>]*)>",
        body,
        re.IGNORECASE,
    )

    external_scripts = []
    missing_sri = []

    for attributes in scripts:

        src_match = re.search(
            r'\bsrc\s*=\s*["\']([^"\']+)',
            attributes,
            re.IGNORECASE,
        )

        integrity_match = re.search(
            r'\bintegrity\s*=\s*["\']([^"\']+)',
            attributes,
            re.IGNORECASE,
        )

        if not src_match:
            continue

        src = absolute_url(
            response.url,
            src_match.group(1),
        )

        # SRI is relevant primarily to external resources.
        if not is_http_url(src):
            continue

        if same_hostname(
            response.url,
            src,
        ):
            continue

        external_scripts.append(src)

        if not integrity_match:
            missing_sri.append(src)

    return {
        "external_scripts": unique_list(
            external_scripts
        ),
        "scripts_without_sri": unique_list(
            missing_sri
        ),
        "external_script_count": len(
            unique_list(
                external_scripts
            )
        ),
        "missing_sri_count": len(
            unique_list(
                missing_sri
            )
        ),
    }


# ============================================================
# MIXED CONTENT - IMPROVED
# ============================================================

def analyze_mixed_content(
    response: requests.Response,
) -> Dict[str, Any]:

    if not is_https_url(
        response.url
    ):

        return {
            "https_page": False,
            "mixed_content_detected": False,
            "http_resources": [],
            "resource_details": [],
        }

    body = get_response_body(
        response
    )

    resources = []

    patterns = [
        (
            "src",
            r'\bsrc\s*=\s*["\'](http://[^"\']+)',
        ),
        (
            "href",
            r'\bhref\s*=\s*["\'](http://[^"\']+)',
        ),
        (
            "action",
            r'\baction\s*=\s*["\'](http://[^"\']+)',
        ),
        (
            "poster",
            r'\bposter\s*=\s*["\'](http://[^"\']+)',
        ),
    ]

    for attribute, pattern in patterns:

        for match in re.finditer(
            pattern,
            body,
            re.IGNORECASE,
        ):

            raw_url = match.group(1)

            absolute = absolute_url(
                response.url,
                raw_url,
            )

            resources.append(
                {
                    "attribute": attribute,
                    "url": absolute,
                }
            )

    unique_resources = []

    seen = set()

    for item in resources:

        key = (
            item["attribute"],
            item["url"],
        )

        if key in seen:
            continue

        seen.add(key)
        unique_resources.append(item)

    # Navigation links are not equivalent to classic mixed
    # active content. Forms/actions and resource src values
    # are more important. We keep navigation links as
    # informational evidence rather than automatically treating
    # every href as high-risk mixed content.
    risky_resources = [
        item
        for item in unique_resources
        if item["attribute"]
        in {
            "src",
            "poster",
            "action",
        }
    ]

    http_urls = [
        item["url"]
        for item in risky_resources
    ]

    navigation_http = [
        item["url"]
        for item in unique_resources
        if item["attribute"] == "href"
    ]

    return {
        "https_page": True,
        "mixed_content_detected": bool(
            risky_resources
        ),
        "http_resources": limit_list(
            unique_list(
                http_urls
            )
        ),
        "navigation_http_links": limit_list(
            unique_list(
                navigation_http
            )
        ),
        "resource_details": limit_list(
            unique_resources
        ),
    }


# ============================================================
# FORM SECURITY
# ============================================================

def analyze_form_security(
    response: requests.Response,
    forms: List[Dict[str, Any]],
) -> Dict[str, Any]:

    insecure_actions = []
    get_forms = []
    password_get_forms = []

    for form in forms:

        action = form["action"]
        method = form["method"]

        if (
            is_https_url(response.url)
            and action.lower().startswith(
                "http://"
            )
        ):
            insecure_actions.append(
                action
            )

        if method == "GET":

            get_forms.append(
                action
            )

            if any(
                field["type"].lower()
                == "password"
                for field in form["inputs"]
            ):

                password_get_forms.append(
                    action
                )

    return {
        "forms": len(forms),
        "insecure_http_actions": unique_list(
            insecure_actions
        ),
        "get_forms": unique_list(
            get_forms
        ),
        "password_submission_using_get": unique_list(
            password_get_forms
        ),
    }


# ============================================================
# API DOCUMENTATION
# ============================================================

def check_api_documentation(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    paths = [
        "/swagger",
        "/swagger/",
        "/swagger-ui/",
        "/swagger-ui.html",
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/api/docs",
        "/docs",
        "/redoc",
        "/redoc/",
    ]

    detected = []

    if not base_url:

        return {
            "detected": False,
            "paths": [],
        }

    for path in paths:

        target = (
            f"{base_url}{path}"
        )

        response = safe_get(
            target,
            timeout=SECONDARY_TIMEOUT,
        )

        if response is None:
            continue

        if response.status_code != 200:
            continue

        body = get_response_body(
            response
        ).lower()

        markers = [
            "swagger",
            "openapi",
            "swagger ui",
            "redoc",
            "api documentation",
        ]

        matched = [
            marker
            for marker in markers
            if marker in body
        ]

        if matched:

            detected.append(
                {
                    "url": target,
                    "status_code": response.status_code,
                    "indicators": matched,
                }
            )

    return {
        "detected": bool(
            detected
        ),
        "paths": detected,
    }


# ============================================================
# DEBUG EXPOSURE
# ============================================================

def check_debug_exposure(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    paths = [
        "/debug",
        "/debug/",
        "/server-status",
        "/server-info",
        "/status",
        "/info",
        "/actuator",
        "/actuator/health",
        "/phpinfo.php",
    ]

    detected = []

    if not base_url:

        return {
            "detected": False,
            "paths": [],
        }

    indicators = [
        "debug",
        "traceback",
        "environment",
        "server status",
        "phpinfo",
        "actuator",
        "stack trace",
    ]

    for path in paths:

        target = (
            f"{base_url}{path}"
        )

        response = safe_get(
            target,
            timeout=SECONDARY_TIMEOUT,
        )

        if response is None:
            continue

        if response.status_code != 200:
            continue

        body = get_response_body(
            response
        ).lower()

        matched = [
            marker
            for marker in indicators
            if marker in body
        ]

        if matched:

            detected.append(
                {
                    "url": target,
                    "status_code": response.status_code,
                    "indicators": matched,
                }
            )

    return {
        "detected": bool(
            detected
        ),
        "paths": detected,
    }


# ============================================================
# SOURCE MAPS
# ============================================================

def check_source_maps(
    response: requests.Response,
) -> Dict[str, Any]:

    body = get_response_body(
        response
    )

    maps = re.findall(
        r'(?:src|href)=["\']([^"\']+\.map(?:\?[^"\']*)?)',
        body,
        re.IGNORECASE,
    )

    return {
        "source_maps_referenced": unique_list(
            maps
        ),
        "count": len(
            unique_list(
                maps
            )
        ),
    }


# ============================================================
# DIRECTORY LISTING
# ============================================================

def check_directory_listing(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    candidates = [
        "/uploads/",
        "/images/",
        "/files/",
        "/assets/",
        "/backup/",
        "/downloads/",
    ]

    detected = []

    for path in candidates:

        target = (
            f"{base_url}{path}"
        )

        response = safe_get(
            target,
            timeout=SECONDARY_TIMEOUT,
        )

        if response is None:
            continue

        if response.status_code != 200:
            continue

        body = get_response_body(
            response
        ).lower()

        markers = [
            "index of /",
            "directory listing",
            "parent directory",
        ]

        matched = any(
            marker in body
            for marker in markers
        )

        if matched:

            detected.append(
                target
            )

    return {
        "detected": bool(
            detected
        ),
        "evidence": unique_list(
            detected
        ),
    }


# ============================================================
# SENSITIVE FILE EXPOSURE
# ============================================================

def check_sensitive_file_exposure(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    candidates = [
        "/.env",
        "/.git/HEAD",
        "/phpinfo.php",
        "/config.php",
        "/wp-config.php",
        "/composer.json",
        "/package.json",
        "/backup.zip",
        "/backup.sql",
        "/database.sql",
    ]

    detected = []

    for path in candidates:

        target = (
            f"{base_url}{path}"
        )

        response = safe_get(
            target,
            timeout=SECONDARY_TIMEOUT,
        )

        if response is None:
            continue

        if response.status_code != 200:
            continue

        body = get_response_body(
            response
        )

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        suspicious = False

        if path == "/.env":

            suspicious = any(
                marker in body
                for marker in [
                    "DB_",
                    "APP_KEY",
                    "SECRET",
                    "PASSWORD",
                ]
            )

        elif path == "/.git/HEAD":

            suspicious = (
                "ref:" in body
                or body.strip() == "HEAD"
            )

        elif path == "/phpinfo.php":

            suspicious = (
                "phpinfo()" in body
                or "php version" in body.lower()
            )

        elif path.endswith(
            (
                ".zip",
                ".sql",
            )
        ):

            suspicious = True

        elif path.endswith(
            ".json"
        ):

            suspicious = (
                "dependencies" in body.lower()
                or "scripts" in body.lower()
            )

        else:

            suspicious = bool(
                body.strip()
            )

        if suspicious:

            detected.append(
                {
                    "url": target,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "size": len(
                        response.content
                    ),
                }
            )

    return {
        "detected": bool(
            detected
        ),
        "evidence": detected,
    }


# ============================================================
# ROBOTS.TXT
# ============================================================

def check_robots(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    target = (
        f"{base_url}/robots.txt"
    )

    response = safe_get(
        target,
        timeout=SECONDARY_TIMEOUT,
    )

    if response is None:

        return {
            "url": target,
            "found": False,
            "status_code": None,
            "content_type": None,
            "size": 0,
            "disallowed_paths": [],
        }

    body = get_response_body(
        response
    )

    disallowed = re.findall(
        r"(?im)^\s*Disallow:\s*(\S+)",
        body,
    )

    return {
        "url": target,
        "found": response.status_code == 200,
        "status_code": response.status_code,
        "content_type": response.headers.get(
            "Content-Type"
        ),
        "size": len(
            response.content
        ),
        "disallowed_paths": unique_list(
            disallowed
        )[:100],
    }


# ============================================================
# SITEMAP
# ============================================================

def check_sitemap(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    candidates = [
        "/sitemap.xml",
        "/sitemap_index.xml",
    ]

    for path in candidates:

        target = (
            f"{base_url}{path}"
        )

        response = safe_get(
            target,
            timeout=SECONDARY_TIMEOUT,
        )

        if response is None:
            continue

        if response.status_code != 200:
            continue

        body = get_response_body(
            response
        ).lower()

        valid = (
            "<urlset" in body
            or "<sitemapindex" in body
            or "<?xml" in body
        )

        if valid:

            urls = re.findall(
                r"<loc>\s*([^<]+)",
                body,
                re.IGNORECASE,
            )

            return {
                "url": target,
                "found": True,
                "status_code": response.status_code,
                "content_type": response.headers.get(
                    "Content-Type"
                ),
                "size": len(
                    response.content
                ),
                "url_count": len(
                    urls
                ),
            }

    return {
        "url": (
            f"{base_url}/sitemap.xml"
        ),
        "found": False,
        "status_code": 404,
        "content_type": None,
        "size": 0,
        "url_count": 0,
    }


# ============================================================
# SECURITY.TXT
# ============================================================

def check_security_txt(
    url: str,
) -> Dict[str, Any]:

    base_url = get_base_url(
        url
    )

    target = (
        f"{base_url}/.well-known/security.txt"
    )

    response = safe_get(
        target,
        timeout=SECONDARY_TIMEOUT,
    )

    if response is None:

        return {
            "found": False,
            "url": target,
            "status_code": None,
            "fields": [],
        }

    body = get_response_body(
        response
    )

    fields = []

    for line in body.splitlines():

        match = re.match(
            r"^\s*([A-Za-z-]+)\s*:",
            line,
        )

        if match:

            fields.append(
                match.group(1)
            )

    return {
        "found": (
            response.status_code == 200
        ),
        "url": target,
        "status_code": response.status_code,
        "fields": unique_list(
            fields
        ),
    }


# ============================================================
# BRUTE FORCE PROTECTION - PASSIVE
# ============================================================

def analyze_bruteforce_protection(
    response: requests.Response,
    authentication: Dict[str, Any],
) -> Dict[str, Any]:

    headers = response.headers

    rate_limit_headers = []

    for name in [
        "Retry-After",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "RateLimit-Limit",
        "RateLimit-Remaining",
    ]:

        if headers.get(name):
            rate_limit_headers.append(
                name
            )

    body = get_response_body(
        response
    ).lower()

    captcha_indicators = any(
        marker in body
        for marker in [
            "captcha",
            "recaptcha",
            "hcaptcha",
            "turnstile",
        ]
    )

    account_lockout_indicators = any(
        marker in body
        for marker in [
            "account locked",
            "temporarily locked",
            "too many attempts",
            "login attempts",
        ]
    )

    progressive_delay_indicators = any(
        marker in body
        for marker in [
            "try again later",
            "please wait",
            "retry after",
        ]
    )

    login_endpoint_detected = (
        authentication["indicators"].get(
            "login_indicator",
            False,
        )
    )

    return {
        "login_endpoint_detected": (
            login_endpoint_detected
        ),
        "rate_limit_headers": rate_limit_headers,
        "captcha_indicators": captcha_indicators,
        "account_lockout_indicators": (
            account_lockout_indicators
        ),
        "progressive_delay_indicators": (
            progressive_delay_indicators
        ),
        "active_bruteforce": False,
    }


# ============================================================
# FINDING BUILDER
# ============================================================

def finding(
    finding_id: str,
    name: str,
    severity: str,
    category: str,
    reason: str,
    evidence: Any,
    recommendation: str,
    confidence: str = "Medium",
    owasp: str = "A05: Security Misconfiguration",
    priority: str = "Recommended",
) -> Dict[str, Any]:

    return {
        "id": finding_id,
        "name": name,
        "type": category,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "owasp": owasp,
        "reason": reason,
        "evidence": (
            evidence
            if isinstance(
                evidence,
                (dict, list),
            )
            else str(evidence)
        ),
        "recommendation": recommendation,
        "priority": priority,
    }


# ============================================================
# FINDING DEDUPLICATION
# ============================================================

def deduplicate_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    result = []
    seen = set()

    for item in findings:

        key = (
            item.get("id"),
            item.get("name"),
            item.get("severity"),
        )

        if key in seen:
            continue

        seen.add(key)

        result.append(item)

    return result[:MAX_FINDINGS]


# ============================================================
# GENERATE FINDINGS
# ============================================================

def generate_findings(
    response,
    security_headers,
    ssl_info,
    cookie_security,
    cors,
    http_methods,
    technologies,
    wordpress,
    wordpress_rest,
    directory_listing,
    sensitive_files,
    security_txt,
    robots,
    sitemap,
    forms,
    sql_analysis,
    xss_analysis,
    csrf_analysis,
    ssrf_analysis,
    authentication,
    authorization,
    command_analysis,
    traversal_analysis,
    upload_analysis,
    api_security,
    bruteforce,
    open_redirect,
    clickjacking,
    cache_security,
    host_header,
    sri,
    mixed_content,
    form_security,
    api_docs,
    debug_exposure,
    source_maps,
    content_type,
    response_security,
):

    findings = []

    # --------------------------------------------------------
    # SECURITY HEADERS
    # --------------------------------------------------------

    if (
        security_headers.get(
            "Content-Security-Policy"
        )
        == "Missing"
    ):

        findings.append(
            finding(
                "WS-001",
                "Content-Security-Policy Missing",
                "Medium",
                "Security Configuration",
                "CSP header is missing.",
                "Content-Security-Policy: Missing",
                "Configure a suitable Content-Security-Policy.",
                "High",
            )
        )

    if (
        security_headers.get(
            "X-Frame-Options"
        )
        == "Missing"
    ):

        findings.append(
            finding(
                "WS-002",
                "X-Frame-Options Missing",
                "Low",
                "Clickjacking Protection",
                "X-Frame-Options is missing.",
                "X-Frame-Options: Missing",
                "Use DENY or SAMEORIGIN where appropriate, or use CSP frame-ancestors.",
                "High",
            )
        )

    if (
        security_headers.get(
            "X-Content-Type-Options"
        )
        == "Missing"
    ):

        findings.append(
            finding(
                "WS-003",
                "X-Content-Type-Options Missing",
                "Low",
                "Security Configuration",
                "X-Content-Type-Options is missing.",
                "X-Content-Type-Options: Missing",
                "Add X-Content-Type-Options: nosniff.",
                "High",
            )
        )

    if (
        ssl_info.get("https")
        and security_headers.get(
            "Strict-Transport-Security"
        )
        == "Missing"
    ):

        findings.append(
            finding(
                "WS-004",
                "Strict-Transport-Security Missing",
                "Medium",
                "Transport Security",
                "HTTPS is enabled but HSTS is missing.",
                "Strict-Transport-Security: Missing",
                "Configure HSTS after confirming HTTPS is fully deployed.",
                "High",
            )
        )

    for header, fid in [
        (
            "Referrer-Policy",
            "WS-005",
        ),
        (
            "Permissions-Policy",
            "WS-006",
        ),
    ]:

        if (
            security_headers.get(header)
            == "Missing"
        ):

            findings.append(
                finding(
                    fid,
                    f"{header} Missing",
                    "Low",
                    "Security Configuration",
                    f"{header} header is missing.",
                    f"{header}: Missing",
                    f"Configure an appropriate {header} policy.",
                    "High",
                    priority="Optional",
                )
            )

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    if not ssl_info.get("https"):

        findings.append(
            finding(
                "WS-TLS-001",
                "HTTPS Not Enabled",
                "High",
                "Transport Security",
                "The scanned URL uses HTTP.",
                response.url,
                "Use HTTPS with a valid TLS certificate.",
                "High",
                "A02: Cryptographic Failures",
            )
        )

    elif (
        ssl_info.get("certificate")
        == "Invalid"
    ):

        findings.append(
            finding(
                "WS-TLS-002",
                "Invalid TLS Certificate",
                "High",
                "Transport Security",
                "TLS certificate validation failed.",
                ssl_info.get(
                    "validation_error",
                    "Validation failed",
                ),
                "Install and correctly configure a valid TLS certificate.",
                "High",
                "A02: Cryptographic Failures",
            )
        )

    days = ssl_info.get(
        "days_remaining"
    )

    if (
        isinstance(
            days,
            (int, float),
        )
        and 0 <= days <= 30
    ):

        findings.append(
            finding(
                "WS-TLS-003",
                "TLS Certificate Expiration",
                "Medium",
                "Transport Security",
                "Certificate expires within 30 days.",
                f"Days remaining: {days}",
                "Renew the TLS certificate before expiration.",
                "High",
                "A02: Cryptographic Failures",
            )
        )

    # --------------------------------------------------------
    # COOKIES
    # --------------------------------------------------------

    for cookie in cookie_security.get(
        "cookies",
        [],
    ):

        name = cookie["name"]

        if (
            ssl_info.get("https")
            and not cookie["secure"]
        ):

            findings.append(
                finding(
                    "WS-COOKIE-001",
                    f"Insecure Cookie: {name}",
                    "Medium",
                    "Cookie Security",
                    "Cookie does not use Secure attribute.",
                    name,
                    "Use Secure for HTTPS session cookies.",
                    "High",
                )
            )

        if not cookie["httponly"]:

            findings.append(
                finding(
                    "WS-COOKIE-002",
                    f"Cookie Without HttpOnly: {name}",
                    "Medium",
                    "Cookie Security",
                    "Cookie does not use HttpOnly.",
                    name,
                    "Use HttpOnly when JavaScript does not need access.",
                    "High",
                )
            )

        if not cookie["samesite"]:

            findings.append(
                finding(
                    "WS-COOKIE-003",
                    f"Cookie Without SameSite: {name}",
                    "Low",
                    "Cookie Security",
                    "Cookie does not specify SameSite.",
                    name,
                    "Configure an appropriate SameSite policy.",
                    "High",
                    priority="Optional",
                )
            )

    # --------------------------------------------------------
    # SQLI
    # --------------------------------------------------------

    if sql_analysis[
        "database_error_indicators"
    ]:

        findings.append(
            finding(
                "WS-SQL-001",
                "Possible SQL Injection Indicator",
                "High",
                "SQL Injection",
                "Database error signatures were observed in the response.",
                sql_analysis[
                    "database_error_indicators"
                ],
                "Use parameterized queries, prepared statements and strict input validation.",
                "Medium",
                "A03: Injection",
            )
        )

    elif sql_analysis[
        "interesting_parameters"
    ]:

        findings.append(
            finding(
                "WS-SQL-002",
                "SQL Injection Review Recommended",
                "Info",
                "SQL Injection",
                "Potential database-related parameters were identified.",
                sql_analysis[
                    "interesting_parameters"
                ],
                "Review these parameters using authorized application security testing.",
                "Low",
                "A03: Injection",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # XSS
    # --------------------------------------------------------

    if xss_analysis[
        "reflected_parameters"
    ]:

        findings.append(
            finding(
                "WS-XSS-001",
                "Reflected Input Detected",
                "Medium",
                "Cross-Site Scripting",
                "User-controlled query input appears to be reflected in the response.",
                xss_analysis[
                    "reflected_parameters"
                ],
                "Apply context-aware output encoding and input validation.",
                "Medium",
                "A03: Injection",
            )
        )

    # --------------------------------------------------------
    # CSRF
    # --------------------------------------------------------

    if csrf_analysis[
        "potential_missing_token_forms"
    ]:

        findings.append(
            finding(
                "WS-CSRF-001",
                "Potential CSRF Protection Gap",
                "Medium",
                "CSRF",
                "A state-changing POST form was observed without an obvious CSRF token.",
                csrf_analysis[
                    "potential_missing_token_forms"
                ],
                "Use server-side CSRF tokens and appropriate SameSite cookie policies.",
                "Medium",
                "A01: Broken Access Control",
            )
        )

    # --------------------------------------------------------
    # SSRF
    # --------------------------------------------------------

    if ssrf_analysis[
        "potential_indicator"
    ]:

        findings.append(
            finding(
                "WS-SSRF-001",
                "Potential SSRF Input",
                "Info",
                "SSRF",
                "A parameter that may accept a URL or remote resource was identified.",
                ssrf_analysis[
                    "url_parameter_candidates"
                ],
                "Validate allowed schemes, hosts and destinations server-side.",
                "Low",
                "A10: Server-Side Request Forgery",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    if authentication[
        "authentication_forms"
    ]:

        indicators = (
            authentication[
                "indicators"
            ]
        )

        if not indicators[
            "mfa_indicator"
        ]:

            findings.append(
                finding(
                    "WS-AUTH-001",
                    "MFA Indicator Not Observed",
                    "Info",
                    "Authentication",
                    "A login form was detected but no obvious MFA indicator was observed.",
                    indicators,
                    "Consider MFA for sensitive accounts and administrative access.",
                    "Medium",
                    priority="Recommended",
                )
            )

    # --------------------------------------------------------
    # BRUTE FORCE PROTECTION
    # --------------------------------------------------------

    if bruteforce[
        "login_endpoint_detected"
    ]:

        protection_present = (
            bool(
                bruteforce[
                    "rate_limit_headers"
                ]
            )
            or bruteforce[
                "captcha_indicators"
            ]
            or bruteforce[
                "account_lockout_indicators"
            ]
            or bruteforce[
                "progressive_delay_indicators"
            ]
        )

        if not protection_present:

            findings.append(
                finding(
                    "WS-AUTH-002",
                    "Authentication Rate Limiting Review",
                    "Medium",
                    "Authentication Security",
                    "No clear rate-limiting, CAPTCHA, lockout or progressive-delay indicator was observed.",
                    "No passive protection indicator observed.",
                    "Implement server-side rate limiting, progressive delays, account protection and monitoring.",
                    "Medium",
                    priority="Recommended",
                )
            )

    # --------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------

    if authorization[
        "potential_indicator"
    ]:

        findings.append(
            finding(
                "WS-AUTHZ-001",
                "Authorization Review Required",
                "Info",
                "Authorization / IDOR",
                "Object or account identifiers were observed in the URL.",
                authorization[
                    "identifier_parameters"
                ],
                "Verify server-side authorization for every object access.",
                "Low",
                "A01: Broken Access Control",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # COMMAND INJECTION
    # --------------------------------------------------------

    if command_analysis[
        "potential_indicator"
    ]:

        findings.append(
            finding(
                "WS-CMD-001",
                "Command Injection Review Indicator",
                "Medium",
                "Command Injection",
                "A parameter or response pattern associated with command execution was observed.",
                command_analysis,
                "Avoid shell invocation with user-controlled data and use strict allowlists.",
                "Low",
                "A03: Injection",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # PATH TRAVERSAL
    # --------------------------------------------------------

    if traversal_analysis[
        "potential_indicator"
    ]:

        findings.append(
            finding(
                "WS-PATH-001",
                "Path Traversal Review Indicator",
                "Medium",
                "Path Traversal",
                "Potential file/path disclosure indicators were observed.",
                traversal_analysis,
                "Canonicalize paths and restrict file access to approved directories.",
                "Medium",
                "A01: Broken Access Control",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # FILE UPLOAD
    # --------------------------------------------------------

    if upload_analysis[
        "upload_forms_detected"
    ]:

        findings.append(
            finding(
                "WS-UPLOAD-001",
                "File Upload Endpoint Detected",
                "Info",
                "File Upload Security",
                "A file upload form was detected.",
                upload_analysis[
                    "forms"
                ],
                "Validate extension, MIME type, size and file content server-side.",
                "High",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # API SECURITY
    # --------------------------------------------------------

    if api_security[
        "api_detected"
    ]:

        findings.append(
            finding(
                "WS-API-001",
                "API Endpoint Detected",
                "Info",
                "API Security",
                "API-related indicators were detected.",
                api_security[
                    "indicators"
                ],
                "Review authentication, authorization, schema validation, rate limiting and error handling.",
                "Medium",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # WORDPRESS
    # --------------------------------------------------------

    if wordpress[
        "detected"
    ]:

        findings.append(
            finding(
                "WS-WP-001",
                "WordPress Detected",
                "Info",
                "Technology Detection",
                "WordPress technology indicators were detected.",
                wordpress[
                    "indicators"
                ],
                "Keep WordPress core, plugins and themes updated and remove unused components.",
                wordpress[
                    "confidence"
                ],
                priority="Informational",
            )
        )

    # --------------------------------------------------------
    # WORDPRESS REST API
    # --------------------------------------------------------

    if wordpress_rest[
        "detected"
    ]:

        findings.append(
            finding(
                "WS-WP-002",
                "WordPress REST API Detected",
                "Info",
                "REST API Detection",
                "A WordPress REST API endpoint appears publicly accessible.",
                wordpress_rest,
                "Review exposed REST endpoints and enforce appropriate authorization.",
                "High",
                "A01: Broken Access Control",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # CORS
    # --------------------------------------------------------

    if cors[
        "wildcard_credentials_risk"
    ]:

        findings.append(
            finding(
                "WS-CORS-001",
                "Wildcard CORS With Credentials",
                "High",
                "CORS",
                "Wildcard origin and credentials were observed together.",
                {
                    "allow_origin": cors[
                        "allow_origin"
                    ],
                    "allow_credentials": cors[
                        "allow_credentials"
                    ],
                },
                "Use explicit trusted origins when credentials are required.",
                "High",
            )
        )

    # --------------------------------------------------------
    # HTTP TRACE
    # --------------------------------------------------------

    if "TRACE" in http_methods[
        "review_methods"
    ]:

        findings.append(
            finding(
                "WS-HTTP-001",
                "TRACE Method Enabled",
                "Low",
                "HTTP Methods",
                "TRACE is advertised by the server.",
                http_methods[
                    "allow_header"
                ],
                "Disable TRACE unless explicitly required.",
                "Medium",
            )
        )

    # --------------------------------------------------------
    # DIRECTORY LISTING
    # --------------------------------------------------------

    if directory_listing[
        "detected"
    ]:

        findings.append(
            finding(
                "WS-DIR-001",
                "Directory Listing",
                "Medium",
                "Directory Listing",
                "A web directory appears to expose directory contents.",
                directory_listing[
                    "evidence"
                ],
                "Disable directory indexing.",
                "High",
            )
        )

    # --------------------------------------------------------
    # SENSITIVE FILES
    # --------------------------------------------------------

    if sensitive_files[
        "detected"
    ]:

        findings.append(
            finding(
                "WS-FILE-001",
                "Sensitive File Exposure",
                "High",
                "Sensitive File Exposure",
                "Potential sensitive files appear publicly accessible.",
                sensitive_files[
                    "evidence"
                ],
                "Remove sensitive files from public web roots or restrict access.",
                "High",
            )
        )

    # --------------------------------------------------------
    # OPEN REDIRECT
    # --------------------------------------------------------

    if open_redirect[
        "redirect_parameters"
    ]:

        findings.append(
            finding(
                "WS-REDIRECT-001",
                "Potential Open Redirect Parameter",
                "Info",
                "Open Redirect",
                "A redirect-related parameter was identified.",
                open_redirect[
                    "redirect_parameters"
                ],
                "Allow only trusted destinations or use server-side destination mapping.",
                "Low",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # CLICKJACKING
    # --------------------------------------------------------

    if not clickjacking[
        "frame_protection_present"
    ]:

        findings.append(
            finding(
                "WS-CLICK-001",
                "Clickjacking Protection Missing",
                "Medium",
                "Clickjacking",
                "No obvious frame protection was detected.",
                "X-Frame-Options and CSP frame-ancestors were not observed.",
                "Configure X-Frame-Options or CSP frame-ancestors.",
                "High",
                "A05: Security Misconfiguration",
            )
        )

    # --------------------------------------------------------
    # CACHE
    # --------------------------------------------------------

    if cache_security[
        "sensitive_content_cache_indicator"
    ]:

        findings.append(
            finding(
                "WS-CACHE-001",
                "Potential Sensitive Content Caching",
                "Low",
                "Cache Security",
                "Potentially sensitive content was observed with a public cache directive.",
                {
                    "cache_control": cache_security[
                        "cache_control"
                    ],
                    "sensitive_content_indicator": cache_security[
                        "sensitive_content_indicator"
                    ],
                },
                "Use appropriate private/no-store cache directives for sensitive responses.",
                "Medium",
            )
        )

    # --------------------------------------------------------
    # HOST HEADER
    # --------------------------------------------------------

    if host_header[
        "suspicious_host_behavior"
    ]:

        findings.append(
            finding(
                "WS-HOST-001",
                "Host Header Handling",
                "Medium",
                "Host Header",
                "Suspicious host handling behavior was observed.",
                host_header,
                "Validate allowed hostnames server-side.",
                "Medium",
            )
        )

    # --------------------------------------------------------
    # SRI
    # --------------------------------------------------------

    if sri[
        "missing_sri_count"
    ]:

        findings.append(
            finding(
                "WS-SRI-001",
                "External Scripts Without SRI",
                "Low",
                "Subresource Integrity",
                "External scripts were detected without integrity attributes.",
                sri[
                    "scripts_without_sri"
                ],
                "Consider Subresource Integrity for third-party scripts where practical.",
                "High",
                priority="Recommended",
            )
        )

    # --------------------------------------------------------
    # MIXED CONTENT
    # --------------------------------------------------------

    if mixed_content[
        "mixed_content_detected"
    ]:

        findings.append(
            finding(
                "WS-MIXED-001",
                "Mixed Content",
                "Medium",
                "Mixed Content",
                "HTTP resources were referenced by an HTTPS page.",
                mixed_content[
                    "resource_details"
                ],
                "Load active resources and form destinations exclusively over HTTPS.",
                "High",
                "A02: Cryptographic Failures",
            )
        )

    # --------------------------------------------------------
    # FORM SECURITY
    # --------------------------------------------------------

    if form_security[
        "insecure_http_actions"
    ]:

        findings.append(
            finding(
                "WS-FORM-001",
                "Insecure Form Action",
                "High",
                "Form Security",
                "An HTTPS page submits a form to an HTTP action.",
                form_security[
                    "insecure_http_actions"
                ],
                "Submit sensitive forms exclusively over HTTPS.",
                "High",
                "A02: Cryptographic Failures",
            )
        )

    if form_security[
        "password_submission_using_get"
    ]:

        findings.append(
            finding(
                "WS-FORM-002",
                "Password Submitted Using GET",
                "High",
                "Form Security",
                "A password field appears inside a GET form.",
                form_security[
                    "password_submission_using_get"
                ],
                "Use POST or another secure method for credential submission.",
                "High",
            )
        )

    # --------------------------------------------------------
    # API DOCUMENTATION
    # --------------------------------------------------------

    if api_docs[
        "detected"
    ]:

        findings.append(
            finding(
                "WS-API-002",
                "API Documentation Exposure",
                "Low",
                "API Documentation Exposure",
                "Swagger/OpenAPI documentation appears publicly accessible.",
                api_docs[
                    "paths"
                ],
                "Restrict API documentation in production when it exposes sensitive implementation details.",
                "High",
                priority="Recommended",
            )
        )

    # --------------------------------------------------------
    # DEBUG
    # --------------------------------------------------------

    if debug_exposure[
        "detected"
    ]:

        findings.append(
            finding(
                "WS-DEBUG-001",
                "Debug/Status Endpoint Exposure",
                "Medium",
                "Debug Exposure",
                "A potential debug, status or diagnostic endpoint was detected.",
                debug_exposure[
                    "paths"
                ],
                "Disable or protect diagnostic endpoints in production.",
                "High",
            )
        )

    # --------------------------------------------------------
    # SOURCE MAPS
    # --------------------------------------------------------

    if source_maps[
        "count"
    ]:

        findings.append(
            finding(
                "WS-SOURCE-001",
                "Source Map Reference",
                "Info",
                "Source Map Exposure",
                "JavaScript source-map references were detected.",
                source_maps[
                    "source_maps_referenced"
                ],
                "Review whether production source maps expose sensitive implementation details.",
                "High",
                priority="Manual Review",
            )
        )

    # --------------------------------------------------------
    # CONTENT TYPE
    # --------------------------------------------------------

    if content_type[
        "html_mismatch"
    ]:

        findings.append(
            finding(
                "WS-MIME-001",
                "Content-Type Mismatch",
                "Low",
                "MIME Security",
                "Response appears to contain HTML but declares another MIME type.",
                content_type[
                    "content_type"
                ],
                "Return the correct Content-Type header.",
                "Medium",
            )
        )

    # --------------------------------------------------------
    # SECURITY.TXT
    # --------------------------------------------------------

    if not security_txt[
        "found"
    ]:

        findings.append(
            finding(
                "WS-DISC-001",
                "security.txt Not Found",
                "Info",
                "Vulnerability Disclosure",
                "No security.txt was found at the standard location.",
                security_txt[
                    "url"
                ],
                "Consider publishing a security.txt file for vulnerability disclosure.",
                "High",
                priority="Optional",
            )
        )

    # --------------------------------------------------------
    # SITEMAP
    # --------------------------------------------------------

    if not sitemap[
        "found"
    ]:

        findings.append(
            finding(
                "WS-DISC-002",
                "Sitemap Not Found",
                "Info",
                "Site Discovery",
                "No standard sitemap was detected.",
                sitemap[
                    "url"
                ],
                "Consider publishing a sitemap when appropriate for site discoverability.",
                "High",
                priority="Optional",
            )
        )

    # --------------------------------------------------------
    # ROBOTS.TXT
    # --------------------------------------------------------

    if robots[
        "found"
    ] and robots[
        "disallowed_paths"
    ]:

        findings.append(
            finding(
                "WS-DISC-003",
                "robots.txt Disallowed Paths Observed",
                "Info",
                "Site Discovery",
                "robots.txt contains paths that are intentionally excluded from crawler indexing.",
                robots[
                    "disallowed_paths"
                ],
                "Do not treat robots.txt as an access-control mechanism; protect sensitive paths with server-side authorization.",
                "High",
                priority="Informational",
            )
        )

    return deduplicate_findings(
        findings
    )


# ============================================================
# FINDING SUMMARY
# ============================================================

def get_finding_summary(
    findings: List[Dict[str, Any]],
) -> Dict[str, int]:

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
    }

    for item in findings:

        severity = str(
            item.get(
                "severity",
                "Info",
            )
        ).lower()

        if severity in summary:
            summary[severity] += 1

        summary["total"] += 1

    return summary


# ============================================================
# SEVERITY DISTRIBUTION
# ============================================================

def get_severity_distribution(
    findings: List[Dict[str, Any]],
) -> Dict[str, int]:

    return {
        "Critical": sum(
            1
            for item in findings
            if item.get("severity")
            == "Critical"
        ),
        "High": sum(
            1
            for item in findings
            if item.get("severity")
            == "High"
        ),
        "Medium": sum(
            1
            for item in findings
            if item.get("severity")
            == "Medium"
        ),
        "Low": sum(
            1
            for item in findings
            if item.get("severity")
            == "Low"
        ),
        "Info": sum(
            1
            for item in findings
            if item.get("severity")
            == "Info"
        ),
    }


# ============================================================
# OWASP SUMMARY
# ============================================================

def get_owasp_summary(
    findings: List[Dict[str, Any]],
) -> Dict[str, int]:

    summary = {}

    for item in findings:

        owasp = item.get(
            "owasp",
            "Unmapped",
        )

        summary[owasp] = (
            summary.get(
                owasp,
                0,
            )
            + 1
        )

    return dict(
        sorted(
            summary.items(),
            key=lambda x: (
                -x[1],
                x[0],
            ),
        )
    )


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    findings: List[Dict[str, Any]],
) -> Tuple[int, str]:

    """
    Professional bounded severity scoring.

    A finding is counted once after deduplication.
    Category caps prevent a large number of repeated
    low-severity findings from destroying the score.
    """

    weights = {
        "Critical": 35,
        "High": 20,
        "Medium": 10,
        "Low": 3,
        "Info": 0,
    }

    caps = {
        "Critical": 70,
        "High": 50,
        "Medium": 35,
        "Low": 15,
        "Info": 0,
    }

    deductions = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for item in findings:

        severity = item.get(
            "severity",
            "Info",
        )

        if severity not in deductions:
            continue

        deductions[severity] += weights[
            severity
        ]

    total_deduction = 0

    for severity, amount in deductions.items():

        total_deduction += min(
            amount,
            caps[severity],
        )

    score = max(
        0,
        min(
            100,
            100 - total_deduction,
        ),
    )

    if score >= 80:
        level = "Low"

    elif score >= 60:
        level = "Medium"

    elif score >= 40:
        level = "High"

    else:
        level = "Critical"

    return score, level


# ============================================================
# SECURITY GRADE
# ============================================================

def calculate_security_grade(
    score: int,
) -> str:

    if score >= 90:
        return "A+"

    if score >= 80:
        return "A"

    if score >= 70:
        return "B"

    if score >= 60:
        return "C"

    if score >= 50:
        return "D"

    if score >= 40:
        return "E"

    return "F"


# ============================================================
# RISK EXPLANATION
# ============================================================

def get_risk_explanation(
    level: str,
) -> str:

    explanations = {

        "Low":
            "The website shows a relatively low security risk based on the checks performed.",

        "Medium":
            "The website has several security weaknesses that should be reviewed and improved.",

        "High":
            "Multiple important security weaknesses were identified and should be addressed.",

        "Critical":
            "Serious security weaknesses were identified and require immediate attention.",
    }

    return explanations.get(
        level,
        "Risk level could not be determined.",
    )


# ============================================================
# RISK GUIDE
# ============================================================

def get_risk_score_guide():

    return {
        "90-100": "A+ / Low",
        "80-89": "A / Low",
        "70-79": "B / Medium",
        "60-69": "C / Medium",
        "50-59": "D / High",
        "40-49": "E / High",
        "0-39": "F / Critical",
    }


# ============================================================
# TOP PRIORITIES
# ============================================================

def get_top_priorities(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
    }

    sorted_findings = sorted(
        findings,
        key=lambda item: (
            severity_order.get(
                item.get(
                    "severity",
                    "Info",
                ),
                4,
            ),
            item.get(
                "priority",
                "Recommended",
            ),
        ),
    )

    result = []

    for item in sorted_findings[:10]:

        result.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "severity": item.get(
                    "severity"
                ),
                "recommendation": item.get(
                    "recommendation"
                ),
            }
        )

    return result


# ============================================================
# SCAN API
# ============================================================

@router.post("/scan")
def scan(
    data: ScanRequest,
):

    scan_started = time.perf_counter()
    scan_started_at = utc_now()

    input_url = str(
        data.url
    ).strip()

    try:

        # ====================================================
        # VALIDATION
        # ====================================================

        input_url = normalize_url(
            input_url
        )

        valid, error = validate_scan_url(
            input_url
        )

        if not valid:

            return {
                "message": "Invalid URL",
                "scan_status": "Failed",
                "url": input_url,
                "error": error,
            }

        # ====================================================
        # MAIN REQUEST
        # ====================================================

        start = time.perf_counter()

        response = requests.get(
            input_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers=SCANNER_HEADERS,
        )

        response_time = round(
            time.perf_counter()
            - start,
            2,
        )

        # ====================================================
        # BASIC RESPONSE
        # ====================================================

        headers = response.headers

        response_headers = {
            key: value
            for key, value
            in headers.items()
        }

        # ====================================================
        # CORE MODULES
        # ====================================================

        redirect_info = analyze_redirects(
            response
        )

        domain_info = get_domain_info(
            input_url
        )

        ssl_info = check_ssl(
            input_url
        )

        security_headers = (
            analyze_security_headers(
                headers
            )
        )

        cookie_security = analyze_cookies(
            response
        )

        cors = analyze_cors(
            response
        )

        http_methods = check_http_methods(
            input_url
        )

        technologies = detect_technologies(
            response
        )

        wordpress = analyze_wordpress(
            response
        )

        wordpress_rest = (
            analyze_wordpress_rest_api(
                input_url
            )
        )

        content_type = analyze_content_type(
            response
        )

        response_security = (
            analyze_response_security(
                response
            )
        )

        robots = check_robots(
            input_url
        )

        sitemap = check_sitemap(
            input_url
        )

        security_txt = check_security_txt(
            input_url
        )

        directory_listing = (
            check_directory_listing(
                input_url
            )
        )

        sensitive_files = (
            check_sensitive_file_exposure(
                input_url
            )
        )

        # ====================================================
        # FORMS
        # ====================================================

        forms = extract_forms(
            response
        )

        # ====================================================
        # ADVANCED PASSIVE MODULES
        # ====================================================

        sql_analysis = (
            analyze_sql_injection(
                response
            )
        )

        xss_analysis = (
            analyze_xss(
                response
            )
        )

        csrf_analysis = (
            analyze_csrf(
                response,
                forms,
                cookie_security,
            )
        )

        ssrf_analysis = (
            analyze_ssrf(
                response,
                forms,
            )
        )

        authentication = (
            analyze_authentication(
                response,
                forms,
                cookie_security,
            )
        )

        bruteforce = (
            analyze_bruteforce_protection(
                response,
                authentication,
            )
        )

        authorization = (
            analyze_authorization(
                response
            )
        )

        command_analysis = (
            analyze_command_injection(
                response
            )
        )

        traversal_analysis = (
            analyze_path_traversal(
                response
            )
        )

        upload_analysis = (
            analyze_file_upload(
                forms
            )
        )

        api_security = (
            analyze_api_security(
                response
            )
        )

        open_redirect = (
            analyze_open_redirect(
                response
            )
        )

        clickjacking = (
            analyze_clickjacking(
                security_headers
            )
        )

        cache_security = (
            analyze_cache_security(
                response
            )
        )

        host_header = (
            analyze_host_header(
                input_url
            )
        )

        sri = analyze_sri(
            response
        )

        mixed_content = (
            analyze_mixed_content(
                response
            )
        )

        form_security = (
            analyze_form_security(
                response,
                forms,
            )
        )

        api_docs = (
            check_api_documentation(
                input_url
            )
        )

        debug_exposure = (
            check_debug_exposure(
                input_url
            )
        )

        source_maps = (
            check_source_maps(
                response
            )
        )

        # ====================================================
        # FINDINGS
        # ====================================================

        findings = generate_findings(

            response,

            security_headers,

            ssl_info,

            cookie_security,

            cors,

            http_methods,

            technologies,

            wordpress,

            wordpress_rest,

            directory_listing,

            sensitive_files,

            security_txt,

            robots,

            sitemap,

            forms,

            sql_analysis,

            xss_analysis,

            csrf_analysis,

            ssrf_analysis,

            authentication,

            authorization,

            command_analysis,

            traversal_analysis,

            upload_analysis,

            api_security,

            bruteforce,

            open_redirect,

            clickjacking,

            cache_security,

            host_header,

            sri,

            mixed_content,

            form_security,

            api_docs,

            debug_exposure,

            source_maps,

            content_type,

            response_security,
        )

        # ====================================================
        # FINDING SUMMARY
        # ====================================================

        finding_summary = (
            get_finding_summary(
                findings
            )
        )

        severity_distribution = (
            get_severity_distribution(
                findings
            )
        )

        owasp_summary = (
            get_owasp_summary(
                findings
            )
        )

        # ====================================================
        # RISK ENGINE
        # ====================================================

        risk_score, risk_level = (
            calculate_risk_score(
                findings
            )
        )

        security_grade = (
            calculate_security_grade(
                risk_score
            )
        )

        risk_explanation = (
            get_risk_explanation(
                risk_level
            )
        )

        top_priorities = (
            get_top_priorities(
                findings
            )
        )

        # ====================================================
        # WARNINGS
        # ====================================================

        warnings = []

        if response.status_code >= 400:

            warnings.append(
                f"Website returned HTTP "
                f"status code "
                f"{response.status_code}."
            )

        if redirect_info[
            "redirect_count"
        ] > 3:

            warnings.append(
                "Website has a long redirect chain."
            )

        if (
            ssl_info["https"]
            and ssl_info["certificate"]
            == "Invalid"
        ):

            warnings.append(
                "TLS certificate validation failed."
            )

        if directory_listing[
            "detected"
        ]:

            warnings.append(
                "Directory listing detected."
            )

        if sensitive_files[
            "detected"
        ]:

            warnings.append(
                "Potential sensitive file exposure detected."
            )

        if mixed_content[
            "mixed_content_detected"
        ]:

            warnings.append(
                "HTTP resources were referenced by an HTTPS page."
            )

        if api_docs[
            "detected"
        ]:

            warnings.append(
                "API documentation may be publicly accessible."
            )

        if debug_exposure[
            "detected"
        ]:

            warnings.append(
                "Potential debug or diagnostic endpoint exposure detected."
            )

        # ====================================================
        # SCAN DURATION
        # ====================================================

        scan_duration = round(
            time.perf_counter()
            - scan_started,
            2,
        )

        # ====================================================
        # SCAN METADATA
        # ====================================================

        scan_metadata = {

            "scanner":
                SCANNER_NAME,

            "version":
                SCANNER_VERSION,

            "scan_started_at":
                scan_started_at,

            "scan_completed_at":
                utc_now(),

            "scan_duration":
                scan_duration,

            "request_timeout":
                REQUEST_TIMEOUT,

            "secondary_timeout":
                SECONDARY_TIMEOUT,

            "response_time":
                response_time,

            "response_size":
                len(
                    response.content
                ),

            "analysis_mode":
                "Safe Non-Destructive",

            "active_exploitation":
                False,

            "credential_bruteforce":
                False,

            "command_execution":
                False,

            "internal_ssrf":
                False,

            "malicious_file_upload":
                False,

            "destructive_testing":
                False,

            "authorized_testing_required":
                True,
        }

        # ====================================================
        # FINAL RESULT
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
                input_url,

            "final_url":
                response.url,

            "status_code":
                response.status_code,

            "server":
                headers.get(
                    "Server",
                    "Unknown",
                ),

            "response_time":
                response_time,

            "response_size":
                len(
                    response.content
                ),

            # ------------------------------------------------
            # 1. URL & NETWORK
            # ------------------------------------------------

            "domain_info":
                domain_info,

            "redirect_info":
                redirect_info,

            # ------------------------------------------------
            # 2. TLS / SSL
            # ------------------------------------------------

            "ssl":
                ssl_info,

            # ------------------------------------------------
            # 3. SECURITY HEADERS
            # ------------------------------------------------

            "security_headers":
                security_headers,

            # ------------------------------------------------
            # 4. COOKIES
            # ------------------------------------------------

            "cookie_security":
                cookie_security,

            # ------------------------------------------------
            # 5. CORS
            # ------------------------------------------------

            "cors":
                cors,

            # ------------------------------------------------
            # 6. HTTP METHODS
            # ------------------------------------------------

            "http_methods":
                http_methods,

            # ------------------------------------------------
            # 7. TECHNOLOGY DETECTION
            # ------------------------------------------------

            "technologies":
                technologies,

            # ------------------------------------------------
            # 8. WORDPRESS
            # ------------------------------------------------

            "wordpress":
                wordpress,

            # ------------------------------------------------
            # 9. REST API
            # ------------------------------------------------

            "wordpress_rest_api":
                wordpress_rest,

            # ------------------------------------------------
            # 10. FORMS
            # ------------------------------------------------

            "forms":
                forms,

            # ------------------------------------------------
            # 11. AUTHENTICATION
            # ------------------------------------------------

            "authentication":
                authentication,

            # ------------------------------------------------
            # 12. AUTHORIZATION
            # ------------------------------------------------

            "authorization_idor":
                authorization,

            # ------------------------------------------------
            # 13. SQLi
            # ------------------------------------------------

            "sql_injection":
                sql_analysis,

            # ------------------------------------------------
            # 14. XSS
            # ------------------------------------------------

            "xss":
                xss_analysis,

            # ------------------------------------------------
            # 15. CSRF
            # ------------------------------------------------

            "csrf":
                csrf_analysis,

            # ------------------------------------------------
            # 16. SSRF
            # ------------------------------------------------

            "ssrf":
                ssrf_analysis,

            # ------------------------------------------------
            # 17. COMMAND INJECTION
            # ------------------------------------------------

            "command_injection":
                command_analysis,

            # ------------------------------------------------
            # 18. PATH TRAVERSAL
            # ------------------------------------------------

            "path_traversal":
                traversal_analysis,

            # ------------------------------------------------
            # 19. FILE UPLOAD
            # ------------------------------------------------

            "file_upload":
                upload_analysis,

            # ------------------------------------------------
            # 20. OPEN REDIRECT
            # ------------------------------------------------

            "open_redirect":
                open_redirect,

            # ------------------------------------------------
            # 21. CLICKJACKING
            # ------------------------------------------------

            "clickjacking":
                clickjacking,

            # ------------------------------------------------
            # 22. CACHE SECURITY
            # ------------------------------------------------

            "cache_security":
                cache_security,

            # ------------------------------------------------
            # 23. HOST HEADER
            # ------------------------------------------------

            "host_header":
                host_header,

            # ------------------------------------------------
            # 24. SRI
            # ------------------------------------------------

            "subresource_integrity":
                sri,

            # ------------------------------------------------
            # 25. MIXED CONTENT
            # ------------------------------------------------

            "mixed_content":
                mixed_content,

            # ------------------------------------------------
            # 26. API DOCUMENTATION
            # ------------------------------------------------

            "api_documentation":
                api_docs,

            # ------------------------------------------------
            # 27. DEBUG EXPOSURE
            # ------------------------------------------------

            "debug_exposure":
                debug_exposure,

            # ------------------------------------------------
            # 28. SOURCE MAPS
            # ------------------------------------------------

            "source_maps":
                source_maps,

            # ------------------------------------------------
            # 29. DIRECTORY LISTING
            # ------------------------------------------------

            "directory_listing":
                directory_listing,

            # ------------------------------------------------
            # 30. SENSITIVE FILES
            # ------------------------------------------------

            "sensitive_file_exposure":
                sensitive_files,

            # ------------------------------------------------
            # 31. SECURITY.TXT
            # ------------------------------------------------

            "security_txt":
                security_txt,

            # ------------------------------------------------
            # 32. ROBOTS.TXT
            # ------------------------------------------------

            "robots":
                robots,

            # ------------------------------------------------
            # 33. SITEMAP
            # ------------------------------------------------

            "sitemap":
                sitemap,

            # ------------------------------------------------
            # 34. RESPONSE SECURITY
            # ------------------------------------------------

            "response_security":
                response_security,

            # ------------------------------------------------
            # EXTRA ANALYSIS
            # ------------------------------------------------

            "content_type":
                content_type,

            "api_security":
                api_security,

            "bruteforce_protection":
                bruteforce,

            "form_security":
                form_security,

            # ------------------------------------------------
            # 35-39. FINDINGS / RISK ENGINE
            # ------------------------------------------------

            "findings":
                findings,

            "finding_summary":
                finding_summary,

            "severity_distribution":
                severity_distribution,

            "owasp_summary":
                owasp_summary,

            # ------------------------------------------------
            # 40. FINAL SECURITY GRADE
            # ------------------------------------------------

            "risk_assessment": {

                "score":
                    risk_score,

                "level":
                    risk_level,

                "grade":
                    security_grade,

                "description":
                    risk_explanation,

                "score_guide":
                    get_risk_score_guide(),
            },

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "security_grade":
                security_grade,

            "top_priorities":
                top_priorities,

            "warnings":
                unique_list(
                    warnings
                ),

            "scan_metadata":
                scan_metadata,
        }

    # ========================================================
    # ERROR HANDLING
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
                "The website did not respond within the allowed time.",

        }

    except requests.exceptions.SSLError as exc:

        return {

            "message":
                "SSL Error",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                clean_text(exc),

        }

    except requests.exceptions.ConnectionError as exc:

        return {

            "message":
                "Connection Error",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                clean_text(exc),

        }

    except requests.exceptions.RequestException as exc:

        return {

            "message":
                "Website Unreachable",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                clean_text(exc),

        }

    except Exception as exc:

        return {

            "message":
                "Internal Scanner Error",

            "scan_status":
                "Failed",

            "url":
                data.url,

            "error":
                clean_text(exc),

        }