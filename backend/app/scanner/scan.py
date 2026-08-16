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
        # URL Validation
        # ==========================
        parsed_url = urlparse(data.url)

        if parsed_url.scheme not in ["http", "https"]:
            return {
                "message": "Invalid URL",
                "scan_status": "Failed",
                "url": data.url,
                "error": "URL must start with http:// or https://"
            }

        if not parsed_url.hostname:
            return {
                "message": "Invalid URL",
                "scan_status": "Failed",
                "url": data.url,
                "error": "Hostname could not be detected"
            }

        hostname = parsed_url.hostname
        base_url = f"{parsed_url.scheme}://{hostname}"

        scan_warnings = []

        # ==========================
        # Main Website Request
        # ==========================
        try:
            start = time.time()

            response = requests.get(
                data.url,
                timeout=10,
                allow_redirects=True
            )

            end = time.time()

        except requests.exceptions.Timeout:
            return {
                "message": "Scan Failed",
                "scan_status": "Failed",
                "url": data.url,
                "error": "Website request timed out"
            }

        except requests.exceptions.ConnectionError:
            return {
                "message": "Scan Failed",
                "scan_status": "Failed",
                "url": data.url,
                "error": "Could not connect to the website"
            }

        except requests.exceptions.RequestException as e:
            return {
                "message": "Scan Failed",
                "scan_status": "Failed",
                "url": data.url,
                "error": str(e)
            }

        headers = response.headers

        # ==========================
        # Response Information
        # ==========================
        redirect_info = {
            "redirected": len(response.history) > 0,
            "redirect_count": len(response.history),
            "final_url": response.url
        }

        # ==========================
        # Response Headers
        # ==========================
        response_headers = {}

        for header_name, header_value in headers.items():
            response_headers[header_name] = header_value

        # ==========================
        # Domain & IP Detection
        # ==========================
        try:
            ip_address = socket.gethostbyname(hostname)

        except socket.gaierror:
            ip_address = "Unknown"
            scan_warnings.append(
                "IP address could not be resolved"
            )

        except Exception:
            ip_address = "Unknown"
            scan_warnings.append(
                "Domain information could not be checked"
            )

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

        except requests.exceptions.Timeout:
            scan_warnings.append(
                "Robots.txt check timed out"
            )

        except requests.exceptions.RequestException:
            scan_warnings.append(
                "Robots.txt could not be checked"
            )

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

        except requests.exceptions.Timeout:
            scan_warnings.append(
                "Sitemap.xml check timed out"
            )

        except requests.exceptions.RequestException:
            scan_warnings.append(
                "Sitemap.xml could not be checked"
            )

        # ==========================
        # SSL Check
        # ==========================
        ssl_info = {
            "https": parsed_url.scheme == "https",
            "certificate": "Not Applicable"
        }

        if parsed_url.scheme == "https":
            ssl_info["certificate"] = "Unknown"

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

            except ssl.SSLCertVerificationError:
                ssl_info["certificate"] = "Invalid"
                scan_warnings.append(
                    "SSL certificate verification failed"
                )

            except (socket.timeout, TimeoutError):
                ssl_info["certificate"] = "Unknown"
                scan_warnings.append(
                    "SSL check timed out"
                )

            except Exception:
                ssl_info["certificate"] = "Invalid"
                scan_warnings.append(
                    "SSL certificate could not be verified"
                )

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
        # Findings
        # ==========================
        findings = []

        if security_headers["Content-Security-Policy"] == "Missing":
            findings.append({
                "type": "Security Header",
                "name": "Content-Security-Policy",
                "severity": "Medium",
                "reason": (
                    "Content Security Policy is not configured."
                ),
                "recommendation": (
                    "Add a suitable Content-Security-Policy "
                    "header to control allowed content sources."
                )
            })

        if security_headers["X-Frame-Options"] == "Missing":
            findings.append({
                "type": "Security Header",
                "name": "X-Frame-Options",
                "severity": "Medium",
                "reason": (
                    "X-Frame-Options header is missing."
                ),
                "recommendation": (
                    "Configure X-Frame-Options to reduce "
                    "clickjacking risk."
                )
            })

        if security_headers["X-Content-Type-Options"] == "Missing":
            findings.append({
                "type": "Security Header",
                "name": "X-Content-Type-Options",
                "severity": "Low",
                "reason": (
                    "X-Content-Type-Options header is missing."
                ),
                "recommendation": (
                    "Add X-Content-Type-Options: nosniff "
                    "to reduce MIME-type sniffing."
                )
            })

        if security_headers["Strict-Transport-Security"] == "Missing":
            findings.append({
                "type": "Security Header",
                "name": "Strict-Transport-Security",
                "severity": "Medium",
                "reason": (
                    "HSTS header is missing."
                ),
                "recommendation": (
                    "Configure Strict-Transport-Security "
                    "when the website is fully HTTPS."
                )
            })

        # ==========================
        # Cookie Security
        # ==========================
        cookies = []

        try:
            cookie_headers = response.raw.headers.get_all(
                "Set-Cookie"
            )

            if cookie_headers:

                unique_cookie_names = set()

                for cookie_header in cookie_headers:

                    first_part = cookie_header.split(
                        ";",
                        1
                    )[0].strip()

                    if "=" not in first_part:
                        continue

                    cookie_name = first_part.split(
                        "=",
                        1
                    )[0].strip()

                    if not cookie_name:
                        continue

                    if cookie_name in unique_cookie_names:
                        continue

                    unique_cookie_names.add(cookie_name)

                    cookie_lower = cookie_header.lower()

                    cookie_info = {
                        "name": cookie_name,
                        "secure": (
                            "secure" in [
                                part.strip().lower()
                                for part in cookie_header.split(";")
                            ]
                        ),
                        "httponly": (
                            "httponly" in cookie_lower
                        ),
                        "samesite": (
                            "samesite=" in cookie_lower
                        )
                    }

                    cookies.append(cookie_info)

        except Exception:
            scan_warnings.append(
                "Cookie security could not be checked"
            )

        cookie_security = {
            "cookies_found": len(cookies),
            "cookies": cookies
        }

        # ==========================
        # Cookie Findings
        # ==========================
        for cookie in cookies:

            if not cookie["secure"]:
                findings.append({
                    "type": "Cookie Security",
                    "name": cookie["name"],
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
                    "name": cookie["name"],
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
                    "name": cookie["name"],
                    "severity": "Low",
                    "reason": (
                        "Cookie does not specify SameSite."
                    ),
                    "recommendation": (
                        "Consider using an appropriate SameSite "
                        "policy for the cookie."
                    )
                })

        # ==========================
        # Remove Duplicate Findings
        # ==========================
        unique_findings = []
        finding_keys = set()

        for finding in findings:

            finding_key = (
                finding["type"],
                finding["name"],
                finding["severity"],
                finding["reason"]
            )

            if finding_key not in finding_keys:
                finding_keys.add(finding_key)
                unique_findings.append(finding)

        findings = unique_findings

        # ==========================
        # Risk Score
        # ==========================
        score = 100

        if security_headers["Content-Security-Policy"] == "Missing":
            score -= 15

        if security_headers["X-Frame-Options"] == "Missing":
            score -= 10

        if security_headers["X-Content-Type-Options"] == "Missing":
            score -= 10

        if security_headers["Strict-Transport-Security"] == "Missing":
            score -= 15

        checked_cookie_names = set()

        for cookie in cookies:

            cookie_name = cookie["name"]

            if cookie_name in checked_cookie_names:
                continue

            checked_cookie_names.add(cookie_name)

            if not cookie["secure"]:
                score -= 5

            if not cookie["httponly"]:
                score -= 5

            if not cookie["samesite"]:
                score -= 5

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
        # Scan Status
        # ==========================
        if scan_warnings:
            scan_status = "Completed with Warnings"
        else:
            scan_status = "Completed"

        # ==========================
        # Final Response
        # ==========================
        return {
            "message": "Scan Completed",
            "scan_status": scan_status,
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
            "risk_score": score,
            "risk_level": risk,
            "warnings": scan_warnings
        }

    except Exception as e:
        return {
            "message": "Scan Failed",
            "scan_status": "Failed",
            "url": data.url,
            "error": str(e)
        }