# ============================================================
# WebShield-AI
# Security Analysis Module
# ============================================================

from typing import List, Dict, Tuple


# ============================================================
# Generate Security Findings
# ============================================================

def generate_findings(
    security_headers: Dict[str, str],
    cookie_security: Dict,
    technologies: Dict[str, str]
) -> List[Dict]:

    findings = []

    # ========================================================
    # Security Header Analysis
    # ========================================================

    if security_headers.get("Content-Security-Policy") == "Missing":
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

    if security_headers.get("X-Frame-Options") == "Missing":
        findings.append({
            "type": "Security Header",
            "name": "X-Frame-Options",
            "severity": "Medium",
            "reason": "X-Frame-Options header is missing.",
            "recommendation": (
                "Add X-Frame-Options such as SAMEORIGIN or DENY "
                "to reduce clickjacking risks."
            )
        })

    if security_headers.get("X-Content-Type-Options") == "Missing":
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

    if security_headers.get("Strict-Transport-Security") == "Missing":
        findings.append({
            "type": "Security Header",
            "name": "Strict-Transport-Security",
            "severity": "Medium",
            "reason": "HSTS header is missing.",
            "recommendation": (
                "Configure Strict-Transport-Security when "
                "the website is fully HTTPS."
            )
        })

    # ========================================================
    # Cookie Security Analysis
    # ========================================================

    cookies = cookie_security.get("cookies", [])

    for cookie in cookies:

        cookie_name = cookie.get(
            "name",
            "Unknown"
        )

        secure = cookie.get(
            "secure",
            False
        )

        httponly = cookie.get(
            "httponly",
            False
        )

        samesite = cookie.get(
            "samesite",
            False
        )

        # ----------------------------------------------------
        # Secure Attribute
        # ----------------------------------------------------

        if not secure:
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

        # ----------------------------------------------------
        # HttpOnly Attribute
        # ----------------------------------------------------

        if not httponly:
            findings.append({
                "type": "Cookie Security",
                "name": cookie_name,
                "severity": "Medium",
                "reason": (
                    "Cookie does not have the HttpOnly attribute."
                ),
                "recommendation": (
                    "Use HttpOnly for cookies that do not need "
                    "to be accessed by client-side JavaScript."
                )
            })

        # ----------------------------------------------------
        # SameSite Attribute
        # ----------------------------------------------------

        if not samesite:
            findings.append({
                "type": "Cookie Security",
                "name": cookie_name,
                "severity": "Low",
                "reason": (
                    "Cookie does not specify SameSite."
                ),
                "recommendation": (
                    "Consider using an appropriate SameSite "
                    "policy for the cookie."
                )
            })

    # ========================================================
    # Technology / Information Disclosure
    # ========================================================

    server = technologies.get(
        "server",
        "Unknown"
    )

    powered_by = technologies.get(
        "powered_by",
        "Unknown"
    )

    if server != "Unknown":
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

    if powered_by != "Unknown":
        findings.append({
            "type": "Information Disclosure",
            "name": "X-Powered-By Header",
            "severity": "Low",
            "reason": (
                "The X-Powered-By header exposes technology "
                "information."
            ),
            "recommendation": (
                "Remove the X-Powered-By header when possible "
                "to reduce technology information disclosure."
            )
        })

    return findings


# ============================================================
# Calculate Risk Score
# ============================================================

def calculate_risk_score(
    findings: List[Dict]
) -> Tuple[int, str, Dict[str, str]]:

    # --------------------------------------------------------
    # Starting Score
    # --------------------------------------------------------

    score = 100

    # --------------------------------------------------------
    # Severity Weight
    # --------------------------------------------------------

    severity_weights = {
        "Critical": 35,
        "High": 25,
        "Medium": 15,
        "Low": 5,
        "Info": 0
    }

    # --------------------------------------------------------
    # Calculate Score
    # --------------------------------------------------------

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        deduction = severity_weights.get(
            severity,
            0
        )

        score -= deduction

    # --------------------------------------------------------
    # Keep Score Between 0 and 100
    # --------------------------------------------------------

    score = max(
        0,
        min(
            100,
            score
        )
    )

    # ========================================================
    # Risk Level Classification
    # ========================================================

    if score >= 80:
        risk_level = "Low"

    elif score >= 60:
        risk_level = "Medium"

    elif score >= 40:
        risk_level = "High"

    else:
        risk_level = "Critical"

    # ========================================================
    # Risk Scale
    # ========================================================

    risk_scale = {
        "Low": "80-100",
        "Medium": "60-79",
        "High": "40-59",
        "Critical": "0-39"
    }

    return (
        score,
        risk_level,
        risk_scale
    )


# ============================================================
# Security Analysis
# ============================================================

def analyze_security(
    security_headers: Dict[str, str],
    cookie_security: Dict,
    technologies: Dict[str, str]
) -> Dict:

    # --------------------------------------------------------
    # Generate Findings
    # --------------------------------------------------------

    findings = generate_findings(
        security_headers=security_headers,
        cookie_security=cookie_security,
        technologies=technologies
    )

    # --------------------------------------------------------
    # Calculate Risk
    # --------------------------------------------------------

    risk_score, risk_level, risk_scale = calculate_risk_score(
        findings
    )

    # --------------------------------------------------------
    # Return Analysis
    # --------------------------------------------------------

    return {
        "findings": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_scale": risk_scale
    }