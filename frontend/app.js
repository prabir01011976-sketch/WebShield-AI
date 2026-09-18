"use strict";

/*
============================================================
 WebShield-AI Professional Security Dashboard
 Frontend Controller
 Version: 6.1.0

 Goals:
 - Safe scan submission
 - No duplicate scan requests
 - Robust backend response mapping
 - Null-safe rendering
 - Professional risk score
 - IP / Server / SSL mapping
 - Problems Highlight
 - Finding search/filter
 - Technical details
 - HTML-safe rendering
============================================================
*/

const API_URL = "/scan";

/* ==========================================================
   APPLICATION STATE
========================================================== */

const appState = {
    scanData: null,
    findings: [],
    filteredFindings: [],

    problemsOnly: true,
    severityFilter: "ALL",
    searchQuery: "",

    expandedFindingIds: new Set(),

    scanning: false,
    scanStartedAt: null,
    elapsedTimer: null
};


/* ==========================================================
   DOM HELPERS
========================================================== */

function getElement(id) {
    return document.getElementById(id);
}


function setText(id, value, fallback = "—") {
    const element = getElement(id);

    if (!element) {
        return;
    }

    if (
        value === null ||
        value === undefined ||
        String(value).trim() === ""
    ) {
        element.textContent = fallback;
        return;
    }

    element.textContent = String(value);
}


function safeString(value, fallback = "") {
    if (
        value === null ||
        value === undefined
    ) {
        return fallback;
    }

    const text = String(value).trim();

    return text || fallback;
}


function clearContainer(id) {
    const element = getElement(id);

    if (element) {
        element.innerHTML = "";
    }
}


function createElement(tag, className = "", text = "") {
    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== "") {
        element.textContent = text;
    }

    return element;
}


/* ==========================================================
   SAFE VALUE HELPERS
========================================================== */

function firstDefined(...values) {
    for (const value of values) {
        if (
            value !== undefined &&
            value !== null &&
            value !== ""
        ) {
            return value;
        }
    }

    return null;
}


function isObject(value) {
    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
}


function formatNumber(value, fallback = "—") {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return fallback;
    }

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return fallback;
    }

    return number.toLocaleString();
}


function formatSeconds(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "—";
    }

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return "—";
    }

    if (number < 1) {
        return `${Math.round(number * 1000)} ms`;
    }

    return `${number.toFixed(2)} s`;
}


function prettyValue(value) {
    if (
        value === null ||
        value === undefined
    ) {
        return "—";
    }

    if (typeof value === "boolean") {
        return value ? "Yes" : "No";
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return "None";
        }

        return value
            .map(item => prettyValue(item))
            .join(", ");
    }

    if (typeof value === "object") {
        try {
            return JSON.stringify(
                value,
                null,
                2
            );
        } catch {
            return String(value);
        }
    }

    return String(value);
}


/* ==========================================================
   MESSAGE / LOADING
========================================================== */

function showMessage(message, type = "info") {
    const element = getElement("scanMessage");

    if (!element) {
        return;
    }

    element.textContent = message;

    element.className =
        `scan-message ${type}`;

    element.hidden = false;
}


function hideMessage() {
    const element = getElement("scanMessage");

    if (!element) {
        return;
    }

    element.hidden = true;
}


function setLoading(
    active,
    message = "Scanning target..."
) {
    const section =
        getElement("loadingSection");

    const messageElement =
        getElement("loadingMessage");

    if (section) {
        section.hidden = !active;
    }

    if (messageElement) {
        messageElement.textContent =
            message;
    }
}


function updateElapsedDisplay() {
    const element =
        getElement("scanElapsed");

    if (!element) {
        return;
    }

    if (!appState.scanStartedAt) {
        element.textContent = "00:00";
        return;
    }

    const elapsedSeconds =
        Math.floor(
            (Date.now() -
                appState.scanStartedAt) /
                1000
        );

    const minutes =
        Math.floor(
            elapsedSeconds / 60
        );

    const seconds =
        elapsedSeconds % 60;

    element.textContent =
        `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}


function startElapsedTimer() {
    stopElapsedTimer();

    appState.scanStartedAt =
        Date.now();

    updateElapsedDisplay();

    appState.elapsedTimer =
        window.setInterval(
            updateElapsedDisplay,
            500
        );
}


function stopElapsedTimer() {
    if (appState.elapsedTimer) {
        window.clearInterval(
            appState.elapsedTimer
        );

        appState.elapsedTimer = null;
    }

    updateElapsedDisplay();
}


/* ==========================================================
   BACKEND RESPONSE NORMALIZATION
========================================================== */

function normalizeRoot(payload) {
    if (
        !payload ||
        typeof payload !== "object"
    ) {
        return {};
    }

    if (
        payload.result &&
        typeof payload.result === "object"
    ) {
        return payload.result;
    }

    if (
        payload.data &&
        typeof payload.data === "object"
    ) {
        return payload.data;
    }

    return payload;
}


/* ==========================================================
   FINDING HELPERS
========================================================== */

function normalizeSeverity(value) {
    const severity =
        safeString(
            value,
            "Info"
        ).toLowerCase();

    if (severity === "critical") {
        return "Critical";
    }

    if (severity === "high") {
        return "High";
    }

    if (severity === "medium") {
        return "Medium";
    }

    if (severity === "low") {
        return "Low";
    }

    return "Info";
}


function severityRank(severity) {
    const ranks = {
        Critical: 5,
        High: 4,
        Medium: 3,
        Low: 2,
        Info: 1
    };

    return (
        ranks[
            normalizeSeverity(
                severity
            )
        ] || 0
    );
}


function getFindingSeverity(finding) {
    return normalizeSeverity(
        firstDefined(
            finding?.severity,
            finding?.risk,
            finding?.priority,
            finding?.level,
            "Info"
        )
    );
}


function getFindingTitle(finding) {
    return safeString(
        firstDefined(
            finding?.title,
            finding?.name,
            finding?.finding,
            finding?.check,
            finding?.issue,
            "Security Observation"
        ),
        "Security Observation"
    );
}


function getFindingCategory(finding) {
    return safeString(
        firstDefined(
            finding?.category,
            finding?.type,
            finding?.module,
            "Security"
        ),
        "Security"
    );
}


function getFindingStatus(finding) {
    return safeString(
        firstDefined(
            finding?.status,
            finding?.verification_status,
            "Not Tested"
        ),
        "Not Tested"
    );
}


function getFindingConfidence(finding) {
    const value =
        firstDefined(
            finding?.confidence,
            finding?.confidence_score,
            finding?.confidence_percent
        );

    if (
        value === null ||
        value === undefined
    ) {
        return null;
    }

    const number =
        Number(value);

    if (!Number.isFinite(number)) {
        return null;
    }

    return number;
}


function getFindingVerified(finding) {
    return (
        finding?.verified === true ||
        finding?.verification === "Verified" ||
        finding?.verification_status === "Verified"
    );
}


function getFindingOWASP(finding) {
    return safeString(
        firstDefined(
            finding?.owasp,
            finding?.owasp_category,
            finding?.owasp_top10
        ),
        "Not mapped"
    );
}


function getFindingDescription(finding) {
    return safeString(
        firstDefined(
            finding?.description,
            finding?.summary,
            finding?.impact,
            finding?.explanation,
            "No additional description provided."
        ),
        "No additional description provided."
    );
}


function getFindingEvidence(finding) {
    return firstDefined(
        finding?.evidence,
        finding?.evidence_items,
        finding?.proof,
        finding?.details,
        finding?.observed
    );
}


function getFindingRemediation(finding) {
    return safeString(
        firstDefined(
            finding?.remediation,
            finding?.recommendation,
            finding?.fix,
            finding?.solution,
            "Review the affected control and apply the recommended security configuration."
        ),
        "Review the affected control and apply the recommended security configuration."
    );
}


function getFindingURL(finding) {
    return safeString(
        firstDefined(
            finding?.url,
            finding?.target_url,
            finding?.location,
            finding?.endpoint
        ),
        ""
    );
}


function getFindingID(
    finding,
    index = 0
) {
    return safeString(
        firstDefined(
            finding?.finding_id,
            finding?.id,
            finding?.code,
            finding?.rule_id
        ),
        `finding-${index + 1}`
    );
}


function normalizeFinding(
    finding,
    index
) {
    return {
        ...finding,

        _index: index,

        _id:
            getFindingID(
                finding,
                index
            ),

        _severity:
            getFindingSeverity(
                finding
            ),

        _title:
            getFindingTitle(
                finding
            ),

        _category:
            getFindingCategory(
                finding
            ),

        _status:
            getFindingStatus(
                finding
            ),

        _confidence:
            getFindingConfidence(
                finding
            ),

        _verified:
            getFindingVerified(
                finding
            ),

        _owasp:
            getFindingOWASP(
                finding
            ),

        _description:
            getFindingDescription(
                finding
            ),

        _evidence:
            getFindingEvidence(
                finding
            ),

        _remediation:
            getFindingRemediation(
                finding
            ),

        _url:
            getFindingURL(
                finding
            )
    };
}


function deduplicateFindings(
    findings
) {
    const map = new Map();

    for (const finding of findings) {
        const fingerprint = [
            finding._severity,
            finding._title
                .toLowerCase()
                .replace(/\s+/g, " ")
                .trim(),
            finding._category
                .toLowerCase()
                .trim(),
            finding._url
        ].join("|");

        const existing =
            map.get(fingerprint);

        if (!existing) {
            map.set(
                fingerprint,
                finding
            );

            continue;
        }

        const currentConfidence =
            finding._confidence || 0;

        const existingConfidence =
            existing._confidence || 0;

        if (
            currentConfidence >
            existingConfidence
        ) {
            map.set(
                fingerprint,
                finding
            );
        }
    }

    return Array.from(
        map.values()
    );
}


/* ==========================================================
   EXTRACT FINDINGS
========================================================== */

function extractFindings(data) {
    const candidates = [
        data?.findings,
        data?.security_findings,
        data?.results?.findings,
        data?.scan_results?.findings,
        data?.security_health_dashboard?.findings
    ];

    let raw = [];

    for (const candidate of candidates) {
        if (Array.isArray(candidate)) {
            raw = candidate;
            break;
        }
    }

    const normalized =
        raw
            .filter(
                item =>
                    item &&
                    typeof item === "object"
            )
            .map(
                (item, index) =>
                    normalizeFinding(
                        item,
                        index
                    )
            );

    return deduplicateFindings(
        normalized
    );
}


/* ==========================================================
   RISK
========================================================== */

function extractRisk(data) {
    const score = firstDefined(
        data?.risk_score,
        data?.risk?.score,
        data?.risk_assessment?.score,
        data?.security_posture?.score,
        data?.risk_calculation_v2?.score,
        data?.risk_calculation_v2?.risk_score
    );

    const level = firstDefined(
        data?.risk_level,
        data?.risk?.level,
        data?.risk_assessment?.level,
        data?.security_posture?.posture,
        data?.security_posture?.level,
        data?.risk_calculation_v2?.level
    );

    const grade = firstDefined(
        data?.security_grade,
        data?.risk?.grade,
        data?.security_posture?.grade
    );

    const description = firstDefined(
        data?.risk?.description,
        data?.risk_assessment?.description,
        data?.security_posture?.description
    );

    return {
        score:
            score !== null
                ? Number(score)
                : null,

        level:
            safeString(
                level,
                "Not Assessed"
            ),

        grade:
            safeString(
                grade,
                "—"
            ),

        description:
            safeString(
                description,
                ""
            )
    };
}


function getRiskClass(level) {
    const value =
        safeString(
            level,
            ""
        ).toLowerCase();

    if (value.includes("critical")) {
        return "critical";
    }

    if (value.includes("high")) {
        return "high";
    }

    if (value.includes("medium")) {
        return "medium";
    }

    if (value.includes("low")) {
        return "low";
    }

    return "unknown";
}


function getRiskDescription(
    level,
    score
) {
    const normalized =
        safeString(
            level,
            ""
        ).toLowerCase();

    if (
        normalized.includes(
            "critical"
        )
    ) {
        return "Critical security posture. Immediate remediation is recommended.";
    }

    if (
        normalized.includes("high")
    ) {
        return "High-risk posture. Important security controls require prompt attention.";
    }

    if (
        normalized.includes("medium")
    ) {
        return "Medium-risk posture. Several security controls require attention.";
    }

    if (
        normalized.includes("low")
    ) {
        return "Low-risk posture based on the passive security checks performed.";
    }

    if (
        Number.isFinite(score)
    ) {
        return "Risk posture calculated from the security findings observed during this scan.";
    }

    return "Security posture could not be fully assessed.";
}


/* ==========================================================
   NETWORK INFORMATION
========================================================== */

function extractDomain(data) {
    const value =
        firstDefined(
            data?.domain,
            data?.hostname,
            data?.target_domain,
            data?.target_control?.domain
        );

    if (value) {
        return String(value)
            .replace(
                /^https?:\/\//i,
                ""
            )
            .split("/")[0];
    }

    const url =
        firstDefined(
            data?.final_url,
            data?.url,
            data?.target_url
        );

    if (url) {
        try {
            return new URL(url).hostname;
        } catch {
            return "—";
        }
    }

    return "—";
}


function extractIPAddress(data) {
    const value =
        firstDefined(
            data?.resolved_ip,
            data?.ip_address,
            data?.ip,
            data?.server_ip,
            data?.target_ip,

            data?.dns?.resolved_ip,
            data?.dns?.ip,
            data?.dns?.address,

            data?.domain_info?.ip,
            data?.domain_info?.ip_address,

            data?.target_control?.resolved_ip,
            data?.target_control?.ip_address
        );

    if (Array.isArray(value)) {
        return value.length
            ? value.join(", ")
            : "—";
    }

    if (
        value &&
        typeof value === "object"
    ) {
        return safeString(
            firstDefined(
                value.address,
                value.ip,
                value.ipv4,
                value.value
            ),
            "—"
        );
    }

    return safeString(
        value,
        "—"
    );
}


function extractServer(data) {
    const value =
        firstDefined(
            data?.server,
            data?.server_header,
            data?.server_name,

            data?.response_headers?.server,
            data?.response_headers?.Server,

            data?.headers?.server,
            data?.headers?.Server,

            data?.website?.server,

            data?.technologies?.server,
            data?.technologies?.Server,

            data?.response_security?.server
        );

    return safeString(
        value,
        "—"
    );
}


function extractHTTPStatus(data) {
    const value =
        firstDefined(
            data?.http_status,
            data?.status_code,
            data?.response_status,
            data?.http?.status,
            data?.response?.status,
            data?.scan_metadata?.http_status
        );

    if (
        value !== null &&
        value !== undefined
    ) {
        return String(value);
    }

    return "—";
}


function extractResponseTime(data) {
    const value =
        firstDefined(
            data?.response_time,
            data?.scan_metadata?.response_time,
            data?.scan_metadata?.response_time_seconds,
            data?.timing?.response_time,
            data?.timing?.duration
        );

    return formatSeconds(value);
}


function extractHTTPS(data) {
    const url =
        firstDefined(
            data?.final_url,
            data?.url
        );

    if (!url) {
        return "—";
    }

    try {
        const parsed =
            new URL(url);

        return parsed.protocol
            .toLowerCase() ===
            "https:"
            ? "HTTPS Enabled"
            : "HTTP Only";
    } catch {
        return "—";
    }
}


/* ==========================================================
   SSL / TLS
========================================================== */

function extractSSLObject(data) {
    const candidates = [
        data?.ssl_analysis,
        data?.ssl,
        data?.tls,
        data?.ssl_certificate,
        data?.certificate,
        data?.security_checks?.ssl,
        data?.security_checks?.tls,
        data?.network?.ssl,
        data?.network?.tls
    ];

    for (const candidate of candidates) {
        if (
            candidate &&
            typeof candidate === "object"
        ) {
            return candidate;
        }
    }

    return null;
}


function extractSSLStatus(data) {
    const ssl =
        extractSSLObject(data);

    if (!ssl) {
        return "Not Assessed";
    }

    const status =
        firstDefined(
            ssl?.certificate,
            ssl?.certificate_status,
            ssl?.verification_status,
            ssl?.status,
            ssl?.tls_status
        );

    if (
        status &&
        typeof status === "object"
    ) {
        return safeString(
            firstDefined(
                status.status,
                status.value,
                status.result
            ),
            "Not Assessed"
        );
    }

    if (status) {
        return String(status);
    }

    if (ssl?.valid === true) {
        return "Valid";
    }

    if (ssl?.valid === false) {
        return "Invalid";
    }

    if (ssl?.verified === true) {
        return "Verified";
    }

    return "Not Assessed";
}


function extractCertificateDays(data) {
    const ssl =
        extractSSLObject(data);

    if (!ssl) {
        return null;
    }

    const value =
        firstDefined(
            ssl?.days_remaining,
            ssl?.certificate_days,
            ssl?.days_to_expiry,
            ssl?.valid_days,
            ssl?.certificate?.days_remaining,
            ssl?.certificate_info?.days_remaining
        );

    if (
        value === null ||
        value === undefined
    ) {
        return null;
    }

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : null;
}


/* ==========================================================
   COOKIE INFORMATION
========================================================== */

function extractCookieCount(data) {
    const cookies =
        firstDefined(
            data?.cookies,
            data?.cookie_analysis,
            data?.security_checks?.cookies
        );

    if (Array.isArray(cookies)) {
        return cookies.length;
    }

    if (
        cookies &&
        typeof cookies === "object"
    ) {
        const count =
            firstDefined(
                cookies.count,
                cookies.total,
                cookies.cookie_count
            );

        if (
            count !== null &&
            count !== undefined
        ) {
            return Number(count);
        }

        if (
            Array.isArray(
                cookies.cookies
            )
        ) {
            return cookies.cookies.length;
        }
    }

    return null;
}


/* ==========================================================
   TECHNICAL DETAILS
========================================================== */

function extractRobotsStatus(data) {
    const robots =
        firstDefined(
            data?.robots,
            data?.robots_txt,
            data?.technical_details?.robots,
            data?.discovery?.robots,
            data?.security_checks?.robots
        );

    if (
        !robots ||
        typeof robots !== "object"
    ) {
        return "Not detected";
    }

    const status =
        firstDefined(
            robots.status,
            robots.http_status,
            robots.code,
            robots.result
        );

    if (
        status === null ||
        status === undefined
    ) {
        if (robots.found === true) {
            return "Found";
        }

        if (robots.found === false) {
            return "Not found";
        }

        return "Detected";
    }

    return String(status);
}


function extractSitemapStatus(data) {
    const sitemap =
        firstDefined(
            data?.sitemap,
            data?.sitemap_xml,
            data?.technical_details?.sitemap,
            data?.discovery?.sitemap,
            data?.security_checks?.sitemap
        );

    if (
        !sitemap ||
        typeof sitemap !== "object"
    ) {
        return "Not detected";
    }

    const status =
        firstDefined(
            sitemap.status,
            sitemap.http_status,
            sitemap.code,
            sitemap.result
        );

    if (
        status !== null &&
        status !== undefined
    ) {
        return String(status);
    }

    if (sitemap.found === true) {
        return "Found";
    }

    if (sitemap.found === false) {
        return "Not found";
    }

    return "Detected";
}


function extractSecurityTxtStatus(data) {
    const securityTxt =
        firstDefined(
            data?.security_txt,
            data?.securityTxt,
            data?.technical_details?.security_txt,
            data?.discovery?.security_txt
        );

    if (
        !securityTxt ||
        typeof securityTxt !== "object"
    ) {
        return "Not detected";
    }

    const status =
        firstDefined(
            securityTxt.status,
            securityTxt.http_status,
            securityTxt.code,
            securityTxt.result
        );

    if (
        status !== null &&
        status !== undefined
    ) {
        return String(status);
    }

    if (securityTxt.found === true) {
        return "Found";
    }

    if (securityTxt.found === false) {
        return "Not found";
    }

    return "Detected";
}


function extractDirectoryListingStatus(data) {
    const listing =
        firstDefined(
            data?.directory_listing,
            data?.directoryListing,
            data?.technical_details?.directory_listing,
            data?.security_checks?.directory_listing
        );

    if (
        !listing ||
        typeof listing !== "object"
    ) {
        return "Not detected";
    }

    const status =
        firstDefined(
            listing.status,
            listing.http_status,
            listing.result
        );

    if (
        status !== null &&
        status !== undefined
    ) {
        return String(status);
    }

    if (listing.exposed === true) {
        return "Exposed";
    }

    if (listing.exposed === false) {
        return "Not exposed";
    }

    return "Not assessed";
}


function extractSensitiveFileStatus(data) {
    const sensitive =
        firstDefined(
            data?.sensitive_files,
            data?.sensitive_file_exposure,
            data?.technical_details?.sensitive_files,
            data?.security_checks?.sensitive_files
        );

    if (!sensitive) {
        return "Not detected";
    }

    if (Array.isArray(sensitive)) {
        return sensitive.length
            ? `${sensitive.length} observed`
            : "None observed";
    }

    if (typeof sensitive !== "object") {
        return String(sensitive);
    }

    const count =
        firstDefined(
            sensitive.count,
            sensitive.total,
            sensitive.found_count
        );

    if (
        count !== null &&
        count !== undefined
    ) {
        return Number(count) > 0
            ? `${count} observed`
            : "None observed";
    }

    const status =
        firstDefined(
            sensitive.status,
            sensitive.result
        );

    return safeString(
        status,
        "Assessed"
    );
}


/* ==========================================================
   SECURITY HEADERS
========================================================== */

const SECURITY_HEADERS = [
    {
        name: "Content-Security-Policy",
        short: "CSP"
    },
    {
        name: "X-Frame-Options",
        short: "X-Frame-Options"
    },
    {
        name: "X-Content-Type-Options",
        short: "X-Content-Type-Options"
    },
    {
        name: "Strict-Transport-Security",
        short: "HSTS"
    },
    {
        name: "Referrer-Policy",
        short: "Referrer-Policy"
    },
    {
        name: "Permissions-Policy",
        short: "Permissions-Policy"
    },
    {
        name: "Cross-Origin-Embedder-Policy",
        short: "COEP"
    },
    {
        name: "Cross-Origin-Opener-Policy",
        short: "COOP"
    },
    {
        name: "Cross-Origin-Resource-Policy",
        short: "CORP"
    }
];


function extractSecurityHeaders(data) {
    const headers =
        firstDefined(
            data?.security_headers,
            data?.headers,
            data?.response_headers,
            data?.security_checks?.headers
        );

    if (
        !headers ||
        typeof headers !== "object"
    ) {
        return {};
    }

    return headers;
}


function findHeaderValue(
    headers,
    headerName
) {
    if (!headers) {
        return null;
    }

    const exact =
        firstDefined(
            headers[headerName],
            headers[
                headerName.toLowerCase()
            ]
        );

    if (
        exact !== null &&
        exact !== undefined
    ) {
        return exact;
    }

    const target =
        headerName.toLowerCase();

    for (
        const key of Object.keys(headers)
    ) {
        if (
            key.toLowerCase() ===
            target
        ) {
            return headers[key];
        }
    }

    return null;
}


function renderSecurityHeaders(data) {
    const container =
        getElement("securityHeaders");

    if (!container) {
        return;
    }

    clearContainer(
        "securityHeaders"
    );

    const headers =
        extractSecurityHeaders(data);

    for (
        const header of SECURITY_HEADERS
    ) {
        const value =
            findHeaderValue(
                headers,
                header.name
            );

        const present =
            value !== null &&
            value !== undefined &&
            String(value).trim() !== "" &&
            String(value).toLowerCase() !== "missing";

        const row =
            createElement(
                "div",
                `security-header-row ${
                    present
                        ? "header-present"
                        : "header-missing"
                }`
            );

        const name =
            createElement(
                "div",
                "security-header-name",
                header.short
            );

        const status =
            createElement(
                "div",
                "security-header-status",
                present
                    ? "Present"
                    : "Missing"
            );

        const valueElement =
            createElement(
                "div",
                "security-header-value",
                present
                    ? String(value)
                    : "Not configured"
            );

        row.appendChild(name);
        row.appendChild(status);
        row.appendChild(valueElement);

        container.appendChild(row);
    }
}


/* ==========================================================
   FINDING SUMMARY
========================================================== */

function calculateFindingCounts(
    findings
) {
    const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0
    };

    for (
        const finding of findings
    ) {
        const severity =
            getFindingSeverity(
                finding
            );

        counts[severity] =
            (counts[severity] || 0) +
            1;
    }

    return counts;
}


function renderFindingSummary(
    findings
) {
    const counts =
        calculateFindingCounts(
            findings
        );

    setText(
        "criticalCount",
        counts.Critical,
        "0"
    );

    setText(
        "highCount",
        counts.High,
        "0"
    );

    setText(
        "mediumCount",
        counts.Medium,
        "0"
    );

    setText(
        "lowCount",
        counts.Low,
        "0"
    );

    setText(
        "infoCount",
        counts.Info,
        "0"
    );

    setText(
        "problemCriticalCount",
        counts.Critical,
        "0"
    );

    setText(
        "problemHighCount",
        counts.High,
        "0"
    );

    setText(
        "problemMediumCount",
        counts.Medium,
        "0"
    );

    setText(
        "problemLowCount",
        counts.Low,
        "0"
    );

    setText(
        "problemInfoCount",
        counts.Info,
        "0"
    );

    setText(
        "totalFindings",
        findings.length,
        "0"
    );

    const actionable =
        findings.filter(
            finding =>
                getFindingSeverity(
                    finding
                ) !== "Info"
        ).length;

    setText(
        "problemsTotalBadge",
        `${actionable} problems`,
        "0 problems"
    );
}


/* ==========================================================
   FINDING CARD
========================================================== */

function findingFingerprint(
    finding
) {
    return safeString(
        finding?._id,
        `finding-${finding?._index || 0}`
    );
}


function createFindingCard(
    finding,
    options = {}
) {
    const expanded =
        options.expanded === true;

    const severity =
        finding._severity;

    const card =
        createElement(
            "article",
            `finding-card finding-${severity.toLowerCase()}`
        );

    card.dataset.findingId =
        findingFingerprint(
            finding
        );

    const header =
        createElement(
            "div",
            "finding-card-header"
        );

    const severityBadge =
        createElement(
            "span",
            `finding-severity severity-${severity.toLowerCase()}`,
            severity
        );

    const title =
        createElement(
            "h3",
            "finding-title",
            finding._title
        );

    header.appendChild(
        severityBadge
    );

    header.appendChild(title);

    card.appendChild(header);

    const confidence =
        finding._confidence !== null
            ? `${Math.round(
                finding._confidence
            )}%`
            : "—";

    const meta =
        createElement(
            "div",
            "finding-meta"
        );

    const metaItems = [
        [
            "Category",
            finding._category
        ],
        [
            "Status",
            finding._status
        ],
        [
            "Verification",
            finding._verified
                ? "Verified"
                : "Not independently verified"
        ],
        [
            "Confidence",
            confidence
        ],
        [
            "OWASP",
            finding._owasp
        ]
    ];

    for (
        const [label, value]
        of metaItems
    ) {
        const item =
            createElement(
                "span",
                "finding-meta-item"
            );

        const labelElement =
            createElement(
                "strong",
                "",
                `${label}: `
            );

        const valueElement =
            createElement(
                "span",
                "",
                String(value)
            );

        item.appendChild(
            labelElement
        );

        item.appendChild(
            valueElement
        );

        meta.appendChild(item);
    }

    card.appendChild(meta);

    const description =
        createElement(
            "p",
            "finding-description",
            finding._description
        );

    card.appendChild(description);

    const button =
        createElement(
            "button",
            "finding-details-button",
            expanded
                ? "Hide Details"
                : "View Details"
        );

    button.type = "button";

    button.addEventListener(
        "click",
        () => {
            toggleFinding(
                findingFingerprint(
                    finding
                )
            );
        }
    );

    card.appendChild(button);

    const details =
        createElement(
            "div",
            "finding-details"
        );

    details.hidden = !expanded;

    details.appendChild(
        createElement(
            "h4",
            "",
            "Description"
        )
    );

    details.appendChild(
        createElement(
            "p",
            "",
            finding._description
        )
    );

    details.appendChild(
        createElement(
            "h4",
            "",
            "Evidence"
        )
    );

    details.appendChild(
        createElement(
            "pre",
            "finding-evidence",
            prettyValue(
                finding._evidence
            )
        )
    );

    details.appendChild(
        createElement(
            "h4",
            "",
            "Recommended Remediation"
        )
    );

    details.appendChild(
        createElement(
            "p",
            "finding-remediation",
            finding._remediation
        )
    );

    if (finding._url) {
        details.appendChild(
            createElement(
                "h4",
                "",
                "Affected URL"
            )
        );

        details.appendChild(
            createElement(
                "code",
                "finding-url",
                finding._url
            )
        );
    }

    card.appendChild(details);

    return card;
}


function toggleFinding(
    findingId
) {
    if (
        appState.expandedFindingIds.has(
            findingId
        )
    ) {
        appState.expandedFindingIds.delete(
            findingId
        );
    } else {
        appState.expandedFindingIds.add(
            findingId
        );
    }

    renderFindings();
    renderPriorityProblems();
    renderHighlightedProblems();
}


/* ==========================================================
   FILTERING
========================================================== */

function isProblemFinding(
    finding
) {
    const severity =
        getFindingSeverity(
            finding
        );

    if (severity === "Info") {
        return false;
    }

    const status =
        getFindingStatus(
            finding
        ).toLowerCase();

    if (
        status.includes("not tested") ||
        status.includes("not assessed") ||
        status.includes("not applicable")
    ) {
        return false;
    }

    return true;
}


function applyFindingFilters() {
    let filtered =
        [...appState.findings];

    if (appState.problemsOnly) {
        filtered =
            filtered.filter(
                isProblemFinding
            );
    }

    if (
        appState.severityFilter !==
        "ALL"
    ) {
        filtered =
            filtered.filter(
                finding =>
                    getFindingSeverity(
                        finding
                    ).toUpperCase() ===
                    appState.severityFilter
            );
    }

    const search =
        appState.searchQuery
            .trim()
            .toLowerCase();

    if (search) {
        filtered =
            filtered.filter(
                finding => {
                    const haystack = [
                        finding._title,
                        finding._category,
                        finding._description,
                        finding._status,
                        finding._owasp,
                        finding._remediation,
                        finding._url
                    ]
                        .join(" ")
                        .toLowerCase();

                    return haystack.includes(
                        search
                    );
                }
            );
    }

    filtered.sort(
        (a, b) => {
            const severityDifference =
                severityRank(
                    b._severity
                ) -
                severityRank(
                    a._severity
                );

            if (
                severityDifference !== 0
            ) {
                return severityDifference;
            }

            return (
                (b._confidence || 0) -
                (a._confidence || 0)
            );
        }
    );

    appState.filteredFindings =
        filtered;

    return filtered;
}


/* ==========================================================
   PRIORITY PROBLEMS
========================================================== */

function renderPriorityProblems() {
    const container =
        getElement(
            "priorityProblemsContainer"
        );

    if (!container) {
        return;
    }

    clearContainer(
        "priorityProblemsContainer"
    );

    const priority =
        appState.findings
            .filter(
                isProblemFinding
            )
            .sort(
                (a, b) => {
                    const severity =
                        severityRank(
                            b._severity
                        ) -
                        severityRank(
                            a._severity
                        );

                    if (
                        severity !== 0
                    ) {
                        return severity;
                    }

                    return (
                        (b._confidence || 0) -
                        (a._confidence || 0)
                    );
                }
            )
            .slice(0, 5);

    setText(
        "priorityCount",
        priority.length,
        "0"
    );

    if (priority.length === 0) {
        container.appendChild(
            createElement(
                "div",
                "empty-state",
                "No high-impact actionable problems were observed."
            )
        );

        return;
    }

    for (
        const finding of priority
    ) {
        const card =
            createFindingCard(
                finding,
                {
                    expanded:
                        appState.expandedFindingIds.has(
                            findingFingerprint(
                                finding
                            )
                        )
                }
            );

        card.classList.add(
            "priority-problem-card"
        );

        container.appendChild(card);
    }
}


/* ==========================================================
   HIGHLIGHTED PROBLEMS
========================================================== */

function renderHighlightedProblems() {
    const container =
        getElement(
            "highlightedProblemsContainer"
        );

    if (!container) {
        return;
    }

    clearContainer(
        "highlightedProblemsContainer"
    );

    const filtered =
        applyFindingFilters();

    if (filtered.length === 0) {
        container.appendChild(
            createElement(
                "div",
                "empty-state",
                "No findings match the current filter."
            )
        );

        updateProblemsControls();

        return;
    }

    for (
        const finding of filtered
    ) {
        const card =
            createFindingCard(
                finding,
                {
                    expanded:
                        appState.expandedFindingIds.has(
                            findingFingerprint(
                                finding
                            )
                        )
                }
            );

        container.appendChild(card);
    }

    updateProblemsControls();
}


function renderFindings() {
    const container =
        getElement(
            "findingsContainer"
        );

    if (!container) {
        return;
    }

    clearContainer(
        "findingsContainer"
    );

    const findings =
        applyFindingFilters();

    if (findings.length === 0) {
        container.appendChild(
            createElement(
                "div",
                "empty-state",
                "No findings are available for the current filter."
            )
        );

        return;
    }

    for (
        const finding of findings
    ) {
        const card =
            createFindingCard(
                finding,
                {
                    expanded:
                        appState.expandedFindingIds.has(
                            findingFingerprint(
                                finding
                            )
                        )
                }
            );

        container.appendChild(card);
    }
}


/* ==========================================================
   FILTER CONTROL
========================================================== */

function updateProblemsControls() {
    const count =
        appState.filteredFindings.length;

    const status =
        getElement(
            "problemFilterStatus"
        );

    if (status) {
        status.textContent =
            appState.problemsOnly
                ? `Problems Only · ${count} results`
                : `All Findings · ${count} results`;
    }

    const problemsButton =
        getElement(
            "problemsOnlyButton"
        );

    const allButton =
        getElement(
            "allFindingsButton"
        );

    if (problemsButton) {
        problemsButton.classList.toggle(
            "active",
            appState.problemsOnly
        );
    }

    if (allButton) {
        allButton.classList.toggle(
            "active",
            !appState.problemsOnly
        );
    }
}


function setupProblemControls() {
    const search =
        getElement(
            "problemsSearch"
        );

    if (search) {
        search.addEventListener(
            "input",
            event => {
                appState.searchQuery =
                    event.target.value;

                renderHighlightedProblems();
                renderFindings();
            }
        );
    }

    const severityFilter =
        getElement(
            "severityFilter"
        );

    if (severityFilter) {
        severityFilter.addEventListener(
            "change",
            event => {
                appState.severityFilter =
                    String(
                        event.target.value
                    ).toUpperCase();

                if (
                    appState.severityFilter ===
                    "ALL"
                ) {
                    appState.problemsOnly =
                        false;
                }

                renderHighlightedProblems();
                renderFindings();
            }
        );
    }

    const problemsButton =
        getElement(
            "problemsOnlyButton"
        );

    if (problemsButton) {
        problemsButton.addEventListener(
            "click",
            () => {
                appState.problemsOnly =
                    true;

                renderHighlightedProblems();
                renderFindings();
            }
        );
    }

    const allButton =
        getElement(
            "allFindingsButton"
        );

    if (allButton) {
        allButton.addEventListener(
            "click",
            () => {
                appState.problemsOnly =
                    false;

                renderHighlightedProblems();
                renderFindings();
            }
        );
    }

    document
        .querySelectorAll(
            "[data-severity-filter]"
        )
        .forEach(
            button => {
                button.addEventListener(
                    "click",
                    () => {
                        const severity =
                            String(
                                button.dataset
                                    .severityFilter
                            )
                                .toUpperCase();

                        appState.severityFilter =
                            severity;

                        if (
                            severity ===
                            "ALL"
                        ) {
                            appState.problemsOnly =
                                false;
                        }

                        const select =
                            getElement(
                                "severityFilter"
                            );

                        if (select) {
                            select.value =
                                severity;
                        }

                        renderHighlightedProblems();
                        renderFindings();
                    }
                );
            }
        );
}


/* ==========================================================
   BASIC RESULT CARDS
========================================================== */

function renderRisk(data) {
    const risk =
        extractRisk(data);

    const score =
        risk.score !== null &&
        Number.isFinite(
            risk.score
        )
            ? Math.max(
                0,
                Math.min(
                    100,
                    risk.score
                )
            )
            : null;

    const level =
        safeString(
            risk.level,
            "Not Assessed"
        );

    const riskClass =
        getRiskClass(level);

    const description =
        risk.description ||
        getRiskDescription(
            level,
            score
        );

    const scoreElement =
        getElement(
            "riskScore"
        );

    if (scoreElement) {
        scoreElement.textContent =
            score !== null
                ? Math.round(score)
                : "—";

        scoreElement.className =
            `risk-score-value ${riskClass}`;
    }

    setText(
        "riskLevel",
        level,
        "Not Assessed"
    );

    setText(
        "riskAssessmentLevel",
        risk.grade !== "—"
            ? `${level} (${risk.grade})`
            : level,
        "Not Assessed"
    );

    setText(
        "riskDescription",
        description,
        "Security posture could not be fully assessed."
    );

    if (scoreElement) {
        const card =
            scoreElement.closest(
                ".result-card"
            );

        if (card) {
            card.classList.add(
                "risk-result-card"
            );

            const safeScore =
                score !== null
                    ? Math.round(score)
                    : "—";

            const safeLevel =
                escapeHTML(level);

            card.innerHTML = `
                <div class="risk-card-label">
                    SECURITY RISK SCORE
                </div>

                <div class="risk-score-main ${riskClass}">
                    <span class="risk-score-number">
                        ${safeScore}
                    </span>

                    <span class="risk-score-out-of">
                        / 100
                    </span>
                </div>

                <div class="risk-level-badge ${riskClass}">
                    ${safeLevel}
                </div>

                <div class="risk-score-bar">
                    <div
                        class="risk-score-fill ${riskClass}"
                        style="width: ${
                            score !== null
                                ? Math.round(score)
                                : 0
                        }%;"
                    ></div>
                </div>

                <div class="risk-card-caption">
                    Lower score indicates greater security risk.
                </div>
            `;
        }
    }
}


function renderBasicResults(data) {
    const url =
        firstDefined(
            data?.final_url,
            data?.url
        );

    setText(
        "scannedUrl",
        url,
        "—"
    );

    const status =
        safeString(
            data?.status,
            "Completed"
        );

    const statusBadge =
        getElement(
            "scanStatusBadge"
        );

    if (statusBadge) {
        statusBadge.textContent =
            status;

        statusBadge.className =
            `status-badge ${
                status.toLowerCase() ===
                "completed"
                    ? "completed"
                    : "failed"
            }`;
    }

    setText(
        "responseTime",
        extractResponseTime(data),
        "—"
    );

    setText(
        "httpStatus",
        extractHTTPStatus(data),
        "—"
    );

    renderRisk(data);
}


/* ==========================================================
   WEBSITE INFORMATION
========================================================== */

function renderWebsiteInformation(data) {
    setText(
        "domain",
        extractDomain(data),
        "—"
    );

    setText(
        "ipAddress",
        extractIPAddress(data),
        "—"
    );

    setText(
        "server",
        extractServer(data),
        "—"
    );

    setText(
        "httpsStatus",
        extractHTTPS(data),
        "—"
    );

    setText(
        "sslCertificate",
        extractSSLStatus(data),
        "Not Assessed"
    );

    const days =
        extractCertificateDays(data);

    setText(
        "sslDays",
        days !== null
            ? `${Math.round(days)} days`
            : "—",
        "—"
    );
}


/* ==========================================================
   TECHNICAL DETAILS
========================================================== */

function renderTechnicalDetails(data) {
    setText(
        "robotsStatus",
        extractRobotsStatus(data),
        "Not detected"
    );

    setText(
        "sitemapStatus",
        extractSitemapStatus(data),
        "Not detected"
    );

    setText(
        "securityTxtStatus",
        extractSecurityTxtStatus(data),
        "Not detected"
    );

    setText(
        "directoryListingStatus",
        extractDirectoryListingStatus(data),
        "Not detected"
    );

    setText(
        "sensitiveFileStatus",
        extractSensitiveFileStatus(data),
        "Not detected"
    );

    const cookieCount =
        extractCookieCount(data);

    setText(
        "cookiesFound",
        cookieCount !== null
            ? cookieCount
            : "—",
        "—"
    );
}


/* ==========================================================
   WARNINGS
========================================================== */

function renderWarnings(data) {
    const panel =
        getElement(
            "warningsPanel"
        );

    const list =
        getElement(
            "warningsList"
        );

    if (!list) {
        return;
    }

    list.innerHTML = "";

    const warnings =
        firstDefined(
            data?.warnings,
            data?.scan_warnings,
            data?.metadata?.warnings
        );

    let values = [];

    if (Array.isArray(warnings)) {
        values = warnings;
    } else if (
        warnings &&
        typeof warnings === "object"
    ) {
        values =
            Object.entries(
                warnings
            ).map(
                ([key, value]) =>
                    `${key}: ${prettyValue(value)}`
            );
    } else if (warnings) {
        values = [
            String(warnings)
        ];
    }

    if (values.length === 0) {
        if (panel) {
            panel.hidden = true;
        }

        return;
    }

    if (panel) {
        panel.hidden = false;
    }

    for (const warning of values) {
        list.appendChild(
            createElement(
                "li",
                "",
                prettyValue(warning)
            )
        );
    }
}


/* ==========================================================
   SCAN METADATA
========================================================== */

function renderScanMetadata(data) {
    const metadata =
        data?.scan_metadata;

    const element =
        getElement(
            "scanMetadataContainer"
        );

    if (!element) {
        return;
    }

    element.innerHTML = "";

    if (
        !metadata ||
        typeof metadata !== "object"
    ) {
        return;
    }

    const scanner =
        firstDefined(
            metadata?.scanner,
            data?.scanner
        );

    const version =
        firstDefined(
            metadata?.version,
            data?.version
        );

    const duration =
        firstDefined(
            metadata?.duration_seconds,
            data?.duration
        );

    const values = [
        [
            "Scanner",
            scanner
        ],
        [
            "Version",
            version
        ],
        [
            "Duration",
            formatSeconds(duration)
        ],
        [
            "Started",
            metadata?.scan_started_at
        ],
        [
            "Completed",
            metadata?.scan_completed_at
        ],
        [
            "Environment",
            metadata?.environment
        ]
    ];

    for (
        const [label, value]
        of values
    ) {
        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            continue;
        }

        const row =
            createElement(
                "div",
                "metadata-row"
            );

        row.appendChild(
            createElement(
                "span",
                "metadata-label",
                label
            )
        );

        row.appendChild(
            createElement(
                "span",
                "metadata-value",
                prettyValue(value)
            )
        );

        element.appendChild(row);
    }
}


/* ==========================================================
   APPLICATION FINDINGS
========================================================== */

function prepareApplicationFindings(data) {
    appState.findings =
        extractFindings(data);

    appState.filteredFindings =
        [];

    appState.expandedFindingIds =
        new Set();

    renderFindingSummary(
        appState.findings
    );

    renderPriorityProblems();

    renderHighlightedProblems();

    renderFindings();
}


/* ==========================================================
   COMPLETE RESULTS RENDER
========================================================== */

function renderResults(payload) {
    const data =
        normalizeRoot(payload);

    if (
        !data ||
        typeof data !== "object"
    ) {
        throw new Error(
            "Invalid scan response received from backend."
        );
    }

    appState.scanData =
        data;

    renderBasicResults(data);

    renderWebsiteInformation(data);

    renderSecurityHeaders(data);

    renderTechnicalDetails(data);

    renderWarnings(data);

    renderScanMetadata(data);

    prepareApplicationFindings(data);

    const results =
        getElement(
            "resultsSection"
        );

    if (results) {
        results.hidden = false;

        window.setTimeout(
            () => {
                results.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });
            },
            100
        );
    }
}


/* ==========================================================
   URL VALIDATION
========================================================== */

function validateURL(value) {
    const raw =
        String(value || "").trim();

    if (!raw) {
        return {
            valid: false,
            message:
                "Please enter a website URL."
        };
    }

    let url;

    try {
        url =
            new URL(
                raw.match(
                    /^https?:\/\//i
                )
                    ? raw
                    : `https://${raw}`
            );
    } catch {
        return {
            valid: false,
            message:
                "Please enter a valid website URL."
        };
    }

    if (
        !["http:", "https:"].includes(
            url.protocol
        )
    ) {
        return {
            valid: false,
            message:
                "Only HTTP and HTTPS URLs are supported."
        };
    }

    const hostname =
        url.hostname.toLowerCase();

    const blockedHosts = [
        "localhost",
        "localhost.localdomain",
        "0.0.0.0",
        "::1"
    ];

    if (
        blockedHosts.includes(
            hostname
        )
    ) {
        return {
            valid: false,
            message:
                "Localhost and internal targets are not allowed."
        };
    }

    return {
        valid: true,
        url: url.href
    };
}


/* ==========================================================
   SCAN REQUEST
========================================================== */

async function startScan(event) {
    if (event) {
        event.preventDefault();
    }

    if (appState.scanning) {
        return;
    }

    const input =
        getElement("urlInput");

    const button =
        getElement("scanButton");

    const buttonText =
        getElement("scanButtonText");

    if (!input) {
        showMessage(
            "URL input field was not found.",
            "error"
        );

        return;
    }

    const validation =
        validateURL(
            input.value
        );

    if (!validation.valid) {
        showMessage(
            validation.message,
            "error"
        );

        input.focus();

        return;
    }

    appState.scanning =
        true;

    hideMessage();

    setLoading(
        true,
        "Running safe passive security checks..."
    );

    startElapsedTimer();

    if (button) {
        button.disabled = true;

        button.classList.add(
            "is-scanning"
        );
    }

    if (buttonText) {
        buttonText.textContent =
            "Scanning...";
    }

    const results =
        getElement(
            "resultsSection"
        );

    if (results) {
        results.hidden = true;
    }

    try {
        showMessage(
            "WebShield-AI is analyzing the target. This may take a few minutes.",
            "info"
        );

        const response =
            await fetch(
                API_URL,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        "Accept":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            url:
                                validation.url,

                            authorized:
                                true,

                            max_pages:
                                10,

                            max_depth:
                                1
                        })
                }
            );

        let payload;

        try {
            payload =
                await response.json();
        } catch {
            throw new Error(
                `Server returned HTTP ${response.status}, but the response was not valid JSON.`
            );
        }

        if (!response.ok) {
            const message =
                firstDefined(
                    payload?.message,
                    payload?.detail,
                    `Scan request failed with HTTP ${response.status}.`
                );

            throw new Error(
                String(message)
            );
        }

        const root =
            normalizeRoot(payload);

        const status =
            safeString(
                root?.status,
                "Completed"
            ).toLowerCase();

        if (
            status === "failed" ||
            status === "error"
        ) {
            throw new Error(
                safeString(
                    root?.message,
                    "The security scan could not be completed."
                )
            );
        }

        renderResults(payload);

        showMessage(
            "Scan completed successfully.",
            "success"
        );
    } catch (error) {
        console.error(
            "WebShield-AI scan error:",
            error
        );

        const message =
            error instanceof Error
                ? error.message
                : String(error);

        showMessage(
            `Scan failed: ${message}`,
            "error"
        );

        if (appState.scanData) {
            const results =
                getElement(
                    "resultsSection"
                );

            if (results) {
                results.hidden =
                    false;
            }
        }
    } finally {
        appState.scanning =
            false;

        stopElapsedTimer();

        setLoading(false);

        if (button) {
            button.disabled =
                false;

            button.classList.remove(
                "is-scanning"
            );
        }

        if (buttonText) {
            buttonText.textContent =
                "Start Scan";
        }
    }
}


/* ==========================================================
   CLEAR RESULTS
========================================================== */

function clearResults() {
    appState.scanData = null;
    appState.findings = [];
    appState.filteredFindings = [];

    appState.expandedFindingIds =
        new Set();

    appState.searchQuery =
        "";

    appState.severityFilter =
        "ALL";

    appState.problemsOnly =
        true;

    const results =
        getElement(
            "resultsSection"
        );

    if (results) {
        results.hidden = true;
    }

    const search =
        getElement(
            "problemsSearch"
        );

    if (search) {
        search.value = "";
    }

    const severity =
        getElement(
            "severityFilter"
        );

    if (severity) {
        severity.value = "all";
    }

    const message =
        getElement(
            "scanMessage"
        );

    if (message) {
        message.hidden = true;
    }

    const loading =
        getElement(
            "loadingSection"
        );

    if (loading) {
        loading.hidden = true;
    }

    setText(
        "scanElapsed",
        "00:00",
        "00:00"
    );

    updateProblemsControls();
}


/* ==========================================================
   HTML ESCAPE
========================================================== */

function escapeHTML(value) {
    return String(value ?? "")
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}


/* ==========================================================
   BUTTON / FORM SETUP
========================================================== */

function setupScanForm() {
    const button =
        getElement("scanButton");

    if (!button) {
        console.warn(
            "WebShield-AI: scan button not found."
        );

        return;
    }

    /*
     * HTML uses a DIV for .scan-form and
     * a type="button" Start Scan button.
     *
     * Therefore the correct event is CLICK,
     * not FORM SUBMIT.
     */
    button.addEventListener(
        "click",
        startScan
    );

    const input =
        getElement("urlInput");

    if (input) {
        input.addEventListener(
            "keydown",
            event => {
                if (
                    event.key === "Enter"
                ) {
                    event.preventDefault();

                    startScan(event);
                }
            }
        );
    }

    const clearButton =
        getElement("clearButton");

    if (clearButton) {
        clearButton.addEventListener(
            "click",
            clearResults
        );
    }
}


function setupKeyboardShortcuts() {
    document.addEventListener(
        "keydown",
        event => {
            if (
                event.ctrlKey &&
                event.key.toLowerCase() ===
                    "enter"
            ) {
                const input =
                    getElement(
                        "urlInput"
                    );

                if (
                    document.activeElement ===
                    input
                ) {
                    event.preventDefault();

                    startScan(event);
                }
            }
        }
    );
}


/* ==========================================================
   INITIALIZATION
========================================================== */

function initializeUI() {
    setupScanForm();

    setupProblemControls();

    setupKeyboardShortcuts();

    const results =
        getElement(
            "resultsSection"
        );

    if (results) {
        results.hidden = true;
    }

    const loading =
        getElement(
            "loadingSection"
        );

    if (loading) {
        loading.hidden = true;
    }

    const elapsed =
        getElement(
            "scanElapsed"
        );

    if (elapsed) {
        elapsed.textContent =
            "00:00";
    }

    updateProblemsControls();

    console.log(
        "WebShield-AI frontend initialized successfully."
    );
}


if (
    document.readyState ===
    "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        initializeUI
    );
} else {
    initializeUI();
}


/* ==========================================================
   OPTIONAL GLOBAL API
========================================================== */

window.WebShieldAI = {
    state: appState,

    startScan,

    renderResults,

    clearResults,

    extractIPAddress,

    extractServer,

    extractSSLStatus,

    extractRisk,

    getFindingCounts:
        calculateFindingCounts
};