/* ============================================================
   WebShield-AI Frontend
   Professional Web Security Scanner Dashboard
============================================================ */


/* ============================================================
   ELEMENTS
============================================================ */

const urlInput =
    document.getElementById("urlInput");

const scanButton =
    document.getElementById("scanButton");

const scanButtonText =
    document.getElementById("scanButtonText");

const scanLoader =
    document.getElementById("scanLoader");

const scanMessage =
    document.getElementById("scanMessage");

const loadingSection =
    document.getElementById("loadingSection");

const loadingProgressBar =
    document.getElementById("loadingProgressBar");

const loadingStatus =
    document.getElementById("loadingStatus");

const resultsSection =
    document.getElementById("resultsSection");

const resultTarget =
    document.getElementById("resultTarget");

const scanStatusBadge =
    document.getElementById("scanStatusBadge");

const riskScore =
    document.getElementById("riskScore");

const scoreBar =
    document.getElementById("scoreBar");

const riskLevel =
    document.getElementById("riskLevel");

const riskLevelLarge =
    document.getElementById("riskLevelLarge");

const riskDescription =
    document.getElementById("riskDescription");

const statusCode =
    document.getElementById("statusCode");

const responseTime =
    document.getElementById("responseTime");

const httpsStatus =
    document.getElementById("httpsStatus");

const sslStatus =
    document.getElementById("sslStatus");

const criticalCount =
    document.getElementById("criticalCount");

const highCount =
    document.getElementById("highCount");

const mediumCount =
    document.getElementById("mediumCount");

const lowCount =
    document.getElementById("lowCount");

const findingCount =
    document.getElementById("findingCount");

const findingsContainer =
    document.getElementById("findingsContainer");

const headersContainer =
    document.getElementById("headersContainer");

const detailHttps =
    document.getElementById("detailHttps");

const detailCertificate =
    document.getElementById("detailCertificate");

const domainName =
    document.getElementById("domainName");

const ipAddress =
    document.getElementById("ipAddress");

const serverName =
    document.getElementById("serverName");

const poweredBy =
    document.getElementById("poweredBy");

const robotsStatus =
    document.getElementById("robotsStatus");

const sitemapStatus =
    document.getElementById("sitemapStatus");

const cookieCount =
    document.getElementById("cookieCount");

const cookiesContainer =
    document.getElementById("cookiesContainer");

const responseHeaders =
    document.getElementById("responseHeaders");

const scanAgainButton =
    document.getElementById("scanAgainButton");


/* ============================================================
   API CONFIGURATION
============================================================ */

const API_URL =
    "/scan";


/* ============================================================
   EVENT LISTENERS
============================================================ */

scanButton.addEventListener(
    "click",
    startScan
);


urlInput.addEventListener(
    "keydown",
    function (event) {

        if (event.key === "Enter") {

            startScan();

        }

    }
);


scanAgainButton.addEventListener(
    "click",
    function () {

        resultsSection.classList.add("hidden");

        urlInput.focus();

        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });

    }
);


/* ============================================================
   START SECURITY SCAN
============================================================ */

async function startScan() {

    const url =
        urlInput.value.trim();


    /* --------------------------------------------------------
       Clear old message
    -------------------------------------------------------- */

    hideMessage();


    /* --------------------------------------------------------
       URL validation
    -------------------------------------------------------- */

    if (!url) {

        showMessage(
            "Please enter a website URL.",
            "error"
        );

        urlInput.focus();

        return;
    }


    if (
        !url.startsWith("http://") &&
        !url.startsWith("https://")
    ) {

        showMessage(
            "URL must start with http:// or https://",
            "error"
        );

        urlInput.focus();

        return;
    }


    /* --------------------------------------------------------
       Start loading
    -------------------------------------------------------- */

    setLoading(true);


    try {

        const response =
            await fetch(
                API_URL,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


        const data =
            await response.json();


        /* ----------------------------------------------------
           HTTP/API error
        ---------------------------------------------------- */

        if (!response.ok) {

            throw new Error(
                data.detail ||
                data.error ||
                data.message ||
                "Scan request failed."
            );

        }


        /* ----------------------------------------------------
           Failed scan
        ---------------------------------------------------- */

        if (
            data.scan_status &&
            String(data.scan_status).toLowerCase() ===
            "failed"
        ) {

            throw new Error(
                data.error ||
                data.message ||
                "Website scan failed."
            );

        }


        /* ----------------------------------------------------
           Display results
        ---------------------------------------------------- */

        displayResults(data);


        showMessage(
            "Security scan completed successfully.",
            "success"
        );


    }

    catch (error) {

        console.error(
            "WebShield-AI Scan Error:",
            error
        );


        showMessage(
            error.message ||
            "Unable to connect to WebShield-AI backend.",
            "error"
        );

    }

    finally {

        setLoading(false);

    }

}


/* ============================================================
   DISPLAY RESULTS
============================================================ */

function displayResults(data) {

    resultsSection.classList.remove(
        "hidden"
    );


    /* --------------------------------------------------------
       Target
    -------------------------------------------------------- */

    resultTarget.textContent =
        `Target: ${data.url || "-"}`;


    /* --------------------------------------------------------
       Scan status
    -------------------------------------------------------- */

    scanStatusBadge.textContent =
        data.scan_status ||
        "Completed";


    /* --------------------------------------------------------
       Basic scan information
    -------------------------------------------------------- */

    statusCode.textContent =
        data.status_code !== undefined
            ? data.status_code
            : "-";


    responseTime.textContent =
        data.response_time !== undefined
            ? `${data.response_time}s`
            : "-";


    /* --------------------------------------------------------
       SSL
    -------------------------------------------------------- */

    const ssl =
        data.ssl || {};


    const httpsEnabled =
        ssl.https === true ||
        data.url?.startsWith("https://");


    httpsStatus.textContent =
        httpsEnabled
            ? "Enabled"
            : "Not Enabled";


    sslStatus.textContent =
        ssl.certificate ||
        "Unknown";


    detailHttps.textContent =
        httpsEnabled
            ? "Enabled"
            : "Not Enabled";


    detailCertificate.textContent =
        ssl.certificate ||
        "Unknown";


    /* --------------------------------------------------------
       Risk assessment
    -------------------------------------------------------- */

    let score = 0;

    let level = "Unknown";

    let description =
        "No risk assessment information available.";


    if (data.risk_assessment) {

        score =
            Number(
                data.risk_assessment.score
            ) || 0;

        level =
            data.risk_assessment.level ||
            "Unknown";

        description =
            data.risk_assessment.description ||
            description;

    }

    else {

        score =
            Number(
                data.risk_score
            ) || 0;

        level =
            data.risk_level ||
            "Unknown";

    }


    riskScore.textContent =
        score;


    riskLevel.textContent =
        level;


    riskLevelLarge.textContent =
        level;


    riskDescription.textContent =
        description;


    /* --------------------------------------------------------
       Score bar
    -------------------------------------------------------- */

    const safeScore =
        Math.max(
            0,
            Math.min(
                100,
                score
            )
        );


    scoreBar.style.width =
        `${safeScore}%`;


    /* --------------------------------------------------------
       Risk styling
    -------------------------------------------------------- */

    applyRiskStyle(
        level
    );


    /* --------------------------------------------------------
       Findings
    -------------------------------------------------------- */

    const findings =
        Array.isArray(data.findings)
            ? data.findings
            : [];


    updateFindingSummary(
        findings
    );


    renderFindings(
        findings
    );


    /* --------------------------------------------------------
       Security headers
    -------------------------------------------------------- */

    renderSecurityHeaders(
        data.security_headers
    );


    /* --------------------------------------------------------
       Domain information
    -------------------------------------------------------- */

    const domainInfo =
        data.domain_info || {};


    domainName.textContent =
        domainInfo.domain ||
        "-";


    ipAddress.textContent =
        domainInfo.ip_address ||
        "-";


    /* --------------------------------------------------------
       Technology information
    -------------------------------------------------------- */

    const technologies =
        data.technologies || {};


    serverName.textContent =
        data.server ||
        technologies.server ||
        "Unknown";


    poweredBy.textContent =
        technologies.powered_by ||
        "Unknown";


    /* --------------------------------------------------------
       Robots.txt
    -------------------------------------------------------- */

    const robots =
        data.robots || {};


    robotsStatus.textContent =
        robots.found
            ? "Found"
            : "Not Found";


    /* --------------------------------------------------------
       Sitemap.xml
    -------------------------------------------------------- */

    const sitemap =
        data.sitemap || {};


    sitemapStatus.textContent =
        sitemap.found
            ? "Found"
            : "Not Found";


    /* --------------------------------------------------------
       Cookies
    -------------------------------------------------------- */

    const cookieSecurity =
        data.cookie_security || {};


    const cookies =
        Array.isArray(
            cookieSecurity.cookies
        )
            ? cookieSecurity.cookies
            : [];


    renderCookies(
        cookies
    );


    /* --------------------------------------------------------
       Response headers
    -------------------------------------------------------- */

    renderResponseHeaders(
        data.response_headers
    );


    /* --------------------------------------------------------
       Scroll to results
    -------------------------------------------------------- */

    setTimeout(
        function () {

            resultsSection.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        },
        150
    );

}


/* ============================================================
   FINDING SUMMARY
============================================================ */

function updateFindingSummary(findings) {

    let critical = 0;

    let high = 0;

    let medium = 0;

    let low = 0;


    findings.forEach(
        function (finding) {

            const severity =
                String(
                    finding.severity ||
                    "Info"
                ).toLowerCase();


            if (severity === "critical") {

                critical++;

            }

            else if (severity === "high") {

                high++;

            }

            else if (severity === "medium") {

                medium++;

            }

            else if (severity === "low") {

                low++;

            }

        }
    );


    criticalCount.textContent =
        critical;


    highCount.textContent =
        high;


    mediumCount.textContent =
        medium;


    lowCount.textContent =
        low;


    findingCount.textContent =
        `${findings.length} ${
            findings.length === 1
                ? "Finding"
                : "Findings"
        }`;

}


/* ============================================================
   RENDER SECURITY FINDINGS
============================================================ */

function renderFindings(findings) {

    findingsContainer.innerHTML =
        "";


    if (findings.length === 0) {

        findingsContainer.innerHTML = `
            <div class="empty-findings">
                No security findings detected.
            </div>
        `;

        return;
    }


    findings.forEach(
        function (finding) {

            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "finding-item";


            const severity =
                finding.severity ||
                "Info";


            const normalizedSeverity =
                String(
                    severity
                ).toLowerCase();


            const severityClass =
                getSeverityClass(
                    normalizedSeverity
                );


            item.innerHTML = `

                <div class="finding-top">

                    <div class="finding-title-group">

                        <div class="finding-name">
                            ${escapeHtml(
                                finding.name ||
                                "Security Finding"
                            )}
                        </div>

                        <div class="finding-type">
                            ${escapeHtml(
                                finding.type ||
                                "Security Analysis"
                            )}
                        </div>

                    </div>

                    <span
                        class="severity-badge ${severityClass}"
                    >
                        ${escapeHtml(
                            severity
                        )}
                    </span>

                </div>


                <div class="finding-reason">

                    ${escapeHtml(
                        finding.reason ||
                        "No description available."
                    )}

                </div>


                <div class="finding-recommendation">

                    ${escapeHtml(
                        finding.recommendation ||
                        "Review the security configuration."
                    )}

                </div>

            `;


            findingsContainer.appendChild(
                item
            );

        }
    );

}


/* ============================================================
   SEVERITY CLASS
============================================================ */

function getSeverityClass(severity) {

    switch (severity) {

        case "critical":
            return "severity-critical";

        case "high":
            return "severity-high";

        case "medium":
            return "severity-medium";

        case "low":
            return "severity-low";

        default:
            return "severity-info";

    }

}


/* ============================================================
   SECURITY HEADERS
============================================================ */

function renderSecurityHeaders(headers) {

    headersContainer.innerHTML =
        "";


    if (
        !headers ||
        typeof headers !== "object"
    ) {

        headersContainer.innerHTML = `
            <div class="empty-findings">
                No security header information available.
            </div>
        `;

        return;
    }


    const headerNames = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ];


    headerNames.forEach(
        function (headerName) {

            const value =
                headers[headerName] ||
                "Missing";


            const isMissing =
                String(value)
                    .toLowerCase() ===
                "missing";


            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "header-item";


            item.innerHTML = `

                <span class="header-name">
                    ${escapeHtml(
                        headerName
                    )}
                </span>

                <span
                    class="header-value ${
                        isMissing
                            ? "header-missing"
                            : "header-present"
                    }"
                >
                    ${escapeHtml(
                        value
                    )}
                </span>

            `;


            headersContainer.appendChild(
                item
            );

        }
    );

}


/* ============================================================
   COOKIE SECURITY
============================================================ */

function renderCookies(cookies) {

    cookieCount.textContent =
        `${cookies.length} ${
            cookies.length === 1
                ? "Cookie"
                : "Cookies"
        }`;


    if (cookies.length === 0) {

        cookiesContainer.innerHTML = `
            <div class="empty-findings">
                No cookies detected.
            </div>
        `;

        return;
    }


    const wrapper =
        document.createElement(
            "div"
        );


    wrapper.className =
        "cookies-container";


    const table =
        document.createElement(
            "table"
        );


    table.className =
        "cookie-table";


    table.innerHTML = `

        <thead>

            <tr>

                <th>
                    Cookie
                </th>

                <th>
                    Secure
                </th>

                <th>
                    HttpOnly
                </th>

                <th>
                    SameSite
                </th>

            </tr>

        </thead>

        <tbody></tbody>

    `;


    const tbody =
        table.querySelector(
            "tbody"
        );


    cookies.forEach(
        function (cookie) {

            const row =
                document.createElement(
                    "tr"
                );


            row.innerHTML = `

                <td class="cookie-name">
                    ${escapeHtml(
                        cookie.name ||
                        "-"
                    )}
                </td>

                <td class="${
                    cookie.secure
                        ? "cookie-yes"
                        : "cookie-no"
                }">
                    ${
                        cookie.secure
                            ? "Yes"
                            : "No"
                    }
                </td>

                <td class="${
                    cookie.httponly
                        ? "cookie-yes"
                        : "cookie-no"
                }">
                    ${
                        cookie.httponly
                            ? "Yes"
                            : "No"
                    }
                </td>

                <td class="${
                    cookie.samesite
                        ? "cookie-yes"
                        : "cookie-no"
                }">
                    ${
                        cookie.samesite
                            ? "Configured"
                            : "Not Set"
                    }
                </td>

            `;


            tbody.appendChild(
                row
            );

        }
    );


    wrapper.appendChild(
        table
    );


    cookiesContainer.innerHTML =
        "";


    cookiesContainer.appendChild(
        wrapper
    );

}


/* ============================================================
   RESPONSE HEADERS
============================================================ */

function renderResponseHeaders(headers) {

    if (
        !headers ||
        typeof headers !== "object"
    ) {

        responseHeaders.textContent =
            "No response headers available.";

        return;
    }


    const entries =
        Object.entries(
            headers
        );


    if (entries.length === 0) {

        responseHeaders.textContent =
            "No response headers available.";

        return;
    }


    responseHeaders.textContent =
        entries
            .map(
                function ([key, value]) {

                    return `${key}: ${value}`;

                }
            )
            .join("\n");

}


/* ============================================================
   RISK STYLE
============================================================ */

function applyRiskStyle(level) {

    const normalized =
        String(level)
            .toLowerCase();


    let color =
        "#8295a6";


    if (normalized === "low") {

        color =
            "#39dcb2";

    }

    else if (
        normalized === "medium"
    ) {

        color =
            "#eac467";

    }

    else if (
        normalized === "high"
    ) {

        color =
            "#e99566";

    }

    else if (
        normalized === "critical"
    ) {

        color =
            "#f57a87";

    }


    riskLevel.style.color =
        color;


    riskScore.style.color =
        color;


    riskLevelLarge.style.color =
        color;


    riskLevelLarge.style.borderColor =
        `${color}40`;


    riskLevelLarge.style.background =
        `${color}12`;

}


/* ============================================================
   LOADING STATE
============================================================ */

function setLoading(isLoading) {

    if (isLoading) {

        scanButton.disabled =
            true;


        scanButtonText.textContent =
            "Scanning Target";


        scanLoader.classList.remove(
            "hidden"
        );


        loadingSection.classList.remove(
            "hidden"
        );


        scanMessage.classList.add(
            "hidden"
        );


        animateLoading();


    }

    else {

        scanButton.disabled =
            false;


        scanButtonText.textContent =
            "Start Security Scan";


        scanLoader.classList.add(
            "hidden"
        );


        loadingSection.classList.add(
            "hidden"
        );

    }

}


/* ============================================================
   LOADING ANIMATION
============================================================ */

let loadingTimer = null;

let loadingProgress = 0;


function animateLoading() {

    clearInterval(
        loadingTimer
    );


    loadingProgress = 10;


    loadingProgressBar.style.width =
        `${loadingProgress}%`;


    loadingStatus.textContent =
        "Connecting to target...";


    loadingTimer =
        setInterval(
            function () {

                if (
                    loadingProgress < 90
                ) {

                    loadingProgress +=
                        Math.floor(
                            Math.random() * 8
                        ) + 2;


                    if (
                        loadingProgress > 90
                    ) {

                        loadingProgress = 90;

                    }


                    loadingProgressBar.style.width =
                        `${loadingProgress}%`;


                    updateLoadingText(
                        loadingProgress
                    );

                }

            },
            500
        );

}


/* ============================================================
   LOADING TEXT
============================================================ */

function updateLoadingText(progress) {

    if (progress < 30) {

        loadingStatus.textContent =
            "Connecting to target...";

    }

    else if (progress < 50) {

        loadingStatus.textContent =
            "Analyzing HTTP response...";

    }

    else if (progress < 70) {

        loadingStatus.textContent =
            "Checking security headers...";

    }

    else if (progress < 85) {

        loadingStatus.textContent =
            "Analyzing SSL and cookies...";

    }

    else {

        loadingStatus.textContent =
            "Finalizing security assessment...";

    }

}


/* ============================================================
   MESSAGE
============================================================ */

function showMessage(
    message,
    type = "error"
) {

    scanMessage.textContent =
        message;


    scanMessage.className =
        `scan-message ${type}`;


    scanMessage.classList.remove(
        "hidden"
    );

}


function hideMessage() {

    scanMessage.classList.add(
        "hidden"
    );

}


/* ============================================================
   HTML ESCAPE
============================================================ */

function escapeHtml(value) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        String(value);


    return div.innerHTML;

}


/* ============================================================
   INITIALIZATION
============================================================ */

console.log(
    "WebShield-AI frontend initialized."
);


console.log(
    "Professional security scanner interface ready."
);