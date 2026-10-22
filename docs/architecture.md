# System & Security Architecture

This document details the architectural design of the **Playwright Security QA Automation Lab**, covering application architecture, security middleware defense layers, test automation architecture, and detection engineering pipelines.

---

## 1. High-Level Architecture Overview

The lab is engineered as an end-to-end security verification ecosystem comprising three tightly coupled subsystems:

1. **Target Web Application & REST API (`src/app.ts`)**: An Express.js application designed with role-based access control (RBAC), session management, and defense-in-depth HTTP security headers.
2. **Automated Security QA Test Harness (`tests/`)**: A TypeScript test suite executing both headless browser workflows and direct API protocol interactions via Playwright Test.
3. **Detection Engineering Engine (`detection/`)**: An independent analytical module demonstrating SIEM-like sliding-window detection for credential brute-force attacks against synthetic authentication logs.

```mermaid
flowchart TB
    subgraph ClientLayer["Client & Automation Layer"]
        PW_UI["Playwright Browser Context\n(Chromium Page / DOM)"]
        PW_API["Playwright APIRequestContext\n(Headless HTTP Client)"]
        UserBrowser["Recruiter / Manual Browser\n(Standard Client)"]
    end

    subgraph SecurityMiddlewareLayer["Express Defense-in-Depth Middleware"]
        HelmetMW["Helmet Security Headers\n(CSP, X-Frame-Options, HSTS, No-Sniff)"]
        SessionMW["Session Engine\n(HttpOnly, SameSite=Lax, Regenerate)"]
        CacheMW["noCacheMiddleware\n(no-store, no-cache, must-revalidate)"]
        RBACMW["requireAuth & requireAdmin\n(Server-Side Role Guard)"]
    end

    subgraph AppEndpoints["Application Resources"]
        LoginUI["/login UI & POST /api/auth/login"]
        DashUI["/dashboard UI (User Role)"]
        AdminUI["/admin UI (Admin Role)"]
        ProfileAPI["GET /api/profile (Sanitized User PII)"]
        AdminAPI["GET /api/admin/users (Sanitized Directory)"]
    end

    subgraph DetectionLayer["Detection Engineering Subsystem"]
        AuthLogs["Synthetic Auth Telemetry\n(sample-auth-events.json)"]
        RuleEngine["detectBruteForce Engine\n(Sliding Window Algorithm)"]
        Alerts["Structured Security Alerts\n(SEC-DET-001)"]
    end

    PW_UI --> HelmetMW
    PW_API --> HelmetMW
    UserBrowser --> HelmetMW
    HelmetMW --> SessionMW
    SessionMW --> CacheMW
    CacheMW --> RBACMW

    RBACMW -->|Public / Auth| LoginUI
    RBACMW -->|role == user / admin| DashUI
    RBACMW -->|role == user / admin| ProfileAPI
    RBACMW -->|role == admin only| AdminUI
    RBACMW -->|role == admin only| AdminAPI

    AuthLogs --> RuleEngine
    RuleEngine --> Alerts
```

---

## 2. Target Application Security Layers

### 2.1 Defense-in-Depth Security Headers (Helmet)

The Express application registers `helmet()` at the root middleware stack, enforcing baseline protective headers across all responses:

| Header | Configured Value | Threat Vector Mitigated | Scope & Senior AppSec Note |
|---|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'` | Cross-Site Scripting (XSS), Data Injection, UI Redress | Prevents browser from loading scripts, plugins, or frames from untrusted origins. Does not replace server-side input sanitization. |
| `X-Frame-Options` | `DENY` | Clickjacking / UI Redress (Legacy Browsers) | Ensures older clients that do not parse CSP `frame-ancestors` refuse iframe embedding. |
| `X-Content-Type-Options` | `nosniff` | MIME-Confusion / Content Sniffing Attacks | Forces browsers to strictly adhere to declared MIME types, preventing executable code disguised as images or text. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Credential & URI Path Leakage | Truncates sensitive path parameters from the HTTP `Referer` header when navigating cross-domain. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Man-in-the-Middle (MITM) & SSL Strip | Enforces persistent HTTPS communication in production environments. |
| `X-Powered-By` | *Removed / Suppressed* | Technology Fingerprinting | Removes obvious server signature (`Express`), forcing automated scanners to work harder. |

### 2.2 Session Security & Fixation Defense

Session handling is implemented via `express-session` configured with strict security flags:

- **Cookie Name**: `secqa.sid` (Non-default name to avoid framework identification).
- **`httpOnly: true`**: Prohibits client-side scripts from reading the cookie via `document.cookie`, mitigating XSS session theft.
- **`sameSite: 'lax'`**: Enforces cross-site request forgery (CSRF) mitigation during top-level cross-domain navigations.
- **Session Regeneration (`req.session.regenerate`)**: Invoked immediately upon successful credential validation in `POST /api/auth/login`. This invalidates the pre-authentication session identifier, mitigating **Session Fixation attacks**.
- **Explicit Invalidation (`req.session.destroy`)**: Triggered on `POST /api/auth/logout`, destroying the server-side session object and instructing the browser to clear `secqa.sid`.

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Client / Attacker
    actor User as Legitimate User
    participant App as Express Web Server
    participant SessionStore as Server Session Store

    Note over User, App: 1. Unauthenticated Initial Request
    User->>App: GET /login
    App-->>User: 200 OK (Clean login page)

    Note over User, App: 2. Authentication with Session Fixation Mitigation
    User->>App: POST /api/auth/login { email, password }
    App->>App: Validate credentials against secure store
    App->>SessionStore: Destroy unauthenticated anonymous session ID
    App->>SessionStore: Generate brand new cryptographic Session ID
    SessionStore-->>App: Session ID established (role: 'user')
    App-->>User: 200 OK + Set-Cookie: secqa.sid (HttpOnly, SameSite=Lax)

    Note over User, App: 3. Authenticated Access to Sensitive Endpoint
    User->>App: GET /dashboard (Cookie: secqa.sid)
    App->>SessionStore: Lookup session ID
    SessionStore-->>App: Valid session (Jane Doe, role: user)
    App-->>User: 200 OK + Cache-Control: no-store

    Note over User, App: 4. Secure Logout & Invalidation
    User->>App: POST /api/auth/logout (Cookie: secqa.sid)
    App->>SessionStore: Destroy session record
    App-->>User: 200 OK + Clear-Cookie: secqa.sid

    Note over Attacker, App: 5. Replay Attack Attempt
    Attacker->>App: GET /api/profile (Cookie: stale secqa.sid)
    App->>SessionStore: Lookup session ID
    SessionStore-->>App: Session Not Found
    App-->>Attacker: 401 Unauthorized (Access Terminated)
```

### 2.3 Server-Side Role-Based Access Control (RBAC)

Authorization is enforced exclusively at the server level via express middleware (`requireAuth` and `requireAdmin`), never relying solely on frontend element hiding:

```mermaid
flowchart TD
    Req([Incoming HTTP Request]) --> CheckAuth{Is Session Active & Valid?}
    
    CheckAuth -- No --> IsApiAuth{Is Request to /api/*?}
    IsApiAuth -- Yes --> Return401[Return HTTP 401 Unauthorized\nJSON: success: false]
    IsApiAuth -- No --> RedirectLogin[Redirect HTTP 302 to /login?redirect=...]

    CheckAuth -- Yes --> CheckRoute{Is Endpoint Admin-Restricted?}
    
    CheckRoute -- No --> AllowUser[Grant Access to Protected Resource]
    
    CheckRoute -- Yes --> CheckAdminRole{Does session.user.role == 'admin'?}
    CheckAdminRole -- Yes --> AllowAdmin[Grant Access to Admin Console / API]
    CheckAdminRole -- No --> IsApiAdmin{Is Request to /api/*?}
    IsApiAdmin -- Yes --> Return403[Return HTTP 403 Forbidden\nJSON: Administrator privileges required]
    IsApiAdmin -- No --> Render403[Redirect HTTP 403 to /access-denied UI]
```

---

## 3. Playwright Test Architecture

Playwright Test acts as both a functional browser automation tool and an API integration testing framework:

```mermaid
flowchart LR
    subgraph PlaywrightHarness["Playwright Test Engine"]
        Config["playwright.config.ts\n(baseURL, webServer, retries, reporting)"]
        Worker1["Worker 1: Browser Context (UI)"]
        Worker2["Worker 2: APIRequestContext (Headless HTTP)"]
    end

    subgraph TestSuites["Automated Suites"]
        AuthSpec["auth.spec.ts\n(8 Test Cases)"]
        AccessSpec["access-control.spec.ts\n(6 Test Cases)"]
        FuncSpec["functional.spec.ts\n(5 Test Cases)"]
        ApiSpec["api.spec.ts\n(6 Test Cases)"]
        SecSpec["security-headers.spec.ts\n(8 Test Cases)"]
    end

    subgraph TargetApp["Express Server (:3333)"]
        Server["Express App Instance\n(Spun up automatically via webServer hook)"]
    end

    Config --> Worker1 & Worker2
    Worker1 --> AuthSpec & AccessSpec & FuncSpec
    Worker2 --> ApiSpec & SecSpec
    AuthSpec & AccessSpec & FuncSpec & ApiSpec & SecSpec --> Server
```

### 3.1 Dual-Paradigm Testing Strategy

1. **Browser UI Layer (`page`)**:
   - Uses accessible, resilient locators (`getByTestId`, `getByRole`).
   - Asserts visual state changes, form validation states, DOM updates, and redirect URLs.
   - Inspects live browser context cookies via `page.context().cookies()`.
2. **Protocol & API Layer (`request`)**:
   - Leverages `APIRequestContext` for direct HTTP request/response validation.
   - Asserts exact status codes (`400`, `401`, `403`, `404`), JSON schema integrity, and raw HTTP header values.
   - Performs negative security tests (e.g., SQL injection strings, XSS vectors, parameter tampering) without browser UI overhead.

---

## 4. Detection Engineering Architecture

The detection subsystem (`detection/detect-bruteforce.js`) models how a Security Operations Center (SOC) or SIEM correlates raw authentication logs to surface automated attacks:

```mermaid
flowchart TD
    RawLogStream["Raw Telemetry Stream\n(Array of Auth Events)"] --> InputSanitization["Defensive Filter & Normalization\n- Check object validity\n- Check event_type == 'login_failure'\n- Parse ISO-8601 timestamps\n- Discard corrupt / malformed data"]

    InputSanitization --> GroupByIP["Group Events by Source IP\nMap: IP -> FailureEvent[]"]

    GroupByIP --> SortEvents["Sort Timestamps Chronologically Ascending"]

    SortEvents --> SlidingWindow["Sliding Window Algorithm\nWindow: windowSeconds (default 300s)\nThreshold: failure_count >= threshold (default 5)"]

    SlidingWindow --> EvaluateThreshold{"Does count in window >= threshold?"}
    
    EvaluateThreshold -- No --> NextWindow[Advance Window]
    EvaluateThreshold -- Yes --> EmitAlert["Construct Structured Alert:\n- rule_id: SEC-DET-001\n- severity: HIGH\n- source_ip\n- failure_count\n- targeted_usernames\n- window_seconds\n- explanation"]
    
    EmitAlert --> Deduplicate["Suppress Duplicate Bursts for Same IP Window"]
    Deduplicate --> OutputAlerts["Structured Alerts Output Array"]
```

### 4.1 Sliding-Window Algorithm Complexity

- **Time Complexity**: $\mathcal{O}(N \log N)$ where $N$ is the number of failure events per IP (due to sorting), followed by an $\mathcal{O}(N)$ two-pointer linear scan.
- **Space Complexity**: $\mathcal{O}(N)$ storage to group events by IP in a hash map.
- **Deduplication**: Once an IP triggers an alert for an active burst, `windowTriggered` prevents duplicate alert spam for subsequent events within that burst.
