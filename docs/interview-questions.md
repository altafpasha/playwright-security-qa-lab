# Security QA & DevSecOps Interview Guide

This guide contains technical interview questions and senior-level answers designed for candidates interviewing for **Security QA Engineer**, **Application Security Automation Engineer**, or **DevSecOps Engineer** roles.

---

## 1. Playwright & Test Automation Engineering

### Q1: Why use Playwright instead of Cypress or Selenium for Security QA automation?
**Answer:**
Playwright provides distinct architectural advantages for Security QA:
1. **Multi-Context & Multi-Role Isolation**: Playwright browser contexts (`BrowserContext`) are completely isolated with zero cookie or cache leakage. In security testing, we can spin up an `adminContext` and a `userContext` concurrently in the same test to verify horizontal and vertical privilege escalation without logging in and out sequentially.
2. **Unified Browser and API Testing**: Playwright includes `APIRequestContext`, allowing us to validate HTTP status codes, headers, and API contracts directly without launching a browser window, alongside full DOM end-to-end tests.
3. **Deep Network & Protocol Inspection**: Playwright allows intercepting, modifying, and asserting network requests, headers, and cookie attributes (`HttpOnly`, `SameSite`, `Secure`).
4. **Resilient Auto-Waiting**: Playwright automatically waits for elements to be actionable, eliminating arbitrary `sleep()` statements that cause test flakiness.

### Q2: What are user-facing / resilient locators in Playwright and why are they critical?
**Answer:**
Playwright recommends accessible, resilient locators such as:
- `page.getByRole('button', { name: 'Sign In' })`
- `page.getByLabel('Work Email')`
- `page.getByTestId('login-card')`

These locators prioritize accessibility attributes and explicit test identifiers over fragile CSS selectors or XPath paths (e.g. `div > div.col-md-4 > button`). If UI designers redesign the styling or change CSS classes, tests built with resilient locators remain intact, avoiding false test failures while ensuring accessibility compliance.

### Q3: How do you debug flaky tests in Playwright?
**Answer:**
I use Playwright's native diagnostic tooling:
1. **Playwright Trace Viewer**: Inspects DOM snapshots before and after every action, network waterfall, console logs, and execution timelines (`npx playwright show-trace`).
2. **UI Mode (`--ui`)**: Provides an interactive time-travel debugger to step through actions, inspect locators, and view network requests live.
3. **Artifact Retention**: Configure `screenshot: 'only-on-failure'` and `video: 'retain-on-failure'` in `playwright.config.ts`.
4. **Auto-Retries**: In CI, we set `retries: 2` to identify whether a failure is intermittent, but we investigate the root cause—such as race conditions in session establishment or unhandled asynchronous state changes.

---

## 2. Authentication, Session Security & RBAC

### Q4: What is the technical difference between Authentication (401) and Authorization (403)?
**Answer:**
- **Authentication (401 Unauthorized)** verifies **identity**: *"Who are you?"* A 401 response means credentials were not supplied or are invalid. In this lab, accessing `/api/profile` without a session cookie returns `401 Unauthorized`.
- **Authorization (403 Forbidden)** verifies **permissions**: *"Are you allowed to do this?"* A 403 response means the server recognizes who you are, but your role or permissions do not permit access to this resource. In this lab, logging in as a standard user (`user@demo.local`) and requesting `/api/admin/users` returns `403 Forbidden`.

### Q5: What is Session Fixation and how did you mitigate it in this lab?
**Answer:**
Session Fixation occurs when an attacker obtains an unauthenticated session ID, induces a victim to authenticate with that fixed ID, and then uses that known ID to hijack the authenticated session.
**Mitigation**: In `src/app.ts`, immediately upon verifying valid credentials in `POST /api/auth/login`, we invoke `req.session.regenerate()`. This forces Express to destroy the pre-auth session ID and issue a cryptographically random, brand new session ID before attaching user identity details.

### Q6: Why did you implement a generic login error message (`TC-AUTH-004`)?
**Answer:**
Returning specific error messages such as *"Email not found"* versus *"Incorrect password"* creates a **User Enumeration vulnerability** (OWASP A07:2021). Attackers script credential sprayers to discover which email addresses belong to valid corporate accounts. Returning the identical generic string `Invalid email or password.` for both non-existent users and wrong passwords denies attackers this reconnaissance vector.

### Q7: Why is hiding an admin button in the UI insufficient for security?
**Answer:**
Client-side UI hiding is merely **cosmetic obstruction**, not security. Anyone can view client source code, disable CSS classes (`hidden`), or craft direct HTTP calls using `fetch()`, `curl`, or Playwright's `APIRequestContext`. True security requires **server-side authorization guards** (like our `requireAdmin` middleware) that check session privilege on every single sensitive request, returning `403 Forbidden` if unauthorized.

---

## 3. REST API & Negative Security Testing

### Q8: What is negative API testing and what did you test in `tests/api.spec.ts`?
**Answer:**
Negative testing verifies that an application responds gracefully, securely, and deterministically to malformed, unexpected, or hostile inputs without crashing or leaking sensitive data:
1. **Empty / Incomplete Payloads (`TC-API-004`)**: Sending `{}` or missing passwords returns structured `400 Bad Request`, not an unhandled `500 Internal Server Error`.
2. **Injection Vectors (`TC-API-005`)**: Supplying SQL injection (`' OR '1'='1`) and XSS strings (`<script>alert(1)</script>`) into login inputs returns `401 Unauthorized`, verifying no injection occurs.
3. **Data Stripping (`TC-API-002` & `TC-API-003`)**: Ensuring user profiles and directory listings omit `password` or `hash` properties from the JSON response before returning to the client.
4. **Undefined Routes (`TC-API-006`)**: Querying invalid routes returns structured JSON `404 Not Found` without leaking Express framework stack traces.

---

## 4. HTTP Security Headers & Defense-in-Depth

### Q9: Does having all green security headers mean an application is secure?
**Answer:**
**Absolutely not.** Security headers provide **defense-in-depth**, not an impenetrable perimeter:
- A strict `Content-Security-Policy` limits script execution contexts, but does not sanitize server-side inputs or prevent business logic flaws.
- An `HttpOnly` cookie prevents `document.cookie` theft via XSS, but does not prevent an attacker's in-browser XSS script from calling authenticated API endpoints on behalf of the victim.
- `Cache-Control: no-store` prevents shared proxies from caching sensitive PII, but does not protect against physical memory dump or compromised client machines.
In interview discussions, a senior engineer always acknowledges that headers harden an application by raising the attacker's cost, but never replace core secure coding practices.

### Q10: Why did you configure `Cache-Control: no-store` on sensitive endpoints?
**Answer:**
By default, web browsers and intermediary caching proxies (corporate egress proxies, CDNs) store HTTP responses on disk or in shared memory caches to accelerate performance. For authenticated routes containing PII (`/dashboard`, `/api/profile`), this creates a risk: if a user logs out at a shared kiosk, the next user could hit "Back" or inspect disk cache to see personal information. Setting `no-store, no-cache, must-revalidate` explicitly forbids all local and proxy caching of sensitive responses.

---

## 5. Detection Engineering & SIEM Rules

### Q11: Explain your brute-force detection rule (`SEC-DET-001`) and the sliding window algorithm.
**Answer:**
`SEC-DET-001` identifies credential guessing and brute-force attacks (MITRE ATT&CK T1110) from synthetic authentication telemetry:
1. **Filtering**: Extracts only valid `login_failure` events, discarding successes, corrupt entries, and malformed timestamps.
2. **Partitioning**: Groups failures by client `source_ip` into independent event queues.
3. **Sliding Time Window**: For each IP, sorts events chronologically and uses a two-pointer sliding window of configurable length (default: 300 seconds).
4. **Threshold Evaluation**: If the number of failures within any window meets or exceeds the threshold (default: 5), it generates a structured alert containing the rule ID, severity, offending IP, failure count, targeted usernames, and human-readable explanation.

### Q12: What are False Positives (FP) in this detection rule and how would you tune them?
**Answer:**
- **Corporate NAT / Proxy Gateways**: Multiple legitimate users share a single public IP. If several employees mistype passwords within 5 minutes, the IP-level threshold triggers a false alert.
- **Tuning**:
  1. Add an IP allowlist for known corporate proxy ranges.
  2. Implement a **unique username ratio check**: Require failures to target multiple distinct usernames (password spray) rather than just counting aggregate failures.
  3. Correlate with successful logins: If a user fails 3 times and immediately succeeds with MFA, lower alert severity.

### Q13: What are False Negatives (FN) and how do attackers bypass single-IP rules?
**Answer:**
- **Distributed Brute-Force / Credential Stuffing**: Attackers route requests across a botnet or residential proxy network, submitting only 1 attempt per IP across 10,000 IPs. An IP-based rule will never fire.
- **Low-and-Slow Attacks**: Submitting 1 attempt every 10 minutes to stay beneath the 5-minute time window.
- **Mitigation**:
  1. Implement **User-Centric detection rules**: Alert on $X$ failures against the *same username* across *any IP*.
  2. Deploy WAF rate limiting and CAPTCHA / Proof-of-Work challenges.
  3. Monitor failed attempt frequency across the entire organization (global anomaly detection).

---

## 6. CI/CD & DevSecOps

### Q14: How does your GitHub Actions workflow enforce DevSecOps principles?
**Answer:**
Our workflow (`.github/workflows/playwright.yml`) acts as an automated security quality gate:
1. **Fails the build early**: Runs static analysis (`tsc --noEmit`) and detection unit tests before executing heavier end-to-end browser tests.
2. **Automated Regression Prevention**: If a developer inadvertently removes Helmet headers, alters cookie flags, or breaks an RBAC check, the CI run fails instantly, blocking the pull request.
3. **Artifact Retention**: Automatically uploads the Playwright HTML report and execution traces as downloadable artifacts, ensuring engineers have immediate diagnostic evidence for any pipeline failure.
