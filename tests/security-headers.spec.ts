import { test, expect } from '@playwright/test';
import { SESSION_COOKIE_NAME } from '../src/app';

/**
 * ============================================================================
 * SECURITY HEADERS & DEFENSE-IN-DEPTH TEST SUITE
 * ============================================================================
 * 
 * Objective:
 * Validates baseline HTTP response headers, cache directives, cookie protections,
 * and information disclosure mitigations against industry hardening standards
 * (OWASP Secure Headers Project, OWASP A05:2021 Security Misconfiguration).
 * 
 * Scope & Limitations (Senior AppSec Note):
 * ⚠️ HTTP security headers provide defense-in-depth, NOT an absolute security boundary.
 * - Content-Security-Policy restricts script execution and framing, but does not fix
 *   underlying injection flaws in application logic or server-side vulnerabilities.
 * - HttpOnly prevents malicious JavaScript from reading the session cookie directly,
 *   but does NOT stop an active XSS payload from issuing authenticated fetch requests.
 * - Cache-Control prevents shared caching of PII, but does not protect against local
 *   memory dumping or physical device compromise.
 * Automated verification of these controls ensures hardening regressions are caught
 * during CI/CD before code merges to production.
 */

test.describe('Baseline Security Headers & Cookie Configurations', () => {

  test('TC-SEC-001: Content-Security-Policy (CSP) enforcement on sensitive routes', async ({ page }) => {
    const response = await page.goto('/login');
    expect(response).not.toBeNull();

    const headers = response!.headers();
    const csp = headers['content-security-policy'];

    // Assert presence of CSP
    expect(csp, 'Content-Security-Policy header must be present').toBeDefined();

    // Verify key directives
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");

    /**
     * Scope & Limitation:
     * While 'frame-ancestors none' prevents the application from being framed in an <iframe>
     * (rendering clickjacking obsolete), CSP alone does not sanitize user inputs.
     */
  });

  test('TC-SEC-002: Clickjacking mitigation via X-Frame-Options', async ({ page }) => {
    const response = await page.goto('/login');
    const headers = response!.headers();

    // Verify legacy clickjacking protection for older user-agents
    expect(headers['x-frame-options']?.toUpperCase()).toBe('DENY');
  });

  test('TC-SEC-003: MIME-type sniffing mitigation via X-Content-Type-Options', async ({ page }) => {
    const response = await page.goto('/login');
    const headers = response!.headers();

    // Prevents browsers from MIME-sniffing a response away from declared content-type
    expect(headers['x-content-type-options']).toBe('nosniff');
  });

  test('TC-SEC-004: Referrer-Policy enforces strict origin isolation', async ({ page }) => {
    const response = await page.goto('/login');
    const headers = response!.headers();

    // Limits credential/path leakage in the HTTP Referer header when navigating cross-origin
    expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });

  test('TC-SEC-005: Information disclosure mitigation - Server technology banners suppressed', async ({ page, request }) => {
    // 1. Browser request
    const pageRes = await page.goto('/login');
    const pageHeaders = pageRes!.headers();
    expect(pageHeaders['x-powered-by'], 'X-Powered-By header should be removed from page responses').toBeUndefined();

    // 2. Direct API request
    const apiRes = await request.get('/api/auth/status');
    const apiHeaders = apiRes.headers();
    expect(apiHeaders['x-powered-by'], 'X-Powered-By header should be removed from API responses').toBeUndefined();

    /**
     * Scope & Limitation:
     * Removing X-Powered-By is security-by-obscurity and does not remediate framework-level CVEs,
     * but it removes easy fingerprinting targets for automated reconnaissance scanners.
     */
  });

  test('TC-SEC-006: Cache-Control on authenticated sensitive endpoints prevents disk/proxy caching', async ({ request }) => {
    // Authenticate to test protected endpoints
    const loginRes = await request.post('/api/auth/login', {
      data: { email: 'user@demo.local', password: 'UserPass123!' }
    });
    const sessionCookie = loginRes.headers()['set-cookie'];

    const protectedEndpoints = ['/dashboard', '/api/profile'];

    for (const endpoint of protectedEndpoints) {
      const res = await request.get(endpoint, {
        headers: { Cookie: sessionCookie }
      });
      const headers = res.headers();

      // Assert aggressive anti-caching directives
      const cacheControl = headers['cache-control'] || '';
      expect(cacheControl).toContain('no-store');
      expect(cacheControl).toContain('no-cache');
      expect(cacheControl).toContain('must-revalidate');

      expect(headers['pragma']).toBe('no-cache');

      /**
       * Scope & Limitation:
       * Cache-Control prevents sensitive PII/tokens from being cached in shared downstream proxies
       * (e.g. CDNs) or stored on disk by the local browser history. It does not encrypt in-memory state.
       */
    }
  });

  test('TC-SEC-007: Session cookie security attributes (HttpOnly, SameSite, Scope)', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('input-password').fill('UserPass123!');
    await page.getByTestId('login-submit-button').click();
    await expect(page).toHaveURL(/\/dashboard/);

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((c) => c.name === SESSION_COOKIE_NAME);

    expect(sessionCookie, 'Session cookie must exist').toBeDefined();
    expect(sessionCookie!.httpOnly, 'HttpOnly must be true to block document.cookie theft').toBe(true);
    expect(sessionCookie!.sameSite, 'SameSite should be Lax to mitigate cross-site request forgery').toBe('Lax');
    expect(sessionCookie!.path, 'Cookie path should be scoped to root').toBe('/');
    expect(sessionCookie!.expires).toBeGreaterThan(Date.now() / 1000);
  });

  test('TC-SEC-008: Error handling does not disclose internal stack traces or directory paths', async ({ request }) => {
    // Send request that triggers 404 or bad routing
    const res = await request.get('/api/invalid-route-triggering-error');
    expect(res.status()).toBe(404);

    const bodyText = await res.text();
    // Verify no server-side internal file paths or node_modules mentions are present
    expect(bodyText).not.toContain('node_modules');
    expect(bodyText).not.toContain('/home/');
    expect(bodyText).not.toContain('at Function.execute');
  });
});
