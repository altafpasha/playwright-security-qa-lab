import { test, expect } from '@playwright/test';

/**
 * ============================================================================
 * ROLE-BASED ACCESS CONTROL (RBAC) & AUTHORIZATION TEST SUITE
 * ============================================================================
 * 
 * Objective:
 * Validates that server-side authorization strictly enforces the principle of
 * least privilege (POLP) and prevents Broken Access Control (OWASP Top 10 A01:2021).
 * 
 * Threat Vectors Tested:
 * 1. Forced Browsing / Direct Navigation: Normal users navigating to /admin directly.
 * 2. Missing Function Level Access Control (MFLAC): Standard users calling admin REST APIs.
 * 3. Unauthenticated Resource Scraping: Accessing privileged APIs with zero authentication.
 * 4. Client-side Navigation Obfuscation: Ensuring authorization is enforced on the server,
 *    not merely hidden in the frontend HTML.
 * 
 * Playwright Concepts Demonstrated:
 * - Browser UI isolation vs APIRequestContext: Testing both visual redirects and pure HTTP response codes.
 * - HTTP status code assertion: Verifying explicit 401 Unauthorized and 403 Forbidden semantics.
 * - Isolated browser contexts: Guaranteeing admin credentials never leak into normal user contexts.
 */

test.describe('Role-Based Access Control (RBAC) & Authorization', () => {

  test('TC-RBAC-001: Standard user is denied access to Administrator Web UI', async ({ page }) => {
    // 1. Authenticate as standard non-privileged user
    await page.goto('/login');
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('input-password').fill('UserPass123!');
    await page.getByTestId('login-submit-button').click();
    await expect(page).toHaveURL(/\/dashboard/);

    // 2. Verify UI does not show admin navigation elements
    await expect(page.getByTestId('nav-admin')).toHaveCount(0);

    // 3. Attempt forced browsing: Navigate directly to /admin URL
    const response = await page.goto('/admin');

    // 4. Assert server enforces 403 Forbidden status code and renders Access Denied page
    expect(response?.status(), 'Admin page must respond with 403 Forbidden for non-admin users').toBe(403);
    await expect(page).toHaveURL(/\/access-denied/);
    await expect(page.getByTestId('access-denied-title')).toContainText('403 Forbidden');
    await expect(page.getByTestId('access-denied-message')).toContainText('You do not have administrative privileges');
  });

  test('TC-RBAC-002: Standard user is denied access to Administrator REST API (/api/admin/users)', async ({ request }) => {
    // 1. Log in as standard user to obtain session cookie
    const loginRes = await request.post('/api/auth/login', {
      data: { email: 'user@demo.local', password: 'UserPass123!' }
    });
    expect(loginRes.status()).toBe(200);
    const sessionCookie = loginRes.headers()['set-cookie'];

    // 2. Attempt to invoke the privileged admin API
    const adminApiRes = await request.get('/api/admin/users', {
      headers: { Cookie: sessionCookie }
    });

    // 3. Assert HTTP 403 Forbidden is returned
    expect(adminApiRes.status(), 'Must return 403 Forbidden for standard user').toBe(403);

    const body = await adminApiRes.json();
    expect(body.success).toBe(false);
    expect(body.error).toContain('Forbidden: Administrator privileges required');
  });

  test('TC-RBAC-003: Administrator user is granted access to Administrator Web UI and API', async ({ page, request }) => {
    // 1. Web UI validation
    await page.goto('/login');
    await page.getByTestId('input-email').fill('admin@demo.local');
    await page.getByTestId('input-password').fill('AdminPass123!');
    await page.getByTestId('login-submit-button').click();
    await expect(page).toHaveURL(/\/dashboard/);

    // Admin should see and click the Admin Portal link
    const adminLink = page.getByTestId('nav-admin');
    await expect(adminLink).toBeVisible();
    await adminLink.click();

    // Verify successful load of admin portal
    await expect(page).toHaveURL(/\/admin/);
    await expect(page.getByTestId('admin-title')).toContainText('Administrator Security Console');
    await expect(page.getByTestId('users-table')).toBeVisible();

    // Verify user list rows are populated in the UI
    const rows = page.getByTestId('users-table-body').locator('tr');
    await expect(rows).toHaveCount(2);

    // 2. Direct API validation using admin session
    const loginRes = await request.post('/api/auth/login', {
      data: { email: 'admin@demo.local', password: 'AdminPass123!' }
    });
    expect(loginRes.status()).toBe(200);
    const adminCookie = loginRes.headers()['set-cookie'];

    const apiRes = await request.get('/api/admin/users', {
      headers: { Cookie: adminCookie }
    });
    expect(apiRes.status()).toBe(200);

    const apiData = await apiRes.json();
    expect(apiData.success).toBe(true);
    expect(apiData.count).toBe(2);
    expect(Array.isArray(apiData.users)).toBe(true);
  });

  test('TC-RBAC-004: Unauthenticated API request to privileged endpoint is rejected with 401', async ({ request }) => {
    // Attempt request with zero credentials or session headers
    const res = await request.get('/api/admin/users');
    
    // Unauthenticated requests must receive 401 Unauthorized (distinct from 403 Forbidden)
    expect(res.status(), 'Unauthenticated request to admin API must return 401').toBe(401);
    
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toContain('Unauthorized: Authentication required');
  });

  test('TC-RBAC-005: Unauthenticated request to protected profile endpoint is rejected with 401', async ({ request }) => {
    const res = await request.get('/api/profile');
    expect(res.status(), 'Unauthenticated request to profile API must return 401').toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
  });

  test('TC-RBAC-006: Direct URL tampering cannot bypass server-side authorization', async ({ page }) => {
    // Attempt to navigate straight to /admin without any session
    const response = await page.goto('/admin');
    
    // Server must intercept and redirect to /login
    await expect(page).toHaveURL(/\/login/);
    expect(response?.request().redirectedFrom()).toBeDefined();
  });
});
