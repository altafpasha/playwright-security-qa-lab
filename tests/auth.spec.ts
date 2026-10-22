import { test, expect } from '@playwright/test';
import { SESSION_COOKIE_NAME } from '../src/app';

/**
 * ============================================================================
 * AUTHENTICATION TEST SUITE
 * ============================================================================
 * 
 * Objective:
 * Verifies core identity, authentication lifecycle, session persistence,
 * and security defenses against common authentication flaws (OWASP A07:2021).
 * 
 * Key Playwright Concepts Demonstrated:
 * - page.goto(): Direct route navigation with wait-until-load.
 * - page.getByTestId(): Resilient, accessible locators decoupled from CSS changes.
 * - page.context().cookies(): Direct inspection of HTTP session cookies and flags.
 * - expect(locator).toBeVisible(): Auto-retrying assertions avoiding arbitrary sleeps.
 * 
 * Recruiter / Interviewer Talking Point:
 * "In this suite, we don't just verify the happy path. We test user enumeration defenses,
 * client-side input validation, clean session invalidation on logout, and that
 * protected routes reject unauthenticated access."
 */

test.describe('Authentication & Session Management', () => {

  test('TC-AUTH-001: Successful login with valid user credentials', async ({ page }) => {
    // 1. Navigate to login page
    await page.goto('/login');
    await expect(page).toHaveTitle(/Sign In \| SecQA Lab/);

    // 2. Fill credentials using robust test-id locators
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('input-password').fill('UserPass123!');
    await page.getByTestId('login-submit-button').click();

    // 3. Verify redirection to protected dashboard
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByTestId('dashboard-welcome')).toContainText('Jane Doe');
    await expect(page.getByTestId('role-badge')).toContainText('USER');

    // 4. Verify session cookie attributes in the browser context
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((c) => c.name === SESSION_COOKIE_NAME);
    expect(sessionCookie, 'Session cookie must be created upon successful authentication').toBeDefined();
    expect(sessionCookie?.httpOnly, 'Session cookie must have HttpOnly flag set').toBe(true);
    expect(sessionCookie?.sameSite, 'Session cookie must have SameSite set to Lax').toBe('Lax');
  });

  test('TC-AUTH-002: Successful login with administrator credentials', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('input-email').fill('admin@demo.local');
    await page.getByTestId('input-password').fill('AdminPass123!');
    await page.getByTestId('login-submit-button').click();

    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByTestId('dashboard-welcome')).toContainText('Security Administrator');
    await expect(page.getByTestId('role-badge')).toContainText('ADMIN');

    // Admin should see the Admin Portal navigation link
    await expect(page.getByTestId('nav-admin')).toBeVisible();
  });

  test('TC-AUTH-003: Login rejection with invalid password', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('input-password').fill('WrongPassword999!');
    await page.getByTestId('login-submit-button').click();

    // Verify error banner is visible and specific to authentication
    const alert = page.getByTestId('login-alert');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('Invalid email or password');

    // Verify user remained on login page and no session was established
    await expect(page).toHaveURL(/\/login/);
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((c) => c.name === SESSION_COOKIE_NAME);
    expect(sessionCookie, 'No session cookie should exist after failed login').toBeUndefined();
  });

  test('TC-AUTH-004: User enumeration defense - Non-existent username returns identical generic error', async ({ page }) => {
    // Security verification: The system should not reveal whether an email address exists
    await page.goto('/login');
    await page.getByTestId('input-email').fill('doesnotexist@demo.local');
    await page.getByTestId('input-password').fill('AnyPassword123!');
    await page.getByTestId('login-submit-button').click();

    const alert = page.getByTestId('login-alert');
    await expect(alert).toBeVisible();
    // Must return the exact same generic error message as an invalid password
    await expect(alert).toHaveText('Invalid email or password.');
  });

  test('TC-AUTH-005: Client-side required field validation', async ({ page }) => {
    await page.goto('/login');

    // Attempt to submit an empty form
    await page.getByTestId('login-submit-button').click();

    // Verify validation errors appear for both required fields
    await expect(page.getByTestId('email-error')).toContainText('Email address is required');
    await expect(page.getByTestId('password-error')).toContainText('Password is required');
    await expect(page.getByTestId('login-alert')).toContainText('Please resolve the errors highlighted below.');

    // Partial input: fill email only
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('login-submit-button').click();
    await expect(page.getByTestId('password-error')).toContainText('Password is required');
  });

  test('TC-AUTH-006: User logout destroys session and redirects to login', async ({ page }) => {
    // 1. Authenticate first
    await page.goto('/login');
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('input-password').fill('UserPass123!');
    await page.getByTestId('login-submit-button').click();
    await expect(page).toHaveURL(/\/dashboard/);

    // 2. Click logout button
    await page.getByTestId('logout-button').click();

    // 3. Verify redirection to login page
    await expect(page).toHaveURL(/\/login/);

    // 4. Verify cookie is cleared in context
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((c) => c.name === SESSION_COOKIE_NAME);
    expect(sessionCookie, 'Session cookie should be cleared upon logout').toBeUndefined();

    // 5. Attempt navigating back to /dashboard via direct URL
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login\?redirect=%2Fdashboard/);
  });

  test('TC-AUTH-007: Accessing protected dashboard without authentication redirects to login with return target', async ({ page }) => {
    await page.goto('/dashboard');
    // Must redirect to login with encoded redirect query parameter
    await expect(page).toHaveURL(/\/login\?redirect=%2Fdashboard/);
    await expect(page.getByTestId('login-card')).toBeVisible();
  });

  test('TC-AUTH-008: Post-logout session invalidation prevents back-button / cookie reuse', async ({ request }) => {
    // 1. Log in via API to capture valid session header
    const loginRes = await request.post('/api/auth/login', {
      data: { email: 'user@demo.local', password: 'UserPass123!' }
    });
    expect(loginRes.status()).toBe(200);

    const headers = loginRes.headers();
    const setCookie = headers['set-cookie'];
    expect(setCookie).toBeDefined();

    // 2. Verify authenticated access to /api/profile succeeds
    const profileRes = await request.get('/api/profile', {
      headers: { Cookie: setCookie }
    });
    expect(profileRes.status()).toBe(200);

    // 3. Perform logout
    const logoutRes = await request.post('/api/auth/logout', {
      headers: { Cookie: setCookie }
    });
    expect(logoutRes.status()).toBe(200);

    // 4. Attempt to reuse old session cookie against protected endpoint
    const postLogoutProfileRes = await request.get('/api/profile', {
      headers: { Cookie: setCookie }
    });
    // Server must reject destroyed session with 401 Unauthorized
    expect(postLogoutProfileRes.status()).toBe(401);
  });
});
