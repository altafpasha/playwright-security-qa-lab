import { test, expect } from '@playwright/test';

/**
 * ============================================================================
 * FUNCTIONAL & REGRESSION TEST SUITE
 * ============================================================================
 * 
 * Objective:
 * Ensures end-to-end user workflows, accessibility standards, interactive components,
 * and regression stability remain uncompromised across iterative deployments.
 * 
 * Quality Engineering Principles Demonstrated:
 * - Deterministic, flake-free locators (data-testid, role selectors).
 * - Multi-stage regression suites verifying that security fixes do not break usability.
 * - Idempotency: Verifying test passes reliably on repeated runs without state pollution.
 * - Client-side validation states and dynamic DOM interactions.
 */

test.describe('Functional Workflows & UI Regression', () => {

  test('TC-FUNC-001: Page title, brand navigation, and footer accessibility', async ({ page }) => {
    await page.goto('/login');

    // Title regression
    await expect(page).toHaveTitle('Sign In | SecQA Lab');

    // Brand logo link exists and points to home
    const brand = page.getByTestId('brand-logo');
    await expect(brand).toBeVisible();
    await expect(brand).toHaveAttribute('href', '/');

    // Footer notice verification
    const footer = page.locator('footer.app-footer');
    await expect(footer).toBeVisible();
    await expect(footer).toContainText('Playwright Security QA Lab');
  });

  test('TC-FUNC-002: Form validation - Email pattern feedback and dynamic correction', async ({ page }) => {
    await page.goto('/login');

    const emailInput = page.getByTestId('input-email');
    const passwordInput = page.getByTestId('input-password');
    const emailError = page.getByTestId('email-error');
    const submitBtn = page.getByTestId('login-submit-button');

    // Enter malformed email
    await emailInput.fill('invalid-email-format');
    await passwordInput.fill('UserPass123!');
    await submitBtn.click();

    // Verify format-specific validation message
    await expect(emailError).toBeVisible();
    await expect(emailError).toContainText('Please enter a valid email address.');

    // Correct the email and verify error clears on resubmission
    await emailInput.fill('user@demo.local');
    await submitBtn.click();

    // Redirection confirms previous client validation was resolved
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('TC-FUNC-003: Dashboard components and interactive Profile API inspection', async ({ page }) => {
    // Log in
    await page.goto('/login');
    await page.getByTestId('input-email').fill('user@demo.local');
    await page.getByTestId('input-password').fill('UserPass123!');
    await page.getByTestId('login-submit-button').click();
    await expect(page).toHaveURL(/\/dashboard/);

    // Verify key UI cards
    await expect(page.getByTestId('profile-card')).toBeVisible();
    await expect(page.getByTestId('security-controls-card')).toBeVisible();

    // Verify profile values
    await expect(page.getByTestId('user-email')).toHaveText('user@demo.local');
    await expect(page.getByTestId('user-id')).toHaveText('usr_001');
    await expect(page.getByTestId('user-role')).toHaveText('user');

    // Test client-side interactive button: "Verify Profile API"
    const apiBtn = page.getByTestId('refresh-profile-btn');
    const apiOutput = page.getByTestId('profile-api-output');

    await expect(apiOutput).toBeHidden();
    await apiBtn.click();

    // Ensure asynchronous fetch response renders in output container
    await expect(apiOutput).toBeVisible();
    await expect(apiOutput).toContainText('"success": true');
    await expect(apiOutput).toContainText('"department": "Quality Assurance"');
  });

  test('TC-FUNC-004: Admin portal directory table rendering and column verification', async ({ page }) => {
    // Log in as admin
    await page.goto('/login');
    await page.getByTestId('input-email').fill('admin@demo.local');
    await page.getByTestId('input-password').fill('AdminPass123!');
    await page.getByTestId('login-submit-button').click();

    // Navigate to admin console
    await page.getByTestId('nav-admin').click();
    await expect(page).toHaveURL(/\/admin/);

    // Verify table headings
    const table = page.getByTestId('users-table');
    await expect(table).toBeVisible();
    await expect(table.locator('th')).toContainText(['ID', 'Name', 'Email', 'Role', 'Department', 'Created']);

    // Verify specific rows exist
    await expect(page.getByTestId('user-row-usr_001')).toBeVisible();
    await expect(page.getByTestId('user-row-adm_001')).toBeVisible();
  });

  test('TC-FUNC-005: Repeated execution idempotency (Regression Stability)', async ({ page }) => {
    // Loop through 2 consecutive login/logout cycles to ensure no lingering session or race conditions
    for (let cycle = 1; cycle <= 2; cycle++) {
      await page.goto('/login');
      await page.getByTestId('input-email').fill('user@demo.local');
      await page.getByTestId('input-password').fill('UserPass123!');
      await page.getByTestId('login-submit-button').click();
      await expect(page).toHaveURL(/\/dashboard/);

      // Verify dashboard rendered
      await expect(page.getByTestId('dashboard-welcome')).toBeVisible();

      // Logout cleanly
      await page.getByTestId('logout-button').click();
      await expect(page).toHaveURL(/\/login/);
    }
  });
});
