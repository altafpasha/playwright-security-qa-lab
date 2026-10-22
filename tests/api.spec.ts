import { test, expect } from '@playwright/test';

/**
 * ============================================================================
 * REST API SECURITY & FUNCTIONAL TEST SUITE
 * ============================================================================
 * 
 * Objective:
 * Validates REST API contracts, HTTP status semantics, payload sanitization,
 * sensitive data exposure (OWASP A02:2021), and robust negative input handling.
 * 
 * Quality & AppSec Principles:
 * - Negative Testing: Malformed payloads, SQL injection, and XSS attack strings.
 * - Data Sanitization: Ensuring password fields and hashes are NEVER exposed in API responses.
 * - HTTP Semantics: Correct status codes for client error (400), unauthenticated (401),
 *   forbidden (403), and route not found (404).
 * - Fast, isolated headless API testing via Playwright's APIRequestContext.
 */

test.describe('REST API Contracts & Negative Testing', () => {

  test('TC-API-001: Unauthenticated session status returns authenticated: false', async ({ request }) => {
    const res = await request.get('/api/auth/status');
    expect(res.status()).toBe(200);

    const body = await res.json();
    expect(body.authenticated).toBe(false);
    expect(body.user).toBeUndefined();
  });

  test('TC-API-002: Profile API schema integrity - Never leaks password hash or secret fields', async ({ request }) => {
    // 1. Authenticate as user
    const loginRes = await request.post('/api/auth/login', {
      data: { email: 'user@demo.local', password: 'UserPass123!' }
    });
    const sessionCookie = loginRes.headers()['set-cookie'];

    // 2. Query profile endpoint
    const profileRes = await request.get('/api/profile', {
      headers: { Cookie: sessionCookie }
    });
    expect(profileRes.status()).toBe(200);

    const data = await profileRes.json();
    expect(data.success).toBe(true);
    expect(data.user).toBeDefined();

    // Verify expected fields
    expect(data.user.id).toBe('usr_001');
    expect(data.user.email).toBe('user@demo.local');
    expect(data.user.role).toBe('user');
    expect(data.user.department).toBe('Quality Assurance');

    // CRITICAL SECURITY ASSERTION: Passwords or hashes must NEVER appear in JSON
    expect(data.user.password, 'Password must not be returned in API response').toBeUndefined();
    expect(data.user.hash, 'Hash field must not exist in API response').toBeUndefined();
  });

  test('TC-API-003: Admin users directory schema validation', async ({ request }) => {
    // Authenticate as admin
    const loginRes = await request.post('/api/auth/login', {
      data: { email: 'admin@demo.local', password: 'AdminPass123!' }
    });
    const sessionCookie = loginRes.headers()['set-cookie'];

    const res = await request.get('/api/admin/users', {
      headers: { Cookie: sessionCookie }
    });
    expect(res.status()).toBe(200);

    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.count).toBe(2);
    expect(Array.isArray(data.users)).toBe(true);

    // Verify all returned users are stripped of password fields
    for (const user of data.users) {
      expect(user.id).toBeDefined();
      expect(user.email).toBeDefined();
      expect(user.role).toBeDefined();
      expect(user.password, `Password should not be present for ${user.email}`).toBeUndefined();
    }
  });

  test('TC-API-004: Negative Test - Missing request body or empty fields returns 400 Bad Request', async ({ request }) => {
    // Empty body
    const resEmpty = await request.post('/api/auth/login', {
      data: {}
    });
    expect(resEmpty.status()).toBe(400);
    const bodyEmpty = await resEmpty.json();
    expect(bodyEmpty.success).toBe(false);
    expect(bodyEmpty.error).toContain('Email and password are required');

    // Missing password
    const resNoPass = await request.post('/api/auth/login', {
      data: { email: 'user@demo.local' }
    });
    expect(resNoPass.status()).toBe(400);

    // Missing email
    const resNoEmail = await request.post('/api/auth/login', {
      data: { password: 'UserPass123!' }
    });
    expect(resNoEmail.status()).toBe(400);
  });

  test('TC-API-005: Negative Test - SQL Injection and XSS attack vectors safely handled without 500 error', async ({ request }) => {
    const maliciousPayloads = [
      { email: "' OR '1'='1", password: "' OR '1'='1" },
      { email: 'admin@demo.local', password: "admin' --" },
      { email: '<script>alert(1)</script>', password: '"><svg onload=alert(1)>' },
      { email: '{{7*7}}', password: '${7*7}' }
    ];

    for (const payload of maliciousPayloads) {
      const res = await request.post('/api/auth/login', { data: payload });
      // Must reject with 401 Unauthorized, NOT crash with 500 or execute injection
      expect(res.status(), `Payload ${JSON.stringify(payload)} should return 401`).toBe(401);
      const data = await res.json();
      expect(data.success).toBe(false);
      expect(data.error).toBe('Invalid email or password.');
    }
  });

  test('TC-API-006: Negative Test - Non-existent API route returns clean structured 404', async ({ request }) => {
    const res = await request.get('/api/unknown-endpoint-test');
    expect(res.status()).toBe(404);

    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toContain('Endpoint not found');
  });
});
