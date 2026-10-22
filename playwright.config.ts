import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright Test Configuration for Security QA Automation Lab
 * See https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['json', { outputFile: 'test-results/test-results.json' }]
  ],
  use: {
    baseURL: 'http://127.0.0.1:3333',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    // Realistic browser viewport
    viewport: { width: 1280, height: 720 },
    // Enforce reasonable timeout
    actionTimeout: 10000,
    navigationTimeout: 15000
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ],
  // Automatically spin up the local Express server before running tests
  webServer: {
    command: 'npm run start:server',
    url: 'http://127.0.0.1:3333/login',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
    stdout: 'pipe',
    stderr: 'pipe'
  }
});
