import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:9000';
const useLocalWebServer = !process.env.E2E_BASE_URL;
const localWebServerCommand =
  process.env.E2E_WEB_SERVER_CMD ??
  'ENCRYPTION_KEY=01234567890123456789012345678901 DATABASE_BACKEND=memory cargo lambda watch --ignore-changes --invoke-address 127.0.0.1 --invoke-port 9000';

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.ts/,
  outputDir: '/tmp/ericauth-playwright-results',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: useLocalWebServer
    ? {
        command:
          localWebServerCommand,
        cwd: '../..',
        url: 'http://127.0.0.1:9000/health',
        reuseExistingServer: !process.env.CI,
        timeout: 300_000,
      }
    : undefined,
});
