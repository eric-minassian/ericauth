import { expect, test } from '@playwright/test';

import {
  AccountPage,
  LoginPage,
  RecoverPage,
  RecoveryCodesPage,
  SignupPage,
} from './pages';
import { uniqueEmail } from './utils/test-data';

test.describe('Auth UI', () => {
  test.beforeEach(async ({ page }, testInfo) => {
    const titleSeed = Array.from(testInfo.title).reduce((sum, ch) => sum + ch.charCodeAt(0), 0);
    const octet = 10 + (titleSeed % 200);
    await page.setExtraHTTPHeaders({
      'X-Forwarded-For': `198.51.100.${octet}`,
    });
  });

  test('renders core auth pages @smoke', async ({ page }) => {
    const loginPage = new LoginPage(page);
    const signupPage = new SignupPage(page);
    const recoverPage = new RecoverPage(page);

    await loginPage.goto();
    await signupPage.goto();
    await recoverPage.goto();
  });

  test('signup mismatch is blocked client-side', async ({ page }) => {
    const signupPage = new SignupPage(page);

    await signupPage.goto();
    await signupPage.signup(uniqueEmail('mismatch'), 'StrongP@ss123', 'DifferentP@ss123');

    await expect(page.getByText('Passwords do not match.')).toBeVisible();
    await expect(page).toHaveURL(/\/signup$/);
  });

  test('signup server validation keeps submitted email', async ({ page }) => {
    const signupPage = new SignupPage(page);
    const email = uniqueEmail('weak');

    await signupPage.goto();
    await signupPage.signup(email, 'short1A');

    await expect(page).toHaveURL(/error=Password/);
    await expect(signupPage.emailInput).toHaveValue(email);
  });

  test('signup and password login flow reaches account page', async ({ page }) => {
    const signupPage = new SignupPage(page);
    const recoveryCodesPage = new RecoveryCodesPage(page);
    const accountPage = new AccountPage(page);
    const loginPage = new LoginPage(page);

    const email = uniqueEmail('happy');
    const password = 'StrongP@ss123';

    await signupPage.goto();
    await signupPage.signup(email, password);

    await recoveryCodesPage.expectLoaded();
    await recoveryCodesPage.continueToAccount();
    await accountPage.expectLoaded();

    await accountPage.logout();
    await expect(page).toHaveURL('/login');

    await loginPage.loginWithPassword(email, password);
    await accountPage.expectLoaded();
  });

  test('failed login keeps submitted email', async ({ page }) => {
    const loginPage = new LoginPage(page);
    const email = uniqueEmail('wrong-login');

    await loginPage.goto();
    await loginPage.loginWithPassword(email, 'WrongP@ssword1');

    await expect(page).toHaveURL(/\/login\?error=/);
    await expect(loginPage.emailInput).toHaveValue(email);
  });

  test('passkey login continues OAuth flow when OAuth params are present', async ({ page }) => {
    const loginPage = new LoginPage(page);

    await page.addInitScript(() => {
      const toBuffer = (input: string): ArrayBuffer => new TextEncoder().encode(input).buffer;

      Object.defineProperty(window, 'PublicKeyCredential', {
        value: function PublicKeyCredential() {},
        configurable: true,
      });

      Object.defineProperty(navigator, 'credentials', {
        configurable: true,
        value: {
          get: async () => ({
            id: 'test-cred-id',
            rawId: toBuffer('raw-id'),
            type: 'public-key',
            response: {
              authenticatorData: toBuffer('authenticator-data'),
              clientDataJSON: toBuffer('client-data-json'),
              signature: toBuffer('signature'),
              userHandle: null,
            },
          }),
        },
      });
    });

    await page.route('**/passkeys/auth/begin', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          challenge_id: 'challenge-1',
          options: {
            publicKey: {
              challenge: 'Y2hhbGxlbmdl',
              allowCredentials: [],
            },
          },
        }),
      });
    });

    await page.route('**/passkeys/auth/complete', async (route) => {
      await route.fulfill({ status: 204 });
    });

    await page.route('**/authorize**', async (route) => {
      await route.fulfill({ status: 200, contentType: 'text/plain', body: 'ok' });
    });

    await loginPage.goto(
      'client_id=e2e-client&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&response_type=code&scope=openid&state=e2e-state&code_challenge=e2e-challenge&code_challenge_method=S256&nonce=e2e-nonce',
    );

    await loginPage.loginWithPasskey('oauth-user@example.com');
    await expect(page).toHaveURL(/\/authorize\?/);

    const redirected = new URL(page.url());
    expect(redirected.searchParams.get('client_id')).toBe('e2e-client');
    expect(redirected.searchParams.get('redirect_uri')).toBe('https://example.com/callback');
    expect(redirected.searchParams.get('response_type')).toBe('code');
    expect(redirected.searchParams.get('scope')).toBe('openid');
    expect(redirected.searchParams.get('state')).toBe('e2e-state');
    expect(redirected.searchParams.get('code_challenge')).toBe('e2e-challenge');
    expect(redirected.searchParams.get('code_challenge_method')).toBe('S256');
    expect(redirected.searchParams.get('nonce')).toBe('e2e-nonce');
  });
});
