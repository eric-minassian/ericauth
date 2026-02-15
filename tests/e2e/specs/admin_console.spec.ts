import { expect, test } from '@playwright/test';

import { AccountPage, RecoveryCodesPage, SignupPage } from '../pages';
import { uniqueEmail } from '../utils/test-data';

test.describe('Admin Console', () => {
  test('requires tenant-admin scopes for tenant management pages', async ({ page }) => {
    const signupPage = new SignupPage(page);
    const recoveryCodesPage = new RecoveryCodesPage(page);
    const accountPage = new AccountPage(page);

    const email = uniqueEmail('admin-console');
    const password = 'StrongP@ss123';

    await signupPage.goto();
    await signupPage.signup(email, password);

    await recoveryCodesPage.expectLoaded();
    await recoveryCodesPage.continueToAccount();
    await accountPage.expectLoaded();

    await page.goto('/admin/console/tenants');
    await expect(page.getByText('admin scope required')).toBeVisible();

    await page.goto('/admin/tenants');
    await expect(page.getByText('admin scope required')).toBeVisible();
  });
});
