import { expect, type Locator, type Page } from '@playwright/test';

export class AccountPage {
  readonly page: Page;
  readonly heading: Locator;
  readonly logoutButton: Locator;
  readonly managePasskeysLink: Locator;
  readonly revokeOthersButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Account Security' });
    this.logoutButton = page.getByRole('button', { name: 'Log Out' });
    this.managePasskeysLink = page.getByRole('link', { name: 'Manage passkeys' });
    this.revokeOthersButton = page.getByRole('button', { name: 'Sign Out Other Devices' });
  }

  async expectLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.page).toHaveURL('/account');
  }

  async logout(): Promise<void> {
    await this.logoutButton.click();
  }
}
