import { expect, type Locator, type Page } from '@playwright/test';

export class AccountPage {
  readonly page: Page;
  readonly heading: Locator;
  readonly logoutButton: Locator;
  readonly managePasskeysLink: Locator;
  readonly revokeOthersButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Account' });
    this.logoutButton = page.getByRole('button', { name: 'Sign out' });
    this.managePasskeysLink = page.getByRole('link', { name: 'Passkeys' });
    this.revokeOthersButton = page.getByRole('button', { name: 'Sign out all other devices' });
  }

  async expectLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.page).toHaveURL('/account');
  }

  async logout(): Promise<void> {
    await this.logoutButton.click();
  }
}
