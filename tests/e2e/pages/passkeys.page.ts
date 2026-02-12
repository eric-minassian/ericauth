import { expect, type Locator, type Page } from '@playwright/test';

export class PasskeysPage {
  readonly page: Page;
  readonly heading: Locator;
  readonly logoutButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Passkeys' });
    this.logoutButton = page.getByRole('button', { name: 'Log Out' });
  }

  async expectLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.page).toHaveURL('/passkeys/manage');
  }

  async logout(): Promise<void> {
    await this.logoutButton.click();
  }
}
