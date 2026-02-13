import { expect, type Locator, type Page } from '@playwright/test';

export class RecoveryCodesPage {
  readonly page: Page;
  readonly heading: Locator;
  readonly continueLink: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Recovery Codes' });
    this.continueLink = page.getByRole('link', { name: 'Continue' });
  }

  async expectLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
  }

  async continueToAccount(): Promise<void> {
    await this.continueLink.click();
  }
}
