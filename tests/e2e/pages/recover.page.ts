import { expect, type Locator, type Page } from '@playwright/test';

export class RecoverPage {
  readonly page: Page;
  readonly heading: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Account Recovery' });
  }

  async goto(): Promise<void> {
    await this.page.goto('/recover');
    await expect(this.heading).toBeVisible();
  }
}
