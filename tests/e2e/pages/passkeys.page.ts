import { expect, type Locator, type Page } from '@playwright/test';

export class PasskeysPage {
  readonly page: Page;
  readonly heading: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Passkeys' });
  }

  async expectLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.page).toHaveURL('/passkeys/manage');
  }
}
