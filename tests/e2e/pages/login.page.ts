import { expect, type Locator, type Page } from '@playwright/test';

export class LoginPage {
  readonly page: Page;
  readonly heading: Locator;
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly loginButton: Locator;
  readonly passkeyButton: Locator;
  readonly signupLink: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Log In' });
    this.emailInput = page.getByLabel('Email');
    this.passwordInput = page.getByLabel('Password', { exact: true });
    this.loginButton = page.getByRole('button', { name: 'Log In' });
    this.passkeyButton = page.getByRole('button', { name: 'Use a Passkey' });
    this.signupLink = page.getByRole('link', { name: 'Sign up' });
  }

  async goto(query = ''): Promise<void> {
    const suffix = query ? `?${query}` : '';
    await this.page.goto(`/login${suffix}`);
    await expect(this.heading).toBeVisible();
  }

  async loginWithPassword(email: string, password: string): Promise<void> {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.loginButton.click();
  }

  async loginWithPasskey(email: string): Promise<void> {
    await this.emailInput.fill(email);
    await this.passkeyButton.click();
  }
}
