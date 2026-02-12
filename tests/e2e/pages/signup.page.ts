import { expect, type Locator, type Page } from '@playwright/test';

export class SignupPage {
  readonly page: Page;
  readonly heading: Locator;
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly confirmPasswordInput: Locator;
  readonly signupButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Sign Up' });
    this.emailInput = page.getByLabel('Email');
    this.passwordInput = page.getByLabel('Password', { exact: true });
    this.confirmPasswordInput = page.getByLabel('Confirm Password');
    this.signupButton = page.getByRole('button', { name: 'Sign Up' });
  }

  async goto(): Promise<void> {
    await this.page.goto('/signup');
    await expect(this.heading).toBeVisible();
  }

  async signup(email: string, password: string, confirmPassword = password): Promise<void> {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.confirmPasswordInput.fill(confirmPassword);
    await this.signupButton.click();
  }
}
