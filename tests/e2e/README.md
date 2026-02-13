# E2E Testing Standards (Playwright)

## Structure

- Use Page Object Model classes in `tests/e2e/pages/`.
- Keep specs in `*.spec.ts` focused on business flows, not selector details.
- Put shared test data/helpers in `tests/e2e/utils/`.

## Locator strategy (in priority order)

1. `getByRole(...)` for buttons/links/headings and other semantic elements.
2. `getByLabel(...)` for form fields.
3. `getByText(...)` only for user-visible assertions where role/label is not suitable.
4. `getByTestId(...)` for non-semantic or unstable UI (add explicit `data-testid` in templates when needed).

Avoid CSS/XPath selectors unless absolutely necessary.

## Assertions

- Assert user-observable outcomes: URL, headings, error text, and form values.
- Prefer `await expect(locator).toBeVisible()` and `await expect(page).toHaveURL(...)`.

## Network mocking

- Mock only external/complex browser APIs for deterministic coverage (e.g., WebAuthn passkey flow).
- Keep mocks in the spec that needs them.

## Artifacts

- Config keeps traces/screenshots/videos on failure for debugging.
- Artifacts are written to `/tmp/ericauth-playwright-results` to avoid triggering Rust file-watch reloads.

## Running against deployed environments

- Set `E2E_BASE_URL` to run tests against a deployed stack (beta/prod) instead of local `cargo lambda watch`.
- Example: `E2E_BASE_URL=https://example.execute-api.us-east-1.amazonaws.com pnpm test`.
- Set `E2E_WEB_SERVER_CMD` to override the local web server command used by Playwright.
