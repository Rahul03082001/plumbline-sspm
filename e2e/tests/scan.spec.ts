import { test, expect, Page, Locator } from "@playwright/test";

// The simulated tenant's card on the dashboard.
function acmeCard(page: Page): Locator {
  return page.locator("#card-github-acme-demo");
}

// Wait until the startup seed scan has finished, so our clicks start clean.
async function openDashboard(page: Page): Promise<Locator> {
  await page.goto("/");
  const card = acmeCard(page);
  await expect(card.getByText(/checks assessed/)).toBeVisible({ timeout: 15_000 });
  await expect(card.locator(".scan-status")).toHaveCount(0, { timeout: 15_000 });
  return card;
}

test("clicking Run scan twice quickly shows 'Scan already running' (409 is swapped)", async ({ page }) => {
  const card = await openDashboard(page);
  const run = card.getByRole("button", { name: "Run scan" });

  await run.click();
  await expect(card.getByText(/Scan (queued|running)/)).toBeVisible();

  await run.click(); // the scan is still running -> server answers 409
  await expect(card.getByText("Scan already running")).toBeVisible();

  // Once the scan finishes, the poller swaps in the refreshed card.
  await expect(card.getByText("Not comparable: visibility dropped")).toBeVisible({ timeout: 15_000 });
});

test("clicking past the rate limit shows 'Slow down' (429 is swapped)", async ({ page }) => {
  const card = await openDashboard(page);
  const run = card.getByRole("button", { name: "Run scan" });
  const slowDown = card.getByText(/Slow down/);

  // 5 scan requests per minute per IP. The first test used 2, so we reach
  // the limit within a few more clicks.
  for (let i = 0; i < 8 && !(await slowDown.isVisible()); i++) {
    await run.click();
    await page.waitForTimeout(250);
  }
  await expect(slowDown).toBeVisible();
});
