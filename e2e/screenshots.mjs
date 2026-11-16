// Captures the README screenshots: a fresh server, the seed scan (v1), one
// more scan (v2: lost MFA visibility), then the dashboard and connection page.
// Usage (from e2e/): node screenshots.mjs   (after `make build`)
import { chromium } from "@playwright/test";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const port = 8098;
const base = `http://127.0.0.1:${port}`;
const db = join(mkdtempSync(join(tmpdir(), "plumbline-shots-")), "shots.db");
const server = spawn("../bin/plumbline", [], {
  env: { ...process.env, PORT: String(port), DB_PATH: db, SIMULATED_SCAN_DELAY: "0s", LOG_LEVEL: "warn" },
  stdio: "inherit",
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function idle() {
  for (let i = 0; i < 100; i++) {
    const r = await fetch(`${base}/api/connections`).then((x) => x.json()).catch(() => null);
    const c = r?.connections?.[0];
    if (c?.latest_scan && !c.active_scan_id) return;
    await sleep(100);
  }
  throw new Error("server not idle");
}

try {
  await idle();
  await fetch(`${base}/api/connections/github:acme-demo/scans`, { method: "POST" });
  await sleep(200);
  await idle();

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 760 }, colorScheme: "light", deviceScaleFactor: 2 });
  await page.goto(base + "/");
  await page.screenshot({ path: "../docs/screenshots/dashboard.png" });
  await page.goto(base + "/c/github:acme-demo");
  await page.setViewportSize({ width: 1200, height: 1100 });
  await page.screenshot({ path: "../docs/screenshots/connection.png" });
  await browser.close();
  console.log("saved docs/screenshots/{dashboard,connection}.png");
} finally {
  server.kill("SIGTERM");
}
