import { defineConfig, devices } from "@playwright/test";
import * as os from "node:os";
import * as path from "node:path";

// A fresh database per run, in the OS temp dir.
const dbPath = path.join(os.tmpdir(), `plumbline-e2e-${Date.now()}.db`);
const port = 8099;

export default defineConfig({
  testDir: "./tests",
  // Both tests hit one server from one IP and share its rate limiter,
  // so they must run one after the other, in file order.
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Built by `make build` (the `make e2e` target does that first).
    command: "../bin/plumbline",
    url: `http://127.0.0.1:${port}/readyz`,
    reuseExistingServer: false,
    timeout: 20_000,
    env: {
      PORT: String(port),
      DB_PATH: dbPath,
      // A slower simulated scan keeps it "running" long enough to click twice.
      SIMULATED_SCAN_DELAY: "3s",
      LOG_LEVEL: "warn",
    },
  },
});
