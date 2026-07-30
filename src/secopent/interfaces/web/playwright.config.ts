import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// web/ -> interfaces/ -> secopent/ -> src/ -> repo root
const repoRoot = path.resolve(__dirname, "../../../..");

export default defineConfig({
  testDir: "./e2e",
  // Serial: the specs share one backend (single in-memory SQLite in uvicorn).
  fullyParallel: false,
  retries: process.env.CI ? 2 : 0,
  // Vite dev cold-transforms the lazy CaseStudio chunk on first load; give
  // expect assertions room for that initial transform.
  expect: { timeout: 15000 },
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: "http://localhost:5173",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      // Backend API (temp SQLite per uvicorn start -> isolated per run).
      // PYTHON_BIN lets CI (ubuntu, which has no `py` launcher) override the
      // interpreter; locally it defaults to the Windows `py -3.12` launcher.
      command: `${process.env.PYTHON_BIN ?? "py -3.12"} -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000`,
      url: "http://localhost:8000/health",
      cwd: repoRoot,
      reuseExistingServer: !process.env.CI,
      timeout: 60000,
    },
    {
      // Vite dev server; proxies /api -> :8000 (rewrite strips /api).
      command: "npm run dev",
      url: "http://localhost:5173",
      reuseExistingServer: !process.env.CI,
      timeout: 60000,
    },
  ],
});
