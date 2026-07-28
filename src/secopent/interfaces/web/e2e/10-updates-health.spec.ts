import { test, expect } from "./fixtures";

test("updates page shows bundle + audit chain, and the chain verifies", async ({
  page,
  request,
}) => {
  await page.goto("/updates");
  await expect(page.getByRole("heading", { name: "Updates" })).toBeVisible();
  await expect(page.getByText("Active Knowledge Bundle")).toBeVisible();
  await expect(page.getByText("Audit Chain")).toBeVisible();
  await expect(page.getByText("Knowledge Health Detectors")).toBeVisible();

  // The tamper-evident audit chain verifies server-side
  const verify = await request.get("/api/audit/verify");
  expect((await verify.json()).valid).toBeTruthy();
});
