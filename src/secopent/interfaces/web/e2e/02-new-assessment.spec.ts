import { test, expect, ensureCatalog } from "./fixtures";

test("new assessment wizard: project -> scope -> freeze -> mode -> plan", async ({
  page,
  request,
}) => {
  await ensureCatalog(request);
  await page.goto("/assessments/new");
  await expect(page.getByRole("heading", { name: "New Assessment" })).toBeVisible();

  // Step 1 - create a new project inline
  await page.getByPlaceholder("Project name").fill("e2e-wizard-project");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.getByRole("button", { name: "Next" }).click();

  // Step 2 - scope include targets
  await page.getByPlaceholder(/juice-shop/).fill("https://target.test");
  await page.getByRole("button", { name: "Next" }).click();

  // Step 3 - freeze the scope (digest appears)
  await page.getByRole("button", { name: "Freeze scope" }).click();
  await expect(page.getByText(/Digest:/)).toBeVisible();
  await page.getByRole("button", { name: "Next" }).click();

  // Step 4 - mode (default: approval)
  await page.getByRole("button", { name: "Next" }).click();

  // Step 5 - create assessment + generate plan (DAG renders)
  await page.getByRole("button", { name: "Create assessment & generate plan" }).click();
  await expect(page.locator(".react-flow")).toBeVisible();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
});
