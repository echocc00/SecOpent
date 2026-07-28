import { test, expect } from "./fixtures";

test("case studio: create model, add state, connect transition, save", async ({ page }) => {
  test.setTimeout(90000);
  await page.goto("/case-studio");
  await expect(page.getByText("App Models")).toBeVisible({ timeout: 30000 });

  // Create a new model via the dialog
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByPlaceholder("e.g. juice-shop").fill("e2e-ui-model");
  await page.getByRole("button", { name: "Create", exact: true }).click();

  // Editor shows the initial "start" state
  await expect(page.locator(".react-flow__node").first()).toBeVisible();

  // Add a second state
  await page.getByRole("button", { name: "+ State" }).click();
  await page.getByPlaceholder("e.g. cart_has_items").fill("processing");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(2);

  // Connect start -> processing by dragging the source handle to the target handle
  await page
    .locator(".react-flow__node", { hasText: "start" })
    .locator(".react-flow__handle.source")
    .dragTo(
      page.locator(".react-flow__node", { hasText: "processing" }).locator(".react-flow__handle.target"),
    );
  // Transition dialog appears; fill the endpoint and add it
  await page.getByPlaceholder("e.g. POST /cart/add").fill("POST /process");
  await page.getByRole("button", { name: "Add transition" }).click();

  // Save (in place, since the model is a draft)
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(/Saved/)).toBeVisible();
});
