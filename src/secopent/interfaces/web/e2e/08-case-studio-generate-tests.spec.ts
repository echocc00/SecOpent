import { test, expect, seedAppModel } from "./fixtures";

test("generate 5-class logic tests from a signed model", async ({
  page,
  request,
  seededSigningKeyId,
}) => {
  // Signed model with structure that yields all 5 classes:
  // 2 chained transitions (replay/skip/out_of_order), a ranged field (boundary),
  // an invariant (invariant_violation).
  const { appId, version } = await seedAppModel(request, {
    sign: true,
    signingKeyId: seededSigningKeyId,
  });

  await page.goto("/case-studio");
  test.setTimeout(90000);
  await expect(page.getByText("App Models")).toBeVisible({ timeout: 30000 });
  await page.getByText(`${appId}@${version}`).click();
  await page.getByRole("tab", { name: "Test Generation" }).click();
  await page.getByRole("button", { name: "Generate 5-class tests" }).click();

  await expect(page.getByText(/Skip step/).first()).toBeVisible();
  await expect(page.getByText(/Out of order/).first()).toBeVisible();
  await expect(page.getByText(/Replay/).first()).toBeVisible();
  await expect(page.getByText(/Boundary/).first()).toBeVisible();
  await expect(page.getByText(/Invariant violation/).first()).toBeVisible();
});
