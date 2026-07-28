import { test, expect, seedAppModel } from "./fixtures";

test("case studio: yaml analyze (risk) + human signing flow", async ({
  page,
  request,
  seededSigningKeyId,
}) => {
  // A human-validated model (ready to sign) + a case to edit in the YAML tab
  const { appId, version } = await seedAppModel(request, { sign: false });
  await request.post("/api/cases", {
    data: {
      id: "e2e-yaml-case",
      version: "1.0",
      author: "e2e",
      risk: "low",
      target_type: "web_app",
      case_schema: "secopent-case/v1",
      steps: [{ id: "s1", action: "http.request", spec: { method: "GET" } }],
      yaml: "id: e2e-yaml-case\ninfo:\n  severity: low\n",
    },
  });

  await page.goto("/case-studio");
  test.setTimeout(90000);
  await expect(page.getByText("App Models")).toBeVisible({ timeout: 30000 });
  await page.getByText(`${appId}@${version}`).click();

  // YAML tab: select the case and analyze its risk
  await page.getByRole("tab", { name: "YAML (Cases)" }).click();
  await page.getByRole("combobox", { name: "Select a case" }).click();
  await page.getByRole("option", { name: /e2e-yaml-case/ }).click();
  await page.getByRole("button", { name: "Analyze risk" }).click();
  await expect(page.getByText(/Declared risk/)).toBeVisible();

  // Signing tab: select a server-held key and sign (human-only)
  await page.getByRole("tab", { name: "Signing" }).click();
  await page.getByRole("combobox", { name: "Select signing key" }).click();
  await page.getByRole("option").first().click();
  await page.getByRole("button", { name: "Sign (Ed25519)" }).click();
  await expect(page.getByText("signed").first()).toBeVisible();
});
