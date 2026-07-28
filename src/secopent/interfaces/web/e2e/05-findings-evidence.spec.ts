import { test, expect } from "./fixtures";

test("findings: severity filter + detail drawer with evidence layer tabs", async ({
  page,
  request,
}) => {
  // Seed two findings of different severities
  await request.post("/api/findings", {
    data: { title: "Critical SQLi", asset: "https://x.test/a", severity: "critical", cwe: ["CWE-89"] },
  });
  await request.post("/api/findings", {
    data: { title: "Low Info Leak", asset: "https://x.test/b", severity: "low" },
  });

  await page.goto("/findings");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();

  // Filter by severity = critical -> one row remains
  await page.getByRole("combobox", { name: "Filter by severity" }).click();
  await page.getByRole("option", { name: "critical" }).click();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.getByText("Critical SQLi")).toBeVisible();

  // Open the detail drawer; the three evidence layer tabs are present
  await page.getByText("Critical SQLi").click();
  await expect(page.getByRole("tab", { name: "raw" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "redacted" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "summary" })).toBeVisible();
  await page.getByRole("tab", { name: "redacted" }).click();
});
