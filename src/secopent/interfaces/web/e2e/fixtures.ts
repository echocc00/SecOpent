import { test as base, expect, type APIRequestContext } from "@playwright/test";

type Fixtures = {
  seededProjectId: string;
  seededSigningKeyId: string;
};

export const test = base.extend<Fixtures>({
  seededProjectId: async ({ request }, use) => {
    const res = await request.post("/api/projects", {
      data: { name: `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` },
    });
    expect(res.status()).toBe(201);
    const body = await res.json();
    await use(body.id);
  },
  seededSigningKeyId: async ({ request }, use) => {
    const res = await request.post("/api/signing-keys", {
      data: { name: `e2e-key-${Date.now()}`, actor_role: "human" },
    });
    expect(res.status()).toBe(201);
    const body = await res.json();
    await use(body.key_id);
  },
});

export { expect };

/** Ensure a baseline TestCatalog exists so plan generation works. */
export async function ensureCatalog(request: APIRequestContext): Promise<void> {
  const latest = await request.get("/api/catalog/latest");
  if (latest.status() === 200) return;
  const res = await request.post("/api/catalog", {
    data: {
      version: "e2e-baseline",
      mappings: {
        web_app: [
          { id: "TC-WEB-RECON", cwe: ["CWE-79"], owasp: ["A03:2021"], risk: "low" },
          { id: "TC-WEB-ACTIVE", cwe: ["CWE-89"], owasp: ["A03:2021"], risk: "active" },
        ],
      },
    },
  });
  expect(res.status()).toBe(201);
}

/** Seed project + scope + assessment + plan -> assessment is awaiting_approval. */
export async function seedAssessmentWithPlan(
  request: APIRequestContext,
): Promise<{ projectId: string; assessmentId: string }> {
  const project = await request.post("/api/projects", {
    data: { name: `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` },
  });
  const { id: projectId } = await project.json();
  await ensureCatalog(request);
  const scope = await request.post("/api/scopes/draft", {
    data: { project_id: projectId, include: ["https://target.test"], approved_by: "e2e" },
  });
  const scopeBody = await scope.json();
  const assessment = await request.post("/api/assessments", {
    data: { project_id: projectId, scope_snapshot_id: scopeBody.id },
  });
  const assessmentBody = await assessment.json();
  const plan = await request.post(`/api/assessments/${assessmentBody.id}/plans`);
  expect(plan.status()).toBe(201);
  return { projectId, assessmentId: assessmentBody.id };
}

/**
 * Seed an app model rich enough to generate all 5 logic-test classes
 * (2 chained transitions -> replay/skip/out_of_order; a ranged field ->
 * boundary; an invariant -> invariant_violation), validated or signed.
 */
export async function seedAppModel(
  request: APIRequestContext,
  opts: { signingKeyId?: string; sign?: boolean } = {},
): Promise<{ appId: string; version: string }> {
  const appId = `e2e-app-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const version = "1.0";
  const created = await request.post("/api/appmodels", {
    data: {
      app_id: appId,
      version,
      states: ["start", "mid", "end"],
      transitions: [
        { id: "t1", from_state: "start", to_state: "mid", endpoint: "POST /step1", params: [], idempotent: false },
        { id: "t2", from_state: "mid", to_state: "end", endpoint: "POST /step2", params: [], idempotent: false },
      ],
      invariants: [{ id: "inv1", expr: "total >= 0" }],
      fields: [{ name: "qty", type: "int", range: [1, 10], trusted_source: "client" }],
      roles: [{ id: "buyer", capabilities: ["step1", "step2"] }],
      out_of_scope_rules: [],
      llm_proposed: false,
    },
  });
  expect(created.status()).toBe(201);
  const validated = await request.post(`/api/appmodels/${appId}/${version}/validate`, {
    data: { actor_role: "human" },
  });
  expect(validated.status()).toBe(200);
  if (opts.sign) {
    const signed = await request.post(`/api/appmodels/${appId}/${version}/sign`, {
      data: { actor_role: "human", key_id: opts.signingKeyId },
    });
    expect(signed.status()).toBe(200);
  }
  return { appId, version };
}
