import { test, expect, seedAssessmentWithPlan } from "./fixtures";

// Core security property (LLM boundary): an agent (actor_role="agent") is
// rejected with 403 on every human-only endpoint. This is the acceptance gate
// for the §2 boundary fix.
test("agent actor_role is rejected (403) on human-only endpoints", async ({ request }) => {
  const { assessmentId } = await seedAssessmentWithPlan(request);

  const cases: { path: string; body: Record<string, unknown> }[] = [
    {
      path: "/api/approvals",
      body: {
        assessment_id: assessmentId,
        approved_by: "agent",
        approved_risks: ["low"],
        actor_role: "agent",
      },
    },
    {
      path: "/api/approvals/reject",
      body: { assessment_id: assessmentId, rejected_by: "agent", reason: "x", actor_role: "agent" },
    },
    { path: "/api/findings/any-finding/verdict", body: { verdict: "confirmed", actor_role: "agent" } },
    { path: "/api/signing-keys", body: { name: "rogue", actor_role: "agent" } },
    { path: "/api/appmodels/any-app/1.0/sign", body: { actor_role: "agent" } },
    { path: "/api/appmodels/any-app/1.0/validate", body: { actor_role: "agent" } },
    { path: "/api/cases/any-case/review", body: { actor_role: "agent" } },
    { path: "/api/cases/any-case/sign", body: { actor_role: "agent" } },
    { path: "/api/cases/any-case/publish", body: { actor_role: "agent" } },
  ];

  for (const c of cases) {
    const res = await request.post(c.path, { data: c.body });
    expect(res.status(), `POST ${c.path}`).toBe(403);
  }
});
