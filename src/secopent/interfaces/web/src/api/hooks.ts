// TanStack Query hooks over the typed OpenAPI client (Phase A P1, W2).
// Each hook returns the openapi-fetch response ({ data, error, response });
// components read `data` and render `error`/loading states explicitly.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { components } from "./generated";

type Schemas = components["schemas"];

// --- Projects ---
export const useProjects = () =>
  useQuery({ queryKey: ["projects"], queryFn: () => api.GET("/projects") });

export const useProject = (id: string) =>
  useQuery({
    queryKey: ["projects", id],
    queryFn: () => api.GET("/projects/{project_id}", { params: { path: { project_id: id } } }),
  });

export const useCreateProject = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["ProjectCreate"]) => api.POST("/projects", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
};

// --- Scopes ---
export const useScope = (id: string) =>
  useQuery({
    queryKey: ["scopes", id],
    queryFn: () => api.GET("/scopes/{snapshot_id}", { params: { path: { snapshot_id: id } } }),
  });

export const useCreateScope = () =>
  useMutation({
    mutationFn: (body: Schemas["ScopeDraftCreate"]) => api.POST("/scopes/draft", { body }),
  });

// --- Assessments ---
export const useAssessments = (projectId?: string) =>
  useQuery({
    queryKey: ["assessments", projectId],
    queryFn: () =>
      api.GET("/assessments", { params: { query: { project_id: projectId } } }),
  });

export const useAssessment = (id: string) =>
  useQuery({
    queryKey: ["assessments", id],
    queryFn: () =>
      api.GET("/assessments/{assessment_id}", { params: { path: { assessment_id: id } } }),
  });

export const useCreateAssessment = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["AssessmentCreate"]) => api.POST("/assessments", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assessments"] }),
  });
};

export const useGeneratePlan = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (assessmentId: string) =>
      api.POST("/assessments/{assessment_id}/plans", {
        params: { path: { assessment_id: assessmentId } },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assessments"] }),
  });
};

// --- Tools ---
export const useTools = () =>
  useQuery({ queryKey: ["tools"], queryFn: () => api.GET("/tools") });

// --- Findings ---
export interface FindingFilters {
  assessment_id?: string;
  severity?: string;
  oracle_verdict?: string;
}

export const useFindings = (filters?: FindingFilters) =>
  useQuery({
    queryKey: ["findings", filters],
    queryFn: () => api.GET("/findings", { params: { query: filters ?? {} } }),
  });

export const useFinding = (id: string) =>
  useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.GET("/findings/{finding_id}", { params: { path: { finding_id: id } } }),
  });

export const useSetFindingVerdict = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ finding_id, body }: { finding_id: string; body: Schemas["FindingVerdict"] }) =>
      api.POST("/findings/{finding_id}/verdict", {
        params: { path: { finding_id } },
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
};

// --- Intel ---
export const useIntelSearch = (params: { keyword?: string; cve?: string; cwe?: string }) =>
  useQuery({
    queryKey: ["intel", "search", params],
    queryFn: () => api.GET("/intel/search", { params: { query: params } }),
  });

// --- Updates ---
export const useActiveBundle = () =>
  useQuery({ queryKey: ["updates", "active"], queryFn: () => api.GET("/updates/active") });

// --- Audit ---
export const useAuditEvents = () =>
  useQuery({ queryKey: ["audit", "events"], queryFn: () => api.GET("/audit/events") });

export const useAuditVerify = () =>
  useQuery({ queryKey: ["audit", "verify"], queryFn: () => api.GET("/audit/verify") });

// --- Plans ---
export const usePlan = (id: string) =>
  useQuery({
    queryKey: ["plans", id],
    queryFn: () => api.GET("/plans/{plan_id}", { params: { path: { plan_id: id } } }),
  });

export const useCreatePlan = () =>
  useMutation({
    mutationFn: (body: Schemas["PlanCreate"]) => api.POST("/plans", { body }),
  });

// --- Approvals ---
export const usePendingApprovals = () =>
  useQuery({ queryKey: ["approvals", "pending"], queryFn: () => api.GET("/approvals/pending") });

export const useApprovalHistory = () =>
  useQuery({ queryKey: ["approvals", "history"], queryFn: () => api.GET("/approvals/history") });

export const useCreateApproval = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["ApprovalCreate"]) => api.POST("/approvals", { body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      qc.invalidateQueries({ queryKey: ["assessments"] });
    },
  });
};

export const useRejectApproval = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["ApprovalReject"]) => api.POST("/approvals/reject", { body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      qc.invalidateQueries({ queryKey: ["assessments"] });
    },
  });
};

// --- Jobs ---
export const useJobs = () =>
  useQuery({ queryKey: ["jobs"], queryFn: () => api.GET("/jobs") });

export const useJob = (id: string) =>
  useQuery({
    queryKey: ["jobs", id],
    queryFn: () => api.GET("/jobs/{job_id}", { params: { path: { job_id: id } } }),
  });

// --- Assets ---
export const useAssetGraph = () =>
  useQuery({ queryKey: ["assets"], queryFn: () => api.GET("/assets") });

// --- Evidence ---
export const useEvidenceByFinding = (findingId: string) =>
  useQuery({
    queryKey: ["evidence", findingId],
    queryFn: () => api.GET("/evidence", { params: { query: { finding_id: findingId } } }),
  });

// --- Reports ---
export const useReports = (assessmentId: string) =>
  useQuery({
    queryKey: ["reports", assessmentId],
    queryFn: () => api.GET("/reports", { params: { query: { assessment_id: assessmentId } } }),
  });

// --- Cases (CaseStudio) ---
export const useCases = () =>
  useQuery({ queryKey: ["cases"], queryFn: () => api.GET("/cases") });

export const useCase = (id: string) =>
  useQuery({
    queryKey: ["cases", id],
    queryFn: () => api.GET("/cases/{case_id}", { params: { path: { case_id: id } } }),
  });

export const useCreateCase = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["CaseCreate"]) => api.POST("/cases", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }),
  });
};

export const useAnalyzeCase = () =>
  useMutation({
    mutationFn: (case_id: string) =>
      api.POST("/cases/{case_id}/analyze", { params: { path: { case_id } } }),
  });

export const useUpdateCaseYaml = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ case_id, body }: { case_id: string; body: Schemas["CaseYamlUpdate"] }) =>
      api.PUT("/cases/{case_id}", { params: { path: { case_id } }, body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }),
  });
};

export const useValidateCase = () => {
  const qc = useQueryClient();
  return useMutation({
    // validate takes no body (the risk gate runs server-side).
    mutationFn: ({ case_id }: { case_id: string }) =>
      api.POST("/cases/{case_id}/validate", { params: { path: { case_id } } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }),
  });
};

const caseActorAction = (action: "review" | "sign" | "publish") => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ case_id, body }: { case_id: string; body: Schemas["CaseAction"] }) =>
      api.POST(`/cases/{case_id}/${action}` as "/cases/{case_id}/review", {
        params: { path: { case_id } },
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }),
  });
};

export const useReviewCase = () => caseActorAction("review");
export const useSignCase = () => caseActorAction("sign");
export const usePublishCase = () => caseActorAction("publish");

// --- AppModels (CaseStudio) ---
export const useAppModels = () =>
  useQuery({ queryKey: ["appmodels"], queryFn: () => api.GET("/appmodels") });

export const useAppModel = (appId: string, version: string) =>
  useQuery({
    queryKey: ["appmodels", appId, version],
    queryFn: () =>
      api.GET("/appmodels/{app_id}/{version}", {
        params: { path: { app_id: appId, version } },
      }),
  });

export const useCreateAppModel = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["AppModelCreate"]) => api.POST("/appmodels", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appmodels"] }),
  });
};

export const useUpdateAppModel = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ app_id, version, body }: { app_id: string; version: string; body: Schemas["AppModelCreate"] }) =>
      api.PUT("/appmodels/{app_id}/{version}", {
        params: { path: { app_id, version } },
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appmodels"] }),
  });
};

export const useReviseAppModel = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ app_id, version, body }: { app_id: string; version: string; body: Schemas["AppModelRevise"] }) =>
      api.POST("/appmodels/{app_id}/{version}/revise", {
        params: { path: { app_id, version } },
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appmodels"] }),
  });
};

export const useValidateAppModel = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ app_id, version, body }: { app_id: string; version: string; body: Schemas["CaseAction"] }) =>
      api.POST("/appmodels/{app_id}/{version}/validate", {
        params: { path: { app_id, version } },
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appmodels"] }),
  });
};

export const useSignAppModel = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ app_id, version, body }: { app_id: string; version: string; body: Schemas["CaseAction"] }) =>
      api.POST("/appmodels/{app_id}/{version}/sign", {
        params: { path: { app_id, version } },
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appmodels"] }),
  });
};

export const useGenerateTests = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ app_id, version }: { app_id: string; version: string }) =>
      api.POST("/appmodels/{app_id}/{version}/generate-tests", {
        params: { path: { app_id, version } },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cases"] });
      qc.invalidateQueries({ queryKey: ["appmodels"] });
    },
  });
};

// --- Signing keys ---
export const useSigningKeys = () =>
  useQuery({ queryKey: ["signing-keys"], queryFn: () => api.GET("/signing-keys") });

export const useCreateSigningKey = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["CreateSigningKey"]) => api.POST("/signing-keys", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["signing-keys"] }),
  });
};
