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

// --- Tools ---
export const useTools = () =>
  useQuery({ queryKey: ["tools"], queryFn: () => api.GET("/tools") });

// --- Findings ---
export const useFindings = () =>
  useQuery({ queryKey: ["findings"], queryFn: () => api.GET("/findings") });

export const useFinding = (id: string) =>
  useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.GET("/findings/{finding_id}", { params: { path: { finding_id: id } } }),
  });

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
export const useApproval = (id: string) =>
  useQuery({
    queryKey: ["approvals", id],
    queryFn: () =>
      api.GET("/approvals/{approval_id}", { params: { path: { approval_id: id } } }),
  });

export const useCreateApproval = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["ApprovalCreate"]) => api.POST("/approvals", { body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assessments"] }),
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

export const useEvidence = (id: string) =>
  useQuery({
    queryKey: ["evidence", "id", id],
    queryFn: () => api.GET("/evidence/{evidence_id}", { params: { path: { evidence_id: id } } }),
  });

// --- Reports ---
export const useReports = (assessmentId: string) =>
  useQuery({
    queryKey: ["reports", assessmentId],
    queryFn: () => api.GET("/reports", { params: { query: { assessment_id: assessmentId } } }),
  });

export const useReport = (id: string) =>
  useQuery({
    queryKey: ["reports", "id", id],
    queryFn: () => api.GET("/reports/{report_id}", { params: { path: { report_id: id } } }),
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
