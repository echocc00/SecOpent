import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useQueryClient } from "@tanstack/react-query";
import { useAssessment, useJobs, usePlan, useReports, useStartAssessment, useStopAssessment } from "@/api/hooks";
import type { components } from "@/api/generated";
import { subscribeAssessmentEvents, type AssessmentEvent } from "@/lib/sse";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/shared/DataTable";
import { DagView, type DagEdgeInput, type DagNodeInput } from "@/components/shared/DagView";
import { StatusBadge } from "@/components/shared/StatusBadge";

type Job = components["schemas"]["JobOut"];

export function AssessmentDetail() {
  const { t } = useTranslation();
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const assessment = useAssessment(id ?? "");
  const a = assessment.data?.data;
  const plan = usePlan(a?.active_plan_id ?? "");
  const jobs = useJobs();
  const reports = useReports(id ?? "");

  const [events, setEvents] = useState<AssessmentEvent[]>([]);

  useEffect(() => {
    if (!id) return;
    const unsubscribe = subscribeAssessmentEvents(id, (event) => {
      setEvents((prev) => [event, ...prev].slice(0, 100));
      queryClient.invalidateQueries({ queryKey: ["assessments", id] });
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    });
    return unsubscribe;
  }, [id, queryClient]);

  const planData = plan.data?.data;
  const dagNodes: DagNodeInput[] =
    planData?.steps.map((s) => ({ id: s.key, label: s.key, status: "pending" })) ?? [];
  const dagEdges: DagEdgeInput[] =
    planData?.steps.flatMap((s) =>
      s.dependencies.map((dep) => ({ source: dep, target: s.key })),
    ) ?? [];

  const stepKeys = new Set(planData?.steps.map((s) => s.key) ?? []);
  const planJobs = (jobs.data?.data ?? []).filter((j) => stepKeys.has(j.plan_step_key));

  const jobColumns: Column<Job>[] = [
    { key: "plan_step_key", header: "Step", sortValue: (j) => j.plan_step_key },
    {
      key: "status",
      header: "Status",
      sortValue: (j) => j.status,
      render: (j) => <StatusBadge status={j.status} />,
    },
    { key: "attempt", header: "Attempt", sortValue: (j) => j.attempt },
    { key: "failure_class", header: "Failure", render: (j) => j.failure_class || "—" },
  ];

  const reportList = reports.data?.data ?? [];

  const startMut = useStartAssessment();
  const stopMut = useStopAssessment();
  const canStart = a?.status === "approved";
  const canStop = a?.status === "queued" || a?.status === "running";

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">{t("pages.assessmentDetail.title")}</h1>
          <span className="font-mono text-sm text-muted-foreground">{id}</span>
          {a && <StatusBadge status={a.status} />}
        </div>
        <div className="flex items-center gap-2">
          {canStart && (
            <Button
              onClick={() => id && startMut.mutate(id)}
              disabled={startMut.isPending}
            >
              {startMut.isPending ? "Starting..." : "Start"}
            </Button>
          )}
          <Button
            variant="destructive"
            disabled={!canStop || stopMut.isPending}
            title={canStop ? "Halt execution" : "Available while running"}
            onClick={() =>
              id && stopMut.mutate({ assessmentId: id, actor: "operator", reason: "manual stop" })
            }
          >
            Emergency Stop
          </Button>
        </div>
      </div>

      {a && (
        <div className="grid gap-4 sm:grid-cols-3">
          <Info label="Project" value={a.project_id} />
          <Info label="Mode" value={a.mode} />
          <Info label="Scope" value={a.scope_snapshot_id} />
        </div>
      )}

      <div className="flex flex-col gap-2">
        <h2 className="text-lg font-medium">Execution Plan</h2>
        {planData ? (
          <DagView nodes={dagNodes} edges={dagEdges} />
        ) : (
          <p className="text-sm text-muted-foreground">No plan attached yet.</p>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="flex flex-col gap-2">
          <h2 className="text-lg font-medium">Jobs</h2>
          <DataTable
            data={planJobs}
            columns={jobColumns}
            rowKey={(j) => j.id}
            emptyMessage="No jobs for this plan yet."
          />
        </div>

        <div className="flex flex-col gap-2">
          <h2 className="text-lg font-medium">Event Stream</h2>
          <Card>
            <CardContent className="max-h-72 overflow-auto p-3">
              {events.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Waiting for events (SSE)…
                </p>
              ) : (
                <ul className="flex flex-col gap-1 font-mono text-xs">
                  {events.map((e, i) => (
                    <li key={i}>
                      <StatusBadge status={e.status} /> {e.status}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <h2 className="text-lg font-medium">Reports</h2>
        {reportList.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No reports rendered yet (report generation lands with the execution layer).
          </p>
        ) : (
          <ul className="flex flex-col gap-1 text-sm">
            {reportList.map((r) => (
              <li key={r.id} className="flex items-center gap-2">
                <span>{r.title}</span>
                <StatusBadge status={r.status} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-xs font-medium text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="font-mono text-sm">{value}</CardContent>
    </Card>
  );
}
