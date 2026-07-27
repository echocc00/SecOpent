import { useNavigate } from "react-router-dom";
import { PlusCircle, ShieldCheck } from "lucide-react";
import { useAssessments, useFindings, usePendingApprovals } from "@/api/hooks";
import type { components } from "@/api/generated";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/shared/DataTable";
import { StatusBadge } from "@/components/shared/StatusBadge";

type Assessment = components["schemas"]["AssessmentOut"];

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold tracking-tight">{value}</div>
      </CardContent>
    </Card>
  );
}

export function Dashboard() {
  const navigate = useNavigate();
  const assessments = useAssessments();
  const pending = usePendingApprovals();
  const confirmed = useFindings({ oracle_verdict: "confirmed" });

  const assessmentList = assessments.data?.data ?? [];
  const pendingCount = pending.data?.data?.length ?? 0;
  const confirmedCount = confirmed.data?.data?.length ?? 0;

  const columns: Column<Assessment>[] = [
    { key: "id", header: "Assessment", sortValue: (a) => a.id },
    { key: "mode", header: "Mode", sortValue: (a) => a.mode },
    {
      key: "status",
      header: "Status",
      sortValue: (a) => a.status,
      render: (a) => <StatusBadge status={a.status} />,
    },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate("/approvals")}>
            <ShieldCheck className="mr-2 h-4 w-4" />
            Approvals
          </Button>
          <Button onClick={() => navigate("/assessments/new")}>
            <PlusCircle className="mr-2 h-4 w-4" />
            New Assessment
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Assessments" value={assessmentList.length} />
        <StatCard label="Pending Approvals" value={pendingCount} />
        <StatCard label="Confirmed Findings" value={confirmedCount} />
      </div>

      <div className="flex flex-col gap-2">
        <h2 className="text-lg font-medium">Recent Assessments</h2>
        <DataTable
          data={assessmentList}
          columns={columns}
          rowKey={(a) => a.id}
          onRowClick={(a) => navigate(`/assessments/${a.id}`)}
          emptyMessage="No assessments yet. Create one to get started."
        />
      </div>
    </div>
  );
}
