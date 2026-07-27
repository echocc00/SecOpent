import { useFindings, useProjects } from "@/api/hooks";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PagePlaceholder } from "@/components/shared/PagePlaceholder";

function StatCard({ label, value }: { label: string; value: string }) {
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
  const projects = useProjects();
  const findings = useFindings();

  const projectCount = projects.data?.data?.length ?? 0;
  const findingCount = findings.data?.data?.length ?? 0;
  const isLive = projects.isSuccess && findings.isSuccess;

  return (
    <PagePlaceholder
      title="Dashboard"
      milestone="W4a"
      description="Overview of projects, assessments, and findings. The counts below are fetched live from the SecOpent API through the /api proxy to confirm the backend wiring."
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard label="Projects" value={String(projectCount)} />
        <StatCard label="Findings" value={String(findingCount)} />
        <StatCard label="API status" value={isLive ? "live" : "…"} />
      </div>
    </PagePlaceholder>
  );
}
