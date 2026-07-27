import { useParams } from "react-router-dom";
import { PagePlaceholder } from "@/components/shared/PagePlaceholder";

export function AssessmentDetail() {
  const { id } = useParams<{ id: string }>();
  return (
    <PagePlaceholder
      title="Assessment Detail"
      milestone="W6"
      description="Execution DAG (react-flow), live job status via SSE, per-step retry, and the rendered report."
    >
      <p className="text-sm text-muted-foreground">
        Assessment id: <code className="font-mono">{id}</code>
      </p>
    </PagePlaceholder>
  );
}
