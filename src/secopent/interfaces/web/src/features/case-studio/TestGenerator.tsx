import { useState } from "react";
import { useGenerateTests } from "@/api/hooks";
import type { components } from "@/api/generated";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/shared/DataTable";
import { StatusBadge } from "@/components/shared/StatusBadge";

type Case = components["schemas"]["CaseOut"];

const TEST_CLASS_LABELS: Record<string, string> = {
  skip_step: "Skip step (RESTler)",
  out_of_order: "Out of order (RESTler)",
  replay: "Replay (RESTler)",
  boundary: "Boundary (Schemathesis)",
  invariant_violation: "Invariant violation (self-built)",
};

interface TestGeneratorProps {
  appId: string;
  version: string;
  status: string;
}

// Generation is deterministic from the SIGNED model (never the LLM); the same
// model always yields the same case signatures (idempotent).
export function TestGenerator({ appId, version, status }: TestGeneratorProps) {
  const generate = useGenerateTests();
  const [generated, setGenerated] = useState<Case[]>([]);
  const [message, setMessage] = useState("");

  const handleGenerate = async () => {
    const res = await generate.mutateAsync({ app_id: appId, version });
    if (res.error || !res.data) {
      setMessage("Generation failed (model must be SIGNED).");
      return;
    }
    setGenerated(res.data);
    setMessage(`Generated ${res.data.length} logic-test case(s).`);
  };

  const columns: Column<Case>[] = [
    {
      key: "test_class",
      header: "Test class",
      render: (c) => {
        const cls = String(c.steps[0]?.spec?.test_class ?? "");
        return TEST_CLASS_LABELS[cls] ?? cls;
      },
    },
    {
      key: "signature",
      header: "Signature",
      render: (c) => (
        <span className="font-mono text-xs">
          {String(c.steps[0]?.spec?.signature ?? "").slice(0, 20)}…
        </span>
      ),
    },
    { key: "origin", header: "Origin", render: (c) => c.origin },
    { key: "status", header: "Status", render: (c) => <StatusBadge status={c.status} /> },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <Button disabled={status !== "signed"} onClick={handleGenerate}>
          Generate 5-class tests
        </Button>
        {status !== "signed" && (
          <span className="text-xs text-muted-foreground">
            Sign the model first (Signing tab) to enable generation.
          </span>
        )}
      </div>
      {message && <p className="text-sm text-muted-foreground">{message}</p>}
      <DataTable
        data={generated}
        columns={columns}
        rowKey={(c) => c.id}
        emptyMessage="No tests generated yet."
      />
    </div>
  );
}
