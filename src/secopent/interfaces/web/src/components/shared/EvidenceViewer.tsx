import { useState } from "react";
import { useEvidenceByFinding } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

const LAYERS = ["raw", "redacted", "summary"] as const;

// Three-layer evidence viewer (raw / redacted / summary). Evidence content is
// content-addressed in the CAS and referenced by storage_uri; the RAW layer is
// write-once and REDACTED/SUMMARY derive from it via source_id.
export function EvidenceViewer({ findingId }: { findingId: string }) {
  const { data, isLoading } = useEvidenceByFinding(findingId);
  const [layer, setLayer] = useState<string>("redacted");
  const items = (data?.data ?? []).filter((e) => e.layer === layer);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading evidence…</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      <Tabs value={layer} onValueChange={setLayer}>
        <TabsList>
          {LAYERS.map((l) => (
            <TabsTrigger key={l} value={l} className="capitalize">
              {l}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No {layer} evidence recorded.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {items.map((e) => (
            <li key={e.id} className="rounded-md border p-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs">{e.id}</span>
                <Badge variant="outline" className="capitalize">
                  {e.layer}
                </Badge>
              </div>
              <dl className="mt-2 grid grid-cols-[80px_1fr] gap-y-1 text-xs text-muted-foreground">
                <dt>sha256</dt>
                <dd className="font-mono">{e.sha256.slice(0, 24)}…</dd>
                <dt>storage</dt>
                <dd className="font-mono">{e.storage_uri}</dd>
                {e.source_id && (
                  <>
                    <dt>derived from</dt>
                    <dd className="font-mono">{e.source_id}</dd>
                  </>
                )}
                {e.signature && (
                  <>
                    <dt>signature</dt>
                    <dd className="font-mono">{e.signature.slice(0, 24)}…</dd>
                  </>
                )}
              </dl>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
