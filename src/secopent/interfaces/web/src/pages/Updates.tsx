import { useTranslation } from "react-i18next";
import { useActiveBundle, useAuditVerify } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// The 5 knowledge-layer health detectors (§7.3). Live status requires the real
// infrastructure checkers (git freshness / OSV reachability / signature state),
// which land with the execution layer (P2); shown as "not wired" until then.
const DETECTORS = [
  { key: "source_stale", label: "Source stale", desc: "nuclei-templates with no commit for 7+ days" },
  { key: "curation_lag", label: "Curation lag", desc: "100+ new upstream tags unmapped in TestCatalog" },
  { key: "coverage_regression", label: "Coverage regression", desc: "new coverage rate below the previous version" },
  { key: "source_unreachable", label: "Source unreachable", desc: "OSV API down - degraded to cache" },
  { key: "signature_invalid", label: "Signature invalid", desc: "bundle signature verification failed" },
];

export function Updates() {
  const { t } = useTranslation();
  const active = useActiveBundle();
  const verify = useAuditVerify();
  const bundle = active.data?.data?.bundle ?? null;
  const chain = verify.data?.data ?? null;

  return (
    <div className="flex flex-col gap-6 p-6">
      <h1 className="text-2xl font-semibold tracking-tight">{t("pages.updates.title")}</h1>

      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Active Knowledge Bundle</CardTitle>
            <CardDescription>Currently activated update bundle</CardDescription>
          </CardHeader>
          <CardContent>
            {bundle ? (
              <dl className="grid grid-cols-[100px_1fr] gap-y-1 text-sm">
                <dt className="text-muted-foreground">Version</dt>
                <dd className="font-mono">{bundle.version}</dd>
                <dt className="text-muted-foreground">Digest</dt>
                <dd className="font-mono">{bundle.digest.slice(0, 24)}…</dd>
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">No active bundle.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Audit Chain</CardTitle>
            <CardDescription>Tamper-evident hash chain integrity</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center gap-3">
            {chain && (
              <>
                <Badge variant={chain.valid ? "default" : "destructive"}>
                  {chain.valid ? "valid" : "broken"}
                </Badge>
                <span className="text-sm text-muted-foreground">
                  {chain.event_count} events
                </span>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="flex flex-col gap-2">
        <h2 className="text-lg font-medium">Knowledge Health Detectors</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {DETECTORS.map((d) => (
            <Card key={d.key}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">{d.label}</CardTitle>
                  <Badge variant="secondary">not wired</Badge>
                </div>
                <CardDescription>{d.desc}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          Detector status lights activate once the real checkers land with the
          execution layer (P2).
        </p>
      </div>
    </div>
  );
}
