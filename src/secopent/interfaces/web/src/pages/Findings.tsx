import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useFindings } from "@/api/hooks";
import type { components } from "@/api/generated";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Drawer,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
} from "@/components/ui/drawer";
import { DataTable, type Column } from "@/components/shared/DataTable";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EvidenceViewer } from "@/components/shared/EvidenceViewer";

type Finding = components["schemas"]["FindingOut"];

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const VERDICTS = ["pending", "confirmed", "refuted", "inconclusive"];

export function Findings() {
  const { t } = useTranslation();
  const [severity, setSeverity] = useState("");
  const [verdict, setVerdict] = useState("");
  const [assetQuery, setAssetQuery] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);

  // severity + oracle verdict filter server-side; asset text filters client-side.
  const { data } = useFindings({
    severity: severity || undefined,
    oracle_verdict: verdict || undefined,
  });
  const findings = useMemo(() => {
    const list = data?.data ?? [];
    const q = assetQuery.trim().toLowerCase();
    if (!q) return list;
    return list.filter((f) => f.asset.toLowerCase().includes(q));
  }, [data, assetQuery]);

  const columns: Column<Finding>[] = [
    {
      key: "severity",
      header: "Severity",
      sortValue: (f) => f.severity,
      render: (f) => <SeverityBadge severity={f.severity} />,
    },
    { key: "title", header: "Title", sortValue: (f) => f.title },
    { key: "asset", header: "Asset", sortValue: (f) => f.asset },
    { key: "cwe", header: "CWE", render: (f) => f.cwe.join(", ") },
    {
      key: "oracle_verdict",
      header: "Oracle",
      sortValue: (f) => f.oracle_verdict,
      render: (f) => <StatusBadge status={f.oracle_verdict} />,
    },
  ];

  return (
    <div className="flex flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold tracking-tight">{t("pages.findings.title")}</h1>

      <div className="flex flex-wrap gap-3">
        <Select value={severity} onValueChange={(v) => setSeverity(v ?? "")}>
          <SelectTrigger className="w-40" aria-label="Filter by severity">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={verdict} onValueChange={(v) => setVerdict(v ?? "")}>
          <SelectTrigger className="w-44" aria-label="Filter by oracle verdict">
            <SelectValue placeholder="Oracle verdict" />
          </SelectTrigger>
          <SelectContent>
            {VERDICTS.map((v) => (
              <SelectItem key={v} value={v}>
                {v}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          placeholder="Filter by asset…"
          value={assetQuery}
          onChange={(e) => setAssetQuery(e.target.value)}
          className="w-64"
        />
      </div>

      <DataTable
        data={findings}
        columns={columns}
        rowKey={(f) => f.id}
        onRowClick={setSelected}
        emptyMessage="No findings match the current filters."
      />

      <Drawer
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>{selected?.title}</DrawerTitle>
          </DrawerHeader>
          {selected && (
            <div className="flex flex-col gap-4 px-4 pb-6">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
                <Meta label="Severity">
                  <SeverityBadge severity={selected.severity} />
                </Meta>
                <Meta label="Oracle verdict">
                  <StatusBadge status={selected.oracle_verdict} />
                </Meta>
                <Meta label="Status">
                  <StatusBadge status={selected.status} />
                </Meta>
                <Meta label="Asset">{selected.asset}</Meta>
                <Meta label="CWE">{selected.cwe.join(", ") || "—"}</Meta>
                <Meta label="CVE">{selected.cve.join(", ") || "—"}</Meta>
                <Meta label="OWASP">{selected.owasp.join(", ") || "—"}</Meta>
                <Meta label="Assessment">{selected.assessment_id || "—"}</Meta>
              </dl>
              <div className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">Evidence</h3>
                <EvidenceViewer findingId={selected.id} />
              </div>
            </div>
          )}
        </DrawerContent>
      </Drawer>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
