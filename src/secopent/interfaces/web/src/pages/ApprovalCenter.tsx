import { useState } from "react";
import {
  useApprovalHistory,
  useCreateApproval,
  usePendingApprovals,
  useRejectApproval,
} from "@/api/hooks";
import type { components } from "@/api/generated";
import { Button } from "@/components/ui/button";
import {
  Drawer,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
} from "@/components/ui/drawer";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { DataTable, type Column } from "@/components/shared/DataTable";
import { StatusBadge } from "@/components/shared/StatusBadge";

type Pending = components["schemas"]["ApprovalRequestOut"];
type Decision = components["schemas"]["ApprovalDecisionOut"];

const RISK_CLASSES = ["passive", "low", "active", "intrusive", "destructive"];

export function ApprovalCenter() {
  const pending = usePendingApprovals();
  const history = useApprovalHistory();
  const approve = useCreateApproval();
  const reject = useRejectApproval();

  const [selected, setSelected] = useState<Pending | null>(null);
  const [approvedBy, setApprovedBy] = useState("analyst");
  const [risks, setRisks] = useState<string[]>(["low", "active"]);
  const [capabilityInput, setCapabilityInput] = useState("");
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [rejectReason, setRejectReason] = useState("");

  const pendingList = pending.data?.data ?? [];
  const historyList = history.data?.data ?? [];

  const closeDrawer = () => {
    setSelected(null);
    setRejectReason("");
    setCapabilities([]);
    setCapabilityInput("");
  };

  const handleApprove = async () => {
    if (!selected) return;
    await approve.mutateAsync({
      assessment_id: selected.assessment_id,
      approved_by: approvedBy,
      approved_risks: risks,
      approved_capabilities: capabilities,
    });
    closeDrawer();
  };

  const handleReject = async () => {
    if (!selected || !rejectReason.trim()) return;
    await reject.mutateAsync({
      assessment_id: selected.assessment_id,
      rejected_by: approvedBy,
      reason: rejectReason.trim(),
    });
    closeDrawer();
  };

  const pendingColumns: Column<Pending>[] = [
    { key: "assessment_id", header: "Assessment", sortValue: (p) => p.assessment_id },
    { key: "project_id", header: "Project", sortValue: (p) => p.project_id },
    { key: "mode", header: "Mode", sortValue: (p) => p.mode },
    {
      key: "plan_digest",
      header: "Plan digest",
      render: (p) => (
        <span className="font-mono text-xs">
          {p.plan_digest ? `${p.plan_digest.slice(0, 12)}…` : "—"}
        </span>
      ),
    },
  ];

  const historyColumns: Column<Decision>[] = [
    { key: "assessment_id", header: "Assessment", sortValue: (d) => d.assessment_id },
    {
      key: "decision",
      header: "Decision",
      sortValue: (d) => d.decision,
      render: (d) => <StatusBadge status={d.decision} />,
    },
    { key: "decided_by", header: "By", sortValue: (d) => d.decided_by },
    { key: "reason", header: "Reason", render: (d) => d.reason || "—" },
  ];

  return (
    <div className="flex flex-col gap-4 p-6">
      <h1 className="text-2xl font-semibold tracking-tight">Approval Center</h1>

      <Tabs defaultValue="pending">
        <TabsList>
          <TabsTrigger value="pending">Pending ({pendingList.length})</TabsTrigger>
          <TabsTrigger value="history">History ({historyList.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="pending" className="mt-4">
          <DataTable
            data={pendingList}
            columns={pendingColumns}
            rowKey={(p) => p.assessment_id}
            onRowClick={setSelected}
            emptyMessage="No assessments awaiting approval."
          />
        </TabsContent>
        <TabsContent value="history" className="mt-4">
          <DataTable
            data={historyList}
            columns={historyColumns}
            rowKey={(d) => `${d.assessment_id}-${d.decision}`}
            emptyMessage="No decisions recorded yet."
          />
        </TabsContent>
      </Tabs>

      <Drawer open={selected !== null} onOpenChange={(open) => !open && closeDrawer()}>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Approve assessment {selected?.assessment_id}</DrawerTitle>
          </DrawerHeader>
          {selected && (
            <div className="flex flex-col gap-4 px-4 pb-6">
              <dl className="grid grid-cols-[120px_1fr] gap-y-1 text-sm">
                <dt className="text-muted-foreground">Plan digest</dt>
                <dd className="font-mono">{selected.plan_digest ?? "—"}</dd>
                <dt className="text-muted-foreground">Scope digest</dt>
                <dd className="font-mono">{selected.scope_digest ?? "—"}</dd>
                <dt className="text-muted-foreground">Mode</dt>
                <dd>{selected.mode}</dd>
              </dl>

              <div className="flex flex-col gap-2">
                <Label>Decided by</Label>
                <Input
                  value={approvedBy}
                  onChange={(e) => setApprovedBy(e.target.value)}
                  className="w-56"
                />
              </div>

              <div className="flex flex-col gap-2">
                <Label>Approve risk classes</Label>
                <div className="flex flex-wrap gap-2">
                  {RISK_CLASSES.map((r) => (
                    <Button
                      key={r}
                      variant={risks.includes(r) ? "default" : "outline"}
                      size="sm"
                      onClick={() =>
                        setRisks((prev) =>
                          prev.includes(r) ? prev.filter((x) => x !== r) : [...prev, r],
                        )
                      }
                    >
                      {r}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="flex items-end gap-2">
                <div className="flex flex-col gap-2">
                  <Label>Capabilities</Label>
                  <Input
                    value={capabilityInput}
                    onChange={(e) => setCapabilityInput(e.target.value)}
                    placeholder="e.g. network.scan"
                    className="w-56"
                  />
                </div>
                <Button
                  variant="outline"
                  onClick={() => {
                    const cap = capabilityInput.trim();
                    if (cap && !capabilities.includes(cap)) {
                      setCapabilities((prev) => [...prev, cap]);
                    }
                    setCapabilityInput("");
                  }}
                >
                  Add
                </Button>
              </div>
              {capabilities.length > 0 && (
                <p className="text-sm text-muted-foreground">{capabilities.join(", ")}</p>
              )}

              <div className="flex flex-col gap-2">
                <Label>Reject reason (if rejecting)</Label>
                <Textarea
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  rows={2}
                />
              </div>

              <div className="flex gap-2">
                <Button onClick={handleApprove}>Approve</Button>
                <Button
                  variant="destructive"
                  disabled={!rejectReason.trim()}
                  onClick={handleReject}
                >
                  Reject
                </Button>
              </div>
            </div>
          )}
        </DrawerContent>
      </Drawer>
    </div>
  );
}
