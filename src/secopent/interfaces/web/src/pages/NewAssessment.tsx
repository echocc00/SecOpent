import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  useCreateAssessment,
  useCreateApproval,
  useCreateProject,
  useCreateScope,
  useGeneratePlan,
  useProjects,
} from "@/api/hooks";
import type { components } from "@/api/generated";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { DagView, type DagEdgeInput, type DagNodeInput } from "@/components/shared/DagView";
import { cn } from "@/lib/utils";

type PlanOut = components["schemas"]["PlanOut"];

const RISK_CLASSES = ["passive", "low", "active", "intrusive", "destructive"];
const MODES = [
  { value: "approval", label: "Approval (human approves the plan)" },
  { value: "scope_autopilot", label: "Scope Autopilot" },
];

export function NewAssessment() {
  const navigate = useNavigate();
  const projects = useProjects();
  const createProject = useCreateProject();
  const createScope = useCreateScope();
  const createAssessment = useCreateAssessment();
  const generatePlan = useGeneratePlan();
  const createApproval = useCreateApproval();

  const [step, setStep] = useState(1);
  // Step 1 - project
  const [projectId, setProjectId] = useState("");
  const [newProjectName, setNewProjectName] = useState("");
  // Step 2 - scope draft
  const [include, setInclude] = useState("");
  const [exclude, setExclude] = useState("");
  const [ports, setPorts] = useState("80, 443");
  const [rps, setRps] = useState("5");
  const [concurrency, setConcurrency] = useState("3");
  const [maxRequests, setMaxRequests] = useState("50000");
  // Step 3 - freeze
  const [scopeId, setScopeId] = useState<string | null>(null);
  const [scopeDigest, setScopeDigest] = useState("");
  // Step 4 - mode + approval
  const [mode, setMode] = useState("approval");
  const [risks, setRisks] = useState<string[]>(["low", "active"]);
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [capabilityInput, setCapabilityInput] = useState("");
  // Step 5 - plan
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [plan, setPlan] = useState<PlanOut | null>(null);
  const [error, setError] = useState("");

  const projectList = projects.data?.data ?? [];

  const handleCreateProject = async () => {
    if (!newProjectName.trim()) return;
    const res = await createProject.mutateAsync({ name: newProjectName.trim() });
    if (res.data) setProjectId(res.data.id);
  };

  const handleFreeze = async () => {
    setError("");
    const parsedPorts = ports
      .split(",")
      .map((p) => Number(p.trim()))
      .filter((n) => Number.isFinite(n));
    const res = await createScope.mutateAsync({
      project_id: projectId,
      include: include.split("\n").map((s) => s.trim()).filter(Boolean),
      exclude: exclude.split("\n").map((s) => s.trim()).filter(Boolean),
      ports: parsedPorts,
      approved_by: "analyst",
      requests_per_second: Number(rps),
      concurrency: Number(concurrency),
      max_requests: Number(maxRequests),
    });
    if (res.error) {
      setError("Failed to freeze scope. Check the include targets.");
      return;
    }
    if (res.data) {
      setScopeId(res.data.id);
      setScopeDigest(res.data.digest);
    }
  };

  const handleGeneratePlan = async () => {
    setError("");
    const assessmentRes = await createAssessment.mutateAsync({
      project_id: projectId,
      scope_snapshot_id: scopeId ?? "",
      mode,
    });
    if (assessmentRes.error || !assessmentRes.data) {
      setError("Failed to create the assessment.");
      return;
    }
    const newAssessmentId = assessmentRes.data.id;
    setAssessmentId(newAssessmentId);
    const planRes = await generatePlan.mutateAsync(newAssessmentId);
    if (planRes.error || !planRes.data) {
      setError("No plan could be generated (no test catalog or no required classes).");
      return;
    }
    setPlan(planRes.data);
  };

  const handleApprove = async () => {
    if (!assessmentId) return;
    await createApproval.mutateAsync({
      assessment_id: assessmentId,
      approved_by: "analyst",
      approved_risks: risks,
      approved_capabilities: capabilities,
      actor_role: "human",
    });
    navigate(`/assessments/${assessmentId}`);
  };

  const canNext =
    (step === 1 && projectId !== "") ||
    (step === 2 && include.trim() !== "") ||
    (step === 3 && scopeId !== null) ||
    (step === 4 && mode !== "");

  const dagNodes: DagNodeInput[] =
    plan?.steps.map((s) => ({ id: s.key, label: s.key, status: "pending" })) ?? [];
  const dagEdges: DagEdgeInput[] =
    plan?.steps.flatMap((s) =>
      s.dependencies.map((dep) => ({ source: dep, target: s.key })),
    ) ?? [];

  return (
    <div className="flex flex-col gap-6 p-6">
      <h1 className="text-2xl font-semibold tracking-tight">New Assessment</h1>

      <Stepper step={step} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {["Project", "Scope", "Freeze", "Mode & Approval", "Plan"][step - 1]}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {step === 1 && (
            <>
              <div className="flex flex-col gap-2">
                <Label>Existing project</Label>
                <Select value={projectId} onValueChange={(v) => setProjectId(v ?? "")}>
                  <SelectTrigger className="w-72">
                    <SelectValue placeholder="Select a project" />
                  </SelectTrigger>
                  <SelectContent>
                    {projectList.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-end gap-2">
                <div className="flex flex-col gap-2">
                  <Label>Or create new</Label>
                  <Input
                    value={newProjectName}
                    onChange={(e) => setNewProjectName(e.target.value)}
                    placeholder="Project name"
                    className="w-56"
                  />
                </div>
                <Button variant="outline" onClick={handleCreateProject}>
                  Create
                </Button>
              </div>
            </>
          )}

          {step === 2 && (
            <>
              <div className="flex flex-col gap-2">
                <Label>Include targets (one per line)</Label>
                <Textarea
                  value={include}
                  onChange={(e) => setInclude(e.target.value)}
                  placeholder={"https://juice-shop.test\n10.0.0.0/24"}
                  rows={4}
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label>Exclude targets (one per line)</Label>
                <Textarea
                  value={exclude}
                  onChange={(e) => setExclude(e.target.value)}
                  rows={2}
                />
              </div>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <NumberField label="Ports" value={ports} onChange={setPorts} />
                <NumberField label="Req/sec" value={rps} onChange={setRps} />
                <NumberField label="Concurrency" value={concurrency} onChange={setConcurrency} />
                <NumberField label="Max requests" value={maxRequests} onChange={setMaxRequests} />
              </div>
            </>
          )}

          {step === 3 && (
            <div className="flex flex-col gap-3">
              <p className="text-sm text-muted-foreground">
                Freezing normalizes the targets and produces an immutable scope
                snapshot with a content digest.
              </p>
              <Button onClick={handleFreeze} disabled={scopeId !== null}>
                {scopeId ? "Scope frozen" : "Freeze scope"}
              </Button>
              {scopeId && (
                <div className="text-sm">
                  <span className="text-muted-foreground">Digest: </span>
                  <span className="font-mono">{scopeDigest.slice(0, 24)}…</span>
                </div>
              )}
            </div>
          )}

          {step === 4 && (
            <>
              <div className="flex flex-col gap-2">
                <Label>Execution mode</Label>
                <Select value={mode} onValueChange={(v) => setMode(v ?? "approval")}>
                  <SelectTrigger className="w-80">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {MODES.map((m) => (
                      <SelectItem key={m.value} value={m.value}>
                        {m.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-2">
                <Label>Risk classes to approve</Label>
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
                <p className="text-sm text-muted-foreground">
                  {capabilities.join(", ")}
                </p>
              )}
            </>
          )}

          {step === 5 && (
            <div className="flex flex-col gap-4">
              {!plan ? (
                <Button onClick={handleGeneratePlan}>
                  Create assessment & generate plan
                </Button>
              ) : (
                <>
                  <div className="text-sm">
                    <span className="text-muted-foreground">Plan digest: </span>
                    <span className="font-mono">{plan.digest.slice(0, 24)}…</span>
                    <span className="ml-4 text-muted-foreground">
                      {plan.steps.length} steps
                    </span>
                  </div>
                  <DagView nodes={dagNodes} edges={dagEdges} />
                  <div className="flex gap-2">
                    {mode === "approval" && (
                      <Button onClick={handleApprove}>Approve & finish</Button>
                    )}
                    <Button
                      variant="outline"
                      onClick={() => navigate(`/assessments/${assessmentId}`)}
                    >
                      Finish (leave awaiting approval)
                    </Button>
                  </div>
                </>
              )}
            </div>
          )}

          {error && <p className="text-sm text-destructive">{error}</p>}

          {step < 5 && (
            <div className="flex justify-between">
              <Button
                variant="ghost"
                disabled={step === 1}
                onClick={() => setStep((s) => s - 1)}
              >
                Back
              </Button>
              <Button disabled={!canNext} onClick={() => setStep((s) => s + 1)}>
                Next
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Stepper({ step }: { step: number }) {
  const labels = ["Project", "Scope", "Freeze", "Mode", "Plan"];
  return (
    <div className="flex items-center gap-2">
      {labels.map((label, i) => (
        <div key={label} className="flex items-center gap-2">
          <span
            className={cn(
              "flex h-7 w-7 items-center justify-center rounded-full text-xs font-medium",
              i + 1 <= step
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground",
            )}
          >
            {i + 1}
          </span>
          <span className="text-sm text-muted-foreground">{label}</span>
        </div>
      ))}
    </div>
  );
}

function NumberField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-col gap-2">
      <Label>{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
