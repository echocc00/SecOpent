// Drift detection (v0.5.0 Phase 3, 3.3): diffs a re-imported model against
// the stored AppModel and renders endpoint-level drift (added / removed /
// changed) so affected logic tests can be regenerated.
import { useState } from "react";
import type { components } from "@/api/generated";
import { useCheckDrift } from "@/api/hooks";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

type DriftReport = components["schemas"]["DriftReportOut"];
type TransitionIn = components["schemas"]["TransitionIn"];

const STATES_PLACEHOLDER = `One state per line, e.g.
start
logged_in
cart_has_items`;

const TRANSITIONS_PLACEHOLDER = `CSV - one per line: id,from_state,to_state,endpoint[,params(; separated)[,idempotent]]
t_login,start,logged_in,POST /rest/user/login,password;email
t_add_cart,logged_in,cart_has_items,POST /api/BasketItems,,false`;

function parseStates(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function parseTransitions(text: string): {
  transitions: TransitionIn[];
  error: string | null;
} {
  const transitions: TransitionIn[] = [];
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  for (const [index, line] of lines.entries()) {
    const cols = line.split(",").map((col) => col.trim());
    if (cols.length < 4) {
      return {
        transitions: [],
        error: `Transition line ${index + 1} needs at least 4 CSV columns (id,from_state,to_state,endpoint): "${line}"`,
      };
    }
    const [id, fromState, toState, endpoint, params, idempotent] = cols;
    transitions.push({
      id,
      from_state: fromState,
      to_state: toState,
      endpoint,
      params: params
        ? params.split(";").map((p) => p.trim()).filter(Boolean)
        : [],
      idempotent: idempotent === "true",
    });
  }
  return { transitions, error: null };
}

function DriftColumn({
  title,
  items,
  tone,
  emptyHint,
}: {
  title: string;
  items: string[];
  tone: "added" | "removed" | "changed";
  emptyHint: string;
}) {
  const toneClasses = {
    added: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200",
    removed: "border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200",
    changed: "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200",
  } as const;
  return (
    <div className={`flex min-h-40 flex-1 flex-col rounded-md border p-3 ${toneClasses[tone]}`}>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-sm font-semibold">{title}</span>
        <span className="rounded-full border px-2 py-0.5 font-mono text-xs">
          {items.length}
        </span>
      </div>
      {items.length === 0 ? (
        <p className="text-xs opacity-70">{emptyHint}</p>
      ) : (
        <ul className="flex flex-col gap-1 overflow-auto">
          {items.map((item) => (
            <li key={item} className="break-all rounded bg-white/50 font-mono text-xs dark:bg-black/20">
              {item}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function DriftView({ appId, version }: { appId: string; version: string }) {
  const [statesText, setStatesText] = useState("");
  const [transitionsText, setTransitionsText] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [report, setReport] = useState<DriftReport | null>(null);
  const checkDrift = useCheckDrift();

  const handleDetect = async () => {
    setMessage(null);
    setReport(null);
    const { transitions, error } = parseTransitions(transitionsText);
    if (error) {
      setMessage(error);
      return;
    }
    const res = await checkDrift.mutateAsync({
      app_id: appId,
      version,
      body: { states: parseStates(statesText), transitions },
    });
    if (res.data) {
      setReport(res.data);
    } else {
      setMessage("Drift check failed (does this model version exist?).");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        Paste the re-imported model (e.g. from a fresh OpenAPI/Postman import)
        to diff it against{" "}
        <span className="font-mono">
          {appId}@{version}
        </span>
        . Endpoint drift highlights which logic tests need regenerating.
      </p>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-2">
          <Label htmlFor="drift-states">States</Label>
          <Textarea
            id="drift-states"
            rows={7}
            value={statesText}
            onChange={(e) => setStatesText(e.target.value)}
            placeholder={STATES_PLACEHOLDER}
            className="font-mono text-xs"
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="drift-transitions">Transitions</Label>
          <Textarea
            id="drift-transitions"
            rows={7}
            value={transitionsText}
            onChange={(e) => setTransitionsText(e.target.value)}
            placeholder={TRANSITIONS_PLACEHOLDER}
            className="font-mono text-xs"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Button
          size="sm"
          onClick={handleDetect}
          disabled={checkDrift.isPending || (!statesText.trim() && !transitionsText.trim())}
        >
          {checkDrift.isPending ? "Checking..." : "Detect drift"}
        </Button>
        {message && <span className="text-xs text-red-600">{message}</span>}
        {report && !report.has_drift && (
          <span className="text-xs text-emerald-600">No drift detected.</span>
        )}
      </div>

      {report && report.has_drift && (
        <div className="flex flex-col gap-3 md:flex-row">
          <DriftColumn
            title="Added"
            items={report.added}
            tone="added"
            emptyHint="Nothing added."
          />
          <DriftColumn
            title="Removed"
            items={report.removed}
            tone="removed"
            emptyHint="Nothing removed."
          />
          <DriftColumn
            title="Changed"
            items={report.changed}
            tone="changed"
            emptyHint="Nothing changed."
          />
        </div>
      )}
    </div>
  );
}
