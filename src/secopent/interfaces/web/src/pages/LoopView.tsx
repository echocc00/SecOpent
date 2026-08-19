import { useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useQueryClient } from "@tanstack/react-query";
import {
  useLoopStatus,
  usePauseLoop,
  useResumeLoop,
  useStopLoop,
} from "@/api/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/shared/StatusBadge";

// Phases in which each control is meaningful. Stop may kill an initializing,
// running, paused or resumed loop (the REST layer applies the direct
// transition); pause applies to an actively running loop; resume to a paused one.
const STOPPABLE = new Set(["initializing", "running", "paused", "resumed"]);
const PAUSABLE = new Set(["running", "resumed"]);
const RESUMABLE = new Set(["paused"]);

const ACTOR = "web-operator";
const ERR_FALLBACK = "control action failed";

type Notice = { kind: "ok" | "err"; text: string };

export function LoopView({ initialId }: { initialId?: string }) {
  const { t } = useTranslation();
  const { id: routeId } = useParams<{ id: string }>();
  // The route may pin an id (`/loops/:id`); otherwise fall back to an input
  // selector on the landing route (`/loops`).
  const [inputId, setInputId] = useState("");
  const loopId = initialId ?? routeId ?? inputId.trim();

  const queryClient = useQueryClient();
  const { data, isPending, isError, error } = useLoopStatus(loopId);
  const loop = data?.data;

  const stop = useStopLoop();
  const pause = usePauseLoop();
  const resume = useResumeLoop();

  const [notice, setNotice] = useState<Notice | null>(null);
  const refresh = () => {
    if (loopId) queryClient.invalidateQueries({ queryKey: ["loops", loopId] });
  };

  const run = async (fn: () => Promise<{ data?: { phase?: string } }>) => {
    setNotice(null);
    try {
      const result = await fn();
      setNotice({ kind: "ok", text: result.data?.phase ? `phase → ${result.data.phase}` : "ok" });
      refresh();
    } catch {
      setNotice({ kind: "err", text: ERR_FALLBACK });
      refresh();
    }
  };

  const doStop = () =>
    run(() =>
      stop.mutateAsync({
        loop_id: loopId,
        body: { actor: ACTOR, reason: "stopped via web", actor_role: "human" },
      }),
    );

  const doPause = () =>
    run(() =>
      pause.mutateAsync({
        loop_id: loopId,
        body: { actor: ACTOR, reason: "paused via web", actor_role: "human" },
      }),
    );

  const doResume = () =>
    run(() =>
      resume.mutateAsync({
        loop_id: loopId,
        body: { actor: ACTOR, actor_role: "human" },
      }),
    );

  const canStop = !!loop && STOPPABLE.has(loop.phase);
  const canPause = !!loop && PAUSABLE.has(loop.phase);
  const canResume = !!loop && RESUMABLE.has(loop.phase);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{t("pages.loops.title")}</h1>
        {loop && <StatusBadge status={loop.phase} />}
      </div>

      {!loopId ? (
        <div className="flex items-center gap-2">
          <Input
            value={inputId}
            onChange={(e) => setInputId(e.target.value)}
            placeholder="Enter loop id…"
            className="w-72"
            aria-label="Loop id"
          />
        </div>
      ) : (
        <span className="font-mono text-sm text-muted-foreground">{loopId}</span>
      )}

      {loopId && isPending && (
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      )}
      {loopId && isError && (
        <p className="text-sm text-destructive">
          {(error as { error?: { detail?: string } }).error?.detail ??
            "No loop found for this id."}
        </p>
      )}

      {loop && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Info label="Executed steps" value={String(loop.step_count)} />
            <Info label="Steps remaining" value={String(loop.budget_remaining.steps)} />
            <Info label="Tokens remaining" value={String(loop.budget_remaining.tokens)} />
            <Info label="Wall seconds" value={`${loop.budget_remaining.wall_seconds}s`} />
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Context hash
              </CardTitle>
            </CardHeader>
            <CardContent className="font-mono text-sm">{loop.context_hash}</CardContent>
          </Card>

          <div className="flex items-center gap-2">
            <Button
              variant="destructive"
              disabled={!canStop || stop.isPending || pause.isPending || resume.isPending}
              onClick={doStop}
            >
              {stop.isPending ? "Stopping…" : "Stop"}
            </Button>
            <Button
              variant="secondary"
              disabled={!canPause || stop.isPending || pause.isPending || resume.isPending}
              onClick={doPause}
            >
              {pause.isPending ? "Pausing…" : "Pause"}
            </Button>
            <Button
              disabled={!canResume || stop.isPending || pause.isPending || resume.isPending}
              onClick={doResume}
            >
              {resume.isPending ? "Resuming…" : "Resume"}
            </Button>
          </div>

          {notice && (
            <p
              className={
                notice.kind === "ok" ? "text-sm text-green-600" : "text-sm text-destructive"
              }
            >
              {notice.text}
            </p>
          )}

          <p className="text-sm text-muted-foreground">
            Per-step history (action type / tool / oracle progress) is not exposed over the
            REST API — only the executed step count. The control plane drives{" "}
            <code className="font-mono text-xs">/loops/{"{id}"}/stop|pause|resume</code>.
          </p>
        </>
      )}
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-xs font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent className="font-mono text-sm">{value}</CardContent>
    </Card>
  );
}
