import { useEffect, useState } from "react";
import Editor, { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor/editor/editor.api";
import editorWorker from "monaco-editor/editor/editor.worker?worker";
import {
  useAnalyzeCase,
  useCases,
  usePublishCase,
  useUpdateCaseYaml,
  useValidateCase,
} from "@/api/hooks";
import type { components } from "@/api/generated";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// Use the locally bundled monaco (not the CDN default): the editor worker runs
// from a bundled worker chunk, so the YAML editor works offline (W11).
(self as unknown as { MonacoEnvironment: { getWorker: () => Worker } }).MonacoEnvironment =
  {
    getWorker: () => new editorWorker(),
  };
loader.config({ monaco });

type Analysis = components["schemas"]["CaseAnalysisOut"];

export function YamlEditor() {
  const cases = useCases();
  const list = cases.data?.data ?? [];
  const [caseId, setCaseId] = useState("");
  const [yaml, setYaml] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [message, setMessage] = useState("");

  const update = useUpdateCaseYaml();
  const analyze = useAnalyzeCase();
  const validate = useValidateCase();
  const publish = usePublishCase();

  const selected = list.find((c) => c.id === caseId);

  useEffect(() => {
    setYaml(selected?.yaml ?? "");
    setAnalysis(null);
    setMessage("");
  }, [caseId, selected?.yaml]);

  const handleSave = async () => {
    const res = await update.mutateAsync({ case_id: caseId, body: { yaml } });
    setMessage(res.error ? "Save failed (case may be signed/published)." : "YAML saved.");
  };

  const handleAnalyze = async () => {
    const res = await analyze.mutateAsync(caseId);
    setAnalysis(res.data ?? null);
  };

  const handleValidate = async () => {
    const res = await validate.mutateAsync({ case_id: caseId });
    setMessage(res.error ? "Validation failed (risk gate)." : "Case validated (DRAFT → VALIDATED).");
  };

  const handlePublish = async () => {
    const res = await publish.mutateAsync({ case_id: caseId, body: { actor_role: "human" } });
    setMessage(res.error ? "Publish failed (must be signed)." : "Case published.");
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <Select value={caseId} onValueChange={(v) => setCaseId(v ?? "")}>
          <SelectTrigger className="w-72" aria-label="Select a case">
            <SelectValue placeholder="Select a case" />
          </SelectTrigger>
          <SelectContent>
            {list.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.id} ({c.status})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground">
          Edit the case YAML, analyze risk, validate, then publish (human).
        </span>
      </div>

      <div className="h-72 overflow-hidden rounded-md border">
        <Editor
          height="100%"
          language="yaml"
          value={yaml}
          onChange={(v) => setYaml(v ?? "")}
          options={{ minimap: { enabled: false }, wordWrap: "on", fontSize: 13 }}
        />
      </div>

      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={!caseId} onClick={handleSave}>
          Save YAML
        </Button>
        <Button variant="outline" disabled={!caseId} onClick={handleAnalyze}>
          Analyze risk
        </Button>
        <Button variant="outline" disabled={!caseId} onClick={handleValidate}>
          Validate
        </Button>
        <Button disabled={!caseId} onClick={handlePublish}>
          Publish
        </Button>
      </div>

      {message && <p className="text-sm text-muted-foreground">{message}</p>}

      {analysis && (
        <div className="flex flex-col gap-2 rounded-md border p-3 text-sm">
          <div className="flex items-center gap-3">
            <span>
              Declared risk: <Badge variant="outline">{analysis.declared_risk}</Badge>
            </span>
            <span>
              Computed risk:{" "}
              <Badge variant="outline">{analysis.computed_risk ?? "denied"}</Badge>
            </span>
            {analysis.denied ? (
              <Badge variant="destructive">deny-listed pattern</Badge>
            ) : analysis.risk_ok ? (
              <Badge>risk ok</Badge>
            ) : (
              <Badge variant="destructive">declared &lt; computed</Badge>
            )}
          </div>
          {analysis.errors.length > 0 && (
            <ul className="list-inside list-disc text-destructive">
              {analysis.errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
