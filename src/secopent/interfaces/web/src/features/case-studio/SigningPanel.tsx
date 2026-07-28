import { useState } from "react";
import { useSignAppModel, useSigningKeys, useValidateAppModel } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { StatusBadge } from "@/components/shared/StatusBadge";

interface SigningPanelProps {
  appId: string;
  version: string;
  status: string;
  signature: string | null;
  digest: string;
}

// The signing flow is human-only (LLM boundary): DRAFT/LLM_PROPOSED ->
// HUMAN_VALIDATED -> SIGNED. The private key stays server-side; the user only
// selects which server-held key signs.
export function SigningPanel({ appId, version, status, signature, digest }: SigningPanelProps) {
  const keys = useSigningKeys();
  const validate = useValidateAppModel();
  const sign = useSignAppModel();
  const [keyId, setKeyId] = useState("");
  const [message, setMessage] = useState("");

  const keyList = keys.data?.data ?? [];

  const handleValidate = async () => {
    const res = await validate.mutateAsync({
      app_id: appId,
      version,
      body: { actor_role: "human" },
    });
    setMessage(res.error ? "Validation failed." : "Model human-validated.");
  };

  const handleSign = async () => {
    const res = await sign.mutateAsync({
      app_id: appId,
      version,
      body: { actor_role: "human", key_id: keyId || undefined },
    });
    setMessage(res.error ? "Signing failed." : "Model signed.");
  };

  return (
    <div className="flex max-w-xl flex-col gap-4">
      <div className="flex items-center gap-3 text-sm">
        <span className="text-muted-foreground">Lifecycle:</span>
        <StatusBadge status={status} />
        <span className="font-mono text-xs text-muted-foreground">
          {appId}@{version}
        </span>
      </div>

      <p className="text-xs text-muted-foreground">
        DRAFT / LLM_PROPOSED → human validate → HUMAN_VALIDATED → sign → SIGNED.
        A signed model is immutable; edit it via “revise” (new version).
      </p>

      {(status === "draft" || status === "llm_proposed") && (
        <div className="flex items-center gap-2">
          <Button onClick={handleValidate}>Human validate</Button>
          <span className="text-xs text-muted-foreground">
            Confirm invariants, fields, and trust boundaries.
          </span>
        </div>
      )}

      {status === "human_validated" && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <Select value={keyId} onValueChange={(v) => setKeyId(v ?? "")}>
              <SelectTrigger className="w-72" aria-label="Select signing key">
                <SelectValue placeholder="Signing key (default if unset)" />
              </SelectTrigger>
              <SelectContent>
                {keyList.map((k) => (
                  <SelectItem key={k.key_id} value={k.key_id}>
                    {k.name} ({k.key_id.slice(0, 12)}…)
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button onClick={handleSign}>Sign (Ed25519)</Button>
          </div>
        </div>
      )}

      {status === "signed" && (
        <div className="flex flex-col gap-1 rounded-md border p-3 text-sm">
          <div className="flex items-center gap-2">
            <Badge>signed</Badge>
            <span className="text-muted-foreground">Generate tests in the next tab.</span>
          </div>
          <span className="font-mono text-xs">digest: {digest.slice(0, 32)}…</span>
          {signature && (
            <span className="font-mono text-xs">signature: {signature.slice(0, 32)}…</span>
          )}
        </div>
      )}

      {message && <p className="text-sm text-muted-foreground">{message}</p>}
    </div>
  );
}
