import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { WorkingModel } from "./types";

interface PropertyPanelProps {
  model: WorkingModel;
  onChange: (model: WorkingModel) => void;
  selectedNodeId: string | null;
  selectedType: "state" | "transition" | null;
}

function nextId(prefix: string, existing: string[]): string {
  const max = existing.reduce((acc, id) => {
    const n = Number(id.replace(/\D/g, ""));
    return Number.isFinite(n) ? Math.max(acc, n) : acc;
  }, 0);
  return `${prefix}${max + 1}`;
}

export function PropertyPanel({
  model,
  onChange,
  selectedNodeId,
  selectedType,
}: PropertyPanelProps) {
  const [invariantExpr, setInvariantExpr] = useState("");
  const [fieldName, setFieldName] = useState("");
  const [fieldType, setFieldType] = useState("int");
  const [fieldRange, setFieldRange] = useState("");
  const [fieldSource, setFieldSource] = useState("client");
  const [roleId, setRoleId] = useState("");
  const [roleCaps, setRoleCaps] = useState("");
  const [rule, setRule] = useState("");

  const selectedTransition =
    selectedType === "transition"
      ? model.transitions.find((t) => t.id === selectedNodeId)
      : undefined;

  const renameState = (oldName: string, newName: string) => {
    const name = newName.trim();
    if (!name || name === oldName || model.states.includes(name)) return;
    onChange({
      ...model,
      states: model.states.map((s) => (s === oldName ? name : s)),
      transitions: model.transitions.map((t) => ({
        ...t,
        from_state: t.from_state === oldName ? name : t.from_state,
        to_state: t.to_state === oldName ? name : t.to_state,
      })),
    });
  };

  const updateTransition = (id: string, patch: Partial<WorkingModel["transitions"][number]>) => {
    onChange({
      ...model,
      transitions: model.transitions.map((t) => (t.id === id ? { ...t, ...patch } : t)),
    });
  };

  return (
    <Tabs defaultValue="properties" className="flex h-full flex-col">
      <TabsList className="grid w-full grid-cols-5">
        <TabsTrigger value="properties">Props</TabsTrigger>
        <TabsTrigger value="invariants">Invar.</TabsTrigger>
        <TabsTrigger value="fields">Fields</TabsTrigger>
        <TabsTrigger value="roles">Roles</TabsTrigger>
        <TabsTrigger value="oos">OoS</TabsTrigger>
      </TabsList>

      <TabsContent value="properties" className="flex flex-col gap-3 pt-3">
        {selectedType === "state" && selectedNodeId && (
          <div className="flex flex-col gap-2">
            <Label>State name (rename)</Label>
            <RenameInput
              key={selectedNodeId}
              initial={selectedNodeId}
              onRename={(name) => renameState(selectedNodeId, name)}
            />
            <p className="text-xs text-muted-foreground">
              Transitions touching this state:{" "}
              {model.transitions.filter(
                (t) => t.from_state === selectedNodeId || t.to_state === selectedNodeId,
              ).length}
            </p>
          </div>
        )}
        {selectedType === "transition" && selectedTransition && (
          <div className="flex flex-col gap-3">
            <p className="text-xs text-muted-foreground">
              {selectedTransition.from_state} → {selectedTransition.to_state}
            </p>
            <div className="flex flex-col gap-2">
              <Label>Endpoint</Label>
              <Input
                value={selectedTransition.endpoint}
                onChange={(e) =>
                  updateTransition(selectedTransition.id, { endpoint: e.target.value })
                }
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label>Params (comma-separated)</Label>
              <Input
                value={selectedTransition.params.join(", ")}
                onChange={(e) =>
                  updateTransition(selectedTransition.id, {
                    params: e.target.value.split(",").map((p) => p.trim()).filter(Boolean),
                  })
                }
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={selectedTransition.idempotent}
                onChange={(e) =>
                  updateTransition(selectedTransition.id, { idempotent: e.target.checked })
                }
              />
              Idempotent
            </label>
          </div>
        )}
        {!selectedNodeId && (
          <p className="text-sm text-muted-foreground">
            Select a state or transition in the editor to edit its properties.
          </p>
        )}
      </TabsContent>

      <TabsContent value="invariants" className="flex flex-col gap-3 pt-3">
        <ul className="flex flex-col gap-1">
          {model.invariants.map((inv) => (
            <li key={inv.id} className="flex items-center justify-between gap-2 text-sm">
              <span className="font-mono">{inv.expr}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  onChange({
                    ...model,
                    invariants: model.invariants.filter((i) => i.id !== inv.id),
                  })
                }
              >
                ✕
              </Button>
            </li>
          ))}
        </ul>
        <div className="flex items-end gap-2">
          <div className="flex flex-1 flex-col gap-2">
            <Label>Add invariant</Label>
            <Input
              value={invariantExpr}
              onChange={(e) => setInvariantExpr(e.target.value)}
              placeholder="e.g. cart.total >= 0"
            />
          </div>
          <Button
            onClick={() => {
              const expr = invariantExpr.trim();
              if (!expr) return;
              onChange({
                ...model,
                invariants: [
                  ...model.invariants,
                  { id: nextId("inv", model.invariants.map((i) => i.id)), expr },
                ],
              });
              setInvariantExpr("");
            }}
          >
            Add
          </Button>
        </div>
      </TabsContent>

      <TabsContent value="fields" className="flex flex-col gap-3 pt-3">
        <ul className="flex flex-col gap-1">
          {model.fields.map((f) => (
            <li key={f.name} className="flex items-center justify-between gap-2 text-sm">
              <span>
                <span className="font-mono">{f.name}</span>
                <span className="text-muted-foreground"> : {f.type}</span>
                {f.range && (
                  <span className="text-muted-foreground"> [{String(f.range[0])}..{String(f.range[1])}]</span>
                )}
                <span className="text-muted-foreground"> ({f.trusted_source})</span>
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  onChange({ ...model, fields: model.fields.filter((x) => x.name !== f.name) })
                }
              >
                ✕
              </Button>
            </li>
          ))}
        </ul>
        <div className="grid grid-cols-2 gap-2">
          <Input value={fieldName} onChange={(e) => setFieldName(e.target.value)} placeholder="name" />
          <Input value={fieldType} onChange={(e) => setFieldType(e.target.value)} placeholder="type (int/str)" />
          <Input value={fieldRange} onChange={(e) => setFieldRange(e.target.value)} placeholder="range min,max" />
          <Select value={fieldSource} onValueChange={(v) => setFieldSource(v ?? "client")}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="client">client</SelectItem>
              <SelectItem value="server">server</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button
          onClick={() => {
            const name = fieldName.trim();
            if (!name || model.fields.some((f) => f.name === name)) return;
            const rangeParts = fieldRange.split(",").map((p) => Number(p.trim()));
            const range =
              rangeParts.length === 2 && rangeParts.every((n) => Number.isFinite(n))
                ? rangeParts
                : null;
            onChange({
              ...model,
              fields: [
                ...model.fields,
                { name, type: fieldType.trim() || "str", range, trusted_source: fieldSource },
              ],
            });
            setFieldName("");
            setFieldRange("");
          }}
        >
          Add field
        </Button>
      </TabsContent>

      <TabsContent value="roles" className="flex flex-col gap-3 pt-3">
        <ul className="flex flex-col gap-1">
          {model.roles.map((r) => (
            <li key={r.id} className="flex items-center justify-between gap-2 text-sm">
              <span>
                <span className="font-mono">{r.id}</span>
                <span className="text-muted-foreground"> [{r.capabilities.join(", ")}]</span>
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  onChange({ ...model, roles: model.roles.filter((x) => x.id !== r.id) })
                }
              >
                ✕
              </Button>
            </li>
          ))}
        </ul>
        <div className="flex flex-col gap-2">
          <Input value={roleId} onChange={(e) => setRoleId(e.target.value)} placeholder="role id (e.g. buyer)" />
          <Input
            value={roleCaps}
            onChange={(e) => setRoleCaps(e.target.value)}
            placeholder="capabilities (comma-separated)"
          />
        </div>
        <Button
          onClick={() => {
            const id = roleId.trim();
            if (!id || model.roles.some((r) => r.id === id)) return;
            onChange({
              ...model,
              roles: [
                ...model.roles,
                {
                  id,
                  capabilities: roleCaps.split(",").map((c) => c.trim()).filter(Boolean),
                },
              ],
            });
            setRoleId("");
            setRoleCaps("");
          }}
        >
          Add role
        </Button>
      </TabsContent>

      <TabsContent value="oos" className="flex flex-col gap-3 pt-3">
        <p className="text-xs text-muted-foreground">
          Complex rules declared out of scope (skipped by test generation, marked
          in coverage).
        </p>
        <ul className="flex flex-col gap-1">
          {model.out_of_scope_rules.map((r, i) => (
            <li key={i} className="flex items-center justify-between gap-2 text-sm">
              <span>{r}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  onChange({
                    ...model,
                    out_of_scope_rules: model.out_of_scope_rules.filter((_, j) => j !== i),
                  })
                }
              >
                ✕
              </Button>
            </li>
          ))}
        </ul>
        <div className="flex items-end gap-2">
          <Input value={rule} onChange={(e) => setRule(e.target.value)} placeholder="out-of-scope rule" />
          <Button
            onClick={() => {
              const text = rule.trim();
              if (!text) return;
              onChange({ ...model, out_of_scope_rules: [...model.out_of_scope_rules, text] });
              setRule("");
            }}
          >
            Add
          </Button>
        </div>
      </TabsContent>
    </Tabs>
  );
}

function RenameInput({ initial, onRename }: { initial: string; onRename: (name: string) => void }) {
  const [value, setValue] = useState(initial);
  return (
    <Input
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onBlur={() => onRename(value)}
    />
  );
}
