import { useMemo, useState } from "react";
import {
  Background,
  Controls,
  MarkerType,
  ReactFlow,
  type Connection,
  type Edge,
  type Node,
} from "@xyflow/react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { WorkingModel } from "./types";

interface AppModelEditorProps {
  model: WorkingModel;
  onChange: (model: WorkingModel) => void;
  selectedNodeId: string | null;
  selectedType: "state" | "transition" | null;
  onSelectNode: (id: string | null, type: "state" | "transition" | null) => void;
}

// Simple layered layout (depth = longest path from roots); avoids a
// graph-layout dependency. Positions are display-only (not persisted).
function layout(states: string[], model: WorkingModel): Record<string, { x: number; y: number }> {
  const incoming = new Map<string, string[]>();
  states.forEach((s) => incoming.set(s, []));
  model.transitions.forEach((t) => {
    if (incoming.has(t.to_state)) incoming.get(t.to_state)!.push(t.from_state);
  });
  const depth = new Map<string, number>();
  const compute = (id: string, visiting: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (visiting.has(id)) return 0;
    visiting.add(id);
    const parents = incoming.get(id) ?? [];
    const d = parents.length === 0 ? 0 : Math.max(...parents.map((p) => compute(p, visiting) + 1));
    depth.set(id, d);
    return d;
  };
  states.forEach((s) => compute(s, new Set()));
  const byDepth = new Map<number, string[]>();
  states.forEach((s) => {
    const d = depth.get(s) ?? 0;
    if (!byDepth.has(d)) byDepth.set(d, []);
    byDepth.get(d)!.push(s);
  });
  const positions: Record<string, { x: number; y: number }> = {};
  byDepth.forEach((ids, d) => ids.forEach((id, i) => (positions[id] = { x: d * 240, y: i * 110 })));
  return positions;
}

function nextTransitionId(model: WorkingModel): string {
  const max = model.transitions.reduce((acc, t) => {
    const n = Number(t.id.replace(/\D/g, ""));
    return Number.isFinite(n) ? Math.max(acc, n) : acc;
  }, 0);
  return `t${max + 1}`;
}

export function AppModelEditor({
  model,
  onChange,
  selectedNodeId,
  selectedType,
  onSelectNode,
}: AppModelEditorProps) {
  const [stateDialogOpen, setStateDialogOpen] = useState(false);
  const [newStateName, setNewStateName] = useState("");
  const [pendingEdge, setPendingEdge] = useState<{ source: string; target: string } | null>(null);
  const [edgeEndpoint, setEdgeEndpoint] = useState("");
  const [edgeParams, setEdgeParams] = useState("");
  const [edgeIdempotent, setEdgeIdempotent] = useState(false);

  const positions = useMemo(() => layout(model.states, model), [model]);

  const flowNodes: Node[] = model.states.map((s) => ({
    id: s,
    position: positions[s] ?? { x: 0, y: 0 },
    data: { label: s },
    style: {
      background: selectedType === "state" && selectedNodeId === s ? "#2563eb" : "#475569",
      color: "#fff",
      borderRadius: 8,
      padding: "8px 14px",
      fontSize: 13,
      border: "1px solid rgba(0,0,0,0.2)",
    },
  }));

  const flowEdges: Edge[] = model.transitions.map((t) => ({
    id: t.id,
    source: t.from_state,
    target: t.to_state,
    label: t.endpoint,
    markerEnd: { type: MarkerType.ArrowClosed },
    style: { stroke: selectedType === "transition" && selectedNodeId === t.id ? "#2563eb" : "#94a3b8", strokeWidth: 2 },
  }));

  const addState = () => {
    const name = newStateName.trim();
    if (name && !model.states.includes(name)) {
      onChange({ ...model, states: [...model.states, name] });
    }
    setNewStateName("");
    setStateDialogOpen(false);
  };

  const deleteSelected = () => {
    if (selectedType === "state" && selectedNodeId) {
      onChange({
        ...model,
        states: model.states.filter((s) => s !== selectedNodeId),
        transitions: model.transitions.filter(
          (t) => t.from_state !== selectedNodeId && t.to_state !== selectedNodeId,
        ),
      });
    } else if (selectedType === "transition" && selectedNodeId) {
      onChange({
        ...model,
        transitions: model.transitions.filter((t) => t.id !== selectedNodeId),
      });
    }
    onSelectNode(null, null);
  };

  const handleConnect = (connection: Connection) => {
    if (connection.source && connection.target && connection.source !== connection.target) {
      setPendingEdge({ source: connection.source, target: connection.target });
      setEdgeEndpoint("");
      setEdgeParams("");
      setEdgeIdempotent(false);
    }
  };

  const addTransition = () => {
    if (!pendingEdge || !edgeEndpoint.trim()) return;
    const transition = {
      id: nextTransitionId(model),
      from_state: pendingEdge.source,
      to_state: pendingEdge.target,
      endpoint: edgeEndpoint.trim(),
      params: edgeParams.split(",").map((p) => p.trim()).filter(Boolean),
      idempotent: edgeIdempotent,
    };
    onChange({ ...model, transitions: [...model.transitions, transition] });
    setPendingEdge(null);
  };

  return (
    <div className="flex h-[520px] flex-col gap-2">
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" onClick={() => setStateDialogOpen(true)}>
          + State
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={!selectedNodeId}
          onClick={deleteSelected}
        >
          Delete selected
        </Button>
        <span className="text-xs text-muted-foreground">
          Drag between two states to create a transition.
        </span>
      </div>

      <div className="flex-1 rounded-md border">
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          fitView
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_, node) => onSelectNode(node.id, "state")}
          onEdgeClick={(_, edge) => onSelectNode(edge.id, "transition")}
          onPaneClick={() => onSelectNode(null, null)}
          onConnect={handleConnect}
        >
          <Background />
          <Controls />
        </ReactFlow>
      </div>

      <Dialog open={stateDialogOpen} onOpenChange={setStateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New state</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            <Label>State name</Label>
            <Input
              value={newStateName}
              onChange={(e) => setNewStateName(e.target.value)}
              placeholder="e.g. cart_has_items"
            />
          </div>
          <DialogFooter>
            <Button onClick={addState}>Add</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pendingEdge !== null} onOpenChange={(o) => !o && setPendingEdge(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              New transition {pendingEdge && `(${pendingEdge.source} → ${pendingEdge.target})`}
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-2">
              <Label>Endpoint</Label>
              <Input
                value={edgeEndpoint}
                onChange={(e) => setEdgeEndpoint(e.target.value)}
                placeholder="e.g. POST /cart/add"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label>Params (comma-separated)</Label>
              <Input
                value={edgeParams}
                onChange={(e) => setEdgeParams(e.target.value)}
                placeholder="item_id, quantity"
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={edgeIdempotent}
                onChange={(e) => setEdgeIdempotent(e.target.checked)}
              />
              Idempotent
            </label>
          </div>
          <DialogFooter>
            <Button onClick={addTransition}>Add transition</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
