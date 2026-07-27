import { useMemo } from "react";
import {
  Background,
  Controls,
  MarkerType,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";

export interface DagNodeInput {
  id: string;
  label: string;
  status?: string;
}

export interface DagEdgeInput {
  source: string;
  target: string;
  label?: string;
}

// Status -> node colour (pending grey, running blue, done green, failed red...).
const STATUS_COLOR: Record<string, string> = {
  pending: "#9ca3af",
  draft: "#9ca3af",
  queued: "#9ca3af",
  blocked: "#9ca3af",
  ready: "#38bdf8",
  leased: "#60a5fa",
  running: "#3b82f6",
  completed: "#22c55e",
  succeeded: "#22c55e",
  done: "#22c55e",
  failed: "#ef4444",
  policy_denied: "#b91c1c",
  skipped: "#eab308",
};

// Simple layered layout: depth = longest path from roots; nodes at the same
// depth share a column. Avoids a graph-layout dependency (dagre/elk).
function computeLayout(
  nodes: DagNodeInput[],
  edges: DagEdgeInput[],
): Record<string, { x: number; y: number }> {
  const incoming = new Map<string, string[]>();
  nodes.forEach((n) => incoming.set(n.id, []));
  edges.forEach((e) => {
    if (incoming.has(e.target)) incoming.get(e.target)!.push(e.source);
  });
  const depth = new Map<string, number>();
  const compute = (id: string, visiting: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (visiting.has(id)) return 0; // cycle guard
    visiting.add(id);
    const parents = incoming.get(id) ?? [];
    const d =
      parents.length === 0
        ? 0
        : Math.max(...parents.map((p) => compute(p, visiting) + 1));
    depth.set(id, d);
    return d;
  };
  nodes.forEach((n) => compute(n.id, new Set()));

  const byDepth = new Map<number, string[]>();
  nodes.forEach((n) => {
    const d = depth.get(n.id) ?? 0;
    if (!byDepth.has(d)) byDepth.set(d, []);
    byDepth.get(d)!.push(n.id);
  });

  const positions: Record<string, { x: number; y: number }> = {};
  byDepth.forEach((ids, d) => {
    ids.forEach((id, i) => {
      positions[id] = { x: d * 240, y: i * 110 };
    });
  });
  return positions;
}

interface DagViewProps {
  nodes: DagNodeInput[];
  edges: DagEdgeInput[];
  onNodeClick?: (id: string) => void;
}

export function DagView({ nodes, edges, onNodeClick }: DagViewProps) {
  const flowNodes: Node[] = useMemo(() => {
    const positions = computeLayout(nodes, edges);
    return nodes.map((n) => ({
      id: n.id,
      position: positions[n.id] ?? { x: 0, y: 0 },
      data: { label: n.label },
      style: {
        background: STATUS_COLOR[n.status ?? "pending"] ?? "#9ca3af",
        color: "#fff",
        border: "1px solid rgba(0,0,0,0.15)",
        borderRadius: 8,
        padding: "8px 12px",
        fontSize: 12,
      },
    }));
  }, [nodes, edges]);

  const flowEdges: Edge[] = useMemo(
    () =>
      edges.map((e, i) => ({
        id: `e-${i}-${e.source}-${e.target}`,
        source: e.source,
        target: e.target,
        label: e.label,
        markerEnd: { type: MarkerType.ArrowClosed },
      })),
    [edges],
  );

  return (
    <div className="h-[420px] w-full rounded-md border">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        fitView
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => onNodeClick?.(node.id)}
      >
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
