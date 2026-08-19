import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";

// Lifecycle/status colour coding shared across pages (assessments, jobs, cases).
const STYLES: Record<string, string> = {
  // progress
  pending: "bg-gray-300 text-black hover:bg-gray-300",
  draft: "bg-gray-300 text-black hover:bg-gray-300",
  queued: "bg-gray-300 text-black hover:bg-gray-300",
  running: "bg-blue-500 text-white hover:bg-blue-500",
  leased: "bg-blue-400 text-white hover:bg-blue-400",
  ready: "bg-sky-400 text-white hover:bg-sky-400",
  blocked: "bg-gray-400 text-black hover:bg-gray-400",
  // positive
  completed: "bg-green-600 text-white hover:bg-green-600",
  succeeded: "bg-green-600 text-white hover:bg-green-600",
  validated: "bg-green-500 text-white hover:bg-green-500",
  confirmed: "bg-green-600 text-white hover:bg-green-600",
  approved: "bg-green-600 text-white hover:bg-green-600",
  signed: "bg-emerald-600 text-white hover:bg-emerald-600",
  published: "bg-emerald-700 text-white hover:bg-emerald-700",
  // awaiting / warning
  awaiting_approval: "bg-amber-500 text-white hover:bg-amber-500",
  skipped: "bg-yellow-400 text-black hover:bg-yellow-400",
  inconclusive: "bg-yellow-400 text-black hover:bg-yellow-400",
  partial: "bg-yellow-500 text-black hover:bg-yellow-500",
  // negative
  failed: "bg-red-600 text-white hover:bg-red-600",
  rejected: "bg-red-600 text-white hover:bg-red-600",
  refuted: "bg-red-500 text-white hover:bg-red-500",
  policy_denied: "bg-red-700 text-white hover:bg-red-700",
  cancelled: "bg-red-400 text-white hover:bg-red-400",
  // reasoning-loop phases
  initializing: "bg-sky-400 text-white hover:bg-sky-400",
  converged: "bg-green-600 text-white hover:bg-green-600",
  catalog_floor_done: "bg-teal-600 text-white hover:bg-teal-600",
  paused: "bg-amber-500 text-white hover:bg-amber-500",
  resumed: "bg-blue-400 text-white hover:bg-blue-400",
  budget_exhausted: "bg-orange-500 text-black hover:bg-orange-500",
  policy_blocked: "bg-red-700 text-white hover:bg-red-700",
  emergency_stopped: "bg-red-600 text-white hover:bg-red-600",
};

export function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <Badge variant="outline" className={STYLES[status] ?? "bg-gray-200 text-black"}>
      {t(`status.${status}`, { defaultValue: status })}
    </Badge>
  );
}
