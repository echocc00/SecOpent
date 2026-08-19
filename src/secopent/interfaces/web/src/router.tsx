import { lazy, Suspense } from "react";
import { createBrowserRouter } from "react-router-dom";
import { Layout } from "@/components/layout/Layout";
import { Dashboard } from "@/pages/Dashboard";
import { NewAssessment } from "@/pages/NewAssessment";
import { AssessmentDetail } from "@/pages/AssessmentDetail";
import { ApprovalCenter } from "@/pages/ApprovalCenter";
import { Findings } from "@/pages/Findings";
import { Updates } from "@/pages/Updates";

// CaseStudio pulls in Monaco + react-flow; lazy-load it to keep the initial
// bundle lean (code-splits the heavy editor into its own chunk).
const CaseStudio = lazy(() =>
  import("@/pages/CaseStudio").then((m) => ({ default: m.CaseStudio })),
);

const LoopView = lazy(() =>
  import("@/pages/LoopView").then((m) => ({ default: m.LoopView })),
);

function CaseStudioRoute() {
  return (
    <Suspense
      fallback={
        <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
          Loading Case Studio…
        </div>
      }
    >
      <CaseStudio />
    </Suspense>
  );
}

function LoopViewRoute() {
  return (
    <Suspense
      fallback={
        <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
          Loading Loop…
        </div>
      }
    >
      <LoopView />
    </Suspense>
  );
}

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "assessments/new", element: <NewAssessment /> },
      { path: "assessments/:id", element: <AssessmentDetail /> },
      { path: "approvals", element: <ApprovalCenter /> },
      { path: "findings", element: <Findings /> },
      { path: "case-studio", element: <CaseStudioRoute /> },
      { path: "loops", element: <LoopViewRoute /> },
      { path: "loops/:id", element: <LoopViewRoute /> },
      { path: "updates", element: <Updates /> },
    ],
  },
]);
