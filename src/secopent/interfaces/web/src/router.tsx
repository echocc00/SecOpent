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
      { path: "updates", element: <Updates /> },
    ],
  },
]);
