import { createBrowserRouter } from "react-router-dom";
import { Layout } from "@/components/layout/Layout";
import { Dashboard } from "@/pages/Dashboard";
import { NewAssessment } from "@/pages/NewAssessment";
import { AssessmentDetail } from "@/pages/AssessmentDetail";
import { ApprovalCenter } from "@/pages/ApprovalCenter";
import { Findings } from "@/pages/Findings";
import { CaseStudio } from "@/pages/CaseStudio";
import { Updates } from "@/pages/Updates";

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
      { path: "case-studio", element: <CaseStudio /> },
      { path: "updates", element: <Updates /> },
    ],
  },
]);
