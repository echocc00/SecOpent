import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// Drift detection compares a new AppModel revision against the signed baseline
// and regenerates only the changed test signatures. The application-layer
// DriftDetector exists, but its REST endpoints are not wired yet, so this tab
// is a graceful placeholder until that lands.
export function DriftView() {
  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle className="text-base">Drift Detection</CardTitle>
        <CardDescription>
          Detect endpoint/field changes between model revisions and incrementally
          regenerate affected tests.
        </CardDescription>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        Not wired yet: the drift REST endpoints (check-drift / drift report) are
        pending. The deterministic <span className="font-mono">DriftDetector</span>{" "}
        already exists in the application layer and will back this view.
      </CardContent>
    </Card>
  );
}
