import { OctagonAlert } from "lucide-react";
import { useProjects } from "@/api/hooks";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useUIStore } from "@/stores/uiStore";

export function Header() {
  const projects = useProjects();
  const currentProjectId = useUIStore((s) => s.currentProjectId);
  const setProject = useUIStore((s) => s.setProject);
  const list = projects.data?.data ?? [];

  return (
    <header className="flex h-14 items-center justify-between border-b px-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Project</span>
        <Select
          value={currentProjectId ?? undefined}
          onValueChange={(id) => setProject(id)}
        >
          <SelectTrigger className="w-56">
            <SelectValue placeholder="Select a project" />
          </SelectTrigger>
          <SelectContent>
            {list.map((p) => (
              <SelectItem key={p.id} value={p.id}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <Button variant="destructive" size="sm">
        <OctagonAlert className="mr-2 h-4 w-4" />
        Emergency Stop
      </Button>
    </header>
  );
}
