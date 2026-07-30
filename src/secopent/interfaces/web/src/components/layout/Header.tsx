import { OctagonAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useProjects } from "@/api/hooks";
import { LanguageSwitcher } from "@/components/layout/LanguageSwitcher";
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
  const { t } = useTranslation();
  const projects = useProjects();
  const currentProjectId = useUIStore((s) => s.currentProjectId);
  const setProject = useUIStore((s) => s.setProject);
  const list = projects.data?.data ?? [];

  return (
    <header className="flex h-14 items-center justify-between border-b px-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">{t("header.project")}</span>
        <Select
          value={currentProjectId ?? undefined}
          onValueChange={(id) => setProject(id)}
        >
          <SelectTrigger className="w-56">
            <SelectValue placeholder={t("header.selectProject")} />
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
      <div className="flex items-center gap-2">
        <LanguageSwitcher />
        <Button variant="destructive" size="sm">
          <OctagonAlert className="mr-2 h-4 w-4" />
          {t("header.emergencyStop")}
        </Button>
      </div>
    </header>
  );
}
