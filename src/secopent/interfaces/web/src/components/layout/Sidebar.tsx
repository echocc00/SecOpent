import { NavLink } from "react-router-dom";
import {
  Bug,
  CheckCircle2,
  FlaskConical,
  LayoutDashboard,
  PlusCircle,
  RefreshCw,
  Repeat,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", key: "dashboard", icon: LayoutDashboard, end: true },
  { to: "/assessments/new", key: "newAssessment", icon: PlusCircle, end: false },
  { to: "/approvals", key: "approvals", icon: CheckCircle2, end: false },
  { to: "/findings", key: "findings", icon: Bug, end: false },
  { to: "/case-studio", key: "caseStudio", icon: FlaskConical, end: false },
  { to: "/loops", key: "loops", icon: Repeat, end: false },
  { to: "/updates", key: "updates", icon: RefreshCw, end: false },
];

export function Sidebar() {
  const { t } = useTranslation();
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground">
      <div className="flex h-14 items-center gap-2 border-b px-4">
        <span className="text-sm font-semibold tracking-tight">SecOpent</span>
        <span className="text-xs text-muted-foreground">{t("nav.caseStudio")}</span>
      </div>
      <nav className="flex flex-col gap-1 p-2">
        {NAV_ITEMS.map(({ to, key, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
              )
            }
          >
            <Icon className="h-4 w-4" />
            {t(`nav.${key}`)}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
