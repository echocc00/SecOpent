import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";

const STYLES: Record<string, string> = {
  critical: "bg-red-600 text-white hover:bg-red-600",
  high: "bg-orange-500 text-white hover:bg-orange-500",
  medium: "bg-yellow-400 text-black hover:bg-yellow-400",
  low: "bg-blue-500 text-white hover:bg-blue-500",
  info: "bg-gray-400 text-black hover:bg-gray-400",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const { t } = useTranslation();
  return (
    <Badge className={STYLES[severity] ?? "bg-gray-300 text-black"}>
      {t(`severity.${severity}`, { defaultValue: severity })}
    </Badge>
  );
}
