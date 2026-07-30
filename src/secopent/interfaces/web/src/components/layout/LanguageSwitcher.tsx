import { Languages } from "lucide-react";
import { useTranslation } from "react-i18next";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { type Lang } from "@/lib/i18n";
import { useUIStore } from "@/stores/uiStore";

export function LanguageSwitcher() {
  const { t } = useTranslation();
  const language = useUIStore((s) => s.language);
  const setLanguage = useUIStore((s) => s.setLanguage);
  return (
    <Select value={language} onValueChange={(v) => setLanguage(v as Lang)}>
      <SelectTrigger className="w-28" aria-label={t("header.language")}>
        <Languages className="mr-2 h-4 w-4" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="zh">中文</SelectItem>
        <SelectItem value="en">English</SelectItem>
      </SelectContent>
    </Select>
  );
}
