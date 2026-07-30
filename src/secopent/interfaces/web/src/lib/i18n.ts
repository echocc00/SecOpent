// i18next bootstrap (T14 / cross-cutting §⑥). Bundled zh/en resources (the app
// is offline-first, so no HTTP i18n backend). Default language is zh-CN; the
// choice persists to localStorage and is mirrored into the Zustand UI store.
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "@/locales/en/common.json";
import zh from "@/locales/zh/common.json";

export const LANG_STORAGE_KEY = "secopent.lang";
export type Lang = "zh" | "en";

export function detectLang(): Lang {
  const stored = localStorage.getItem(LANG_STORAGE_KEY);
  return stored === "en" || stored === "zh" ? stored : "zh";
}

void i18n.use(initReactI18next).init({
  resources: {
    zh: { common: zh },
    en: { common: en },
  },
  lng: detectLang(),
  fallbackLng: "en",
  defaultNS: "common",
  ns: ["common"],
  interpolation: { escapeValue: false },
});

export default i18n;
