import { create } from "zustand";
import i18n, { LANG_STORAGE_KEY, detectLang, type Lang } from "@/lib/i18n";

interface UIState {
  sidebarCollapsed: boolean;
  currentProjectId: string | null;
  language: Lang;
  toggleSidebar: () => void;
  setProject: (id: string | null) => void;
  setLanguage: (lang: Lang) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  currentProjectId: null,
  language: detectLang(),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setProject: (id) => set({ currentProjectId: id }),
  setLanguage: (lang) => {
    localStorage.setItem(LANG_STORAGE_KEY, lang);
    void i18n.changeLanguage(lang);
    set({ language: lang });
  },
}));
