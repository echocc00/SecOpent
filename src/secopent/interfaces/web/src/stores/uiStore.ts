import { create } from "zustand";

interface UIState {
  sidebarCollapsed: boolean;
  currentProjectId: string | null;
  toggleSidebar: () => void;
  setProject: (id: string | null) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  currentProjectId: null,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setProject: (id) => set({ currentProjectId: id }),
}));
