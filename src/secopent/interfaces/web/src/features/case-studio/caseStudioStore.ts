import { create } from "zustand";

interface CaseStudioState {
  selectedAppId: string | null;
  selectedVersion: string | null;
  selectedNodeId: string | null;
  selectedType: "state" | "transition" | null;
  isDirty: boolean;
  selectModel: (appId: string, version: string) => void;
  selectNode: (id: string | null, type: "state" | "transition" | null) => void;
  setDirty: (dirty: boolean) => void;
}

export const useCaseStudioStore = create<CaseStudioState>((set) => ({
  selectedAppId: null,
  selectedVersion: null,
  selectedNodeId: null,
  selectedType: null,
  isDirty: false,
  selectModel: (appId, version) =>
    set({
      selectedAppId: appId,
      selectedVersion: version,
      selectedNodeId: null,
      selectedType: null,
      isDirty: false,
    }),
  selectNode: (id, type) => set({ selectedNodeId: id, selectedType: type }),
  setDirty: (dirty) => set({ isDirty: dirty }),
}));
