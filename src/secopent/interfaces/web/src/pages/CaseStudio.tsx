import { useEffect, useState } from "react";
import {
  useAppModel,
  useAppModels,
  useCreateAppModel,
  useReviseAppModel,
  useUpdateAppModel,
} from "@/api/hooks";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { AppModelEditor } from "@/features/case-studio/AppModelEditor";
import { DriftView } from "@/features/case-studio/DriftView";
import { PropertyPanel } from "@/features/case-studio/PropertyPanel";
import { SigningPanel } from "@/features/case-studio/SigningPanel";
import { TestGenerator } from "@/features/case-studio/TestGenerator";
import { YamlEditor } from "@/features/case-studio/YamlEditor";
import { useCaseStudioStore } from "@/features/case-studio/caseStudioStore";
import { toWorkingModel, type WorkingModel } from "@/features/case-studio/types";
import { cn } from "@/lib/utils";

export function CaseStudio() {
  const models = useAppModels();
  const list = models.data?.data ?? [];
  const {
    selectedAppId,
    selectedVersion,
    selectedNodeId,
    selectedType,
    isDirty,
    selectModel,
    selectNode,
    setDirty,
  } = useCaseStudioStore();

  const modelQuery = useAppModel(selectedAppId ?? "", selectedVersion ?? "");
  const loaded = modelQuery.data?.data;

  const [working, setWorking] = useState<WorkingModel | null>(null);
  const [newDialogOpen, setNewDialogOpen] = useState(false);
  const [newAppId, setNewAppId] = useState("");
  const [newVersion, setNewVersion] = useState("1.0");
  const [message, setMessage] = useState("");

  const createModel = useCreateAppModel();
  const updateModel = useUpdateAppModel();
  const reviseModel = useReviseAppModel();

  // Load the selected model into a working (editable) copy.
  useEffect(() => {
    if (loaded) {
      setWorking(toWorkingModel(loaded));
      setDirty(false);
    }
  }, [loaded, setDirty]);

  const handleChange = (m: WorkingModel) => {
    setWorking(m);
    setDirty(true);
  };

  const handleCreate = async () => {
    const appId = newAppId.trim();
    if (!appId) return;
    const res = await createModel.mutateAsync({
      app_id: appId,
      version: newVersion.trim() || "1.0",
      states: ["start"],
      transitions: [],
      invariants: [],
      fields: [],
      roles: [],
      out_of_scope_rules: [],
      llm_proposed: false,
    });
    if (res.data) {
      selectModel(res.data.app_id, res.data.version);
    } else {
      setMessage("Failed to create the model (version may already exist).");
    }
    setNewDialogOpen(false);
    setNewAppId("");
    setNewVersion("1.0");
  };

  const handleSave = async () => {
    if (!working || !loaded) return;
    const body = {
      app_id: loaded.app_id,
      version: loaded.version,
      states: working.states,
      transitions: working.transitions,
      invariants: working.invariants,
      fields: working.fields,
      roles: working.roles,
      out_of_scope_rules: working.out_of_scope_rules,
      llm_proposed: false,
    };
    if (loaded.status === "draft" || loaded.status === "human_validated") {
      const res = await updateModel.mutateAsync({
        app_id: loaded.app_id,
        version: loaded.version,
        body,
      });
      setMessage(res.error ? "Save failed." : "Saved in place.");
    } else {
      // Signed/published models are immutable -> revise into a new version.
      const res = await reviseModel.mutateAsync({
        app_id: loaded.app_id,
        version: loaded.version,
        body: { ...body, new_version: null },
      });
      if (res.data) {
        selectModel(res.data.app_id, res.data.version);
        setMessage(`Revised → new draft version ${res.data.version}.`);
      } else {
        setMessage("Revise failed.");
      }
    }
  };

  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r">
        <div className="flex items-center justify-between border-b p-3">
          <span className="text-sm font-semibold">App Models</span>
          <Button size="sm" variant="outline" onClick={() => setNewDialogOpen(true)}>
            New
          </Button>
        </div>
        <div className="flex-1 overflow-auto p-2">
          {list.length === 0 ? (
            <p className="p-2 text-xs text-muted-foreground">
              No models yet. Create one to start.
            </p>
          ) : (
            <ul className="flex flex-col gap-1">
              {list.map((m) => (
                <li key={`${m.app_id}@${m.version}`}>
                  <button
                    type="button"
                    onClick={() => selectModel(m.app_id, m.version)}
                    className={cn(
                      "flex w-full items-center justify-between rounded-md px-3 py-2 text-left text-sm",
                      selectedAppId === m.app_id && selectedVersion === m.version
                        ? "bg-accent text-accent-foreground"
                        : "hover:bg-accent/50",
                    )}
                  >
                    <span className="font-mono text-xs">
                      {m.app_id}@{m.version}
                    </span>
                    <StatusBadge status={m.status} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col p-4">
        {!loaded ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            Select an App Model on the left, or create a new one.
          </div>
        ) : (
          <>
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <h1 className="font-mono text-lg font-semibold">
                  {loaded.app_id}@{loaded.version}
                </h1>
                <StatusBadge status={loaded.status} />
                {isDirty && (
                  <span className="text-xs text-amber-600">● unsaved changes</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {message && (
                  <span className="text-xs text-muted-foreground">{message}</span>
                )}
                <Button size="sm" disabled={!isDirty || !working} onClick={handleSave}>
                  {loaded.status === "draft" || loaded.status === "human_validated"
                    ? "Save"
                    : "Save as new version"}
                </Button>
              </div>
            </div>

            <Tabs defaultValue="editor" className="flex min-h-0 flex-1 flex-col">
              <TabsList className="w-fit">
                <TabsTrigger value="editor">Model Editor</TabsTrigger>
                <TabsTrigger value="yaml">YAML (Cases)</TabsTrigger>
                <TabsTrigger value="drift">Drift</TabsTrigger>
                <TabsTrigger value="signing">Signing</TabsTrigger>
                <TabsTrigger value="tests">Test Generation</TabsTrigger>
              </TabsList>

              <TabsContent value="editor" className="mt-3 min-h-0 flex-1">
                {working && (
                  <div className="flex h-full gap-3">
                    <div className="min-w-0 flex-1">
                      <AppModelEditor
                        model={working}
                        onChange={handleChange}
                        selectedNodeId={selectedNodeId}
                        selectedType={selectedType}
                        onSelectNode={selectNode}
                      />
                    </div>
                    <div className="w-80 shrink-0 overflow-auto rounded-md border p-3">
                      <PropertyPanel
                        model={working}
                        onChange={handleChange}
                        selectedNodeId={selectedNodeId}
                        selectedType={selectedType}
                      />
                    </div>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="yaml" className="mt-3">
                <YamlEditor />
              </TabsContent>

              <TabsContent value="drift" className="mt-3">
                <DriftView appId={loaded.app_id} version={loaded.version} />
              </TabsContent>

              <TabsContent value="signing" className="mt-3">
                <SigningPanel
                  appId={loaded.app_id}
                  version={loaded.version}
                  status={loaded.status}
                  signature={loaded.signature}
                  digest={loaded.digest}
                />
              </TabsContent>

              <TabsContent value="tests" className="mt-3">
                <TestGenerator
                  appId={loaded.app_id}
                  version={loaded.version}
                  status={loaded.status}
                />
              </TabsContent>
            </Tabs>
          </>
        )}
      </main>

      <Dialog open={newDialogOpen} onOpenChange={setNewDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New App Model</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-2">
              <Label>App id</Label>
              <Input
                value={newAppId}
                onChange={(e) => setNewAppId(e.target.value)}
                placeholder="e.g. juice-shop"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label>Version</Label>
              <Input value={newVersion} onChange={(e) => setNewVersion(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button onClick={handleCreate}>Create</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
