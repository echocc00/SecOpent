import type { components } from "@/api/generated";

export type Transition = components["schemas"]["TransitionOut"];
export type Invariant = components["schemas"]["InvariantOut"];
export type ModelField = components["schemas"]["FieldOut"];
export type Role = components["schemas"]["RoleOut"];
export type AppModel = components["schemas"]["AppModelOut"];

// Mutable working copy of an AppModel's editable content.
export interface WorkingModel {
  states: string[];
  transitions: Transition[];
  invariants: Invariant[];
  fields: ModelField[];
  roles: Role[];
  out_of_scope_rules: string[];
}

export function toWorkingModel(model: AppModel): WorkingModel {
  return {
    states: [...model.states],
    transitions: model.transitions.map((t) => ({ ...t, params: [...t.params] })),
    invariants: model.invariants.map((i) => ({ ...i })),
    fields: model.fields.map((f) => ({ ...f })),
    roles: model.roles.map((r) => ({ ...r, capabilities: [...r.capabilities] })),
    out_of_scope_rules: [...model.out_of_scope_rules],
  };
}
