// OpenAPI client generated types + openapi-fetch wrapper (Phase A P1, W2).
// `generated.ts` is produced by `openapi-typescript` from the backend's
// /openapi.json - do not edit it by hand. Regenerate after any backend change.
import createClient from "openapi-fetch";
import type { paths } from "./generated";

// Requests go to /api/* which the Vite dev proxy rewrites to the FastAPI
// backend root (e.g. /api/projects -> http://localhost:8000/projects).
export const api = createClient<paths>({ baseUrl: "/api" });

export type { paths, components } from "./generated";
