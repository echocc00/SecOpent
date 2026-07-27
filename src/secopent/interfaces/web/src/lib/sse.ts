// Minimal EventSource helper for the assessment long-task stream (§13 SSE).
// The backend emits `data: {"assessment_id", "status"}` frames on
// /assessments/{id}/events (proxied to the backend root by Vite).

export interface AssessmentEvent {
  assessment_id: string;
  status: string;
}

export function subscribeAssessmentEvents(
  assessmentId: string,
  onEvent: (event: AssessmentEvent) => void,
  onError?: (error: Event) => void,
): () => void {
  const source = new EventSource(`/api/assessments/${assessmentId}/events`);
  source.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data) as AssessmentEvent);
    } catch {
      // Ignore malformed frames; the stream is best-effort progress signalling.
    }
  };
  if (onError) source.onerror = onError;
  return () => source.close();
}
