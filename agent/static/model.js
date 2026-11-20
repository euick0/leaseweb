// What each flight strip shows, worked out from the API responses.
// Pure functions only: no DOM, no fetch, so they run under `node --test`.

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ESCAPES[c]);

export const STRIP_COLOURS = 4;
export const stripColour = (envIndex) => envIndex % STRIP_COLOURS;

const byRank = (a, b) => (a.item.rank ?? Infinity) - (b.item.rank ?? Infinity);

/** One bay per environment, one strip per workload; run items attach to their workload. */
export function buildBoard(fleet, detail) {
  const items = detail?.items ?? [];
  const bays = fleet.environments.map((env, i) => ({ env, colour: stripColour(i), error: env.error ?? null, strips: [] }));
  const bayFor = (target) => bays.find((b) => b.env.name === target);
  const seen = new Set();
  for (const workload of fleet.workloads) {
    const item = items.find((it) => it.workload_id === workload.id) ?? null;
    if (item) seen.add(item.id);
    bayFor(workload.target)?.strips.push({ workload, item });
  }
  // an affected workload that discovery no longer returns (its cluster is unreachable) keeps its strip
  for (const item of items) {
    if (!seen.has(item.id)) bayFor(item.workload.target)?.strips.push({ workload: item.workload, item });
  }
  for (const bay of bays) {
    const affected = bay.strips.filter((s) => s.item).sort(byRank);
    bay.strips = [...affected, ...bay.strips.filter((s) => !s.item)];
  }
  return { bays };
}

const ACT_STEPS = new Set(["change", "build", "canary", "promote", "mitigate"]);

/** The six stages of the pipeline as drawn on the strip. */
export function routeStages(item, events) {
  const mitigate = item.decision?.action === "mitigate";
  const done = {
    match: true,
    triage: Boolean(item.triage),
    vet: events.some((e) => e.step === "vet") || Boolean(item.decision),
    policy: Boolean(item.decision),
    act: events.some((e) => ACT_STEPS.has(e.step) && e.status === "ok"),
    proof: Boolean(item.proof?.after) || item.proof?.level === "re-scan + health",
  };
  const labels = { match: "match", triage: "triage", vet: "vet fix", policy: "policy", act: mitigate ? "shield" : "patch", proof: "proof" };
  const blocker = ["matched", "running"].includes(item.status) ? "now"
    : ["failed", "rolled_back"].includes(item.status) ? "fail" : "todo";
  let firstOpen = true;
  return Object.keys(labels).map((key) => {
    let state = "done";
    if (!done[key]) { state = firstOpen ? blocker : "todo"; firstOpen = false; }
    return { key, label: labels[key], state };
  });
}

const STATUS_VERDICTS = {
  awaiting_approval: ["wait", "Needs you"],
  escalated: ["human", "Needs a human"],
  queued: ["queued", "Queued"],
  running: ["working", "Working"],
  matched: ["working", "Working"],
  blocked: ["refused", "Fix refused"],
  failed: ["failed", "Failed"],
  rolled_back: ["rolledback", "Rolled back"],
  ignored: ["ignored", "Ignored"],
};

/** The verdict cell at the right end of a strip in a run. */
export function verdictFor(item) {
  if (item.status === "done") {
    const proof = item.proof;
    const after = proof?.after?.result;
    if (after === "SAFE") return { kind: "safe", label: "SAFE", struck: "VULNERABLE", note: "proven by the exploit probe" };
    if (after === "BLOCKED") return { kind: "shielded", label: "SHIELDED", struck: "VULNERABLE", note: "probe blocked by gateway rule" };
    if (after) return { kind: "patched", label: "Patched", struck: null, note: "probe error, not proven" };
    return { kind: "patched", label: "Patched", struck: null, note: proof?.level ?? "no proof recorded" };
  }
  const [kind, label] = STATUS_VERDICTS[item.status] ?? ["working", item.status];
  if (kind === "wait") return { kind, label, struck: null, note: `${actionLabel(item).toLowerCase()} below` };
  if (kind === "rolledback") return { kind, label, struck: null, note: "old version still serving" };
  return { kind, label, struck: null, note: item.outcome ?? item.decision?.reason ?? "" };
}

/** Verdict cell before any advisory: the last probe results for the workload. */
export function idleVerdict(workload) {
  const results = (workload.probes ?? []).map((p) => p.result);
  if (results.includes("VULNERABLE")) return { kind: "vuln", label: "VULNERABLE", note: "last probe" };
  if (results.length) return { kind: "safe", label: "SAFE", note: "last probe" };
  return { kind: "unknown", label: "Not probed yet", note: "" };
}

/** Label of the approve button for an item waiting on a person, or null. */
export function actionLabel(item) {
  if (item.status === "queued") return "Act now";
  if (item.status !== "awaiting_approval") return null;
  return item.decision?.action === "mitigate" ? "Approve gateway rule" : "Approve patch";
}

/**
 * Which run the board shows. `follow` is the newest run id when the viewer triggered an
 * advisory (0 when there was none): the board jumps to the first run newer than that.
 */
export function pickRun(runs, selectedRun, follow) {
  const newest = runs[0]?.id ?? null;
  if (follow !== null && newest !== null && newest > follow) return { selectedRun: newest, follow: null };
  if (selectedRun === null || !runs.some((r) => r.id === selectedRun)) return { selectedRun: newest, follow };
  return { selectedRun, follow };
}

const SUMMARY_WORDS = [
  ["done", "safe"], ["awaiting_approval", "needs you"], ["escalated", "needs a human"], ["queued", "queued"],
  ["blocked", "refused"], ["failed", "failed"], ["rolled_back", "rolled back"],
];

/** "1 safe, 1 queued" for an advisory tab. */
export function ticketSummary(run) {
  const parts = SUMMARY_WORDS
    .map(([status, word]) => [run.items.filter((i) => i.status === status).length, word])
    .filter(([n]) => n > 0)
    .map(([n, word]) => `${n} ${word}`);
  return parts.length ? parts.join(", ") : "Working";
}
