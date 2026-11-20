// What each part of the dashboard shows, worked out from the API responses.
// Pure functions only: no DOM, no fetch, so they run under `node --test`.

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ESCAPES[c]);

export const STRIP_COLOURS = 4;
export const stripColour = (envIndex) => envIndex % STRIP_COLOURS;

const OTHER_BAY = { name: "_other", label: "Other targets" };
const byRank = (a, b) => (a.item.rank ?? Infinity) - (b.item.rank ?? Infinity);

/** One bay per environment, one strip per workload; run items attach to their workload. */
export function buildBoard(fleet, detail) {
  const items = detail?.items ?? [];
  const bays = fleet.environments.map((env, i) => ({ env, colour: stripColour(i), error: env.error ?? null, strips: [] }));
  const bayFor = (target) => {
    let bay = bays.find((b) => b.env.name === target) ?? bays.find((b) => b.env === OTHER_BAY);
    if (!bay) {
      bay = { env: OTHER_BAY, colour: stripColour(bays.length), error: null, strips: [] };
      bays.push(bay);
    }
    return bay;
  };
  const seen = new Set();
  for (const workload of fleet.workloads) {
    const item = items.find((it) => it.workload_id === workload.id) ?? null;
    if (item) seen.add(item.id);
    bayFor(workload.target).strips.push({ workload, item });
  }
  // an affected workload that discovery no longer returns (its cluster is unreachable) keeps its strip
  for (const item of items) {
    if (!seen.has(item.id)) bayFor(item.workload.target).strips.push({ workload: item.workload, item });
  }
  for (const bay of bays) {
    const affected = bay.strips.filter((s) => s.item).sort(byRank);
    bay.strips = [...affected, ...bay.strips.filter((s) => !s.item)];
  }
  return { bays };
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
  proposed: ["proposed", "Fix proposed"],
};

/** The verdict for one workload in a run. */
export function verdictFor(item) {
  if (item.status === "done") {
    const proof = item.proof;
    const after = proof?.after?.result;
    const struck = proof?.before?.result === "VULNERABLE" ? "Vulnerable" : null;
    if (after === "SAFE") return { kind: "safe", label: "Safe", struck, note: "proven by the exploit probe" };
    if (after === "BLOCKED") return { kind: "shielded", label: "Shielded", struck, note: "probe blocked by gateway rule" };
    if (after) return { kind: "patched", label: "Patched", struck: null, note: "probe error, not proven" };
    if (item.decision?.action === "mitigate") return { kind: "shielded", label: "Shielded", struck: null, note: "rule active, not proven by a probe" };
    return { kind: "patched", label: "Patched", struck: null, note: proof?.level ?? "no proof recorded" };
  }
  const [kind, label] = STATUS_VERDICTS[item.status] ?? ["working", item.status];
  if (kind === "wait") return { kind, label, struck: null, note: `${actionLabel(item).toLowerCase()} below` };
  if (kind === "rolledback") return { kind, label, struck: null, note: "old version still serving" };
  return { kind, label, struck: null, note: item.outcome ?? item.decision?.reason ?? "" };
}

/** Verdict before any advisory: the last probe results for the workload. */
export function idleVerdict(workload) {
  const results = (workload.probes ?? []).map((p) => p.result);
  if (results.includes("VULNERABLE")) return { kind: "vuln", label: "Vulnerable", note: "last probe" };
  if (results.length) return { kind: "safe", label: "Safe", note: "last probe" };
  return { kind: "unknown", label: "Not probed yet", note: "" };
}

/** Label of the approve button for an item waiting on a person, or null. */
export function actionLabel(item) {
  if (item.status === "queued") return "Act now";
  if (item.status !== "awaiting_approval") return null;
  return item.decision?.action === "mitigate" ? "Approve gateway rule" : "Approve patch";
}

const SUMMARY_WORDS = [
  ["done", "safe"], ["awaiting_approval", "needs you"], ["escalated", "needs a human"], ["queued", "queued"],
  ["blocked", "refused"], ["failed", "failed"], ["rolled_back", "rolled back"], ["ignored", "ignored"],
  ["proposed", "fix proposed"],
];

/** "1 safe, 1 queued" for an advisory in the list. */
export function ticketSummary(run) {
  const parts = SUMMARY_WORDS
    .map(([status, word]) => [run.items.filter((i) => i.status === status).length, word])
    .filter(([n]) => n > 0)
    .map(([n, word]) => `${n} ${word}`);
  if (parts.length) return parts.join(", ");
  if (run.items.length || run.status === "running" || !run.status) return "Working";
  return run.status === "failed" ? "Pipeline error" : "No workload affected";
}

/** Which run the board shows: the newest, unless the viewer pinned one that still exists. */
export function pickRun(runs, selectedRun, pinned) {
  const newest = runs[0]?.id ?? null;
  if (pinned && runs.some((r) => r.id === selectedRun)) return { selectedRun, pinned: true };
  return { selectedRun: newest, pinned: false };
}

const LANGUAGES = { maven: { name: "Java", colour: "#b07219" }, pypi: { name: "Python", colour: "#3572a5" }, npm: { name: "JavaScript", colour: "#f1e05a" } };

/** Language of the affected component, with the colour GitHub uses for it. */
export function language(item) {
  return LANGUAGES[item?.component?.ecosystem] ?? null;
}

const PILLS = { safe: "safe", shielded: "safe", patched: "safe", vuln: "vuln", refused: "vuln", failed: "vuln", wait: "wait", human: "wait", rolledback: "wait", proposed: "wait" };

/** Colour group of a status pill. */
export const pillClass = (kind) => PILLS[kind] ?? "queued";

/** Items a person has to act on. */
export function decisions(detail) {
  return (detail?.items ?? []).filter((i) => i.status === "awaiting_approval" || i.status === "escalated");
}

/** Numbers for the header strip. */
export function runStats(fleet, detail) {
  const items = detail?.items ?? [];
  const known = new Set(fleet.workloads.map((w) => w.id));
  const total = known.size + items.filter((i) => !known.has(i.workload_id)).length;
  const kinds = items.map((i) => verdictFor(i).kind);
  const run = detail?.run;
  const seconds = run?.finished ? Math.round((run.finished - run.started) * 10) / 10 : null;
  return {
    affected: items.length,
    total,
    safe: kinds.filter((k) => ["safe", "shielded", "patched"].includes(k)).length,
    waiting: kinds.filter((k) => ["queued", "wait", "human", "proposed"].includes(k)).length,
    seconds,
  };
}
