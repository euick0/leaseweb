// Unit tests for the dashboard's strip model. Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  esc, stripColour, buildBoard, verdictFor, idleVerdict, actionLabel, ticketSummary, pickRun,
  language, pillClass, decisions, runStats,
} from "../../agent/static/model.js";

const wl = (name, target, extra = {}) => ({ id: `${target}/shop/${name}`, name, target, probes: [], ...extra });
const fleet = {
  environments: [{ name: "eu", label: "EU sovereign cloud" }, { name: "hyperscaler", label: "Hyperscaler" }],
  workloads: [wl("orders-java", "hyperscaler"), wl("reports-java", "eu"), wl("billing-py", "eu")],
};
const item = (id, workload, extra = {}) => ({ id, workload_id: workload.id, workload, status: "done", ...extra });

test("esc escapes markup and quotes", () => {
  assert.equal(esc('<b a="1">&\''), "&lt;b a=&quot;1&quot;&gt;&amp;&#39;");
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
});

test("stripColour cycles through four colours", () => {
  assert.equal(stripColour(5), 1);
  assert.equal(stripColour(0), 0);
});

test("buildBoard groups strips by environment and ranks affected first", () => {
  const detail = { items: [item(1, fleet.workloads[0], { rank: 1 }), item(2, fleet.workloads[1], { rank: 2 })] };
  const { bays } = buildBoard(fleet, detail);
  assert.deepEqual(bays.map((b) => b.env.name), ["eu", "hyperscaler"]);
  assert.deepEqual(bays.map((b) => b.colour), [0, 1]);
  assert.deepEqual(bays[0].strips.map((s) => s.workload.name), ["reports-java", "billing-py"]);
  assert.equal(bays[0].strips[1].item, null);
  assert.equal(bays[1].strips[0].item.id, 1);
});

test("buildBoard keeps an item whose workload vanished from an unreachable environment", () => {
  const ghost = wl("reports-java", "eu");
  const board = buildBoard({ environments: [{ name: "eu", label: "EU", error: "timeout" }], workloads: [] },
    { items: [item(7, ghost, { rank: 1 })] });
  assert.equal(board.bays[0].error, "timeout");
  assert.equal(board.bays[0].strips.length, 1);
  assert.equal(board.bays[0].strips[0].workload.name, "reports-java");
});

test("buildBoard without a run shows every workload idle", () => {
  const { bays } = buildBoard(fleet, null);
  assert.ok(bays.flatMap((b) => b.strips).every((s) => s.item === null));
  assert.equal(bays.flatMap((b) => b.strips).length, 3);
});

test("buildBoard puts a workload whose environment is unknown in an extra bay", () => {
  const stray = wl("legacy", "nowhere");
  const { bays } = buildBoard({ environments: fleet.environments, workloads: [...fleet.workloads, stray] }, null);
  assert.equal(bays.length, 3);
  assert.equal(bays[2].env.label, "Other targets");
  assert.equal(bays[2].strips[0].workload.name, "legacy");
});

test("verdictFor only crosses out Vulnerable when the probe saw it vulnerable before", () => {
  const v = verdictFor({ status: "done", proof: { before: { result: "SAFE" }, after: { result: "BLOCKED" } } });
  assert.equal(v.kind, "shielded");
  assert.equal(v.struck, null);
});

test("verdictFor marks a mitigation without a probe as shielded but unproven", () => {
  const v = verdictFor({ status: "done", decision: { action: "mitigate" }, proof: null });
  assert.equal(v.kind, "shielded");
  assert.equal(v.struck, null);
  assert.match(v.note, /not proven/);
});

test("language comes from the affected component's ecosystem", () => {
  assert.deepEqual(language({ component: { ecosystem: "maven" } }), { name: "Java", colour: "#b07219" });
  assert.deepEqual(language({ component: { ecosystem: "pypi" } }), { name: "Python", colour: "#3572a5" });
  assert.equal(language(null), null);
  assert.equal(language({ component: { ecosystem: "cargo" } }), null);
});

test("pillClass groups verdict kinds into four colours", () => {
  assert.deepEqual(["safe", "shielded", "patched"].map(pillClass), ["safe", "safe", "safe"]);
  assert.deepEqual(["vuln", "refused", "failed"].map(pillClass), ["vuln", "vuln", "vuln"]);
  assert.deepEqual(["wait", "human", "rolledback"].map(pillClass), ["wait", "wait", "wait"]);
  assert.deepEqual(["queued", "working", "ignored", "unknown"].map(pillClass), ["queued", "queued", "queued", "queued"]);
});

test("decisions lists the items a person has to act on", () => {
  const its = [{ id: 1, status: "done" }, { id: 2, status: "awaiting_approval" }, { id: 3, status: "escalated" }, { id: 4, status: "queued" }];
  assert.deepEqual(decisions({ items: its }).map((i) => i.id), [2, 3]);
  assert.deepEqual(decisions(null), []);
});

test("runStats counts affected, safe and waiting workloads and the run time", () => {
  const ghost = wl("ghost", "eu");
  const detail = {
    run: { started: 100, finished: 107.4 },
    items: [
      item(1, fleet.workloads[0], { status: "done", proof: { after: { result: "SAFE" } } }),
      item(2, fleet.workloads[1], { status: "queued" }),
      item(3, ghost, { status: "awaiting_approval" }),
    ],
  };
  assert.deepEqual(runStats(fleet, detail), { affected: 3, total: 4, safe: 1, waiting: 2, seconds: 7.4 });
  assert.equal(runStats(fleet, { run: { started: 1, finished: null }, items: [] }).seconds, null);
});

test("verdictFor crosses out VULNERABLE when the probe proves SAFE", () => {
  const v = verdictFor({ status: "done", proof: { level: "exploit probe", before: { result: "VULNERABLE" }, after: { result: "SAFE" } } });
  assert.equal(v.kind, "safe");
  assert.equal(v.label, "Safe");
  assert.equal(v.struck, "Vulnerable");
});

test("verdictFor shows SHIELDED when the gateway blocks the probe", () => {
  const v = verdictFor({ status: "done", proof: { level: "exploit probe", before: { result: "VULNERABLE" }, after: { result: "BLOCKED" } } });
  assert.deepEqual([v.kind, v.label, v.struck, v.note], ["shielded", "Shielded", "Vulnerable", "probe blocked by gateway rule"]);
});

test("verdictFor never claims SAFE when the proof probe errored", () => {
  const v = verdictFor({ status: "done", proof: { level: "exploit probe", before: { result: "VULNERABLE" }, after: { result: "ERROR" } } });
  assert.equal(v.kind, "patched");
  assert.equal(v.struck, null);
  assert.match(v.note, /probe error/);
});

test("verdictFor reports re-scan proof as patched", () => {
  const v = verdictFor({ status: "done", proof: { level: "re-scan + health", rescan: "x", health: true } });
  assert.equal(v.kind, "patched");
  assert.equal(v.note, "re-scan + health");
});

test("verdictFor maps every other item status", () => {
  const cases = {
    awaiting_approval: ["wait", "Needs you"], escalated: ["human", "Needs a human"], queued: ["queued", "Queued"],
    running: ["working", "Working"], matched: ["working", "Working"], blocked: ["refused", "Fix refused"],
    failed: ["failed", "Failed"], rolled_back: ["rolledback", "Rolled back"], ignored: ["ignored", "Ignored"],
  };
  for (const [status, [kind, label]] of Object.entries(cases)) {
    const v = verdictFor({ status, decision: { action: "patch", reason: "r" } });
    assert.deepEqual([v.kind, v.label], [kind, label], status);
  }
});

test("idleVerdict prefers VULNERABLE and handles no probes", () => {
  const vuln = idleVerdict(wl("a", "eu", { probes: [{ result: "SAFE" }, { result: "VULNERABLE" }] }));
  assert.deepEqual([vuln.kind, vuln.label], ["vuln", "Vulnerable"]);
  assert.equal(idleVerdict(wl("a", "eu", { probes: [{ result: "SAFE" }, { result: "BLOCKED" }] })).kind, "safe");
  const none = idleVerdict(wl("a", "eu"));
  assert.equal(none.kind, "unknown");
  assert.equal(none.label, "Not probed yet");
});

test("actionLabel names the pending action", () => {
  assert.equal(actionLabel({ status: "awaiting_approval", decision: { action: "mitigate" } }), "Approve gateway rule");
  assert.equal(actionLabel({ status: "awaiting_approval", decision: { action: "patch" } }), "Approve patch");
  assert.equal(actionLabel({ status: "queued", decision: { action: "patch" } }), "Act now");
  assert.equal(actionLabel({ status: "done", decision: { action: "patch" } }), null);
});

test("ticketSummary counts outcomes in plain words", () => {
  assert.equal(ticketSummary({ items: [{ status: "done" }, { status: "queued" }] }), "1 safe, 1 queued");
  assert.equal(ticketSummary({ status: "running", items: [] }), "Working");
  assert.equal(ticketSummary({ items: [{ status: "awaiting_approval" }, { status: "blocked" }] }), "1 needs you, 1 refused");
  assert.equal(ticketSummary({ items: [{ status: "ignored" }] }), "1 ignored");
});

test("ticketSummary tells a crashed or empty run apart from a running one", () => {
  assert.equal(ticketSummary({ status: "failed", items: [] }), "Pipeline error");
  assert.equal(ticketSummary({ status: "done", items: [] }), "No workload affected");
});

const runs = (...ids) => ids.map((id) => ({ id }));

test("pickRun follows the newest run unless the viewer pinned one", () => {
  assert.deepEqual(pickRun(runs(2, 1), null, false), { selectedRun: 2, pinned: false });
  assert.deepEqual(pickRun(runs(3, 2, 1), 2, false), { selectedRun: 3, pinned: false });
  assert.deepEqual(pickRun([], null, false), { selectedRun: null, pinned: false });
});

test("pickRun keeps a pinned run, and unpins when it disappears", () => {
  assert.deepEqual(pickRun(runs(3, 2, 1), 1, true), { selectedRun: 1, pinned: true });
  assert.deepEqual(pickRun(runs(3, 2), 1, true), { selectedRun: 3, pinned: false });
});
