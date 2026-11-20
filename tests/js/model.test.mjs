// Unit tests for the dashboard's strip model. Run: node --test tests/js/
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  esc, stripColour, buildBoard, routeStages, verdictFor, idleVerdict, actionLabel, ticketSummary,
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

const states = (stages) => stages.map((s) => s.state);

test("routeStages pulses triage for a freshly matched item", () => {
  assert.deepEqual(states(routeStages({ status: "matched" }, [])), ["done", "now", "todo", "todo", "todo", "todo"]);
});

test("routeStages marks every stage done for a proven patch", () => {
  const it = { status: "done", triage: {}, decision: { action: "patch" }, proof: { after: { result: "SAFE" } } };
  const evs = [{ step: "vet", status: "ok" }, { step: "canary", status: "ok" }, { step: "promote", status: "ok" }];
  const stages = routeStages(it, evs);
  assert.deepEqual(states(stages), ["done", "done", "done", "done", "done", "done"]);
  assert.equal(stages[4].label, "patch");
  assert.deepEqual(stages.map((s) => s.key), ["match", "triage", "vet", "policy", "act", "proof"]);
});

test("routeStages marks the act stage failed after a rollback", () => {
  const stages = routeStages({ status: "rolled_back", triage: {}, decision: { action: "patch" } }, [{ step: "vet", status: "ok" }]);
  assert.equal(stages[4].state, "fail");
  assert.equal(stages[5].state, "todo");
});

test("routeStages names the act stage shield for a mitigation", () => {
  const stages = routeStages({ status: "awaiting_approval", triage: {}, decision: { action: "mitigate" } }, []);
  assert.equal(stages[4].label, "shield");
  assert.equal(stages[2].label, "vet fix");
});

test("verdictFor crosses out VULNERABLE when the probe proves SAFE", () => {
  const v = verdictFor({ status: "done", proof: { level: "exploit probe", before: { result: "VULNERABLE" }, after: { result: "SAFE" } } });
  assert.equal(v.kind, "safe");
  assert.equal(v.label, "SAFE");
  assert.equal(v.struck, "VULNERABLE");
});

test("verdictFor shows SHIELDED when the gateway blocks the probe", () => {
  const v = verdictFor({ status: "done", proof: { level: "exploit probe", before: { result: "VULNERABLE" }, after: { result: "BLOCKED" } } });
  assert.deepEqual([v.kind, v.label, v.struck, v.note], ["shielded", "SHIELDED", "VULNERABLE", "probe blocked by gateway rule"]);
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
  assert.deepEqual([vuln.kind, vuln.label], ["vuln", "VULNERABLE"]);
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
  assert.equal(ticketSummary({ items: [] }), "Working");
  assert.equal(ticketSummary({ items: [{ status: "awaiting_approval" }, { status: "blocked" }] }), "1 needs you, 1 refused");
});
