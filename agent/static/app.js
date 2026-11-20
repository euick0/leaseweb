// PatchPilot dashboard: polls the decision log every 2 s and renders it.
// What each workload shows is decided in model.js; this file only builds HTML and handles input.
import {
  esc, buildBoard, verdictFor, idleVerdict, actionLabel, ticketSummary, pickRun,
  language, pillClass, decisions, runStats,
} from "/static/model.js";

const REFRESH_MS = 2000;
const ACTION_ERROR_MS = 6000;
const FEED_LIMIT = 12;
const $ = (sel) => document.querySelector(sel);

const state = {
  selectedRun: null,     // run shown on the board
  pinned: false,         // true once the viewer picks a run; otherwise the newest run is shown
  openKey: null,         // "item:<id>" or "wl:<workload id>" of the expanded row
  justOpened: false,     // animate the detail only on the render right after it opens
  openEvents: new Set(), // raw events the viewer expanded
  inFlight: new Set(),   // "approve:<id>" / "reject:<id>" requests not answered yet
  menuOpen: false,
  errorUntil: 0,
  data: null,            // last { fleet, runs, scenarios, detail }
};
const rendered = {};
let busy = false, again = false;

// ------------------------------------------------------------------ helpers

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `${res.status} ${res.statusText}`);
  return res.json();
}

function showError(message, holdMs = 0) {
  const bar = $("#errors");
  bar.textContent = message;
  bar.hidden = false;
  state.errorUntil = Date.now() + holdMs;
}

const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const icon = (id, cls = "") => `<svg class="l ${cls}"><use href="#i-${id}"/></svg>`;
const pill = (label, cls) => `<span class="st ${cls}">${esc(label)}</span>`;
const imageTag = (image) => String(image || "").split("/").pop();

function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  return `${Math.floor(s / 3600)} h ago`;
}

function setHtml(sel, html) {
  if (rendered[sel] === html) return;
  rendered[sel] = html;
  const focus = focusSelector($(sel));
  $(sel).innerHTML = html;
  if (focus) document.querySelector(focus)?.focus({ preventScroll: true });
}

// keep keyboard focus on the same control when its container is re-rendered
function focusSelector(container) {
  const el = document.activeElement;
  if (!el || !container.contains(el)) return null;
  for (const attr of ["key", "approve", "reject", "run", "scenario"]) {
    if (el.dataset?.[attr]) return `[data-${attr}="${CSS.escape(el.dataset[attr])}"]`;
  }
  if (el.tagName === "SUMMARY" && el.parentElement?.dataset.ev) return `[data-ev="${el.parentElement.dataset.ev}"] > summary`;
  return null;
}

const busyFor = (kind, id) => state.inFlight.has(`${kind}:${id}`);

// ------------------------------------------------------------------ chrome

function renderChrome({ fleet, runs, scenarios }) {
  const providers = String(fleet.llm.providers || "model");
  $("#model-name").textContent = providers;
  $("#model-mode").textContent = fleet.llm.mode === "cache" ? "Our hardware, cached answers" : "Our hardware, live answers";
  const count = $("#nav-count");
  count.hidden = !runs.length;
  count.textContent = runs.length;
  setHtml("#scenarios", scenarios.map((s) => `<button type="button" role="menuitem" class="${s.triggered ? "ran" : ""}" data-scenario="${esc(s.name)}">
      <b>${esc(s.name)}</b><span>${esc(s.title || s.summary || "")}</span></button>`).join(""));
  $("#scenarios").hidden = !state.menuOpen;
  $("#simulate").setAttribute("aria-expanded", String(state.menuOpen));
}

function renderHero({ fleet, runs, detail }) {
  const run = detail?.run;
  if (!run) {
    const idle = fleet.workloads.map(idleVerdict);
    setHtml("#crumbs", `Fleet <span>/</span> <b>Overview</b>`);
    setHtml("#hero-body", `<div class="greet"><p class="eyebrow">Fleet</p><h1>No advisory yet</h1>
      <p class="meta">Use Simulate advisory to publish one, or Probe fleet to see what is exploitable right now.</p></div>
      <div class="kpis">
        <div class="kpi"><p class="v">${fleet.workloads.length}</p><p class="k">Workloads</p></div>
        <div class="kpi"><p class="v">${fleet.environments.length}</p><p class="k">Environments</p></div>
        <div class="kpi"><p class="v">${fleet.workloads.filter((w) => w.internet_exposed).length}</p><p class="k">Internet-exposed</p></div>
        <div class="kpi"><p class="v ${idle.some((v) => v.kind === "vuln") ? "bad" : ""}">${idle.filter((v) => v.kind === "vuln").length}</p><p class="k">Vulnerable at last probe</p></div>
      </div>`);
    return;
  }
  const summary = runs.find((r) => r.id === run.id);
  const stats = runStats(fleet, detail);
  const comp = detail.items[0]?.component;
  const meta = [
    summary?.severity ? `<span class="crit">${esc(summary.severity)}</span>` : "",
    esc(run.advisory_id),
    comp ? esc(`${comp.name}${detail.items[0].fixed_version ? `, fixed in ${detail.items[0].fixed_version}` : ""}`) : "",
    `arrived ${ago(run.started)}`,
  ].filter(Boolean).join(" · ");
  const time = stats.seconds !== null ? `${stats.seconds} s` : run.status === "running" ? "running" : "n/a";
  setHtml("#crumbs", `Advisories <span>/</span> <b>${esc(run.advisory_id)}</b>`);
  setHtml("#hero-body", `<div class="greet">
      <p class="eyebrow">Advisory ${run.status === "running" ? `<span class="live">Live</span>` : ""}</p>
      <h1>${esc(run.summary || run.title)}</h1><p class="meta">${meta}</p></div>
    <div class="kpis">
      <div class="kpi"><p class="v">${stats.affected}<small> / ${stats.total}</small></p><p class="k">Workloads affected</p></div>
      <div class="kpi"><p class="v ok">${stats.safe}</p><p class="k">Proven or shielded</p></div>
      <div class="kpi"><p class="v wait">${stats.waiting}</p><p class="k">Waiting with a reason</p></div>
      <div class="kpi"><p class="v">${esc(time)}</p><p class="k">Run time</p></div>
    </div>`);
}

// ------------------------------------------------------------------ decisions

function vetEvent(item, events) {
  return events.filter((e) => e.item_id === item.id && e.step === "vet" && e.data && e.data.verdict).pop() ?? null;
}

function decisionCard(item, events, envLabel) {
  const w = item.workload, d = item.decision || {};
  const title = item.status === "escalated" ? `${w.name} needs a human`
    : d.action === "mitigate" ? `Shield ${w.name} at its gateway?` : `Patch ${w.name} now?`;
  const vet = vetEvent(item, events)?.data;
  const checks = [];
  if (vet) {
    checks.push(vet.verdict === "clean"
      ? `<li>${icon("ok", "good")}<span>Fix <span class="mono">${esc(vet.to_version)}</span> passed vetting</span></li>`
      : `<li>${icon("x", "bad")}<span>Fix <span class="mono">${esc(vet.to_version)}</span> judged ${esc(vet.verdict)}${firstFlag(vet)}</span></li>`);
  } else if (!item.fixed_version) {
    checks.push(`<li>${icon("x", "bad")}<span>No fix has been released for ${esc(item.component.name)}</span></li>`);
  }
  if (item.triage) {
    checks.push(`<li>${icon("alert", "info")}<span>Model triage: ${esc(item.triage.severity_for_this_workload)}, ${item.triage.reachable ? "reachable" : "not reachable"}</span></li>`);
  }
  const buttons = item.status === "awaiting_approval"
    ? `<button type="button" class="btn-brand" data-approve="${item.id}" ${busyFor("approve", item.id) ? "disabled" : ""}>${esc(actionLabel(item))}</button>
       <button type="button" class="btn-line" data-reject="${item.id}" ${busyFor("reject", item.id) ? "disabled" : ""}>Reject</button>
       <span class="decide-note">Rejecting leaves ${esc(w.name)} exposed. Both choices are logged.</span>`
    : `<span class="decide-note">${esc(item.outcome || "PatchPilot could not act on its own.")}</span>`;
  return `<div class="decide">
    <div class="decide-h"><span class="decide-ic">${icon("shield-alert")}</span><div>
      <p class="decide-k">Needs your decision</p><p class="decide-t">${esc(title)}</p>
      ${d.reason ? `<p class="decide-d">${esc(d.reason)}</p>` : ""}</div></div>
    <div class="decide-body">
      <div class="decide-wl"><span class="dot" style="background:${language(item)?.colour ?? ""}"></span>
        <div class="flex1"><p class="nm">${esc(w.name)}</p><p class="sub">${esc(envLabel)} · ${w.internet_exposed ? "public" : "internal"}</p></div>
        ${pill(w.internet_exposed ? "Exposed" : "At risk", "vuln")}</div>
      ${checks.length ? `<ul class="checks">${checks.join("")}</ul>` : ""}
    </div>
    <div class="decide-f">${buttons}</div></div>`;
}

function firstFlag(vet) {
  const flag = (vet.flags || []).find((f) => f.severity === "hard") || (vet.flags || []).find((f) => f.severity === "soft");
  return flag ? `: ${esc(flag.message)}` : "";
}

// ------------------------------------------------------------------ workloads

const stripKey = (s) => (s.item ? `item:${s.item.id}` : `wl:${s.workload.id}`);

function rowHtml(strip, bay, hasRun) {
  const w = strip.workload, it = strip.item, key = stripKey(strip), open = key === state.openKey;
  let sub, right;
  if (it) {
    const c = it.component, v = verdictFor(it);
    const fix = it.fixed_version ? ` → ${it.fixed_version}` : ", no fix released";
    sub = `${bay.env.label || bay.env.name} · ${w.internet_exposed ? "public" : "internal"} · ${c.name} ${c.version}${fix}`;
    right = `${v.struck ? `<span class="was">${esc(v.struck)}</span>` : ""}${pill(v.label, pillClass(v.kind))}`;
  } else if (hasRun) {
    sub = `${bay.env.label || bay.env.name} · ${w.internet_exposed ? "public" : "internal"} · not affected by this advisory`;
    right = pill("Not affected", "queued");
  } else {
    const v = idleVerdict(w);
    sub = `${w.internet_exposed ? "public" : "internal"} · ${w.exposure} · image ${imageTag(w.image)}`;
    right = pill(v.label, pillClass(v.kind));
  }
  const lang = language(it);
  return `<button type="button" class="row ${open ? "open" : ""} ${hasRun && !it ? "faded" : ""}" data-key="${esc(key)}" aria-expanded="${open}">
      <span class="l"><span class="dot" style="background:${lang?.colour ?? ""}" title="${esc(lang?.name ?? "")}"></span>
        <span><span class="nm" style="display:block">${esc(w.name)}</span><span class="sub" style="display:block">${esc(sub)}</span></span></span>
      <span class="r">${right}${icon("down", "chev")}</span>
    </button>${open ? detailHtml(strip) : ""}`;
}

function proofBoxes(item) {
  const p = item.proof, v = verdictFor(item);
  const box = (when, res) => {
    if (!res) return `<div><p class="t">${when}</p><p class="v mid">Not probed</p></div>`;
    const cls = res.result === "VULNERABLE" ? "bad" : res.result === "ERROR" ? "mid" : "good";
    const ic = res.result === "VULNERABLE" ? "x" : res.result === "ERROR" ? "alert" : "ok";
    const word = { VULNERABLE: "Vulnerable", SAFE: "Safe", BLOCKED: "Blocked", ERROR: "Probe error" }[res.result] ?? res.result;
    return `<div><p class="t">${when}, ${esc(res.via)} path</p><p class="v ${cls}">${icon(ic)}${esc(word)}</p><p class="n">${esc(res.detail || "")}</p></div>`;
  };
  if (p?.before || p?.after) return `<div class="ba">${box("Before", p.before)}${box("After", p.after)}</div>`;
  if (p?.level === "re-scan + health") {
    return `<p class="dt">Proof</p><p class="dp">No exploit probe exists for this advisory. A re-scan found ${esc(p.rescan)} and the health check ${p.health ? "passed" : "failed"}.</p>`;
  }
  const text = ["failed", "rolled_back", "blocked"].includes(item.status) && item.outcome ? item.outcome
    : item.status === "done" ? v.note : "Not proven yet. The exploit probe runs again after the action.";
  return `<p class="dt">Proof</p><p class="dp">${esc(text)}</p>`;
}

function vetHtml(item, events) {
  const vet = vetEvent(item, events)?.data;
  if (!vet) return `<p class="dt">Fix checked before install</p><p class="dp">${item.fixed_version ? "Not checked yet." : "No fix has been released, so there is nothing to check."}</p>`;
  const flags = (vet.flags || []).filter((f) => f.severity === "hard" || f.severity === "soft");
  const lines = flags.map((f) => `<li>${icon("x", "bad")}<span>${esc(f.file ? `${f.file}: ` : "")}${esc(f.message)}</span></li>`);
  if (!flags.length) lines.push(`<li>${icon("ok", "good")}<span>No hard or soft flags in the diff</span></li>`);
  for (const r of (vet.reviews || []).filter((r) => r.review && r.review.suspicious)) {
    lines.push(`<li>${icon("x", "bad")}<span>Model review of ${esc(r.file)}: ${esc(r.review.explanation)}</span></li>`);
  }
  const evidence = flags.filter((f) => (f.lines || []).length).slice(0, 2)
    .map((f) => `<pre class="evidence">${esc(f.file || "")}\n${f.lines.map((l) => `+ ${esc(l)}`).join("\n")}</pre>`).join("");
  return `<p class="dt">Fix checked before install</p>
    <p class="dp">${esc(vet.artifact)} <span class="mono">${esc(vet.to_version)}</span> judged <b>${esc(vet.verdict)}</b>${vet.cached ? ", verdict reused" : ""}.</p>
    <ul class="checks">${lines.join("")}</ul>${evidence}`;
}

function policyHtml(item) {
  const d = item.decision;
  const label = item.status === "queued" ? actionLabel(item) : null;
  const buttons = label ? `<div class="actions"><button type="button" class="btn-brand" data-approve="${item.id}" ${busyFor("approve", item.id) ? "disabled" : ""}>${esc(label)}</button>
    <button type="button" class="btn-line" data-reject="${item.id}" ${busyFor("reject", item.id) ? "disabled" : ""}>Reject</button></div>` : "";
  if (!d) return buttons;
  const how = { auto: "allowed automatically", needs_approval: "needs a person to approve", block: "blocked", queue: "queued" }[d.decision] || d.decision;
  const what = d.action === "mitigate" ? "Shield at the gateway" : d.action === "patch" ? "Patch the dependency" : d.action;
  return `<p class="dt">Policy</p><p class="dp"><b>${esc(what)}</b>, ${esc(how)}. ${esc(d.reason)}</p>${buttons}`;
}

function rawEvents(events) {
  if (!events.length) return "";
  const rows = events.map((e) => {
    const body = [e.detail, e.data ? JSON.stringify(e.data, null, 2) : ""].filter(Boolean).join("\n\n");
    const head = `<b>${esc(e.step)}</b> ${esc(e.title)}`;
    return `<li><time>${clock(e.ts)}</time>${body
      ? `<details data-ev="${e.id}"${state.openEvents.has(e.id) ? " open" : ""}><summary style="display:inline">${head}</summary><pre>${esc(body)}</pre></details>`
      : head}</li>`;
  }).join("");
  return `<details class="raw"><summary>Raw events (${events.length})</summary><ol>${rows}</ol></details>`;
}

function detailHtml(strip) {
  const fresh = state.justOpened ? " fresh" : "";
  const it = strip.item, w = strip.workload;
  if (!it) {
    const probes = (w.probes || []).map((p) => `<li>${icon(p.result === "VULNERABLE" ? "x" : "ok", p.result === "VULNERABLE" ? "bad" : "good")}
      <span><b>${esc(p.probe)}</b>: ${esc(p.result)} on the ${esc(p.via)} path, ${clock(p.ts)}</span></li>`).join("");
    return `<div class="detail${fresh}">
      <p class="dt">Last probes</p>${probes ? `<ul class="checks" style="margin-top:0">${probes}</ul>` : `<p class="dp">Not probed yet. Use Probe fleet.</p>`}
      <p class="dt">Where it runs</p><p class="dp">${esc(w.provider)}${w.region ? `, ${esc(w.region)}` : ""}. ${esc(w.exposure)}.</p>
      <p class="dby">image <span class="mono">${esc(w.image)}</span></p></div>`;
  }
  const events = state.data.detail.events;
  const mine = events.filter((e) => e.item_id === it.id);
  const t = it.triage;
  const source = { live: "live answer", cache: "cached answer", fallback: "fallback answer", seed: "seeded answer" }[it.triage_source] || it.triage_source || "";
  const why = t ? `<p class="dt">${it.rank === 1 ? "Why it went first" : "Why this verdict"}</p><p class="dp">${esc(t.explanation)}</p>
    <p class="dby">${icon("cpu")}${esc(String(state.data.fleet.llm.providers || "model"))} · ${esc(source)} · ${esc(t.severity_for_this_workload)}, ${t.reachable ? "reachable" : "not reachable"}</p>` : "";
  return `<div class="detail${fresh}">${proofBoxes(it)}${why}${vetHtml(it, events)}${policyHtml(it)}${rawEvents(mine)}</div>`;
}

function workloadsCard(fleet, detail) {
  const { bays } = buildBoard(fleet, detail);
  const keys = new Set(bays.flatMap((b) => b.strips.map(stripKey)));
  if (state.openKey && !keys.has(state.openKey)) state.openKey = null;
  const hasRun = Boolean(detail);
  const body = bays.map((bay) => `<div class="bay-h">${icon("server")}${esc(bay.env.label || bay.env.name)}
      ${bay.env.provider ? `<span>· ${esc(bay.env.provider)}</span>` : ""}${bay.error ? `<span class="unreach">· unreachable: ${esc(bay.error)}</span>` : ""}</div>
    ${bay.strips.map((s) => rowHtml(s, bay, hasRun)).join("") || `<div class="empty">No workloads here</div>`}`).join("");
  return `<section class="card" id="workloads"><div class="card-h"><h2>Workloads</h2>
      <span class="more">${hasRun ? "Most exposed first" : plural(fleet.workloads.length, "workload")}</span></div>
    ${body || `<div class="empty">No targets in fleet.yaml</div>`}</section>`;
}

// ------------------------------------------------------------------ feed and advisories

const FEED_ICONS = {
  match: "alert", triage: "cpu", vet: "shield-check", policy: "scroll", change: "commit", build: "flask",
  canary: "flask", promote: "rocket", rollback: "refresh", mitigate: "shield-check", probe: "radar",
  discover: "server", inventory: "server", watch: "alert", rank: "scroll", error: "x",
};
const FEED_TONE = { ok: "ok", fail: "bad", warn: "warn", ai: "ai", info: "mid", pending: "mid" };

function feedCard(detail) {
  const events = detail ? [...detail.events].sort((a, b) => b.ts - a.ts || b.id - a.id).slice(0, FEED_LIMIT) : [];
  const names = new Map((detail?.items ?? []).map((i) => [i.id, i.workload.name]));
  const items = events.map((e) => `<div class="item">${icon(FEED_ICONS[e.step] || "scroll", FEED_TONE[e.status] || "mid")}
      <div><p class="a">${esc(e.title)}</p><p class="b">${esc(e.item_id ? names.get(e.item_id) ?? e.step : e.step)}</p><p class="c">${clock(e.ts)}</p></div></div>`).join("");
  return `<section class="card feed" id="log"><div class="card-h"><h2>Decision log</h2>${icon("scroll", "mid")}</div>
    ${items || `<div class="empty">No decisions yet.</div>`}</section>`;
}

const SEV_DOT = { critical: "var(--red-400)", high: "var(--amber-400)" };

function advisoriesCard(runs) {
  const rows = runs.map((r) => {
    const text = ticketSummary(r);
    const cls = /refused|failed|error/i.test(text) ? "vuln" : /needs/.test(text) ? "wait" : /safe/.test(text) ? "safe" : "queued";
    return `<button type="button" class="row ${r.id === state.selectedRun ? "sel" : ""}" data-run="${r.id}" aria-pressed="${r.id === state.selectedRun}">
      <span class="l"><span class="dot" style="background:${SEV_DOT[r.severity] ?? ""}"></span>
        <span><span class="nm" style="display:block">${esc(r.summary || r.title)}</span>
        <span class="sub" style="display:block">${esc(r.advisory_id)}${r.severity ? ` · ${esc(r.severity)}` : ""} · ${ago(r.started)}</span></span></span>
      ${pill(text, cls)}</button>`;
  }).join("");
  return `<section class="card" id="advisories"><div class="card-h"><h2>Advisories</h2><span class="more">${plural(runs.length, "run")}</span></div>
    ${rows || `<div class="empty">None yet. Use Simulate advisory.</div>`}</section>`;
}

function renderBoard({ fleet, runs, detail }) {
  const envLabel = (target) => fleet.environments.find((e) => e.name === target)?.label || target;
  const cards = decisions(detail).map((it) => decisionCard(it, detail.events, envLabel(it.workload.target))).join("");
  const html = `<div class="grid"><div class="c3">${cards}${workloadsCard(fleet, detail)}</div>
    <div class="c2">${feedCard(detail)}${advisoriesCard(runs)}</div></div>`;
  state.justOpened = false;
  setHtml("#board", html);
}

function render() {
  if (!state.data) return;
  renderChrome(state.data);
  renderHero(state.data);
  renderBoard(state.data);
}

// ------------------------------------------------------------------ loop

async function tick() {
  if (busy) { again = true; return; }
  busy = true;
  try {
    const [fleet, runs, scenarios] = await Promise.all([api("/api/fleet"), api("/api/runs"), api("/api/scenarios")]);
    const before = state.selectedRun;
    Object.assign(state, pickRun(runs, state.selectedRun, state.pinned));
    if (state.selectedRun !== before) { state.openKey = null; state.openEvents.clear(); }
    const detail = state.selectedRun === null ? null : await api(`/api/runs/${state.selectedRun}`);
    state.data = { fleet, runs, scenarios, detail };
    render();
    if (Date.now() > state.errorUntil) $("#errors").hidden = true;
  } catch (e) {
    showError(`Could not reach PatchPilot: ${e.message}`);
  } finally {
    busy = false;
    if (again) { again = false; tick(); }
  }
}

async function act(key, work) {
  state.inFlight.add(key);
  render();
  try { await work(); } catch (e) { showError(e.message, ACTION_ERROR_MS); }
  state.inFlight.delete(key);
  tick();
}

function setMenu(open) {
  state.menuOpen = open;
  $("#scenarios").hidden = !open;
  $("#simulate").setAttribute("aria-expanded", String(open));
  if (open) $("#scenarios button")?.focus();
}

document.addEventListener("click", (ev) => {
  const el = ev.target.closest("#simulate,[data-scenario],[data-run],[data-approve],[data-reject],#probe,#refresh,.row[data-key]");
  if (state.menuOpen && !ev.target.closest("#scenarios,#simulate")) setMenu(false);
  if (!el) return;
  if (el.id === "simulate") {
    setMenu(!state.menuOpen);
  } else if (el.dataset.scenario) {
    setMenu(false);
    act(`scenario:${el.dataset.scenario}`, async () => {
      await api(`/api/scenarios/${encodeURIComponent(el.dataset.scenario)}`, { method: "POST" });
      state.pinned = false;
    });
  } else if (el.dataset.run) {
    state.selectedRun = Number(el.dataset.run);
    state.pinned = true;
    state.openKey = null;
    state.openEvents.clear();
    tick();
  } else if (el.dataset.approve) {
    act(`approve:${el.dataset.approve}`, () => api(`/api/items/${el.dataset.approve}/approve`, { method: "POST" }));
  } else if (el.dataset.reject) {
    act(`reject:${el.dataset.reject}`, () => api(`/api/items/${el.dataset.reject}/reject`, { method: "POST" }));
  } else if (el.id === "probe") {
    el.disabled = true;
    el.querySelector("span").textContent = "Probing";
    act("probe", () => api("/api/probe", { method: "POST" })).finally(() => { el.disabled = false; el.querySelector("span").textContent = "Probe fleet"; });
  } else if (el.id === "refresh") {
    el.disabled = true;
    act("refresh", () => api("/api/fleet?refresh=true")).finally(() => { el.disabled = false; });
  } else if (el.dataset.key) {
    state.openKey = state.openKey === el.dataset.key ? null : el.dataset.key;
    state.justOpened = state.openKey !== null;
    render();
  }
});

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && state.menuOpen) { setMenu(false); $("#simulate").focus(); }
});

document.addEventListener("toggle", (ev) => {
  const id = Number(ev.target.dataset?.ev);
  if (!id) return;
  if (ev.target.open) state.openEvents.add(id); else state.openEvents.delete(id);
}, true);

tick();
setInterval(tick, REFRESH_MS);
