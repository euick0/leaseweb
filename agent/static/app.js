// PatchPilot dashboard: fetches the decision log every 2 s and draws the fleet as flight strips.
// What a strip says is decided in model.js; this file only turns it into HTML and handles clicks.
import { esc, buildBoard, routeStages, verdictFor, idleVerdict, actionLabel, ticketSummary, pickRun } from "/static/model.js";

const REFRESH_MS = 2000;
const $ = (sel) => document.querySelector(sel);

const state = {
  selectedRun: null,     // run id shown on the board; null follows the newest
  follow: null,          // newest run id when an advisory was triggered; jump to the run it creates
  newestRun: 0,
  openKey: null,         // "item:<id>" or "wl:<workload id>" of the strip pulled out
  justOpened: false,     // animate the detail only on the render right after it opens
  openEvents: new Set(), // decision-log entries expanded by the viewer
};
let busy = false, again = false, lastHtml = "";

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `${res.status} ${res.statusText}`);
  return res.json();
}

function showError(message) {
  const bar = $("#errors");
  bar.textContent = message;
  bar.hidden = false;
}
const clearError = () => { $("#errors").hidden = true; };

const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const imageTag = (image) => String(image || "").split("/").pop();

// ------------------------------------------------------------------ render

function renderHeader(fleet, scenarios) {
  $("#model").innerHTML = `Model: <b>${esc(fleet.llm.providers)}</b>${fleet.llm.mode === "cache" ? ", cached answers" : ""}`;
  const html = `<span>Simulate</span>` + scenarios.map((s) =>
    `<button type="button" class="${s.triggered ? "done" : ""}" data-scenario="${esc(s.name)}" title="${esc(s.summary)}">${esc(s.name)}</button>`).join("");
  if ($("#scenarios").innerHTML !== html) $("#scenarios").innerHTML = html;
}

function renderTickets(runs) {
  const html = runs.map((r) => {
    const sev = r.severity ? `<span class="${["critical", "high"].includes(r.severity) ? "sev" : ""}">${esc(r.severity)}</span>, ` : "";
    return `<button type="button" class="ticket ${r.id === state.selectedRun ? "on" : ""}" data-run="${r.id}" aria-pressed="${r.id === state.selectedRun}">
      <b>${esc(r.advisory_id)}</b><small>${sev}${esc(ticketSummary(r))}</small></button>`;
  }).join("");
  if ($("#tickets").innerHTML !== html) $("#tickets").innerHTML = html;
}

function headline(fleet, detail) {
  if (!detail) {
    return `<div class="adv"><h1>No advisory yet</h1>
      <p>Pick an advisory under Simulate to watch PatchPilot work through the fleet.</p></div>`;
  }
  const { run, items } = detail;
  const count = items.length
    ? `Running in ${items.length} of ${plural(fleet.workloads.length, "workload")}`
    : run.status === "running" ? "Matching the fleet" : "No workload carries it";
  return `<div class="adv"><p class="id">${esc(run.advisory_id)}</p><h1>${esc(run.summary || run.title)}</h1><p class="count">${esc(count)}</p>
    ${run.outcome ? `<p>${esc(run.outcome)}</p>` : ""}</div>`;
}

function componentCell(item, hasRun) {
  if (!item) return `<div class="comp">${hasRun ? "Not affected by this advisory" : "Waiting for an advisory"}</div>`;
  const c = item.component;
  const fix = item.fixed_version ? `, fix ${esc(item.fixed_version)}` : ", no fix released";
  return `<div class="comp"><b>${esc(c.name)}</b> ${esc(c.version)}${fix}</div>`;
}

function routeCell(item, events) {
  const stages = routeStages(item, events);
  return `<div class="route" aria-hidden="true">${stages.map((s) => `<i class="${s.state}"></i>`).join("")}</div>
    <div class="route-l">${stages.map((s) => `<span>${esc(s.label)}</span>`).join("")}</div>`;
}

function verdictCell(strip, hasRun) {
  if (!strip.item) {
    if (hasRun) return `<span class="v quiet">Not affected</span>`;
    const v = idleVerdict(strip.workload);
    return `<span class="v ${v.kind}">${esc(v.label)}</span>${v.note ? `<span class="when">${esc(v.note)}</span>` : ""}`;
  }
  const v = verdictFor(strip.item);
  return `${v.struck ? `<span class="struck">${esc(v.struck)}</span>` : ""}<span class="v ${v.kind}">${esc(v.label)}</span>
    ${v.note ? `<span class="when">${esc(v.note)}</span>` : ""}`;
}

const stripKey = (s) => (s.item ? `item:${s.item.id}` : `wl:${s.workload.id}`);

function renderStrip(strip, colour, detail, events) {
  const w = strip.workload, it = strip.item, hasRun = Boolean(detail);
  const key = stripKey(strip), open = key === state.openKey;
  const kind = it ? verdictFor(it).kind : "";
  const cls = ["strip", `c${colour}`, hasRun && !it ? "faded" : "", kind === "wait" ? "hatch" : "", open ? "sel" : ""].filter(Boolean).join(" ");
  const itemEvents = it ? events.filter((e) => e.item_id === it.id) : [];
  return `<div class="${cls}" role="button" tabindex="0" aria-expanded="${open}" data-key="${esc(key)}">
      <div class="band"></div>
      <div><div class="call">${esc(w.name)}</div><div class="sub">repo ${esc(w.repo || "unlinked")}, image ${esc(imageTag(w.image))}</div></div>
      <div><div class="expo">${w.internet_exposed ? `<span class="pub">Public</span>` : `<span class="int">Internal</span>`}</div>
        <div class="sub">${esc(w.exposure)}</div></div>
      <div>${componentCell(it, hasRun)}${it ? routeCell(it, itemEvents) : ""}</div>
      <div class="verdict">${verdictCell(strip, hasRun)}</div>
    </div>${open ? renderDetail(strip, detail, events) : ""}`;
}

// ------------------------------------------------------------------ detail

function proofSection(item) {
  const v = verdictFor(item), p = item.proof;
  if (v.struck) {
    return `<section><h3>How we know</h3>
      <div class="big-proof"><span class="struck">${esc(v.struck)}</span><span class="g">${esc(v.label)}</span></div>
      <p>${esc(p.after.detail || v.note)}</p><div class="who">${esc(p.level)}, ${esc(p.after.via)} path</div></section>`;
  }
  if (p?.level === "re-scan + health") {
    return `<section><h3>How we know</h3><p>No exploit probe exists for this advisory. A re-scan found ${esc(p.rescan)} and the health check ${p.health ? "passed" : "failed"}.</p></section>`;
  }
  const failed = ["failed", "rolled_back", "blocked"].includes(item.status) && item.outcome;
  return `<section><h3>How we know</h3><p>${failed ? esc(item.outcome) : "Not proven yet. The exploit probe runs again after the action."}</p></section>`;
}

function decisionSection(item) {
  const d = item.decision;
  const label = actionLabel(item);
  const buttons = label
    ? `<div class="actions"><button type="button" class="btn ok" data-approve="${item.id}">${esc(label)}</button>
         <button type="button" class="btn" data-reject="${item.id}">Reject</button></div>` : "";
  if (!d) return buttons;
  const how = { auto: "allowed automatically", needs_approval: "needs a person to approve", block: "blocked", queue: "queued" }[d.decision] || d.decision;
  const what = d.action === "mitigate" ? "Shield at the gateway" : d.action === "patch" ? "Patch the dependency" : d.action;
  return `<section><h3>Policy</h3><p><b>${esc(what)}</b>, ${esc(how)}. ${esc(d.reason)}</p>${buttons}</section>`;
}

function whySection(item) {
  const t = item.triage;
  if (!t) return `<section><h3>Why</h3><p>The model has not triaged this workload yet.</p></section>`;
  const source = { live: "live answer", cache: "cached answer", fallback: "fallback answer", seed: "seeded answer" }[item.triage_source] || item.triage_source;
  return `<section><h3>${item.rank === 1 ? "Why it went first" : `Why it ranked ${esc(item.rank ?? "")}`}</h3>
    <p>${esc(t.explanation)}</p>
    <div class="who">${esc(t.severity_for_this_workload)} for this workload, ${t.reachable ? "reachable" : "not reachable"}, ${esc(source)}</div></section>`;
}

function vetSection(item, events) {
  const vet = events.filter((e) => e.step === "vet" && e.data && e.data.verdict).pop();
  if (!vet) {
    const text = item.fixed_version ? "Not checked yet." : "No fix has been released, so there is nothing to check.";
    return `<section><h3>Was the fix safe?</h3><p>${text}</p></section>`;
  }
  const d = vet.data;
  const flags = (d.flags || []).filter((f) => f.severity === "hard" || f.severity === "soft");
  const evidence = flags.map((f) => `<pre class="evidence">${esc(f.file || "")}: ${esc(f.message)}${(f.lines || []).map((l) => `\n+ ${esc(l)}`).join("")}</pre>`).join("")
    || `<pre class="evidence clean">No hard or soft flags</pre>`;
  const reviews = (d.reviews || []).filter((r) => r.review && r.review.suspicious)
    .map((r) => `<div class="who">Model review of ${esc(r.file)} (${esc(r.source)}): ${esc(r.review.explanation)}</div>`).join("");
  return `<section><h3>Was the fix safe?</h3>
    <p>${esc(d.artifact)} ${esc(d.to_version)} was judged <b>${esc(d.verdict)}</b>${d.cached ? ", reusing an earlier check" : ""}.</p>${evidence}${reviews}</section>`;
}

function logSection(events) {
  const rows = events.map((e) => {
    const body = [e.detail, e.data ? JSON.stringify(e.data, null, 2) : ""].filter(Boolean).join("\n\n");
    const head = `<b>${esc(e.step)}</b> ${esc(e.title)}`;
    const content = body
      ? `<details data-ev="${e.id}"${state.openEvents.has(e.id) ? " open" : ""}><summary>${head}</summary><pre>${esc(body)}</pre></details>`
      : `<span>${head}</span>`;
    return `<li class="${esc(e.status)}"><time>${clock(e.ts)}</time>${content}</li>`;
  }).join("");
  return `<section><h3>Decision log</h3><ol class="log">${rows}</ol></section>`;
}

function renderDetail(strip, detail, events) {
  const fresh = state.justOpened ? " fresh" : "";
  const it = strip.item;
  if (!it) {
    const w = strip.workload;
    const probes = (w.probes || []).map((p) => `<li><time>${clock(p.ts)}</time><span><b>${esc(p.probe)}</b> ${esc(p.result)}, ${esc(p.via)} path</span></li>`).join("");
    return `<div class="detail${fresh}">
      <section><h3>Last probes</h3>${probes ? `<ol class="log">${probes}</ol>` : `<p>Not probed yet. Use Probe fleet.</p>`}</section>
      <section><h3>Where it runs</h3><p>${esc(w.target)}${w.provider ? `, ${esc(w.provider)}` : ""}${w.region ? `, ${esc(w.region)}` : ""}. ${esc(w.exposure)}.</p>
        <div class="who">image ${esc(w.image)}</div></section>
      <section>${detail ? `<h3>This advisory</h3><p>This workload does not carry the affected package.</p>` : ""}</section>
    </div>`;
  }
  const itemEvents = events.filter((e) => e.item_id === it.id);
  const logEvents = events.filter((e) => e.item_id === it.id || !e.item_id);
  return `<div class="detail${fresh}">
    <div>${proofSection(it)}${decisionSection(it)}</div>
    <div>${whySection(it)}${vetSection(it, itemEvents)}</div>
    <div>${logSection(logEvents)}</div>
  </div>`;
}

// ------------------------------------------------------------------ board

function renderBoard(fleet, detail) {
  const events = detail?.events ?? [];
  const { bays } = buildBoard(fleet, detail);
  const keys = new Set(bays.flatMap((b) => b.strips.map(stripKey)));
  if (state.openKey && !keys.has(state.openKey)) state.openKey = null;
  const html = headline(fleet, detail) + bays.map((bay) => `<section class="bay">
      <h2 class="bay-name">${esc(bay.env.label || bay.env.name)}<span>${esc(bay.env.provider || bay.env.kind || "")}${bay.env.provider || bay.env.kind ? ", " : ""}${plural(bay.strips.length, "workload")}</span></h2>
      ${bay.error ? `<p class="unreachable">Unreachable: ${esc(bay.error)}</p>` : ""}
      <div class="rack">${bay.strips.map((s) => renderStrip(s, bay.colour, detail, events)).join("")}</div>
    </section>`).join("") + (bays.length ? "" : `<p>No targets in fleet.yaml.</p>`);
  state.justOpened = false;
  if (html === lastHtml) return;
  const focus = focusSelector();
  $("#board-body").innerHTML = html;
  lastHtml = html;
  if (focus) document.querySelector(focus)?.focus({ preventScroll: true });
}

// keep keyboard focus on the same control across re-renders
function focusSelector() {
  const el = document.activeElement;
  if (!el || !$("#board-body").contains(el)) return null;
  for (const attr of ["key", "approve", "reject", "ev"]) {
    if (el.dataset?.[attr]) return `[data-${attr}="${CSS.escape(el.dataset[attr])}"]`;
  }
  if (el.tagName === "SUMMARY" && el.parentElement?.dataset.ev) return `[data-ev="${el.parentElement.dataset.ev}"] > summary`;
  return null;
}

// ------------------------------------------------------------------ loop

async function tick() {
  if (busy) { again = true; return; }
  busy = true;
  try {
    const [fleet, runs, scenarios] = await Promise.all([api("/api/fleet"), api("/api/runs"), api("/api/scenarios")]);
    const before = state.selectedRun;
    Object.assign(state, pickRun(runs, state.selectedRun, state.follow));
    if (state.selectedRun !== before) { state.openKey = null; state.openEvents.clear(); }
    state.newestRun = runs[0]?.id ?? 0;
    const detail = state.selectedRun === null ? null : await api(`/api/runs/${state.selectedRun}`);
    renderHeader(fleet, scenarios);
    renderTickets(runs);
    renderBoard(fleet, detail);
    clearError();
  } catch (e) {
    showError(`Could not reach PatchPilot: ${e.message}`);
  } finally {
    busy = false;
    if (again) { again = false; tick(); }
  }
}

function toggleStrip(key) {
  state.openKey = state.openKey === key ? null : key;
  state.justOpened = state.openKey !== null;
  tick();
}

async function act(el, work) {
  el.disabled = true;
  try { await work(); } catch (e) { showError(e.message); } finally { el.disabled = false; }
  tick();
}

document.addEventListener("click", (ev) => {
  const el = ev.target.closest("[data-scenario],[data-run],[data-approve],[data-reject],#probe,#refresh,.strip");
  if (!el) return;
  if (el.dataset.scenario) {
    act(el, async () => {
      await api(`/api/scenarios/${encodeURIComponent(el.dataset.scenario)}`, { method: "POST" });
      state.follow = state.newestRun;
    });
  } else if (el.dataset.run) {
    state.selectedRun = Number(el.dataset.run); state.follow = null; state.openKey = null; state.openEvents.clear(); tick();
  } else if (el.dataset.approve) {
    act(el, () => api(`/api/items/${el.dataset.approve}/approve`, { method: "POST" }));
  } else if (el.dataset.reject) {
    act(el, () => api(`/api/items/${el.dataset.reject}/reject`, { method: "POST" }));
  } else if (el.id === "probe") {
    el.textContent = "Probing";
    act(el, () => api("/api/probe", { method: "POST" })).then(() => { el.textContent = "Probe fleet"; });
  } else if (el.id === "refresh") {
    act(el, () => api("/api/fleet?refresh=true"));
  } else if (el.classList.contains("strip")) {
    toggleStrip(el.dataset.key);
  }
});

document.addEventListener("keydown", (ev) => {
  const el = ev.target;
  if (!el.classList?.contains("strip") || (ev.key !== "Enter" && ev.key !== " ")) return;
  ev.preventDefault();
  toggleStrip(el.dataset.key);
});

document.addEventListener("toggle", (ev) => {
  const id = Number(ev.target.dataset?.ev);
  if (!id) return;
  if (ev.target.open) state.openEvents.add(id); else state.openEvents.delete(id);
}, true);

tick();
setInterval(tick, REFRESH_MS);
