const state = {
  auth: sessionStorage.getItem("ash-auth") || "",
  authType: sessionStorage.getItem("ash-auth-type") || "key",
  data: { cases: [], agents: [], routes: [], invocations: [], approvals: [], audit: [], workflows: [] },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c]));
const short = (value) => value ? `${String(value).slice(0, 13)}${String(value).length > 13 ? "…" : ""}` : "—";
const badge = (value) => `<span class="badge ${esc(String(value).toLowerCase())}">${esc(value)}</span>`;
const empty = (message) => `<div class="empty">${esc(message)}</div>`;

function headers() {
  if (!state.auth) return { "Content-Type": "application/json" };
  return { "Content-Type": "application/json", [state.authType === "token" ? "Authorization" : "X-API-Key"]: state.authType === "token" ? `Bearer ${state.auth}` : state.auth };
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...headers(), ...(options.headers || {}) } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || body.error || `Request failed (${response.status})`);
  }
  if (response.status === 204) return null;
  return response.json();
}

async function optional(path, fallback) {
  try { return await api(path); } catch { return fallback; }
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(node.timer);
  node.timer = setTimeout(() => node.classList.remove("show"), 2800);
}

function caseRows(cases) {
  if (!cases.length) return empty("No investigations match this view.");
  return `<table><thead><tr><th>Investigation</th><th>Severity</th><th>State</th><th>Owner</th><th>Updated</th></tr></thead><tbody>${cases.map((item) => `<tr><td><div class="title-cell"><strong>${esc(item.title)}</strong><small>${esc(item.id)}</small></div></td><td>${badge(item.severity)}</td><td>${badge(item.status)}</td><td>${esc(item.created_by)}</td><td>${formatTime(item.updated_at)}</td></tr>`).join("")}</tbody></table>`;
}

function invocationRows(items) {
  if (!items.length) return empty("No external-agent invocations have been recorded.");
  return `<table><thead><tr><th>Invocation</th><th>Capability</th><th>Agent</th><th>State</th><th>Attempts</th><th>Latency</th><th>Created</th></tr></thead><tbody>${items.map((item) => `<tr><td><div class="title-cell"><strong class="mono">${esc(short(item.id))}</strong><small>${esc(short(item.idempotency_key))}</small></div></td><td>${esc(item.capability)}</td><td class="mono">${esc(short(item.agent_id))}</td><td>${badge(item.status)}</td><td>${item.attempts}</td><td>${item.duration_ms == null ? "—" : `${Number(item.duration_ms).toFixed(1)} ms`}</td><td>${formatTime(item.created_at)}</td></tr>`).join("")}</tbody></table>`;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function renderMetrics() {
  const { cases, agents, invocations, approvals } = state.data;
  const failed = invocations.filter((i) => i.status === "failed").length;
  const completed = invocations.filter((i) => i.status === "completed").length;
  const success = invocations.length ? Math.round((completed / invocations.length) * 100) : 100;
  const pending = approvals.filter((a) => a.status === "pending").length;
  const metrics = [
    ["Open investigations", cases.filter((c) => !["resolved", "closed"].includes(c.status)).length, `${cases.length} total durable cases`, 68],
    ["External agents", agents.filter((a) => a.enabled).length, `${agents.filter((a) => a.status === "healthy").length} healthy`, 82],
    ["Execution success", `${success}%`, `${completed} complete · ${failed} failed`, success],
    ["Pending decisions", pending, "Human approval required", pending ? 45 : 100],
  ];
  $("#metricGrid").innerHTML = metrics.map(([label, value, note, width]) => `<article class="metric"><div class="metric-head"><span>${label}</span><span>LIVE</span></div><strong>${value}</strong><p>${note}</p><div class="metric-line"><i style="width:${Math.max(4, width)}%"></i></div></article>`).join("");
}

function renderOverview() {
  const { cases, invocations, approvals } = state.data;
  $("#recentCases").innerHTML = caseRows(cases.slice(0, 7));
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  cases.forEach((c) => { counts[c.severity] = (counts[c.severity] || 0) + 1; });
  const total = Math.max(1, cases.length);
  $("#postureChart").innerHTML = `<div class="posture-content"><div class="posture-total"><div><strong>${cases.length}</strong><span> cases in view</span></div><span>severity mix</span></div>${[["Critical", counts.critical, "high"], ["High", counts.high, "high"], ["Medium", counts.medium, "medium"], ["Low", counts.low, "low"]].map(([name, count, cls]) => `<div class="bar-row ${cls}"><span>${name}</span><div class="bar"><i style="width:${Math.max(count ? 8 : 0, count / total * 100)}%"></i></div><strong>${count}</strong></div>`).join("")}</div>`;
  renderApprovals("#approvalPreview", approvals.filter((a) => a.status === "pending").slice(0, 3));
  $("#activityTimeline").innerHTML = invocations.length ? `<div class="activity-list">${invocations.slice(0, 4).map((item) => `<article class="activity"><div class="activity-top"><span class="mono">${esc(short(item.id))}</span>${badge(item.status)}</div><strong>${esc(item.capability)}</strong><small>${formatTime(item.updated_at)} · ${item.duration_ms == null ? "pending" : `${Number(item.duration_ms).toFixed(1)} ms`}</small></article>`).join("")}</div>` : empty("External-agent activity will appear here after the first dispatch.");
}

function renderApprovals(selector, items) {
  $(selector).innerHTML = items.length ? items.map((item) => `<article class="approval-card"><strong>${esc(item.tool)}</strong><small>${esc(short(item.id))} · ${esc(item.risk_tier)} risk · requested by ${esc(item.requested_by)}</small><div class="actions"><button class="button primary small" data-approval="${esc(item.id)}" data-decision="true">Approve</button><button class="button danger small" data-approval="${esc(item.id)}" data-decision="false">Reject</button></div></article>`).join("") : empty("No decisions require human review.");
  $$(`${selector} [data-approval]`).forEach((button) => button.onclick = () => decideApproval(button.dataset.approval, button.dataset.decision === "true"));
}

function renderCases() {
  const needle = $("#caseSearch").value.toLowerCase();
  const status = $("#caseStatus").value;
  const rows = state.data.cases.filter((item) => (!needle || JSON.stringify(item).toLowerCase().includes(needle)) && (!status || item.status === status));
  $("#caseTable").innerHTML = caseRows(rows);
}

function renderAgents() {
  const agents = state.data.agents;
  $("#agentRegistry").innerHTML = agents.length ? agents.map((agent) => `<article class="agent-row"><div class="agent-name"><span class="transport">${esc(agent.transport)}</span><div><strong>${esc(agent.name)}</strong><small class="mono">${esc(agent.id)} · v${esc(agent.version)}</small></div></div><div class="chips">${agent.capabilities.map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</div><div class="agent-state"><i class="dot ${esc(agent.status)}"></i>${esc(agent.status)}</div><div class="agent-actions"><button class="icon-button" data-health="${esc(agent.id)}" title="Run health check" aria-label="Run health check">↻</button><button class="button secondary small" data-route="${esc(agent.id)}" data-capability="${esc(agent.capabilities[0] || "")}">Route</button><button class="toggle ${agent.enabled ? "on" : ""}" data-toggle="${esc(agent.id)}" data-enabled="${agent.enabled}" title="${agent.enabled ? "Disable" : "Enable"} agent" aria-label="${agent.enabled ? "Disable" : "Enable"} agent"><i></i></button></div></article>`).join("") : empty("No external agents registered. Register one to begin capability routing.");
  $("#routeList").innerHTML = state.data.routes.length ? state.data.routes.map((route) => `<article class="route-item"><strong>${esc(route.capability)}</strong><small>${esc(route.strategy)} · ${route.agent_ids.length} target${route.agent_ids.length === 1 ? "" : "s"}</small></article>`).join("") : empty("No explicit routes. Discovery fallback is active.");
  $$('[data-health]').forEach((b) => b.onclick = () => mutate(`/api/v1/external-agents/${b.dataset.health}/health`, { method: "POST" }, "Health status updated"));
  $$('[data-toggle]').forEach((b) => b.onclick = () => mutate(`/api/v1/external-agents/${b.dataset.toggle}`, { method: "PATCH", body: JSON.stringify({ enabled: b.dataset.enabled !== "true" }) }, b.dataset.enabled === "true" ? "Agent disabled" : "Agent enabled"));
  $$('[data-route]').forEach((b) => b.onclick = () => mutate(`/api/v1/external-agent-routes/${b.dataset.capability}`, { method: "PUT", body: JSON.stringify({ capability: b.dataset.capability, agent_ids: [b.dataset.route], strategy: "priority", enabled: true }) }, "Capability route saved"));
}

function renderInvocations() {
  const needle = $("#invocationSearch").value.toLowerCase();
  const status = $("#invocationStatus").value;
  const rows = state.data.invocations.filter((item) => (!needle || JSON.stringify(item).toLowerCase().includes(needle)) && (!status || item.status === status));
  $("#invocationTable").innerHTML = invocationRows(rows);
}

function renderGovernance() {
  const pending = state.data.approvals.filter((a) => a.status === "pending");
  renderApprovals("#approvalList", pending);
  $("#auditTable").innerHTML = state.data.audit.length ? `<table><thead><tr><th>Sequence</th><th>Action</th><th>Actor</th><th>Target</th><th>Time</th></tr></thead><tbody>${state.data.audit.slice(-50).reverse().map((item) => `<tr><td class="mono">${item.seq}</td><td>${esc(item.action)}</td><td>${esc(item.actor)}</td><td class="mono">${esc(short(item.target))}</td><td>${formatTime(item.ts)}</td></tr>`).join("")}</tbody></table>` : empty("Audit access is unavailable for this role or no records exist.");
  $("#chainState").textContent = state.data.auditVerify?.ok ? `Audit chain verified · ${state.data.auditVerify.entries} entries` : "Audit verification unavailable";
}

function render() {
  renderMetrics(); renderOverview(); renderCases(); renderAgents(); renderInvocations(); renderGovernance();
  const pending = state.data.approvals.filter((a) => a.status === "pending").length;
  $("#caseCountNav").textContent = state.data.cases.length;
  $("#agentCountNav").textContent = state.data.agents.length;
  $("#approvalCountNav").textContent = pending;
  $("#approvalCount").textContent = pending;
}

async function refresh(showMessage = false) {
  const health = await api("/health");
  const [cases, agents, routes, invocations, approvals, audit, auditVerify, workflows] = await Promise.all([
    optional("/api/v1/cases?limit=200", []), optional("/api/v1/external-agents", []),
    optional("/api/v1/external-agent-routes", []), optional("/api/v1/external-agent-invocations?limit=500", []),
    optional("/api/v1/approvals?status=pending", []), optional("/api/v1/audit?limit=200", []),
    optional("/api/v1/audit/verify", null), optional("/api/v1/workflows", []),
  ]);
  state.data = { cases, agents, routes, invocations, approvals, audit, auditVerify, workflows };
  $("#environment").textContent = health.environment;
  $("#systemDot").className = "good";
  $("#systemLabel").textContent = "Control plane online";
  $("#systemDetail").textContent = `ASH ${health.version}`;
  $("#lastSync").textContent = `Synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  render();
  if (showMessage) toast("Workspace synchronized");
}

async function connectWithKey(event) {
  event.preventDefault();
  state.auth = $("#apiKey").value.trim(); state.authType = "key";
  await completeLogin();
}

async function connectWithUser(event) {
  event.preventDefault();
  try {
    const result = await api("/api/v1/auth/token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: $("#username").value.trim(), password: $("#password").value }) });
    state.auth = result.access_token; state.authType = "token";
    await completeLogin();
  } catch (error) { toast(error.message); }
}

async function completeLogin() {
  try {
    await api("/api/v1/auth/me");
    sessionStorage.setItem("ash-auth", state.auth); sessionStorage.setItem("ash-auth-type", state.authType);
    $("#loginLayer").hidden = true; $("#workspace").hidden = false;
    await refresh();
  } catch (error) { state.auth = ""; toast(error.message); }
}

async function mutate(path, options, message) {
  try { await api(path, options); await refresh(); toast(message); } catch (error) { toast(error.message); }
}

async function decideApproval(id, approve) {
  await mutate(`/api/v1/approvals/${id}/decide`, { method: "POST", body: JSON.stringify({ approve, note: "Decision from ASH operator console", auto_resume: true }) }, approve ? "Action approved" : "Action rejected");
}

function selectView(name) {
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `${name}View`));
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const titles = { overview: "Command center", cases: "Investigations", agents: "Agent registry", invocations: "Invocation ledger", governance: "Governance" };
  $("#pageTitle").textContent = titles[name]; $("#crumb").textContent = titles[name].toUpperCase();
  $("#primaryAction").textContent = name === "agents" ? "Register agent" : name === "invocations" ? "Dispatch work" : "Ingest alert";
  $("#primaryAction").onclick = name === "agents" ? () => $("#agentDialog").showModal() : name === "invocations" ? () => $("#dispatchDialog").showModal() : () => $("#alertDialog").showModal();
}

$("#keyLogin").addEventListener("submit", connectWithKey);
$("#userLogin").addEventListener("submit", connectWithUser);
$$('[data-login]').forEach((button) => button.onclick = () => {
  $$('[data-login]').forEach((b) => b.classList.toggle("active", b === button));
  $("#keyLogin").hidden = button.dataset.login !== "key"; $("#userLogin").hidden = button.dataset.login !== "user";
});
$$('[data-view]').forEach((button) => button.onclick = () => selectView(button.dataset.view));
$$('[data-go]').forEach((button) => button.onclick = () => selectView(button.dataset.go));
$$('[data-close]').forEach((button) => button.onclick = () => $(`#${button.dataset.close}`).close());
$$('[data-action="ingest"]').forEach((button) => button.onclick = () => $("#alertDialog").showModal());
$("#refreshButton").onclick = () => refresh(true).catch((error) => toast(error.message));
$("#registerButton").onclick = () => $("#agentDialog").showModal();
$("#dispatchButton").onclick = () => $("#dispatchDialog").showModal();
$("#overviewSearch").oninput = (event) => { const q = event.target.value.toLowerCase(); $("#recentCases").innerHTML = caseRows(state.data.cases.filter((c) => JSON.stringify(c).toLowerCase().includes(q)).slice(0, 7)); };
$("#caseSearch").oninput = renderCases; $("#caseStatus").onchange = renderCases;
$("#invocationSearch").oninput = renderInvocations; $("#invocationStatus").onchange = renderInvocations;
$("#primaryAction").onclick = () => $("#alertDialog").showModal();

$("#alertForm").addEventListener("submit", async (event) => {
  event.preventDefault(); const data = new FormData(event.target);
  const body = { title: data.get("title"), source: data.get("source"), severity: data.get("severity"), description: data.get("description"), asset_id: data.get("asset_id") || null, indicators: String(data.get("indicators") || "").split(",").map((v) => v.trim()).filter(Boolean) };
  try { await api("/api/v1/alerts", { method: "POST", body: JSON.stringify(body) }); $("#alertDialog").close(); await refresh(); toast("Alert persisted as a governed case"); } catch (error) { toast(error.message); }
});

$("#agentForm").addEventListener("submit", async (event) => {
  event.preventDefault(); const data = new FormData(event.target);
  const body = { name: data.get("name"), version: data.get("version"), protocol_version: "1.0", capabilities: [data.get("capability")], transport: data.get("transport"), endpoint: data.get("endpoint"), health_endpoint: data.get("health_endpoint") || null, scopes: String(data.get("scopes") || "").split(",").map((v) => v.trim()).filter(Boolean) };
  try { const result = await api("/api/v1/external-agents", { method: "POST", body: JSON.stringify(body) }); $("#agentDialog").close(); $("#credentialValue").textContent = result.api_key; $("#credentialDialog").showModal(); await refresh(); } catch (error) { toast(error.message); }
});

$("#dispatchForm").addEventListener("submit", async (event) => {
  event.preventDefault(); const data = new FormData(event.target);
  const body = { capability: data.get("capability"), event: { id: data.get("event_id"), severity: data.get("severity"), title: data.get("title") }, idempotency_key: data.get("idempotency_key") || null, asynchronous: Boolean(data.get("asynchronous")) };
  try { await api("/api/v1/external-agent-dispatch", { method: "POST", body: JSON.stringify(body) }); $("#dispatchDialog").close(); await refresh(); selectView("invocations"); toast("Work dispatched through the agent runtime"); } catch (error) { toast(error.message); }
});

if (state.auth) { $("#loginLayer").hidden = true; $("#workspace").hidden = false; refresh().catch(() => { state.auth = ""; sessionStorage.clear(); $("#loginLayer").hidden = false; $("#workspace").hidden = true; }); }
