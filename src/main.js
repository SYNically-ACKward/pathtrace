import "./styles.css";

let invoke = null;
let isTauri = false;

// ── Application state ──────────────────────────────────────────────────────
const state = {
  snapshot: null,
  trace: null,
  selectedInterface: null,
  lastUpdatedAt: Date.now(),
  history: [],
  activeRouteTab: "matched",
  activeMainTab: "trace",          // trace | timeline | diff | probes | coverage | simulate | report
  lastInterfaceSignature: "",
  error: "",
  // Feature 2: diff snapshots
  baselineSnapshot: null,
  diffResult: null,
  // Feature 3: timeline
  timeline: [],                    // array of {trace, ts}
  selectedTimelineIndex: null,
  // Feature 4: packet tests
  probeResult: null,
  probeRunning: false,
  // Feature 7: report
  reportFormat: "markdown",
  // Feature 8: redaction
  redactMode: false,
  // Feature 9: simulate
  simOverrides: {
    added_routes: [],
    removed_destinations: [],
    interface_states: [],
    dns_answer_override: null,
    metric_overrides: [],
  },
  simResult: null,
  // Feature 10: resolver tests
  resolverTestResults: null,
  resolverTestRunning: false,
  // Feature 1: explanation expanded state
  explanationExpanded: false,
};

// ── Demo data ──────────────────────────────────────────────────────────────
const demoSnapshot = {
  platform: "demo",
  updated_at: new Date().toISOString(),
  interfaces: [
    { name: "en0", status: "up", interface_type: "Wi-Fi", ipv4: "192.168.1.42", ipv6: null, mtu: 1500, ssid: "North-SOC", signal_strength: "-51 dBm", band: "5 GHz" },
    { name: "utun3", status: "up", interface_type: "VPN", ipv4: "10.8.0.4", ipv6: null, mtu: 1420, tunnel_protocol: "WireGuard / UDP", tunnel_endpoint: "vpn.corp.io:51820", encapsulation_overhead: 60, last_handshake: "12s ago" },
    { name: "en5", status: "up", interface_type: "Eth", ipv4: "10.0.1.12", ipv6: null, mtu: 1500 },
    { name: "en1", status: "down", interface_type: "Other", ipv4: null, ipv6: null, mtu: null },
  ],
  dns_resolvers: [
    { scope: "corp.internal", server: "10.8.0.1", port: 53, interface: "utun3", source: "split DNS" },
    { scope: "default", server: "1.1.1.1", port: 53, interface: "en0", source: "DHCP" },
    { scope: "default", server: "8.8.8.8", port: 53, interface: "en0", source: "DHCP" },
  ],
  routes: [
    { destination: "10.0.0.0/8", gateway: "10.8.0.1", interface: "utun3", metric: 50, source: "VPN push", matched: true },
    { destination: "192.168.1.0/24", gateway: "link#", interface: "en0", metric: 1, source: "local link", matched: false },
    { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "en0", metric: 100, source: "DHCP", matched: false },
  ],
  firewall: { detectable: true, status: "pf detected", rules: [] },
  events: [
    { timestamp: new Date().toISOString(), category: "route", message: "default route stable via en0" },
    { timestamp: new Date(Date.now() - 20000).toISOString(), category: "vpn", message: "utun3 handshake refreshed" },
    { timestamp: new Date(Date.now() - 47000).toISOString(), category: "dns", message: "corp.internal resolver scoped to utun3" },
  ],
};

function buildDemoTrace(query) {
  const directIp = isIp(query) || isCidr(query);
  const resultIp = directIp ? query.split("/")[0] : query.endsWith("corp.internal") ? "10.22.14.88" : "104.18.32.47";
  const vpn = query.endsWith("corp.internal") || resultIp.startsWith("10.");
  const iface = vpn ? "utun3" : "en0";
  const matchedRoute = vpn
    ? { destination: "10.0.0.0/8", gateway: "10.8.0.1", interface: "utun3", metric: 50, source: "VPN push", matched: true }
    : { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "en0", metric: 100, source: "DHCP", matched: true };
  const routes = demoSnapshot.routes.map((r) => ({ ...r, matched: r.destination === matchedRoute.destination }));
  const egressIface = demoSnapshot.interfaces.find((i) => i.name === iface);

  const dns = directIp
    ? { required: false, query, resolver_used: null, status: "direct IP", result: resultIp, flow: [{ label: "destination", value: query, kind: "query" }], matched_rule: null, fallback_resolver: "1.1.1.1 (not used)", cache_status: "not applicable", ttl_remaining: null, failure_reason: null, tried_resolvers: [] }
    : { required: true, query, resolver_used: vpn ? "10.8.0.1:53" : "1.1.1.1:53", status: vpn ? "split-dns → VPN resolver" : "default resolver", result: resultIp, flow: [{ label: "query", value: query, kind: "query" }, { label: vpn ? "corp.internal resolver" : "default resolver", value: vpn ? "10.8.0.1:53" : "1.1.1.1:53", kind: "resolver" }, { label: "A record · 30s TTL", value: resultIp, kind: "resolved" }], matched_rule: vpn ? "*.corp.internal → utun3" : null, fallback_resolver: vpn ? "1.1.1.1 (not used)" : "8.8.8.8 (not used)", cache_status: "yes — 28s remaining", ttl_remaining: 28, failure_reason: null, tried_resolvers: [vpn ? "10.8.0.1:53" : "1.1.1.1:53"] };

  const explanation = {
    summary: vpn
      ? "Traffic will be tunneled through utun3 (WireGuard / UDP) with no detectable blocking rules. VPN encapsulation adds 60 bytes overhead."
      : "Traffic will egress via en0 (Wi-Fi). DNS resolved successfully. No blocking rules detected.",
    dns_explanation: {
      headline: dns.required ? (vpn ? "Split-DNS routed query to VPN resolver" : "Resolved via default resolver") : "No DNS lookup required",
      detail: dns.required ? `Query «${query}» routed via ${dns.resolver_used}, returned ${resultIp}.` : "Direct IP — DNS skipped.",
      severity: "ok",
    },
    route_explanation: {
      headline: `Route matched: ${matchedRoute.destination} → ${iface}`,
      detail: vpn ? "Matched VPN push route 10.0.0.0/8. Traffic encapsulated via WireGuard." : "Matched default route via gateway 192.168.1.1 on en0.",
      severity: vpn ? "info" : "ok",
    },
    egress_explanation: {
      headline: `Egress: ${iface} via ${egressIface.tunnel_protocol || "Wi-Fi 802.11ax"}`,
      detail: vpn ? `Tunnel endpoint: ${egressIface.tunnel_endpoint}. Protocol: WireGuard / UDP. MTU 1420 — clamping may apply.` : "MTU 1500. SSID: North-SOC, signal: -51 dBm.",
      severity: vpn ? "warn" : "ok",
    },
    firewall_explanation: {
      headline: "No blocking firewall rules matched",
      detail: "pf detected — no rules for this destination.",
      severity: "ok",
    },
    reason_codes: vpn
      ? [{ code: "VPN_TUNNEL", label: "Traffic tunneled through VPN", description: "Packet will be encapsulated via utun3 using WireGuard / UDP", severity: "info" }, { code: "MTU_LOW", label: "Low MTU detected", description: "Egress interface MTU is 1420 (< 1500). Path MTU clamping may apply.", severity: "warn" }, { code: "DNS_SPLIT", label: "Split-DNS policy applied", description: "Query routed via split-DNS rule: *.corp.internal → utun3", severity: "info" }]
      : [{ code: "DNS_OK", label: "DNS resolution successful", description: "Resolved to 104.18.32.47 via 1.1.1.1:53", severity: "ok" }],
  };

  const policy_conflicts = vpn
    ? [{ id: "MTU_LOW", severity: "warn", title: "Low MTU on VPN interface", description: "utun3 MTU is 1420. Large packets will be fragmented or clamped.", affected: ["utun3"] }]
    : [];

  const tunnel_coverage = {
    vpn_prefixes: vpn ? ["10.0.0.0/8"] : [],
    local_prefixes: ["192.168.1.0/24"],
    default_route_interface: "en0",
    default_captured_by_vpn: false,
    dns_scopes: [
      { scope: "corp.internal", servers: ["10.8.0.1:53"], interface: "utun3" },
      { scope: "default", servers: ["1.1.1.1:53", "8.8.8.8:53"], interface: "en0" },
    ],
    unknown_prefixes: [],
  };

  return {
    query, input_kind: directIp ? "Ip" : "Hostname", analyzed_at: new Date().toISOString(),
    dns, route: { status: vpn ? "tunneled via utun3" : "egress via en0", matched_interface: iface, matched_route: matchedRoute, routes, lookup_error: null },
    egress: { name: iface, interface_type: egressIface.interface_type, protocol: egressIface.tunnel_protocol || (iface === "en0" ? "Wi-Fi 802.11ax" : "physical Ethernet"), tunnel_endpoint: egressIface.tunnel_endpoint || null, source_ip: egressIface.ipv4, mtu: egressIface.mtu, mtu_warning: Number(egressIface.mtu) < 1500, encapsulation_overhead: egressIface.encapsulation_overhead || null, last_handshake: egressIface.last_handshake || null, ssid: egressIface.ssid || null, signal_strength: egressIface.signal_strength || null, band: egressIface.band || null },
    firewall: { detectable: true, status: "no blocking rules matched", rules: [] },
    reachability: "reachable",
    snapshot: demoSnapshot,
    explanation,
    policy_conflicts,
    tunnel_coverage,
  };
}

// ── DOM setup ──────────────────────────────────────────────────────────────
const app = document.querySelector("#app");

app.innerHTML = `
  <div class="app-shell">
    <aside class="sidebar" aria-label="Network state">
      <header class="sidebar-header">
        <div class="brand-row">
          <svg class="brand-mark" viewBox="0 0 32 32" aria-label="PathTrace mark" fill="none">
            <path d="M5 17.5h7.5l3-9 4 16 3-7h4.5" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
            <circle cx="5" cy="17.5" r="2.2" fill="currentColor"/>
            <circle cx="27" cy="17.5" r="2.2" fill="currentColor"/>
          </svg>
          <div>
            <h1 class="app-name">PathTrace</h1>
            <div class="app-sub">network decision analyzer</div>
          </div>
        </div>
      </header>
      <div class="section-label">interfaces</div>
      <div class="interface-list" data-interface-list></div>
      <div class="panel-resize-handle" data-panel-resize="interfaces" title="Drag to resize"></div>
      <div class="section-label">dns resolvers</div>
      <div class="dns-list" data-dns-list></div>
      <div class="panel-resize-handle" data-panel-resize="dns" title="Drag to resize"></div>
      <div class="section-label">what changed</div>
      <div class="event-list" data-event-list></div>
      <footer class="sidebar-footer">
        <div class="live-tag"><span class="live-dot"></span><span data-live-text>live — last updated 0s ago</span></div>
      </footer>
    </aside>
    <div class="sidebar-resize-handle" data-sidebar-resize title="Drag to resize sidebar"></div>
    <main class="main">
      <form class="query-bar" data-query-form>
        <label for="query" class="query-label">trace</label>
        <div class="query-stack">
          <input id="query" class="query-input" data-query-input value="google.com" autocomplete="off" spellcheck="false" aria-describedby="query-error" />
          <div id="query-error" class="query-error" data-query-error></div>
        </div>
        <div class="history-wrap">
          <button class="button secondary optional" type="button" data-history-button>history</button>
          <div class="history-menu" data-history-menu aria-label="Recent traces"></div>
        </div>
        <button class="button secondary optional" type="button" data-paste-button>paste</button>
        <button class="button secondary optional" type="button" data-export-button>export</button>
        <button class="button secondary optional redact-toggle" type="button" data-redact-button title="Toggle redaction mode">redact</button>
        <button class="button primary" type="submit">→ analyze</button>
      </form>
      <div class="main-tabs" role="tablist" aria-label="Main sections">
        <button class="main-tab active" type="button" data-main-tab="trace" role="tab">trace</button>
        <button class="main-tab" type="button" data-main-tab="timeline" role="tab">timeline</button>
        <button class="main-tab" type="button" data-main-tab="diff" role="tab">diff</button>
        <button class="main-tab" type="button" data-main-tab="probes" role="tab">probes</button>
        <button class="main-tab" type="button" data-main-tab="coverage" role="tab">coverage</button>
        <button class="main-tab" type="button" data-main-tab="simulate" role="tab">simulate</button>
        <button class="main-tab" type="button" data-main-tab="report" role="tab">report</button>
      </div>
      <section class="content" id="results" data-results aria-live="polite"></section>
    </main>
  </div>
`;

const els = {
  interfaceList: document.querySelector("[data-interface-list]"),
  dnsList: document.querySelector("[data-dns-list]"),
  eventList: document.querySelector("[data-event-list]"),
  liveText: document.querySelector("[data-live-text]"),
  queryForm: document.querySelector("[data-query-form]"),
  queryInput: document.querySelector("[data-query-input]"),
  queryError: document.querySelector("[data-query-error]"),
  historyButton: document.querySelector("[data-history-button]"),
  historyMenu: document.querySelector("[data-history-menu]"),
  pasteButton: document.querySelector("[data-paste-button]"),
  exportButton: document.querySelector("[data-export-button]"),
  redactButton: document.querySelector("[data-redact-button]"),
  results: document.querySelector("[data-results]"),
};

// ── Utility functions ──────────────────────────────────────────────────────
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function isIp(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[a-f0-9:]+:[a-f0-9:]+/i.test(value);
}

function isCidr(value) {
  return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(value) || /^[a-f0-9:]+:[a-f0-9:]+\/\d{1,3}$/i.test(value);
}

function isValidDestination(value) {
  const trimmed = value.trim();
  if (!trimmed || /\s/.test(trimmed)) return false;
  if (isIp(trimmed) || isCidr(trimmed)) return true;
  return /^(?=.{1,253}$)([a-z0-9_*-]{1,63}\.)*[a-z0-9_*-]{1,63}\.?$/i.test(trimmed);
}

function compact(value, fallback = "—") {
  return value === undefined || value === null || value === "" ? fallback : String(value);
}

function typeClass(type) {
  const n = String(type || "Other").toLowerCase();
  if (n.includes("vpn")) return "badge-vpn";
  if (n.includes("wi")) return "badge-wifi";
  if (n.includes("eth")) return "badge-eth";
  if (n.includes("lo")) return "badge-lo";
  return "badge-other";
}

function dotClass(iface) {
  if (iface.interface_type === "VPN") return "dot-vpn";
  return iface.status === "up" ? "dot-up" : "dot-down";
}

function statusClass(status) {
  const lower = String(status || "").toLowerCase();
  if (lower.includes("failed") || lower.includes("unavailable") || lower.includes("timeout") || lower.includes("error")) return "status-danger";
  if (lower.includes("vpn") || lower.includes("tunnel") || lower.includes("split")) return "status-vpn";
  if (lower.includes("warn") || lower.includes("clamp") || lower.includes("permission") || lower.includes("low")) return "status-warn";
  if (lower.includes("ok") || lower.includes("no blocking") || lower.includes("direct") || lower.includes("default") || lower.includes("egress") || lower.includes("reachable")) return "status-ok";
  return "status-neutral";
}

// ── Feature 8: Redaction ───────────────────────────────────────────────────
const REDACT_PATTERNS = [
  { pattern: /\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g, label: "[PRIVATE-IP]" },
  { pattern: /\b(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})\b/g, label: "[IPV6]" },
  { pattern: /\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/gi, label: "[MAC]" },
  { pattern: /\b(vpn\.[a-z0-9.-]+\.[a-z]{2,}|wg\.[a-z0-9.-]+\.[a-z]{2,})\b/gi, label: "[VPN-ENDPOINT]" },
  { pattern: /\b(corp\.[a-z0-9.-]+|internal\.[a-z0-9.-]+)\b/gi, label: "[INTERNAL-HOST]" },
];

function redact(text) {
  if (!state.redactMode) return text;
  let result = String(text ?? "");
  for (const { pattern, label } of REDACT_PATTERNS) {
    result = result.replace(pattern, label);
  }
  return result;
}

function r(text) {
  return escapeHtml(redact(String(text ?? "")));
}

// ── Sidebar rendering ──────────────────────────────────────────────────────
function renderSidebar() {
  const snapshot = state.snapshot || demoSnapshot;
  const currentSignature = JSON.stringify(snapshot.interfaces.map((i) => [i.name, i.status, i.ipv4, i.ipv6, i.mtu]));
  const changed = state.lastInterfaceSignature && state.lastInterfaceSignature !== currentSignature;
  state.lastInterfaceSignature = currentSignature;

  els.interfaceList.innerHTML = snapshot.interfaces
    .map((iface, index) => {
      const selected = state.selectedInterface ? state.selectedInterface === iface.name : index === 0;
      const ip = iface.ipv4 || iface.ipv6 || "—";
      return `
        <button class="iface ${selected ? "active" : ""} ${changed ? "changed" : ""}" data-interface="${escapeHtml(iface.name)}" type="button">
          <span class="iface-dot ${dotClass(iface)}"></span>
          <span class="iface-info">
            <span class="iface-name">${r(iface.name)}</span>
            <span class="iface-ip">${r(ip)}</span>
          </span>
          <span class="badge ${typeClass(iface.interface_type)}">${escapeHtml(iface.interface_type || "Other")}</span>
        </button>
      `;
    })
    .join("");

  els.dnsList.innerHTML = (snapshot.dns_resolvers || [])
    .slice(0, 8)
    .map((res) => `
      <div class="dns-item">
        <span class="dns-scope">${r(res.scope || "default")}</span>
        <span class="dns-server">${r(res.server)}${res.port ? `:${res.port}` : ""}</span>
      </div>
    `)
    .join("") || `<div class="dns-item"><span class="dns-scope">unavailable</span><span class="dns-server">—</span></div>`;

  els.eventList.innerHTML = (snapshot.events || [])
    .slice(0, 5)
    .map((event) => {
      const ts = new Date(event.timestamp || Date.now());
      return `
        <div class="event-item">
          <span class="event-time">${ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
          <span class="event-message">${escapeHtml(event.message || event.category)}</span>
        </div>
      `;
    })
    .join("");
}

function renderHistory() {
  if (!state.history.length) {
    els.historyMenu.innerHTML = `<div class="history-item">No recent traces</div>`;
    return;
  }
  els.historyMenu.innerHTML = state.history
    .map((item) => `<button class="history-item" type="button" data-history-query="${escapeHtml(item)}">${r(item)}</button>`)
    .join("");
}

// ── Card building helpers ──────────────────────────────────────────────────
function detailRow(key, value, tone = "") {
  return `<div class="trace-row"><span class="trace-key">${escapeHtml(key)}</span><span class="trace-val ${tone}">${value}</span></div>`;
}

function clickableIp(value) {
  const text = compact(redact(String(value ?? "")));
  if (isIp(text) && !state.redactMode) {
    return `<button class="click-ip" type="button" data-retrace="${escapeHtml(text)}">${escapeHtml(text)}</button>`;
  }
  return escapeHtml(text);
}

function resultCard(icon, iconClass, title, status, body, extraClass = "") {
  return `
    <article class="result-card ${extraClass}">
      <header class="card-header">
        <div class="card-icon ${iconClass}">${escapeHtml(icon)}</div>
        <h2 class="card-title">${escapeHtml(title)}</h2>
        <div class="status-pill ${statusClass(status)}">${escapeHtml(status)}</div>
      </header>
      ${body}
    </article>
  `;
}

// ── Feature 1: Explanation card ────────────────────────────────────────────
function renderExplanationCard(trace) {
  const exp = trace.explanation;
  if (!exp) return "";

  const sevIcon = { ok: "✓", warn: "⚠", error: "✗", info: "ℹ" };
  const sevClass = { ok: "green", warn: "amber", error: "danger", info: "" };

  function expBlock(block) {
    const icon = sevIcon[block.severity] || "ℹ";
    const cls = sevClass[block.severity] || "";
    return `
      <div class="exp-block">
        <span class="exp-icon exp-${block.severity}">${icon}</span>
        <div>
          <div class="exp-headline ${cls}">${escapeHtml(block.headline)}</div>
          <div class="exp-detail">${escapeHtml(block.detail)}</div>
        </div>
      </div>
    `;
  }

  const reasonCodes = (exp.reason_codes || []).map((code) => {
    const cls = sevClass[code.severity] || "";
    return `
      <div class="reason-code reason-${code.severity}">
        <span class="reason-code-id mono">${escapeHtml(code.code)}</span>
        <span class="reason-code-label ${cls}">${escapeHtml(code.label)}</span>
        <span class="reason-code-desc">${escapeHtml(code.description)}</span>
      </div>
    `;
  }).join("");

  const expandedClass = state.explanationExpanded ? "" : "collapsed";

  const body = `
    <div class="card-body exp-summary">${escapeHtml(exp.summary)}</div>
    <button class="exp-toggle" type="button" data-exp-toggle>
      ${state.explanationExpanded ? "▲ hide details" : "▼ show decision details"}
    </button>
    <div class="exp-details ${expandedClass}">
      <div class="exp-blocks">
        ${expBlock(exp.dns_explanation)}
        ${expBlock(exp.route_explanation)}
        ${expBlock(exp.egress_explanation)}
        ${expBlock(exp.firewall_explanation)}
      </div>
      ${reasonCodes ? `<div class="section-label" style="padding:8px 14px 4px">reason codes</div><div class="reason-codes card-body">${reasonCodes}</div>` : ""}
    </div>
  `;

  return resultCard("EXP", "icon-exp", "decision explanation", "ok", body);
}

// ── Feature 6: Conflict card ───────────────────────────────────────────────
function renderConflictsCard(trace) {
  const conflicts = trace.policy_conflicts || [];
  if (!conflicts.length) return "";

  const items = conflicts.map((c) => {
    const badge = c.severity === "error" ? "status-danger" : c.severity === "warn" ? "status-warn" : "status-neutral";
    return `
      <div class="conflict-item">
        <div class="conflict-header">
          <span class="status-pill ${badge}">${escapeHtml(c.severity)}</span>
          <span class="conflict-title">${escapeHtml(c.title)}</span>
          <span class="mono conflict-id">${escapeHtml(c.id)}</span>
        </div>
        <div class="conflict-desc">${escapeHtml(c.description)}</div>
        ${c.affected?.length ? `<div class="conflict-affected">${c.affected.map((a) => `<span class="mono conflict-tag">${r(a)}</span>`).join(" ")}</div>` : ""}
      </div>
    `;
  }).join("");

  const status = conflicts.some((c) => c.severity === "error") ? "errors detected" : "warnings detected";
  return resultCard("CFG", "icon-fw", "policy conflicts", status, `<div class="card-body conflicts-list">${items}</div>`);
}

// ── Trace core cards ───────────────────────────────────────────────────────
function renderDnsCard(trace) {
  const dns = trace.dns;
  if (!dns.required) {
    const body = `
      <div class="card-body">
        ${detailRow("decision", "no DNS lookup required — direct IP", "green")}
        ${detailRow("destination", clickableIp(dns.result || trace.query))}
        ${detailRow("fallback resolver", r(compact(dns.fallback_resolver, "not used")))}
      </div>
    `;
    return resultCard("DNS", "icon-dns", "DNS resolution", dns.status, body);
  }

  const flow = (dns.flow || [])
    .map((node, index, array) => {
      const html = `
        <div class="flow-node">
          <div class="flow-box fn-${node.kind === "resolver" ? "route" : node.kind}">${clickableIp(node.value)}</div>
          <div class="flow-label">${escapeHtml(node.label)}</div>
        </div>
      `;
      return index < array.length - 1 ? `${html}<div class="flow-arrow"></div>` : html;
    })
    .join("");

  const details = dns.failure_reason
    ? [
        detailRow("failure", r(dns.failure_reason), "danger"),
        detailRow("tried", r((dns.tried_resolvers || []).join(", ") || "system resolver")),
      ].join("")
    : [
        detailRow("matched rule", r(compact(dns.matched_rule, "none")), dns.matched_rule ? "highlight" : ""),
        detailRow("fallback resolver", r(compact(dns.fallback_resolver, "none"))),
        detailRow("cached", r(compact(dns.cache_status, "unknown")), String(dns.cache_status || "").includes("yes") ? "green" : ""),
      ].join("");

  return resultCard("DNS", "icon-dns", "DNS resolution", dns.status, `
    <div class="flow-viz">${flow}</div>
    <div class="card-body detail-section">${details}</div>
  `);
}

function routeRows(routes) {
  return `
    <table class="route-table">
      <thead><tr><th>destination</th><th>gateway</th><th>interface</th><th>metric</th><th>source</th></tr></thead>
      <tbody>
        ${(routes || []).map((route) => `
          <tr class="${route.matched ? "matched" : ""}">
            <td>${escapeHtml(route.destination)}</td>
            <td>${clickableIp(route.gateway)}</td>
            <td>${r(route.interface)}</td>
            <td>${escapeHtml(compact(route.metric))}</td>
            <td>${escapeHtml(route.source)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderRouteCard(trace) {
  const route = trace.route;
  const matched = route.matched_route ? [route.matched_route] : [];
  const routes = state.activeRouteTab === "matched" ? matched : route.routes;
  const body = `
    <div class="tabs" role="tablist" aria-label="Routing table view">
      <button class="tab ${state.activeRouteTab === "matched" ? "active" : ""}" type="button" data-route-tab="matched" role="tab">matched route</button>
      <button class="tab ${state.activeRouteTab === "full" ? "active" : ""}" type="button" data-route-tab="full" role="tab">full table</button>
    </div>
    <div class="card-body">
      ${route.lookup_error ? detailRow("lookup error", r(route.lookup_error), "danger") : routeRows(routes)}
    </div>
  `;
  return resultCard("RTB", "icon-route", "routing decision", route.status, body);
}

function renderEgressCard(trace) {
  const egress = trace.egress;
  const iface = `${r(egress.name)} · ${escapeHtml(egress.interface_type)}`;
  const mtuTone = egress.mtu_warning ? "amber" : "";
  const rows = [
    detailRow("protocol", r(compact(egress.protocol))),
    detailRow("tunnel endpoint", clickableIp(egress.tunnel_endpoint)),
    detailRow("source IP", clickableIp(egress.source_ip)),
    detailRow("MTU", escapeHtml(compact(egress.mtu)) + (egress.mtu_warning ? " (clamped)" : ""), mtuTone),
    detailRow("encap overhead", escapeHtml(egress.encapsulation_overhead ? `${egress.encapsulation_overhead} bytes` : "—")),
    detailRow("handshake", r(compact(egress.last_handshake)), egress.last_handshake ? "green" : ""),
    detailRow("SSID", r(compact(egress.ssid))),
    detailRow("signal / band", r([egress.signal_strength, egress.band].filter(Boolean).join(" · ") || "—")),
  ].join("");
  return resultCard("IF", "icon-iface", "egress interface", iface, `<div class="card-body"><div class="detail-grid">${rows}</div></div>`);
}

function renderFirewallCard(trace) {
  const fw = trace.firewall;
  if (!fw.detectable && !fw.status) return "";
  const rules = fw.rules || [];
  const body = rules.length
    ? `<div class="card-body">${rules.map((rule) => [
        detailRow("rule", r(rule.name)),
        detailRow("action", r(rule.action), String(rule.action).match(/drop|reject|block/i) ? "danger" : "green"),
        detailRow("direction", r(rule.direction)),
        detailRow("source", r(rule.source)),
      ].join("")).join('<div class="detail-section"></div>')}</div>`
    : `<div class="card-body">${detailRow("decision", r(fw.status || "no blocking rules matched"), fw.detectable ? "green" : "amber")}</div>`;
  return resultCard("FW", "icon-fw", "firewall & policy", fw.detectable ? "detectable" : "not detectable", body);
}

function renderErrorCard(message, command) {
  return resultCard("ERR", "icon-fw", "trace error", "needs attention", `
    <div class="card-body">
      ${detailRow("reason", escapeHtml(message), "danger")}
      ${command ? `<div class="code-line">${escapeHtml(command)}</div>` : ""}
    </div>
  `, "error-card");
}

// ── Feature 3: Timeline tab ────────────────────────────────────────────────
function renderTimelineTab() {
  if (!state.timeline.length) {
    return `<div class="empty-card"><div class="empty-inner">
      <div class="empty-title">No traces yet</div>
      <p class="empty-text">Run a trace to start recording the timeline.</p>
    </div></div>`;
  }

  const entries = state.timeline.map((entry, index) => {
    const ts = new Date(entry.ts);
    const selected = state.selectedTimelineIndex === index;
    const conflicts = (entry.trace.policy_conflicts || []).length;
    const conflictBadge = conflicts ? `<span class="badge status-warn" style="margin-left:4px">${conflicts} conflict${conflicts > 1 ? "s" : ""}</span>` : "";
    return `
      <button class="timeline-entry ${selected ? "active" : ""}" type="button" data-timeline-index="${index}">
        <span class="timeline-time mono">${ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
        <span class="timeline-query mono">${r(entry.trace.query)}</span>
        <span class="timeline-status ${statusClass(entry.trace.route?.status || "")}">${escapeHtml(entry.trace.route?.status || "—")}</span>
        ${conflictBadge}
      </button>
    `;
  }).join("");

  let preview = "";
  if (state.selectedTimelineIndex !== null && state.timeline[state.selectedTimelineIndex]) {
    const trace = state.timeline[state.selectedTimelineIndex].trace;
    preview = `
      <div class="timeline-preview">
        <div class="section-label" style="padding:8px 0 4px">snapshot at ${new Date(state.timeline[state.selectedTimelineIndex].ts).toLocaleString()}</div>
        ${renderDnsCard(trace)}
        ${renderRouteCard(trace)}
        ${renderEgressCard(trace)}
      </div>
    `;
  }

  return `
    <article class="result-card">
      <header class="card-header">
        <div class="card-icon icon-exp">TL</div>
        <h2 class="card-title">trace timeline</h2>
        <div class="status-pill status-neutral">${state.timeline.length} traces</div>
      </header>
      <div class="timeline-list">${entries}</div>
    </article>
    ${preview}
  `;
}

// ── Feature 2: Diff tab ────────────────────────────────────────────────────
function buildDiff(before, after) {
  const diff = { interfaces: [], routes: [], dns: [], firewall: [] };

  const beforeNames = new Set((before.interfaces || []).map((i) => i.name));
  const afterNames = new Set((after.interfaces || []).map((i) => i.name));

  for (const name of beforeNames) {
    if (!afterNames.has(name)) diff.interfaces.push({ change: "removed", label: name });
  }
  for (const iface of after.interfaces || []) {
    if (!beforeNames.has(iface.name)) {
      diff.interfaces.push({ change: "added", label: iface.name });
    } else {
      const beforeIface = (before.interfaces || []).find((i) => i.name === iface.name);
      if (beforeIface && JSON.stringify(beforeIface) !== JSON.stringify(iface)) {
        const changes = [];
        if (beforeIface.status !== iface.status) changes.push(`status: ${beforeIface.status} → ${iface.status}`);
        if (beforeIface.ipv4 !== iface.ipv4) changes.push(`ipv4: ${beforeIface.ipv4 || "—"} → ${iface.ipv4 || "—"}`);
        if (beforeIface.mtu !== iface.mtu) changes.push(`mtu: ${beforeIface.mtu || "—"} → ${iface.mtu || "—"}`);
        if (changes.length) diff.interfaces.push({ change: "changed", label: `${iface.name}: ${changes.join("; ")}` });
      }
    }
  }

  const beforeRoutes = new Set((before.routes || []).map((r) => `${r.destination}|${r.interface}`));
  const afterRoutes = new Set((after.routes || []).map((r) => `${r.destination}|${r.interface}`));

  for (const key of beforeRoutes) {
    if (!afterRoutes.has(key)) {
      const [dest, iface] = key.split("|");
      diff.routes.push({ change: "removed", label: `${dest} via ${iface}` });
    }
  }
  for (const key of afterRoutes) {
    if (!beforeRoutes.has(key)) {
      const [dest, iface] = key.split("|");
      diff.routes.push({ change: "added", label: `${dest} via ${iface}` });
    }
  }

  const beforeResolvers = new Set((before.dns_resolvers || []).map((r) => `${r.scope}|${r.server}`));
  const afterResolvers = new Set((after.dns_resolvers || []).map((r) => `${r.scope}|${r.server}`));
  for (const key of beforeResolvers) {
    if (!afterResolvers.has(key)) { const [scope, server] = key.split("|"); diff.dns.push({ change: "removed", label: `${scope}: ${server}` }); }
  }
  for (const key of afterResolvers) {
    if (!beforeResolvers.has(key)) { const [scope, server] = key.split("|"); diff.dns.push({ change: "added", label: `${scope}: ${server}` }); }
  }

  if (before.firewall?.status !== after.firewall?.status) {
    diff.firewall.push({ change: "changed", label: `${before.firewall?.status || "—"} → ${after.firewall?.status || "—"}` });
  }

  return diff;
}

function diffChangeClass(change) {
  if (change === "added") return "diff-added";
  if (change === "removed") return "diff-removed";
  return "diff-changed";
}

function renderDiffSection(title, items) {
  if (!items.length) return `<div class="diff-section"><span class="diff-section-title">${escapeHtml(title)}</span><span class="diff-none">no changes</span></div>`;
  return `
    <div class="diff-section">
      <span class="diff-section-title">${escapeHtml(title)}</span>
      ${items.map((item) => `<div class="diff-row ${diffChangeClass(item.change)}"><span class="diff-marker">${item.change === "added" ? "+" : item.change === "removed" ? "−" : "~"}</span><span class="mono diff-label">${r(item.label)}</span></div>`).join("")}
    </div>
  `;
}

function renderDiffTab() {
  const snapshot = state.snapshot || demoSnapshot;
  const hasBaseline = Boolean(state.baselineSnapshot);

  const actions = `
    <div class="diff-actions card-body">
      <button class="button secondary" type="button" data-set-baseline>set current as baseline</button>
      ${hasBaseline ? `<span class="diff-meta">baseline set at ${new Date(state.baselineSnapshot._capturedAt || Date.now()).toLocaleTimeString()}</span>` : ""}
    </div>
  `;

  if (!hasBaseline) {
    return `
      <article class="result-card">
        <header class="card-header">
          <div class="card-icon icon-route">DF</div>
          <h2 class="card-title">before / after diff</h2>
        </header>
        ${actions}
        <div class="card-body"><div class="diff-empty">Set a baseline snapshot to compare against the current state.</div></div>
      </article>
    `;
  }

  const diff = buildDiff(state.baselineSnapshot, snapshot);
  const totalChanges = diff.interfaces.length + diff.routes.length + diff.dns.length + diff.firewall.length;

  return `
    <article class="result-card">
      <header class="card-header">
        <div class="card-icon icon-route">DF</div>
        <h2 class="card-title">before / after diff</h2>
        <div class="status-pill ${totalChanges ? "status-warn" : "status-ok"}">${totalChanges} change${totalChanges !== 1 ? "s" : ""}</div>
      </header>
      ${actions}
      <div class="diff-body">
        ${renderDiffSection("Interfaces", diff.interfaces)}
        ${renderDiffSection("Routes", diff.routes)}
        ${renderDiffSection("DNS resolvers", diff.dns)}
        ${renderDiffSection("Firewall", diff.firewall)}
      </div>
    </article>
  `;
}

// ── Feature 4: Probes tab ──────────────────────────────────────────────────
function renderProbesTab() {
  const destination = (state.trace?.query) || (state.snapshot ? "" : "");
  const probeStatusClass = { ok: "status-ok", failed: "status-danger", timeout: "status-warn", unsupported: "status-neutral", skipped: "status-neutral", running: "status-neutral" };

  let content = `
    <div class="card-body">
      <div class="probe-warning">⚠ Active probes send real network traffic. ICMP, TCP, and HTTP packets will be sent to the destination.</div>
      <div class="probe-actions">
        ${destination ? `<button class="button primary" type="button" data-run-probes>${state.probeRunning ? "running…" : "run active probes → " + destination}</button>` : `<span class="diff-empty">Run a trace first to enable probes.</span>`}
      </div>
    </div>
  `;

  if (state.probeResult) {
    const suite = state.probeResult;
    const tests = suite.tests || [];
    const passCount = tests.filter((t) => t.status === "ok").length;
    const failCount = tests.filter((t) => t.status === "failed" || t.status === "timeout").length;

    content += `
      <div class="probe-results">
        <div class="probe-header mono">
          ${escapeHtml(suite.destination)} · started ${new Date(suite.started_at).toLocaleTimeString()} · ${passCount} ok / ${failCount} failed
        </div>
        <table class="probe-table">
          <thead>
            <tr>
              <th>status</th>
              <th>test</th>
              <th>latency</th>
              <th>result / error</th>
              <th>note</th>
            </tr>
          </thead>
          <tbody>
            ${tests.map((test) => `
              <tr>
                <td><span class="status-pill ${probeStatusClass[test.status] || "status-neutral"}">${escapeHtml(test.status)}</span></td>
                <td class="probe-test-name">${escapeHtml(test.name)}</td>
                <td class="probe-latency mono">${test.latency_ms != null ? `${test.latency_ms.toFixed(0)}ms` : "—"}</td>
                <td>${test.result ? `<span class="probe-result mono">${r(test.result)}</span>` : ""}${test.error ? `<span class="probe-error">${escapeHtml(test.error)}</span>` : ""}</td>
                <td class="probe-note-cell">${test.note ? escapeHtml(test.note) : ""}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  return `
    <article class="result-card">
      <header class="card-header">
        <div class="card-icon icon-dns">PB</div>
        <h2 class="card-title">packet test suite</h2>
        ${state.probeResult ? `<div class="status-pill ${probeStatusClass[(state.probeResult.tests || []).every((t) => t.status === "ok" || t.status === "skipped") ? "ok" : "failed"] || "status-neutral"}">${(state.probeResult.tests || []).filter((t) => t.status === "ok").length} / ${(state.probeResult.tests || []).length} passed</div>` : ""}
      </header>
      ${content}
    </article>
  `;
}

// ── Feature 5: Coverage tab ────────────────────────────────────────────────
function renderCoverageTab() {
  const coverage = state.trace?.tunnel_coverage || null;
  const snapshot = state.snapshot || demoSnapshot;

  const cov = coverage || {
    vpn_prefixes: snapshot.routes?.filter((r) => snapshot.interfaces?.find((i) => i.interface_type === "VPN" && i.name === r.interface))?.map((r) => r.destination) || [],
    local_prefixes: snapshot.routes?.filter((r) => r.destination.startsWith("192.168.") || r.destination.startsWith("10."))?.map((r) => r.destination) || [],
    default_route_interface: snapshot.routes?.find((r) => r.destination === "0.0.0.0/0")?.interface || null,
    default_captured_by_vpn: false,
    dns_scopes: [],
    unknown_prefixes: [],
  };

  const vpnIfaces = snapshot.interfaces?.filter((i) => i.interface_type === "VPN" && i.status === "up") || [];

  const prefixGroup = (title, items, cls) => {
    if (!items.length) return `<div class="coverage-group"><div class="coverage-group-title">${escapeHtml(title)}</div><span class="diff-none">none</span></div>`;
    return `
      <div class="coverage-group">
        <div class="coverage-group-title">${escapeHtml(title)}</div>
        ${items.map((p) => `<span class="coverage-prefix ${cls}">${escapeHtml(p)}</span>`).join("")}
      </div>
    `;
  };

  const dnsScopes = (cov.dns_scopes || []).map((scope) => `
    <div class="dns-scope-row">
      <span class="badge ${scope.scope === "default" ? "badge-eth" : "badge-vpn"}">${escapeHtml(scope.scope)}</span>
      <span class="mono">${scope.servers.map((s) => r(s)).join(", ")}</span>
      ${scope.interface ? `<span class="diff-meta">via ${r(scope.interface)}</span>` : ""}
    </div>
  `).join("");

  return `
    <article class="result-card">
      <header class="card-header">
        <div class="card-icon icon-iface">CV</div>
        <h2 class="card-title">split tunnel coverage</h2>
        <div class="status-pill ${cov.default_captured_by_vpn ? "status-vpn" : "status-ok"}">${cov.default_captured_by_vpn ? "full tunnel" : "split tunnel"}</div>
      </header>
      <div class="card-body">
        <div class="coverage-meta">
          <span>Default route: <span class="mono">${r(cov.default_route_interface || "—")}</span></span>
          ${cov.default_captured_by_vpn ? `<span class="status-vpn badge-vpn" style="padding:2px 6px;border-radius:4px">VPN captures default route (full tunnel)</span>` : ""}
          <span>VPN interfaces: ${vpnIfaces.map((i) => `<span class="mono">${r(i.name)}</span>`).join(", ") || "none"}</span>
        </div>
      </div>
      <div class="card-body coverage-prefixes">
        ${prefixGroup("VPN route prefixes", cov.vpn_prefixes, "prefix-vpn")}
        ${prefixGroup("Local route prefixes", cov.local_prefixes, "prefix-local")}
        ${prefixGroup("Unknown / unclassified", cov.unknown_prefixes, "prefix-unknown")}
      </div>
      ${dnsScopes ? `
        <div class="section-label" style="padding:8px 14px 4px">DNS scopes</div>
        <div class="card-body dns-scopes-list">${dnsScopes}</div>
      ` : ""}
    </article>
  `;
}

// ── Feature 9: Simulate tab ────────────────────────────────────────────────
function renderSimulateTab() {
  const destination = state.trace?.query || "";
  const sim = state.simResult;
  const overrides = state.simOverrides;

  const addedRouteRows = overrides.added_routes.map((r, idx) => `
    <div class="sim-row">
      <span class="mono">${escapeHtml(r.destination)} via ${escapeHtml(r.gateway)} on ${escapeHtml(r.interface)}</span>
      <button class="button secondary" type="button" data-sim-remove-route="${idx}">×</button>
    </div>
  `).join("");

  const removedRows = overrides.removed_destinations.map((d, idx) => `
    <div class="sim-row">
      <span class="mono diff-removed">${escapeHtml(d)}</span>
      <button class="button secondary" type="button" data-sim-remove-dest="${idx}">×</button>
    </div>
  `).join("");

  const ifaceStateRows = overrides.interface_states.map((s, idx) => `
    <div class="sim-row">
      <span class="mono">${r(s.name)} → ${s.up ? "up" : "down"}</span>
      <button class="button secondary" type="button" data-sim-remove-iface="${idx}">×</button>
    </div>
  `).join("");

  const simResultHtml = sim ? `
    <div class="sim-result">
      <div class="probe-warning">${escapeHtml(sim.note)}</div>
      <div class="section-label" style="padding:8px 0 4px">simulation result</div>
      ${detailRow("destination", r(sim.destination))}
      ${detailRow("DNS answer", r(sim.dns_answer || "—"))}
      ${detailRow("winning interface", r(sim.winning_interface || "none matched"))}
      ${sim.winning_route ? detailRow("winning route", r(`${sim.winning_route.destination} via ${sim.winning_route.gateway}`)) : ""}
      ${sim.changes_applied?.length ? `
        <div class="section-label" style="padding:8px 0 4px">changes applied</div>
        ${sim.changes_applied.map((c) => `<div class="mono diff-row diff-changed"><span class="diff-marker">~</span><span>${escapeHtml(c)}</span></div>`).join("")}
      ` : ""}
    </div>
  ` : "";

  return `
    <article class="result-card">
      <header class="card-header">
        <div class="card-icon icon-route">SIM</div>
        <h2 class="card-title">route simulator</h2>
        <div class="status-pill status-neutral">read-only · no system changes</div>
      </header>
      <div class="card-body">
        <div class="probe-warning">⚠ Simulation only — no system configuration is modified. Results show hypothetical routing decisions.</div>
        <div class="sim-controls">
          <div class="sim-section-title">Add hypothetical route</div>
          <div class="sim-inputs">
            <input class="query-input sim-input" data-sim-dest placeholder="destination (CIDR)" />
            <input class="query-input sim-input" data-sim-gw placeholder="gateway IP" />
            <input class="query-input sim-input" data-sim-iface placeholder="interface" />
            <input class="query-input sim-input" data-sim-metric placeholder="metric" type="number" />
            <button class="button secondary" type="button" data-sim-add-route>+ add route</button>
          </div>
          ${addedRouteRows}

          <div class="sim-section-title" style="margin-top:8px">Remove route by destination</div>
          <div class="sim-inputs">
            <input class="query-input sim-input" data-sim-remove-dest-input placeholder="destination to remove" />
            <button class="button secondary" type="button" data-sim-add-remove>− remove</button>
          </div>
          ${removedRows}

          <div class="sim-section-title" style="margin-top:8px">Interface state overrides</div>
          <div class="sim-inputs">
            <input class="query-input sim-input" data-sim-iface-name placeholder="interface name" />
            <select class="query-input sim-input" data-sim-iface-state>
              <option value="up">up</option>
              <option value="down">down</option>
            </select>
            <button class="button secondary" type="button" data-sim-add-iface>+ override</button>
          </div>
          ${ifaceStateRows}

          <div class="sim-section-title" style="margin-top:8px">DNS answer override</div>
          <div class="sim-inputs">
            <input class="query-input sim-input" data-sim-dns-override placeholder="override DNS answer (IP)" value="${escapeHtml(overrides.dns_answer_override || "")}" />
          </div>
        </div>
        <div class="sim-run-row">
          <button class="button primary" type="button" data-run-sim ${!destination ? "disabled" : ""}>
            → simulate${destination ? ` for ${destination}` : " (run a trace first)"}
          </button>
          <button class="button secondary" type="button" data-clear-sim>clear overrides</button>
        </div>
      </div>
      ${simResultHtml ? `<div class="card-body">${simResultHtml}</div>` : ""}
    </article>
  `;
}

// ── Feature 10: Resolver tests tab (combined with report) ──────────────────
function renderResolverTestsCard() {
  const hostname = state.trace?.query || "";
  const results = state.resolverTestResults;

  const statusCls = { ok: "status-ok", failed: "status-danger", timeout: "status-warn", nxdomain: "status-warn", unsupported: "status-neutral" };

  let content = `
    <div class="card-body">
      ${hostname ? `<button class="button primary" type="button" data-run-resolver-tests>${state.resolverTestRunning ? "testing…" : `test resolvers for ${hostname}`}</button>` : `<span class="diff-empty">Run a trace first.</span>`}
    </div>
  `;

  if (results?.length) {
    const rows = results.map((r) => `
      <div class="resolver-test-row">
        <div class="resolver-test-header">
          <span class="status-pill ${statusCls[r.status] || "status-neutral"}">${escapeHtml(r.status)}</span>
          <span class="mono resolver-name">${escapeHtml(r.resolver)}</span>
          <span class="badge ${r.scope === "default" ? "badge-eth" : "badge-vpn"}">${escapeHtml(r.scope)}</span>
          ${r.latency_ms != null ? `<span class="probe-latency mono">${r.latency_ms.toFixed(0)}ms</span>` : ""}
        </div>
        ${r.answers?.length ? `<div class="resolver-answers">${r.answers.map((a) => `<span class="mono resolver-answer">${escapeHtml(a)}</span>`).join("")}</div>` : ""}
        ${r.error ? `<div class="probe-error">${escapeHtml(r.error)}</div>` : ""}
        ${r.findings?.length ? r.findings.map((f) => `<div class="probe-note finding-note">${escapeHtml(f)}</div>`).join("") : ""}
      </div>
    `).join("");

    const hasSplitBrain = results.some((r) => r.findings?.some((f) => f.includes("Split-brain")));
    content += `
      ${hasSplitBrain ? `<div class="probe-warning card-body">⚠ Split-brain detected: different resolvers returned different answers for the same hostname.</div>` : ""}
      <div class="resolver-results">${rows}</div>
    `;
  }

  return resultCard("RES", "icon-dns", "resolver-specific DNS testing", results ? `${results.length} resolvers tested` : "not run", content);
}

// ── Feature 7: Report tab ──────────────────────────────────────────────────
function buildMarkdownReport(trace) {
  const now = new Date().toISOString();
  const r = state.redactMode ? (s) => redact(String(s ?? "")) : (s) => String(s ?? "");

  const conflictSection = (trace.policy_conflicts || []).length
    ? `## Policy Conflicts\n\n${(trace.policy_conflicts || []).map((c) => `### [${c.severity.toUpperCase()}] ${c.title}\n${c.description}\nAffected: ${(c.affected || []).map(r).join(", ")}`).join("\n\n")}`
    : "## Policy Conflicts\n\nNone detected.";

  const reasonCodes = (trace.explanation?.reason_codes || []).length
    ? `## Reason Codes\n\n| Code | Severity | Summary |\n|------|----------|--------|\n${(trace.explanation?.reason_codes || []).map((c) => `| ${c.code} | ${c.severity} | ${c.label} |`).join("\n")}`
    : "";

  return `# PathTrace Report

**Generated:** ${now}${state.redactMode ? " (REDACTED)" : ""}
**Destination:** ${r(trace.query)}
**Analyzed at:** ${trace.analyzed_at}
**Platform:** ${trace.snapshot?.platform || "unknown"}

---

## Summary

${trace.explanation?.summary || "Trace completed."}

---

## DNS Resolution

**Status:** ${r(trace.dns.status)}
**Required:** ${trace.dns.required}
${trace.dns.resolver_used ? `**Resolver used:** ${r(trace.dns.resolver_used)}` : ""}
${trace.dns.result ? `**Result:** ${r(trace.dns.result)}` : ""}
${trace.dns.matched_rule ? `**Split-DNS rule:** ${r(trace.dns.matched_rule)}` : ""}
${trace.dns.failure_reason ? `**Failure reason:** ${trace.dns.failure_reason}` : ""}

---

## Routing Decision

**Status:** ${r(trace.route.status)}
${trace.route.matched_route ? `**Matched route:** ${r(trace.route.matched_route.destination)} via ${r(trace.route.matched_route.gateway)} on ${r(trace.route.matched_route.interface)}` : ""}
${trace.route.lookup_error ? `**Error:** ${trace.route.lookup_error}` : ""}

---

## Egress Interface

**Interface:** ${r(trace.egress.name)} (${trace.egress.interface_type})
**Protocol:** ${r(trace.egress.protocol)}
${trace.egress.source_ip ? `**Source IP:** ${r(trace.egress.source_ip)}` : ""}
${trace.egress.mtu ? `**MTU:** ${trace.egress.mtu}${trace.egress.mtu_warning ? " ⚠ below 1500" : ""}` : ""}
${trace.egress.tunnel_endpoint ? `**Tunnel endpoint:** ${r(trace.egress.tunnel_endpoint)}` : ""}
${trace.egress.ssid ? `**SSID:** ${r(trace.egress.ssid)}` : ""}

---

## Firewall

**Detectable:** ${trace.firewall.detectable}
**Status:** ${trace.firewall.status}
${(trace.firewall.rules || []).length ? `**Blocking rules:** ${trace.firewall.rules.map((rule) => rule.name).join(", ")}` : ""}

---

${conflictSection}

---

${reasonCodes}

---

## Interfaces at Snapshot

${(trace.snapshot?.interfaces || []).map((i) => `- **${r(i.name)}** (${i.interface_type}) ${i.status} · ${r(i.ipv4 || i.ipv6 || "no IP")} · MTU ${i.mtu || "—"}`).join("\n")}

---

## DNS Resolvers

${(trace.snapshot?.dns_resolvers || []).map((res) => `- **${r(res.scope)}** → ${r(res.server)}:${res.port || 53} (${res.source})`).join("\n")}

---

*Generated by PathTrace — network decision analyzer*
`;
}

function buildPlainReport(trace) {
  const r = state.redactMode ? (s) => redact(String(s ?? "")) : (s) => String(s ?? "");
  return [
    `PathTrace Report — ${new Date().toISOString()}${state.redactMode ? " [REDACTED]" : ""}`,
    `Destination: ${r(trace.query)}`,
    ``,
    `SUMMARY`,
    trace.explanation?.summary || "Trace completed.",
    ``,
    `DNS: ${r(trace.dns.status)} — ${trace.dns.result ? r(trace.dns.result) : "failed"}`,
    `Route: ${r(trace.route.status)}`,
    `Egress: ${r(trace.egress.name)} (${trace.egress.interface_type}) · ${r(trace.egress.protocol)}`,
    `MTU: ${trace.egress.mtu || "—"}${trace.egress.mtu_warning ? " [LOW]" : ""}`,
    `Firewall: ${trace.firewall.status}`,
    ``,
    ...(trace.policy_conflicts || []).map((c) => `[${c.severity.toUpperCase()}] ${c.title}: ${c.description}`),
  ].join("\n");
}

function buildJsonReport(trace) {
  const clean = state.redactMode ? JSON.parse(redact(JSON.stringify(trace))) : trace;
  return JSON.stringify(clean, null, 2);
}

function renderReportTab() {
  if (!state.trace) {
    return `<div class="empty-card"><div class="empty-inner">
      <div class="empty-title">No trace to report</div>
      <p class="empty-text">Run a trace first to generate a report.</p>
    </div></div>`;
  }

  const fmt = state.reportFormat;
  const reportText = fmt === "markdown" ? buildMarkdownReport(state.trace)
    : fmt === "plain" ? buildPlainReport(state.trace)
    : buildJsonReport(state.trace);

  return `
    <article class="result-card">
      <header class="card-header">
        <div class="card-icon icon-exp">RPT</div>
        <h2 class="card-title">troubleshooting report</h2>
        <div class="status-pill status-ok">${state.redactMode ? "redacted" : "full"}</div>
      </header>
      <div class="card-body report-controls">
        <div class="tabs" role="tablist">
          <button class="tab ${fmt === "markdown" ? "active" : ""}" type="button" data-report-format="markdown">Markdown</button>
          <button class="tab ${fmt === "plain" ? "active" : ""}" type="button" data-report-format="plain">Plain text</button>
          <button class="tab ${fmt === "json" ? "active" : ""}" type="button" data-report-format="json">JSON</button>
        </div>
        <div class="report-actions">
          <button class="button secondary" type="button" data-copy-report>copy to clipboard</button>
          <button class="button secondary" type="button" data-download-report>download</button>
          ${state.redactMode ? '<span class="badge status-warn" style="padding:4px 7px">redaction ON</span>' : '<span class="badge status-neutral" style="padding:4px 7px">redaction OFF</span>'}
        </div>
      </div>
      <div class="report-body">
        <pre class="report-pre" data-report-text>${escapeHtml(reportText)}</pre>
      </div>
    </article>
    ${renderResolverTestsCard()}
  `;
}

// ── Main trace tab ─────────────────────────────────────────────────────────
function renderTraceTab() {
  if (state.error) {
    return renderErrorCard(state.error, state.error.includes("permission") ? "Linux: retry with sudo or grant CAP_NET_ADMIN where required" : "");
  }
  if (!state.trace) {
    return `
      <div class="empty-card">
        <div class="empty-inner">
          <svg class="empty-mark" viewBox="0 0 64 64" fill="none" aria-hidden="true">
            <path d="M10 34h15l6-18 8 32 6-14h9" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
            <circle cx="10" cy="34" r="4" fill="currentColor"/>
            <circle cx="54" cy="34" r="4" fill="currentColor"/>
          </svg>
          <div class="empty-title">Trace a destination</div>
          <p class="empty-text">Enter an IP address, FQDN, hostname, or CIDR to see the resolver, winning route, egress interface, tunnel details, and detectable firewall policy.</p>
        </div>
      </div>
    `;
  }
  return [
    renderExplanationCard(state.trace),
    renderConflictsCard(state.trace),
    renderDnsCard(state.trace),
    renderRouteCard(state.trace),
    renderEgressCard(state.trace),
    renderFirewallCard(state.trace),
  ].filter(Boolean).join("");
}

// ── Render dispatch ────────────────────────────────────────────────────────
function renderResults() {
  // Update main tab buttons
  document.querySelectorAll("[data-main-tab]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.mainTab === state.activeMainTab);
  });
  // Update redact button
  if (els.redactButton) {
    els.redactButton.classList.toggle("active", state.redactMode);
  }

  switch (state.activeMainTab) {
    case "trace":    els.results.innerHTML = renderTraceTab(); break;
    case "timeline": els.results.innerHTML = renderTimelineTab(); break;
    case "diff":     els.results.innerHTML = renderDiffTab(); break;
    case "probes":   els.results.innerHTML = renderProbesTab(); break;
    case "coverage": els.results.innerHTML = renderCoverageTab(); break;
    case "simulate": els.results.innerHTML = renderSimulateTab(); break;
    case "report":   els.results.innerHTML = renderReportTab(); break;
    default:         els.results.innerHTML = renderTraceTab();
  }
}

function render() {
  renderSidebar();
  renderHistory();
  renderResults();
}

// ── Network operations ─────────────────────────────────────────────────────
async function refreshSnapshot(autoRerun = false) {
  try {
    state.snapshot = isTauri ? await invoke("get_network_snapshot") : { ...demoSnapshot, updated_at: new Date().toISOString() };
    state.lastUpdatedAt = Date.now();
    state.error = "";
    if (!state.selectedInterface && state.snapshot.interfaces?.length) {
      state.selectedInterface = state.snapshot.interfaces[0].name;
    }
    if (autoRerun && state.trace?.query) {
      await analyze(state.trace.query, { silent: true });
    }
  } catch (err) {
    state.error = String(err);
  }
  render();
}

async function analyze(query, options = {}) {
  const trimmed = query.trim();
  els.queryError.classList.remove("visible");
  els.queryError.textContent = "";
  if (!isValidDestination(trimmed)) {
    els.queryError.textContent = "Destination is unparseable. Use an IP, CIDR, hostname, or FQDN.";
    els.queryError.classList.add("visible");
    return;
  }

  try {
    state.trace = isTauri ? await invoke("analyze_destination", { destination: trimmed }) : buildDemoTrace(trimmed);
    state.snapshot = state.trace.snapshot || state.snapshot;
    state.selectedInterface = state.trace.route?.matched_interface || state.selectedInterface;
    state.error = "";
    state.history = [trimmed, ...state.history.filter((item) => item !== trimmed)].slice(0, 10);
    state.lastUpdatedAt = Date.now();

    // Feature 3: add to timeline (only for explicit user-initiated traces)
    if (!options.silent) {
      state.timeline.unshift({ trace: state.trace, ts: new Date().toISOString() });
      if (state.timeline.length > 20) state.timeline.pop();
      state.selectedTimelineIndex = null;
    }

    // Clear stale probe/resolver results when query changes
    if (state.probeResult?.destination !== trimmed) {
      state.probeResult = null;
    }
    if (state.resolverTestResults) {
      state.resolverTestResults = null;
    }
  } catch (err) {
    state.error = String(err);
    if (String(err).toLowerCase().includes("permission")) {
      state.error += " Permission-sensitive route or firewall data may require elevated access.";
    }
  }
  if (!options.silent) {
    els.results.scrollTo?.({ top: 0, behavior: "smooth" });
  }
  render();
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      els.queryInput.value = text.trim();
      els.queryInput.focus();
    }
  } catch {
    els.queryError.textContent = "Clipboard access was blocked by the OS or browser preview.";
    els.queryError.classList.add("visible");
  }
}

async function exportTrace() {
  if (!state.trace) return;
  const json = isTauri ? await invoke("export_trace_json", { trace: state.trace }) : JSON.stringify(state.trace, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `pathtrace-${state.trace.query.replace(/[^a-z0-9.-]+/gi, "_")}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function runProbes() {
  if (!state.trace) return;
  state.probeRunning = true;
  renderResults();
  try {
    state.probeResult = isTauri
      ? await invoke("run_packet_tests", { destination: state.trace.query })
      : buildDemoProbeResult(state.trace.query);
  } catch (err) {
    state.probeResult = { destination: state.trace.query, started_at: new Date().toISOString(), tests: [{ name: "Error", kind: "dns", status: "failed", result: null, latency_ms: null, error: String(err), note: null }] };
  }
  state.probeRunning = false;
  renderResults();
}

function buildDemoProbeResult(destination) {
  const vpn = destination.endsWith("corp.internal");
  return {
    destination,
    started_at: new Date().toISOString(),
    tests: [
      { name: "DNS resolution", kind: "dns", status: "ok", result: vpn ? "10.22.14.88" : "104.18.32.47", latency_ms: 8.4, error: null, note: null },
      { name: "ICMP ping", kind: "ping", status: vpn ? "ok" : "ok", result: vpn ? "reachable" : "reachable", latency_ms: 12.1, error: null, note: "⚠ active probe: sends ICMP packets" },
      { name: "TCP connect :443", kind: "tcp", status: vpn ? "ok" : "ok", result: "connected", latency_ms: 18.7, error: null, note: "⚠ active probe: opens TCP connection" },
      { name: "TCP connect :80", kind: "tcp", status: "ok", result: "connected", latency_ms: 16.2, error: null, note: "⚠ active probe: opens TCP connection" },
      { name: "MTU probe (ping 1400B)", kind: "mtu", status: vpn ? "failed" : "ok", result: vpn ? null : "MTU 1400+ path OK", latency_ms: null, error: vpn ? "MTU probe failed — possible fragmentation" : null, note: "⚠ active probe: sends large ICMP packet" },
      { name: "HTTP HEAD", kind: "http", status: "ok", result: "HTTP 200", latency_ms: null, error: null, note: "⚠ active probe: sends HTTP HEAD request" },
    ],
  };
}

async function runSimulation() {
  if (!state.trace) return;
  // Update dns_answer_override from input
  const dnsOverrideEl = document.querySelector("[data-sim-dns-override]");
  if (dnsOverrideEl) {
    state.simOverrides.dns_answer_override = dnsOverrideEl.value.trim() || null;
  }
  try {
    state.simResult = isTauri
      ? await invoke("simulate_route", { destination: state.trace.query, overrides: state.simOverrides })
      : buildDemoSimResult(state.trace.query, state.simOverrides);
  } catch (err) {
    state.simResult = { destination: state.trace.query, simulated: true, winning_route: null, winning_interface: null, dns_answer: null, changes_applied: [], note: `⚠ SIMULATED — Error: ${err}` };
  }
  renderResults();
}

function buildDemoSimResult(destination, overrides) {
  const changes = [];
  overrides.added_routes?.forEach((r) => changes.push(`added route: ${r.destination} via ${r.gateway} on ${r.interface}`));
  overrides.removed_destinations?.forEach((d) => changes.push(`removed route: ${d}`));
  overrides.interface_states?.forEach((s) => changes.push(`interface ${s.name} → ${s.up ? "up" : "down"}`));
  if (overrides.dns_answer_override) changes.push(`DNS override: ${destination} → ${overrides.dns_answer_override}`);

  const vpnDown = overrides.interface_states?.some((s) => s.name === "utun3" && !s.up);
  const removedVpn = overrides.removed_destinations?.includes("10.0.0.0/8");

  return {
    destination,
    simulated: true,
    winning_route: (vpnDown || removedVpn)
      ? { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "en0", metric: 100, source: "DHCP (simulated fallback)", matched: true }
      : { destination: "10.0.0.0/8", gateway: "10.8.0.1", interface: "utun3", metric: 50, source: "VPN push", matched: true },
    winning_interface: (vpnDown || removedVpn) ? "en0" : "utun3",
    dns_answer: overrides.dns_answer_override || (destination.endsWith("corp.internal") ? "10.22.14.88" : "104.18.32.47"),
    changes_applied: changes,
    note: "⚠ SIMULATED — no system configuration was modified.",
  };
}

async function runResolverTests() {
  if (!state.trace) return;
  state.resolverTestRunning = true;
  renderResults();
  try {
    state.resolverTestResults = isTauri
      ? await invoke("test_resolvers", { hostname: state.trace.query })
      : buildDemoResolverResults(state.trace.query);
  } catch (err) {
    state.resolverTestResults = [{ resolver: "error", scope: "default", interface: null, status: "failed", answers: [], latency_ms: null, error: String(err), findings: [] }];
  }
  state.resolverTestRunning = false;
  renderResults();
}

function buildDemoResolverResults(hostname) {
  const vpn = hostname.endsWith("corp.internal");
  return [
    {
      resolver: "10.8.0.1:53",
      scope: "corp.internal",
      interface: "utun3",
      status: vpn ? "ok" : "nxdomain",
      answers: vpn ? ["10.22.14.88"] : [],
      latency_ms: 4.2,
      error: vpn ? null : "NXDOMAIN — domain not in corp.internal zone",
      findings: vpn ? [] : ["ℹ This resolver only serves corp.internal domains"],
    },
    {
      resolver: "1.1.1.1:53",
      scope: "default",
      interface: "en0",
      status: vpn ? "nxdomain" : "ok",
      answers: vpn ? [] : ["104.18.32.47", "104.18.33.47"],
      latency_ms: 18.7,
      error: vpn ? "NXDOMAIN — corp.internal not resolvable via public DNS" : null,
      findings: vpn ? ["⚠ Split-brain: corp.internal resolver returned different answer", "ℹ Private IP returned by default-scope resolver — possible internal DNS leakage"] : [],
    },
    {
      resolver: "8.8.8.8:53",
      scope: "default",
      interface: "en0",
      status: vpn ? "nxdomain" : "ok",
      answers: vpn ? [] : ["142.250.80.46"],
      latency_ms: 22.1,
      error: vpn ? "NXDOMAIN" : null,
      findings: vpn ? ["⚠ Split-brain: different answers than 1.1.1.1"] : [],
    },
    {
      resolver: "system resolver",
      scope: "default",
      interface: null,
      status: "ok",
      answers: vpn ? ["10.22.14.88"] : ["104.18.32.47"],
      latency_ms: 2.1,
      error: null,
      findings: [],
    },
  ];
}

function tick() {
  const seconds = Math.max(0, Math.floor((Date.now() - state.lastUpdatedAt) / 1000));
  els.liveText.textContent = `live — last updated ${seconds}s ago`;
}

// ── Event handling ─────────────────────────────────────────────────────────
els.queryForm.addEventListener("submit", (e) => {
  e.preventDefault();
  analyze(els.queryInput.value);
});

els.historyButton.addEventListener("click", () => {
  els.historyMenu.classList.toggle("open");
});

els.historyMenu.addEventListener("click", (e) => {
  const button = e.target.closest("[data-history-query]");
  if (!button) return;
  els.queryInput.value = button.dataset.historyQuery;
  els.historyMenu.classList.remove("open");
  analyze(button.dataset.historyQuery);
});

els.pasteButton.addEventListener("click", pasteFromClipboard);
els.exportButton.addEventListener("click", exportTrace);

els.redactButton.addEventListener("click", () => {
  state.redactMode = !state.redactMode;
  render();
});

document.addEventListener("click", async (e) => {
  // Dismiss history menu
  if (!e.target.closest(".history-wrap")) {
    els.historyMenu.classList.remove("open");
  }

  // Interface selection
  const ifaceButton = e.target.closest("[data-interface]");
  if (ifaceButton) {
    state.selectedInterface = ifaceButton.dataset.interface;
    renderSidebar();
    return;
  }

  // Route tabs
  const routeTab = e.target.closest("[data-route-tab]");
  if (routeTab) {
    state.activeRouteTab = routeTab.dataset.routeTab;
    renderResults();
    return;
  }

  // Main tabs
  const mainTab = e.target.closest("[data-main-tab]");
  if (mainTab) {
    state.activeMainTab = mainTab.dataset.mainTab;
    renderResults();
    return;
  }

  // Retrace IP click
  const retrace = e.target.closest("[data-retrace]");
  if (retrace) {
    els.queryInput.value = retrace.dataset.retrace;
    analyze(retrace.dataset.retrace);
    return;
  }

  // Feature 1: expand explanation
  const expToggle = e.target.closest("[data-exp-toggle]");
  if (expToggle) {
    state.explanationExpanded = !state.explanationExpanded;
    renderResults();
    return;
  }

  // Feature 2: set baseline
  const setBaseline = e.target.closest("[data-set-baseline]");
  if (setBaseline) {
    state.baselineSnapshot = { ...(state.snapshot || demoSnapshot), _capturedAt: Date.now() };
    renderResults();
    return;
  }

  // Feature 3: timeline entry
  const timelineEntry = e.target.closest("[data-timeline-index]");
  if (timelineEntry) {
    const idx = parseInt(timelineEntry.dataset.timelineIndex, 10);
    state.selectedTimelineIndex = state.selectedTimelineIndex === idx ? null : idx;
    renderResults();
    return;
  }

  // Feature 4: run probes
  const runProbesBtn = e.target.closest("[data-run-probes]");
  if (runProbesBtn && !state.probeRunning) {
    await runProbes();
    return;
  }

  // Feature 7: report format
  const reportFmt = e.target.closest("[data-report-format]");
  if (reportFmt) {
    state.reportFormat = reportFmt.dataset.reportFormat;
    renderResults();
    return;
  }

  // Feature 7: copy report
  const copyReport = e.target.closest("[data-copy-report]");
  if (copyReport) {
    const pre = document.querySelector("[data-report-text]");
    if (pre) {
      try {
        await navigator.clipboard.writeText(pre.textContent);
        copyReport.textContent = "copied!";
        setTimeout(() => { copyReport.textContent = "copy to clipboard"; }, 1500);
      } catch {}
    }
    return;
  }

  // Feature 7: download report
  const downloadReport = e.target.closest("[data-download-report]");
  if (downloadReport) {
    if (!state.trace) return;
    const fmt = state.reportFormat;
    const text = fmt === "markdown" ? buildMarkdownReport(state.trace) : fmt === "plain" ? buildPlainReport(state.trace) : buildJsonReport(state.trace);
    const ext = { markdown: "md", plain: "txt", json: "json" }[fmt] || "txt";
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pathtrace-report-${(state.trace?.query || "trace").replace(/[^a-z0-9.-]+/gi, "_")}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
    return;
  }

  // Feature 9: simulate
  const runSim = e.target.closest("[data-run-sim]");
  if (runSim && !runSim.disabled) {
    await runSimulation();
    return;
  }

  const clearSim = e.target.closest("[data-clear-sim]");
  if (clearSim) {
    state.simOverrides = { added_routes: [], removed_destinations: [], interface_states: [], dns_answer_override: null, metric_overrides: [] };
    state.simResult = null;
    renderResults();
    return;
  }

  const simAddRoute = e.target.closest("[data-sim-add-route]");
  if (simAddRoute) {
    const dest = document.querySelector("[data-sim-dest]")?.value?.trim();
    const gw = document.querySelector("[data-sim-gw]")?.value?.trim();
    const iface = document.querySelector("[data-sim-iface]")?.value?.trim();
    const metric = parseInt(document.querySelector("[data-sim-metric]")?.value || "0", 10) || undefined;
    if (dest && gw && iface) {
      state.simOverrides.added_routes.push({ destination: dest, gateway: gw, interface: iface, metric });
      renderResults();
    }
    return;
  }

  const simAddRemove = e.target.closest("[data-sim-add-remove]");
  if (simAddRemove) {
    const dest = document.querySelector("[data-sim-remove-dest-input]")?.value?.trim();
    if (dest) {
      state.simOverrides.removed_destinations.push(dest);
      renderResults();
    }
    return;
  }

  const simAddIface = e.target.closest("[data-sim-add-iface]");
  if (simAddIface) {
    const name = document.querySelector("[data-sim-iface-name]")?.value?.trim();
    const up = document.querySelector("[data-sim-iface-state]")?.value === "up";
    if (name) {
      state.simOverrides.interface_states.push({ name, up });
      renderResults();
    }
    return;
  }

  const simRemoveRoute = e.target.closest("[data-sim-remove-route]");
  if (simRemoveRoute) {
    state.simOverrides.added_routes.splice(parseInt(simRemoveRoute.dataset.simRemoveRoute, 10), 1);
    renderResults();
    return;
  }

  const simRemoveDest = e.target.closest("[data-sim-remove-dest]");
  if (simRemoveDest) {
    state.simOverrides.removed_destinations.splice(parseInt(simRemoveDest.dataset.simRemoveDest, 10), 1);
    renderResults();
    return;
  }

  const simRemoveIface = e.target.closest("[data-sim-remove-iface]");
  if (simRemoveIface) {
    state.simOverrides.interface_states.splice(parseInt(simRemoveIface.dataset.simRemoveIface, 10), 1);
    renderResults();
    return;
  }

  // Feature 10: resolver tests
  const runResolverTestsBtn = e.target.closest("[data-run-resolver-tests]");
  if (runResolverTestsBtn && !state.resolverTestRunning) {
    await runResolverTests();
    return;
  }
});

// ── Resizable panels ───────────────────────────────────────────────────────
function initResize() {
  const sidebar = document.querySelector(".sidebar");
  const ifaceList = document.querySelector(".interface-list");
  const dnsList = document.querySelector(".dns-list");

  const LS_SIDEBAR = "pt_sidebar_w";
  const LS_IFACE   = "pt_iface_h";
  const LS_DNS     = "pt_dns_h";

  // Restore saved sizes
  const savedSidebar = localStorage.getItem(LS_SIDEBAR);
  if (savedSidebar) sidebar.style.width = savedSidebar;
  const savedIface = localStorage.getItem(LS_IFACE);
  if (savedIface) ifaceList.style.maxHeight = savedIface;
  const savedDns = localStorage.getItem(LS_DNS);
  if (savedDns) dnsList.style.maxHeight = savedDns;

  function makeDrag({ handle, onMove, onDone }) {
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      document.body.style.userSelect = "none";
      handle.classList.add("dragging");
      const move = (e) => onMove(e);
      const up = () => {
        document.body.style.userSelect = "";
        handle.classList.remove("dragging");
        onDone?.();
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
      };
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    });
  }

  // Sidebar width
  const sidebarHandle = document.querySelector("[data-sidebar-resize]");
  if (sidebarHandle) {
    let startX, startW;
    makeDrag({
      handle: sidebarHandle,
      onMove(e) {
        if (startX === undefined) { startX = e.clientX; startW = sidebar.getBoundingClientRect().width; }
        const w = Math.max(160, Math.min(420, startW + (e.clientX - startX)));
        sidebar.style.width = w + "px";
      },
      onDone() { startX = undefined; localStorage.setItem(LS_SIDEBAR, sidebar.style.width); },
    });
  }

  // Interface panel height
  const ifaceHandle = document.querySelector('[data-panel-resize="interfaces"]');
  if (ifaceHandle) {
    let startY, startH;
    makeDrag({
      handle: ifaceHandle,
      onMove(e) {
        if (startY === undefined) { startY = e.clientY; startH = ifaceList.getBoundingClientRect().height; }
        const h = Math.max(52, Math.min(480, startH + (e.clientY - startY)));
        ifaceList.style.maxHeight = h + "px";
      },
      onDone() { startY = undefined; localStorage.setItem(LS_IFACE, ifaceList.style.maxHeight); },
    });
  }

  // DNS panel height
  const dnsHandle = document.querySelector('[data-panel-resize="dns"]');
  if (dnsHandle) {
    let startY, startH;
    makeDrag({
      handle: dnsHandle,
      onMove(e) {
        if (startY === undefined) { startY = e.clientY; startH = dnsList.getBoundingClientRect().height; }
        const h = Math.max(36, Math.min(360, startH + (e.clientY - startY)));
        dnsList.style.maxHeight = h + "px";
      },
      onDone() { startY = undefined; localStorage.setItem(LS_DNS, dnsList.style.maxHeight); },
    });
  }
}

// ── Boot ───────────────────────────────────────────────────────────────────
async function boot() {
  try {
    const tauriCore = await import("@tauri-apps/api/core");
    invoke = tauriCore.invoke;
    isTauri = Boolean(window.__TAURI_INTERNALS__ && invoke);
  } catch {
    invoke = null;
    isTauri = false;
  }

  document.documentElement.setAttribute("data-theme", matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  initResize();
  await refreshSnapshot(false);
  await analyze(els.queryInput.value, { silent: true });
  setInterval(tick, 1000);
  setInterval(() => refreshSnapshot(Boolean(state.trace)), 5000);
}

boot();
