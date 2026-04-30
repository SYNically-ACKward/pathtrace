use serde::{Deserialize, Serialize};

// ── Core network models ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<NetworkInterface>,
    pub dns_resolvers: Vec<DnsResolver>,
    pub routes: Vec<RouteEntry>,
    pub firewall: FirewallSummary,
    pub events: Vec<ChangeEvent>,
    pub updated_at: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub display_name: Option<String>,
    pub status: String,
    pub interface_type: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub tunnel_protocol: Option<String>,
    pub tunnel_endpoint: Option<String>,
    pub encapsulation_overhead: Option<u32>,
    pub last_handshake: Option<String>,
    pub ssid: Option<String>,
    pub signal_strength: Option<String>,
    pub band: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolver {
    pub scope: String,
    pub server: String,
    pub port: Option<u16>,
    pub interface: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: Option<u32>,
    pub source: String,
    pub matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallSummary {
    pub detectable: bool,
    pub rules: Vec<FirewallRule>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub action: String,
    pub direction: String,
    pub protocol: Option<String>,
    pub destination: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub timestamp: String,
    pub category: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub query: String,
    pub input_kind: String,
    pub dns: DnsDecision,
    pub route: RouteDecision,
    pub egress: EgressInterface,
    pub firewall: FirewallSummary,
    pub reachability: Option<String>,
    pub snapshot: NetworkSnapshot,
    pub analyzed_at: String,
    // Feature 1: explanation
    pub explanation: Option<TraceExplanation>,
    // Feature 6: policy conflicts
    pub policy_conflicts: Vec<PolicyConflict>,
    // Feature 5: split tunnel coverage
    pub tunnel_coverage: Option<TunnelCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDecision {
    pub required: bool,
    pub query: String,
    pub resolver_used: Option<String>,
    pub status: String,
    pub result: Option<String>,
    pub flow: Vec<FlowNode>,
    pub matched_rule: Option<String>,
    pub fallback_resolver: Option<String>,
    pub cache_status: String,
    pub ttl_remaining: Option<u32>,
    pub failure_reason: Option<String>,
    pub tried_resolvers: Vec<String>,
}

impl DnsDecision {
    pub fn failed(query: &str, tried_resolvers: Vec<String>, reason: &str) -> Self {
        Self {
            required: true,
            query: query.to_string(),
            resolver_used: tried_resolvers.first().cloned(),
            status: "resolution failed".to_string(),
            result: None,
            flow: vec![FlowNode {
                label: "query".to_string(),
                value: query.to_string(),
                kind: "query".to_string(),
            }],
            matched_rule: None,
            fallback_resolver: None,
            cache_status: "miss / unavailable".to_string(),
            ttl_remaining: None,
            failure_reason: Some(reason.to_string()),
            tried_resolvers,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNode {
    pub label: String,
    pub value: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    pub status: String,
    pub matched_interface: Option<String>,
    pub matched_route: Option<RouteEntry>,
    pub routes: Vec<RouteEntry>,
    pub lookup_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressInterface {
    pub name: String,
    pub interface_type: String,
    pub protocol: String,
    pub tunnel_endpoint: Option<String>,
    pub source_ip: Option<String>,
    pub mtu: Option<u32>,
    pub mtu_warning: bool,
    pub encapsulation_overhead: Option<u32>,
    pub last_handshake: Option<String>,
    pub ssid: Option<String>,
    pub signal_strength: Option<String>,
    pub band: Option<String>,
}

// ── Feature 1: Decision explanation ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceExplanation {
    pub summary: String,
    pub dns_explanation: ExplanationBlock,
    pub route_explanation: ExplanationBlock,
    pub egress_explanation: ExplanationBlock,
    pub firewall_explanation: ExplanationBlock,
    pub reason_codes: Vec<ReasonCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationBlock {
    pub headline: String,
    pub detail: String,
    pub severity: String, // "ok" | "warn" | "error" | "info"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonCode {
    pub code: String,
    pub label: String,
    pub description: String,
    pub severity: String,
}

// ── Feature 4: Packet test suite ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketTestSuite {
    pub destination: String,
    pub started_at: String,
    pub tests: Vec<PacketTest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketTest {
    pub name: String,
    pub kind: String, // "dns" | "ping" | "tcp" | "http" | "tls" | "mtu"
    pub status: String, // "ok" | "failed" | "timeout" | "unsupported" | "skipped"
    pub result: Option<String>,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
    pub note: Option<String>, // label for active traffic warning
}

// ── Feature 5: Split tunnel coverage ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelCoverage {
    pub vpn_prefixes: Vec<String>,
    pub local_prefixes: Vec<String>,
    pub default_route_interface: Option<String>,
    pub default_captured_by_vpn: bool,
    pub dns_scopes: Vec<DnsScope>,
    pub unknown_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsScope {
    pub scope: String,
    pub servers: Vec<String>,
    pub interface: Option<String>,
}

// ── Feature 6: Policy conflict detector ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConflict {
    pub id: String,
    pub severity: String, // "error" | "warn" | "info"
    pub title: String,
    pub description: String,
    pub affected: Vec<String>,
}

// ── Feature 9: Route simulator ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimulatorOverrides {
    pub added_routes: Vec<SimRouteOverride>,
    pub removed_destinations: Vec<String>,
    pub interface_states: Vec<SimInterfaceState>,
    pub dns_answer_override: Option<String>,
    pub metric_overrides: Vec<SimMetricOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimRouteOverride {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimInterfaceState {
    pub name: String,
    pub up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimMetricOverride {
    pub destination: String,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub destination: String,
    pub simulated: bool,
    pub winning_route: Option<RouteEntry>,
    pub winning_interface: Option<String>,
    pub dns_answer: Option<String>,
    pub changes_applied: Vec<String>,
    pub note: String,
}

// ── Feature 10: Resolver-specific DNS testing ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverTestResult {
    pub resolver: String,
    pub scope: String,
    pub interface: Option<String>,
    pub status: String, // "ok" | "failed" | "timeout" | "nxdomain"
    pub answers: Vec<String>,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
    pub findings: Vec<String>, // split-brain, stale, leakage notices
}
