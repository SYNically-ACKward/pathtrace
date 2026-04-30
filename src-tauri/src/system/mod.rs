pub mod models;
mod platform;

use dns_lookup::lookup_host;
use ipnetwork::IpNetwork;
use models::*;
use std::net::IpAddr;
use std::str::FromStr;

pub fn snapshot() -> Result<NetworkSnapshot, String> {
    platform::snapshot()
}

pub fn trace_destination(destination: String) -> Result<TraceResult, String> {
    let query = destination.trim().to_string();
    if query.is_empty() {
        return Err("Enter an IP address, FQDN, hostname, or CIDR.".to_string());
    }

    let snapshot = platform::snapshot().unwrap_or_else(|err| NetworkSnapshot {
        interfaces: vec![],
        dns_resolvers: vec![],
        routes: vec![],
        firewall: FirewallSummary {
            detectable: false,
            rules: vec![],
            status: format!("snapshot unavailable: {err}"),
        },
        events: vec![],
        updated_at: chrono::Utc::now().to_rfc3339(),
        platform: std::env::consts::OS.to_string(),
    });

    let input_kind = classify_destination(&query);
    let mut resolved_ip: Option<String> = None;
    let dns_decision = match input_kind {
        DestinationKind::Ip | DestinationKind::Cidr => {
            let direct = query.split('/').next().unwrap_or(query.as_str()).to_string();
            resolved_ip = Some(direct.clone());
            DnsDecision {
                required: false,
                query: query.clone(),
                resolver_used: None,
                status: "direct IP".to_string(),
                result: Some(direct),
                flow: vec![FlowNode {
                    label: "destination".to_string(),
                    value: query.clone(),
                    kind: "query".to_string(),
                }],
                matched_rule: None,
                fallback_resolver: snapshot
                    .dns_resolvers
                    .iter()
                    .find(|r| r.scope == "default")
                    .map(|r| format!("{} (not used)", r.server)),
                cache_status: "not applicable".to_string(),
                ttl_remaining: None,
                failure_reason: None,
                tried_resolvers: vec![],
            }
        }
        DestinationKind::Hostname => {
            let resolver = choose_resolver(&query, &snapshot.dns_resolvers);
            let mut tried = Vec::new();
            if let Some(sel) = &resolver {
                tried.push(format!("{}:{}", sel.server, sel.port.unwrap_or(53)));
            }

            match lookup_host(&query) {
                Ok(ips) if !ips.is_empty() => {
                    let ip = ips[0].to_string();
                    resolved_ip = Some(ip.clone());
                    let resolver_label = resolver
                        .as_ref()
                        .map(|r| format!("{}:{}", r.server, r.port.unwrap_or(53)))
                        .unwrap_or_else(|| "system resolver".to_string());
                    let resolver_scope = resolver
                        .as_ref()
                        .map(|r| r.scope.clone())
                        .unwrap_or_else(|| "system".to_string());
                    DnsDecision {
                        required: true,
                        query: query.clone(),
                        resolver_used: Some(resolver_label.clone()),
                        status: if resolver_scope == "default" {
                            "default resolver".to_string()
                        } else {
                            format!("split-dns → {resolver_scope}")
                        },
                        result: Some(ip.clone()),
                        flow: vec![
                            FlowNode { label: "query".to_string(), value: query.clone(), kind: "query".to_string() },
                            FlowNode { label: resolver_scope.clone(), value: resolver_label.clone(), kind: "resolver".to_string() },
                            FlowNode { label: "resolved result".to_string(), value: ip, kind: "resolved".to_string() },
                        ],
                        matched_rule: resolver.as_ref().and_then(|r| {
                            if r.scope == "default" {
                                None
                            } else {
                                Some(format!("{} → {}", r.scope, r.interface.clone().unwrap_or_default()))
                            }
                        }),
                        fallback_resolver: snapshot
                            .dns_resolvers
                            .iter()
                            .find(|r| r.scope == "default")
                            .map(|r| {
                                if tried.iter().any(|t| t.starts_with(&r.server)) {
                                    format!("{} (used)", r.server)
                                } else {
                                    format!("{} (not used)", r.server)
                                }
                            }),
                        cache_status: "OS resolver cache".to_string(),
                        ttl_remaining: None,
                        failure_reason: None,
                        tried_resolvers: tried,
                    }
                }
                Ok(_) => DnsDecision::failed(&query, tried, "resolver returned no records"),
                Err(err) => DnsDecision::failed(&query, tried, &err.to_string()),
            }
        }
    };

    let lookup_target = resolved_ip.clone().unwrap_or_else(|| query.clone());
    let route_lookup = platform::route_lookup(&lookup_target).unwrap_or_else(|err| RouteDecision {
        status: "route lookup unavailable".to_string(),
        matched_interface: None,
        matched_route: None,
        routes: snapshot.routes.clone(),
        lookup_error: Some(err),
    });

    let egress = build_egress(&route_lookup, &snapshot.interfaces);
    let firewall = platform::firewall_for_destination(&lookup_target)
        .unwrap_or_else(|_| snapshot.firewall.clone());
    let reachability = platform::ping_once(&lookup_target).ok();

    // Feature 5: tunnel coverage from snapshot
    let tunnel_coverage = Some(build_tunnel_coverage(&snapshot));

    // Feature 6: policy conflict detection
    let policy_conflicts = detect_policy_conflicts(&snapshot, &dns_decision, &route_lookup, &egress);

    // Feature 1: decision explanation
    let explanation = Some(build_explanation(&dns_decision, &route_lookup, &egress, &firewall, &policy_conflicts));

    Ok(TraceResult {
        query,
        input_kind: format!("{input_kind:?}"),
        dns: dns_decision,
        route: route_lookup,
        egress,
        firewall,
        reachability,
        snapshot,
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        explanation,
        policy_conflicts,
        tunnel_coverage,
    })
}

// ── Feature 1: Decision explanation ───────────────────────────────────────

pub fn build_explanation(
    dns: &DnsDecision,
    route: &RouteDecision,
    egress: &EgressInterface,
    firewall: &FirewallSummary,
    conflicts: &[PolicyConflict],
) -> TraceExplanation {
    let dns_block = build_dns_explanation(dns);
    let route_block = build_route_explanation(route, egress);
    let egress_block = build_egress_explanation(egress);
    let fw_block = build_firewall_explanation(firewall);

    let conflict_codes: Vec<ReasonCode> = conflicts.iter().map(|c| ReasonCode {
        code: c.id.clone(),
        label: c.title.clone(),
        description: c.description.clone(),
        severity: c.severity.clone(),
    }).collect();

    let mut reason_codes = vec![];

    // DNS reason codes
    if dns.failure_reason.is_some() {
        reason_codes.push(ReasonCode {
            code: "DNS_FAIL".to_string(),
            label: "DNS resolution failed".to_string(),
            description: dns.failure_reason.clone().unwrap_or_default(),
            severity: "error".to_string(),
        });
    } else if dns.required && dns.matched_rule.is_some() {
        reason_codes.push(ReasonCode {
            code: "DNS_SPLIT".to_string(),
            label: "Split-DNS policy applied".to_string(),
            description: format!("Query routed via split-DNS rule: {}", dns.matched_rule.clone().unwrap_or_default()),
            severity: "info".to_string(),
        });
    }

    // Route reason codes
    if route.lookup_error.is_some() {
        reason_codes.push(ReasonCode {
            code: "ROUTE_ERR".to_string(),
            label: "Route lookup failed".to_string(),
            description: route.lookup_error.clone().unwrap_or_default(),
            severity: "error".to_string(),
        });
    }

    if egress.mtu_warning {
        reason_codes.push(ReasonCode {
            code: "MTU_LOW".to_string(),
            label: "Low MTU detected".to_string(),
            description: format!("Egress interface MTU is {} (< 1500). Path MTU clamping may apply.", egress.mtu.unwrap_or(0)),
            severity: "warn".to_string(),
        });
    }

    if egress.interface_type == "VPN" {
        reason_codes.push(ReasonCode {
            code: "VPN_TUNNEL".to_string(),
            label: "Traffic tunneled through VPN".to_string(),
            description: format!("Packet will be encapsulated via {} using {}", egress.name, egress.protocol),
            severity: "info".to_string(),
        });
    }

    reason_codes.extend(conflict_codes);

    let summary = build_summary(dns, egress, firewall, &reason_codes);

    TraceExplanation {
        summary,
        dns_explanation: dns_block,
        route_explanation: route_block,
        egress_explanation: egress_block,
        firewall_explanation: fw_block,
        reason_codes,
    }
}

fn build_dns_explanation(dns: &DnsDecision) -> ExplanationBlock {
    if !dns.required {
        return ExplanationBlock {
            headline: "No DNS lookup required".to_string(),
            detail: "The destination is an IP address or CIDR. DNS resolution is skipped entirely — the OS routes the packet directly.".to_string(),
            severity: "ok".to_string(),
        };
    }
    if let Some(reason) = &dns.failure_reason {
        return ExplanationBlock {
            headline: format!("DNS resolution failed for «{}»", dns.query),
            detail: format!("The OS resolver returned an error: {reason}. Check that your DNS resolver is reachable and the domain exists."),
            severity: "error".to_string(),
        };
    }
    if let Some(rule) = &dns.matched_rule {
        return ExplanationBlock {
            headline: format!("Split-DNS policy routed «{}» to a scoped resolver", dns.query),
            detail: format!(
                "A split-DNS rule matched this query: {rule}. The name was resolved by {} instead of the default public resolver. Result: {}.",
                dns.resolver_used.clone().unwrap_or_else(|| "unknown".to_string()),
                dns.result.clone().unwrap_or_else(|| "no answer".to_string()),
            ),
            severity: "info".to_string(),
        };
    }
    ExplanationBlock {
        headline: format!("«{}» resolved via default resolver", dns.query),
        detail: format!(
            "No split-DNS rule matched. The system used {} and returned {}.",
            dns.resolver_used.clone().unwrap_or_else(|| "system resolver".to_string()),
            dns.result.clone().unwrap_or_else(|| "no answer".to_string()),
        ),
        severity: "ok".to_string(),
    }
}

fn build_route_explanation(route: &RouteDecision, egress: &EgressInterface) -> ExplanationBlock {
    if let Some(err) = &route.lookup_error {
        return ExplanationBlock {
            headline: "Route lookup failed".to_string(),
            detail: format!("The OS could not determine a route: {err}. This may require elevated permissions (sudo) or the destination is unreachable."),
            severity: "error".to_string(),
        };
    }
    if let Some(matched) = &route.matched_route {
        let src = &matched.source;
        let detail = if src.contains("VPN") || egress.interface_type == "VPN" {
            format!(
                "The most specific matching route is {} via {} ({}). Traffic will be encapsulated through the VPN tunnel — the VPN endpoint performs the final forwarding.",
                matched.destination, matched.gateway, matched.interface
            )
        } else if matched.destination == "0.0.0.0/0" {
            format!(
                "Traffic matched the default route (0.0.0.0/0) via gateway {} on {}. No more-specific route exists.",
                matched.gateway, matched.interface
            )
        } else {
            format!(
                "Traffic matched route {} via {} on interface {}.",
                matched.destination, matched.gateway, matched.interface
            )
        };
        return ExplanationBlock {
            headline: format!("Route matched: {} → {}", matched.destination, matched.interface),
            detail,
            severity: if egress.interface_type == "VPN" { "info" } else { "ok" }.to_string(),
        };
    }
    ExplanationBlock {
        headline: route.status.clone(),
        detail: "No specific route entry could be identified for the destination.".to_string(),
        severity: "warn".to_string(),
    }
}

fn build_egress_explanation(egress: &EgressInterface) -> ExplanationBlock {
    let mut detail = format!("Traffic exits via {} ({}). ", egress.name, egress.interface_type);
    if let Some(mtu) = egress.mtu {
        if egress.mtu_warning {
            detail.push_str(&format!("MTU is {mtu} — lower than standard 1500. Path MTU clamping is likely. "));
        }
    }
    if egress.interface_type == "VPN" {
        if let Some(ep) = &egress.tunnel_endpoint {
            detail.push_str(&format!("Tunnel endpoint: {ep}. "));
        }
        if let Some(proto) = egress.tunnel_endpoint.as_ref().map(|_| &egress.protocol) {
            detail.push_str(&format!("Protocol: {proto}. "));
        }
    }
    if let Some(ssid) = &egress.ssid {
        detail.push_str(&format!("Wi-Fi SSID: {ssid}. "));
        if let Some(sig) = &egress.signal_strength {
            detail.push_str(&format!("Signal: {sig}. "));
        }
    }
    ExplanationBlock {
        headline: format!("Egress: {} via {}", egress.name, egress.protocol),
        detail,
        severity: if egress.mtu_warning { "warn" } else { "ok" }.to_string(),
    }
}

fn build_firewall_explanation(fw: &FirewallSummary) -> ExplanationBlock {
    if !fw.detectable {
        return ExplanationBlock {
            headline: "Firewall rules not detectable".to_string(),
            detail: format!("{} Elevated permissions may be required.", fw.status),
            severity: "warn".to_string(),
        };
    }
    let blocking: Vec<&FirewallRule> = fw.rules.iter()
        .filter(|r| r.action.contains("block") || r.action.contains("drop") || r.action.contains("reject"))
        .collect();
    if blocking.is_empty() {
        return ExplanationBlock {
            headline: "No blocking firewall rules matched".to_string(),
            detail: format!("{} — traffic to this destination is not explicitly blocked.", fw.status),
            severity: "ok".to_string(),
        };
    }
    ExplanationBlock {
        headline: format!("{} blocking rule(s) matched", blocking.len()),
        detail: format!(
            "Rules with drop/block/reject actions were found: {}",
            blocking.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", ")
        ),
        severity: "error".to_string(),
    }
}

fn build_summary(
    dns: &DnsDecision,
    egress: &EgressInterface,
    firewall: &FirewallSummary,
    reason_codes: &[ReasonCode],
) -> String {
    let has_errors = reason_codes.iter().any(|c| c.severity == "error");
    let has_warnings = reason_codes.iter().any(|c| c.severity == "warn");

    if has_errors {
        return "One or more critical issues were detected. Connectivity to this destination is likely impaired.".to_string();
    }

    let vpn = egress.interface_type == "VPN";
    let fw_ok = !firewall.detectable || firewall.rules.iter().all(|r| !r.action.contains("block") && !r.action.contains("drop") && !r.action.contains("reject"));
    let dns_ok = dns.failure_reason.is_none();

    if vpn && dns_ok && fw_ok && !has_warnings {
        format!(
            "Traffic will be tunneled through {} ({}) with no detectable blocking rules. VPN encapsulation adds {} bytes overhead.",
            egress.name,
            egress.protocol,
            egress.encapsulation_overhead.unwrap_or(0)
        )
    } else if dns_ok && fw_ok && !has_warnings {
        format!(
            "Traffic will egress via {} ({}). DNS resolved successfully. No blocking rules detected.",
            egress.name,
            egress.protocol
        )
    } else {
        "Trace completed with warnings. Review the reason codes and policy conflicts below.".to_string()
    }
}

// ── Feature 5: Tunnel coverage ────────────────────────────────────────────

pub fn build_tunnel_coverage(snapshot: &NetworkSnapshot) -> TunnelCoverage {
    let vpn_ifaces: Vec<&NetworkInterface> = snapshot.interfaces.iter()
        .filter(|i| i.interface_type == "VPN" && i.status == "up")
        .collect();

    let mut vpn_prefixes: Vec<String> = vec![];
    let mut local_prefixes: Vec<String> = vec![];
    let mut unknown_prefixes: Vec<String> = vec![];

    let vpn_iface_names: Vec<&str> = vpn_ifaces.iter().map(|i| i.name.as_str()).collect();

    for route in &snapshot.routes {
        if vpn_iface_names.contains(&route.interface.as_str()) {
            vpn_prefixes.push(route.destination.clone());
        } else if route.destination.starts_with("10.") || route.destination.starts_with("192.168.") || route.destination.starts_with("172.") {
            local_prefixes.push(route.destination.clone());
        } else if route.interface.is_empty() || route.interface == "unknown" {
            unknown_prefixes.push(route.destination.clone());
        }
    }

    let default_route = snapshot.routes.iter().find(|r| r.destination == "0.0.0.0/0" || r.destination == "default");
    let default_route_interface = default_route.map(|r| r.interface.clone());
    let default_captured_by_vpn = default_route
        .map(|r| vpn_iface_names.contains(&r.interface.as_str()))
        .unwrap_or(false);

    let dns_scopes: Vec<DnsScope> = {
        let mut scopes: std::collections::BTreeMap<String, (Vec<String>, Option<String>)> = std::collections::BTreeMap::new();
        for resolver in &snapshot.dns_resolvers {
            let entry = scopes.entry(resolver.scope.clone()).or_insert_with(|| (vec![], resolver.interface.clone()));
            entry.0.push(format!("{}:{}", resolver.server, resolver.port.unwrap_or(53)));
        }
        scopes.into_iter().map(|(scope, (servers, interface))| DnsScope { scope, servers, interface }).collect()
    };

    TunnelCoverage {
        vpn_prefixes,
        local_prefixes,
        default_route_interface,
        default_captured_by_vpn,
        dns_scopes,
        unknown_prefixes,
    }
}

// ── Feature 6: Policy conflict detection ─────────────────────────────────

pub fn detect_policy_conflicts(
    snapshot: &NetworkSnapshot,
    dns: &DnsDecision,
    route: &RouteDecision,
    egress: &EgressInterface,
) -> Vec<PolicyConflict> {
    let mut conflicts: Vec<PolicyConflict> = vec![];

    // Split-DNS without matching VPN route
    let has_split_dns = snapshot.dns_resolvers.iter().any(|r| r.scope != "default");
    let vpn_ifaces: Vec<&str> = snapshot.interfaces.iter()
        .filter(|i| i.interface_type == "VPN" && i.status == "up")
        .map(|i| i.name.as_str())
        .collect();
    let has_vpn_routes = snapshot.routes.iter().any(|r| vpn_ifaces.contains(&r.interface.as_str()) && r.destination != "0.0.0.0/0");

    if has_split_dns && !has_vpn_routes && !vpn_ifaces.is_empty() {
        conflicts.push(PolicyConflict {
            id: "SPLIT_DNS_NO_ROUTE".to_string(),
            severity: "warn".to_string(),
            title: "Split-DNS without matching VPN routes".to_string(),
            description: "Split-DNS resolvers are configured but no specific VPN routes exist for those domains. DNS answers may resolve to internal IPs that are unreachable without a tunnel route.".to_string(),
            affected: snapshot.dns_resolvers.iter().filter(|r| r.scope != "default").map(|r| r.scope.clone()).collect(),
        });
    }

    // Competing default routes
    let default_routes: Vec<&RouteEntry> = snapshot.routes.iter().filter(|r| r.destination == "0.0.0.0/0").collect();
    if default_routes.len() > 1 {
        conflicts.push(PolicyConflict {
            id: "COMPETING_DEFAULTS".to_string(),
            severity: "warn".to_string(),
            title: "Competing default routes".to_string(),
            description: format!(
                "{} default routes exist (0.0.0.0/0). The OS will use the one with the lowest metric; the others are inactive but may cause confusion or failover issues.",
                default_routes.len()
            ),
            affected: default_routes.iter().map(|r| format!("{} metric={}", r.interface, r.metric.unwrap_or(0))).collect(),
        });
    }

    // Low MTU without tunnel
    if egress.mtu_warning && egress.interface_type != "VPN" {
        conflicts.push(PolicyConflict {
            id: "LOW_MTU_NO_TUNNEL".to_string(),
            severity: "warn".to_string(),
            title: "Low MTU on non-tunnel interface".to_string(),
            description: format!(
                "Interface {} has MTU {} which is below 1500. Without a VPN tunnel this may cause fragmentation or connectivity issues for large packets.",
                egress.name,
                egress.mtu.unwrap_or(0)
            ),
            affected: vec![egress.name.clone()],
        });
    }

    // IPv4/IPv6 asymmetry: has IPv6 resolvers but no IPv6 route or vice versa
    let has_ipv6_resolver = snapshot.dns_resolvers.iter().any(|r| r.server.contains(':'));
    let has_ipv6_route = snapshot.routes.iter().any(|r| r.destination.contains(':'));
    if has_ipv6_resolver && !has_ipv6_route {
        conflicts.push(PolicyConflict {
            id: "IPV6_ASYMMETRY".to_string(),
            severity: "info".to_string(),
            title: "IPv6 resolver without IPv6 route".to_string(),
            description: "An IPv6 DNS resolver is configured but no IPv6 routes are in the routing table. IPv6 DNS queries may fail or fall back.".to_string(),
            affected: snapshot.dns_resolvers.iter().filter(|r| r.server.contains(':')).map(|r| r.server.clone()).collect(),
        });
    }

    // DNS on down interface
    for resolver in &snapshot.dns_resolvers {
        if let Some(iface_name) = &resolver.interface {
            if let Some(iface) = snapshot.interfaces.iter().find(|i| &i.name == iface_name || i.display_name.as_deref() == Some(iface_name)) {
                if iface.status == "down" {
                    conflicts.push(PolicyConflict {
                        id: "DNS_DOWN_IFACE".to_string(),
                        severity: "error".to_string(),
                        title: "DNS resolver on down interface".to_string(),
                        description: format!(
                            "Resolver {} is bound to interface {} which is currently down. DNS queries to this resolver will fail.",
                            resolver.server, iface_name
                        ),
                        affected: vec![resolver.server.clone(), iface_name.clone()],
                    });
                }
            }
        }
    }

    // Default route captured by VPN (full tunnel)
    let default_on_vpn = default_routes.iter().any(|r| vpn_ifaces.contains(&r.interface.as_str()));
    if default_on_vpn {
        conflicts.push(PolicyConflict {
            id: "FULL_TUNNEL_VPN".to_string(),
            severity: "info".to_string(),
            title: "Full-tunnel VPN: all traffic through VPN".to_string(),
            description: "The default route (0.0.0.0/0) is captured by the VPN. All internet traffic will be routed through the tunnel. Local network access may be limited.".to_string(),
            affected: vpn_ifaces.iter().map(|s| s.to_string()).collect(),
        });
    }

    // Private DNS without private route
    if let Some(res) = &dns.resolver_used {
        let is_private_dns = res.starts_with("10.") || res.starts_with("192.168.") || res.starts_with("172.");
        let has_private_route = snapshot.routes.iter().any(|r| {
            r.destination.starts_with("10.") || r.destination.starts_with("192.168.") || r.destination.starts_with("172.")
        });
        if is_private_dns && !has_private_route {
            conflicts.push(PolicyConflict {
                id: "PRIVATE_DNS_NO_ROUTE".to_string(),
                severity: "warn".to_string(),
                title: "Private DNS resolver without private route".to_string(),
                description: format!("Resolver {} uses a private IP but no private-range route exists. The DNS query may be unreachable.", res),
                affected: vec![res.clone()],
            });
        }
    }

    // Resolver route leakage check
    if route.matched_interface.as_deref() != egress.tunnel_endpoint.as_deref().map(|_| "").or(Some("")).and_then(|_| None::<&str>) {
        // Check if a non-VPN interface is being used despite having a VPN resolver
        if !vpn_ifaces.is_empty() && egress.interface_type != "VPN" && dns.matched_rule.is_some() {
            conflicts.push(PolicyConflict {
                id: "RESOLVER_LEAK".to_string(),
                severity: "warn".to_string(),
                title: "Potential resolver route leakage".to_string(),
                description: "A split-DNS rule matched this query but the routing decision did not use the VPN interface. The resolved IP may not be reachable through the expected path.".to_string(),
                affected: vec![egress.name.clone()],
            });
        }
    }

    conflicts
}

// ── Feature 4: Packet test suite ──────────────────────────────────────────

pub fn run_packet_tests(destination: String) -> Result<PacketTestSuite, String> {
    let dest = destination.trim().to_string();
    let started_at = chrono::Utc::now().to_rfc3339();
    let mut tests = vec![];

    // Resolve hostname if needed
    let ip = if is_ip_str(&dest) {
        dest.clone()
    } else {
        match lookup_host(&dest) {
            Ok(ips) if !ips.is_empty() => {
                let ip = ips[0].to_string();
                tests.push(PacketTest {
                    name: "DNS resolution".to_string(),
                    kind: "dns".to_string(),
                    status: "ok".to_string(),
                    result: Some(ip.clone()),
                    latency_ms: None,
                    error: None,
                    note: None,
                });
                ip
            }
            Ok(_) => {
                tests.push(PacketTest {
                    name: "DNS resolution".to_string(),
                    kind: "dns".to_string(),
                    status: "failed".to_string(),
                    result: None,
                    latency_ms: None,
                    error: Some("no records returned".to_string()),
                    note: None,
                });
                dest.clone()
            }
            Err(e) => {
                tests.push(PacketTest {
                    name: "DNS resolution".to_string(),
                    kind: "dns".to_string(),
                    status: "failed".to_string(),
                    result: None,
                    latency_ms: None,
                    error: Some(e.to_string()),
                    note: None,
                });
                dest.clone()
            }
        }
    };

    // Ping test
    let ping_start = std::time::Instant::now();
    let ping_result = platform::ping_once(&ip);
    let ping_latency = ping_start.elapsed().as_secs_f64() * 1000.0;
    tests.push(PacketTest {
        name: "ICMP ping".to_string(),
        kind: "ping".to_string(),
        status: match &ping_result {
            Ok(s) if s.contains("reachable") => "ok",
            Ok(_) => "failed",
            Err(_) => "timeout",
        }.to_string(),
        result: ping_result.ok(),
        latency_ms: Some(ping_latency),
        error: None,
        note: Some("⚠ active probe: sends ICMP packets".to_string()),
    });

    // TCP connect test port 443
    let tcp_start = std::time::Instant::now();
    let tcp_result = tcp_connect(&ip, 443, 2000);
    let tcp_latency = tcp_start.elapsed().as_secs_f64() * 1000.0;
    tests.push(PacketTest {
        name: "TCP connect :443".to_string(),
        kind: "tcp".to_string(),
        status: match &tcp_result { Ok(_) => "ok", Err(_) => "failed" }.to_string(),
        result: tcp_result.as_ref().ok().map(|_| "connected".to_string()),
        latency_ms: Some(tcp_latency),
        error: tcp_result.err(),
        note: Some("⚠ active probe: opens TCP connection".to_string()),
    });

    // TCP connect test port 80
    let tcp80_start = std::time::Instant::now();
    let tcp80_result = tcp_connect(&ip, 80, 2000);
    let tcp80_latency = tcp80_start.elapsed().as_secs_f64() * 1000.0;
    tests.push(PacketTest {
        name: "TCP connect :80".to_string(),
        kind: "tcp".to_string(),
        status: match &tcp80_result { Ok(_) => "ok", Err(_) => "failed" }.to_string(),
        result: tcp80_result.as_ref().ok().map(|_| "connected".to_string()),
        latency_ms: Some(tcp80_latency),
        error: tcp80_result.err(),
        note: Some("⚠ active probe: opens TCP connection".to_string()),
    });

    // MTU probe via ping with large payload
    let mtu_result = mtu_probe(&ip);
    tests.push(PacketTest {
        name: "MTU probe (ping 1400B)".to_string(),
        kind: "mtu".to_string(),
        status: mtu_result.as_ref().map(|_| "ok").unwrap_or("failed").to_string(),
        result: mtu_result.ok(),
        latency_ms: None,
        error: None,
        note: Some("⚠ active probe: sends large ICMP packet".to_string()),
    });

    // HTTP HEAD test (if hostname)
    if !is_ip_str(&dest) {
        let http_result = http_head_test(&dest);
        let (http_ok, http_err) = match http_result {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };
        tests.push(PacketTest {
            name: "HTTP HEAD".to_string(),
            kind: "http".to_string(),
            status: http_ok.as_ref().map(|_| "ok").unwrap_or("failed").to_string(),
            result: http_ok,
            latency_ms: None,
            error: http_err,
            note: Some("⚠ active probe: sends HTTP HEAD request".to_string()),
        });
    } else {
        tests.push(PacketTest {
            name: "HTTP HEAD".to_string(),
            kind: "http".to_string(),
            status: "skipped".to_string(),
            result: None,
            latency_ms: None,
            error: None,
            note: Some("Skipped: requires hostname not IP".to_string()),
        });
    }

    Ok(PacketTestSuite { destination: dest, started_at, tests })
}

fn is_ip_str(s: &str) -> bool {
    IpAddr::from_str(s).is_ok()
}

fn tcp_connect(host: &str, port: u16, timeout_ms: u64) -> Result<(), String> {
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{host}:{port}");
    TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        Duration::from_millis(timeout_ms),
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn mtu_probe(destination: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    let args = ["-n", "1", "-w", "1000", "-l", "1400", destination];
    #[cfg(target_os = "macos")]
    let args = ["-c", "1", "-W", "1000", "-s", "1400", destination];
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let args = ["-c", "1", "-W", "1", "-s", "1400", destination];

    let output = std::process::Command::new("ping")
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let lower = stdout.to_lowercase();
    if lower.contains("ttl=") || lower.contains("ttl ") || lower.contains("1 packets received") || lower.contains("1 received") || lower.contains("0% packet loss") || lower.contains("0.0% packet loss") {
        Ok("MTU 1400+ path OK".to_string())
    } else {
        Err("MTU probe failed — possible fragmentation".to_string())
    }
}

fn http_head_test(hostname: &str) -> Result<String, String> {
    // Use curl if available for HTTP HEAD
    let result = std::process::Command::new("curl")
        .args([
            "-sI",
            "--connect-timeout", "3",
            "--max-time", "4",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            &format!("https://{hostname}"),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let code = String::from_utf8_lossy(&result.stdout).trim().to_string();
    if code.starts_with('2') || code.starts_with('3') || code.starts_with('4') {
        Ok(format!("HTTP {code}"))
    } else if code.is_empty() || code == "000" {
        Err("connection refused or timeout".to_string())
    } else {
        Ok(format!("HTTP {code}"))
    }
}

// ── Feature 9: Route simulator ────────────────────────────────────────────

pub fn simulate_route(
    destination: String,
    overrides: SimulatorOverrides,
) -> Result<SimulationResult, String> {
    let snapshot = platform::snapshot().unwrap_or_else(|_| NetworkSnapshot {
        interfaces: vec![], dns_resolvers: vec![], routes: vec![],
        firewall: FirewallSummary { detectable: false, rules: vec![], status: "unavailable".to_string() },
        events: vec![], updated_at: chrono::Utc::now().to_rfc3339(), platform: std::env::consts::OS.to_string(),
    });

    let mut changes_applied = vec![];

    // Build simulated route table
    let mut routes: Vec<RouteEntry> = snapshot.routes.iter()
        .filter(|r| !overrides.removed_destinations.contains(&r.destination))
        .map(|r| {
            let mut entry = r.clone();
            if let Some(mo) = overrides.metric_overrides.iter().find(|mo| mo.destination == r.destination) {
                entry.metric = Some(mo.metric);
                changes_applied.push(format!("metric {} on {} → {}", r.destination, r.interface, mo.metric));
            }
            entry
        })
        .collect();

    for rem in &overrides.removed_destinations {
        changes_applied.push(format!("removed route: {rem}"));
    }

    // Apply interface state overrides
    let down_ifaces: Vec<&str> = overrides.interface_states.iter()
        .filter(|s| !s.up)
        .map(|s| s.name.as_str())
        .collect();
    routes.retain(|r| !down_ifaces.contains(&r.interface.as_str()));
    for s in &overrides.interface_states {
        changes_applied.push(format!("interface {} → {}", s.name, if s.up { "up" } else { "down" }));
    }

    // Add new routes
    for added in &overrides.added_routes {
        routes.push(RouteEntry {
            destination: added.destination.clone(),
            gateway: added.gateway.clone(),
            interface: added.interface.clone(),
            metric: added.metric,
            source: "simulated".to_string(),
            matched: false,
        });
        changes_applied.push(format!("added route: {} via {} on {}", added.destination, added.gateway, added.interface));
    }

    // Resolve destination
    let dest_ip = if IpAddr::from_str(&destination).is_ok() {
        destination.clone()
    } else if let Some(override_answer) = &overrides.dns_answer_override {
        changes_applied.push(format!("DNS override: {} → {}", destination, override_answer));
        override_answer.clone()
    } else {
        match lookup_host(&destination) {
            Ok(ips) if !ips.is_empty() => ips[0].to_string(),
            _ => destination.clone(),
        }
    };

    let dns_answer = Some(dest_ip.clone());

    // Find best matching route via longest prefix match simulation
    let winning_route = find_best_route(&dest_ip, &routes);
    let winning_interface = winning_route.as_ref().map(|r| r.interface.clone());

    Ok(SimulationResult {
        destination: destination.clone(),
        simulated: true,
        winning_route,
        winning_interface,
        dns_answer,
        changes_applied,
        note: "⚠ SIMULATED — no system configuration was modified.".to_string(),
    })
}

fn find_best_route(dest_ip: &str, routes: &[RouteEntry]) -> Option<RouteEntry> {
    let dest: IpAddr = match IpAddr::from_str(dest_ip) {
        Ok(ip) => ip,
        Err(_) => return routes.iter().find(|r| r.destination == "0.0.0.0/0").cloned(),
    };

    let mut best: Option<(&RouteEntry, u8)> = None;
    for route in routes {
        if let Ok(network) = IpNetwork::from_str(&route.destination) {
            if network.contains(dest) {
                let prefix = network.prefix();
                if best.map_or(true, |(_, p)| prefix > p) {
                    best = Some((route, prefix));
                }
            }
        } else if route.destination == "0.0.0.0/0" || route.destination == "default" {
            if best.is_none() {
                best = Some((route, 0));
            }
        }
    }
    best.map(|(r, _)| r.clone())
}

// ── Feature 10: Resolver-specific DNS testing ─────────────────────────────

pub fn test_resolvers(hostname: String) -> Result<Vec<ResolverTestResult>, String> {
    let snapshot = platform::snapshot().unwrap_or_else(|_| NetworkSnapshot {
        interfaces: vec![], dns_resolvers: vec![], routes: vec![],
        firewall: FirewallSummary { detectable: false, rules: vec![], status: "unavailable".to_string() },
        events: vec![], updated_at: chrono::Utc::now().to_rfc3339(), platform: std::env::consts::OS.to_string(),
    });

    let mut results: Vec<ResolverTestResult> = vec![];
    let mut all_answers: Vec<(String, Vec<String>)> = vec![];

    for resolver in &snapshot.dns_resolvers {
        let start = std::time::Instant::now();
        let (status, answers, error) = query_resolver_dig(&hostname, &resolver.server, resolver.port.unwrap_or(53));
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        if !answers.is_empty() {
            all_answers.push((resolver.server.clone(), answers.clone()));
        }

        results.push(ResolverTestResult {
            resolver: format!("{}:{}", resolver.server, resolver.port.unwrap_or(53)),
            scope: resolver.scope.clone(),
            interface: resolver.interface.clone(),
            status: status.clone(),
            answers: answers.clone(),
            latency_ms: Some(latency_ms),
            error,
            findings: vec![], // filled below
        });
    }

    // Also test system resolver
    let start = std::time::Instant::now();
    let sys_answers: Vec<String> = match lookup_host(&hostname) {
        Ok(ips) => ips.iter().map(|ip| ip.to_string()).collect(),
        Err(_) => vec![],
    };
    let sys_latency = start.elapsed().as_secs_f64() * 1000.0;

    if !sys_answers.is_empty() {
        all_answers.push(("system".to_string(), sys_answers.clone()));
    }

    results.push(ResolverTestResult {
        resolver: "system resolver".to_string(),
        scope: "default".to_string(),
        interface: None,
        status: if sys_answers.is_empty() { "failed" } else { "ok" }.to_string(),
        answers: sys_answers,
        latency_ms: Some(sys_latency),
        error: None,
        findings: vec![],
    });

    // Post-process: detect split-brain / stale / leakage
    let mut unique_answer_sets: Vec<Vec<String>> = all_answers.iter().map(|(_, a)| {
        let mut v = a.clone();
        v.sort();
        v
    }).collect();
    unique_answer_sets.dedup();
    let has_split_brain = unique_answer_sets.windows(2).any(|w| w[0] != w[1]);

    if has_split_brain {
        for res in &mut results {
            if !res.answers.is_empty() {
                res.findings.push("⚠ Split-brain: different resolvers returned different answers".to_string());
            }
        }
    }

    // Flag resolvers that returned private IPs when queried from a non-VPN context
    for res in &mut results {
        let has_private = res.answers.iter().any(|a| {
            a.starts_with("10.") || a.starts_with("192.168.") || a.starts_with("172.")
        });
        if has_private && res.scope == "default" {
            res.findings.push("ℹ Private IP returned by default-scope resolver — possible internal DNS leakage".to_string());
        }
    }

    Ok(results)
}

fn query_resolver_dig(hostname: &str, server: &str, port: u16) -> (String, Vec<String>, Option<String>) {
    // Use dig if available, fallback to nslookup
    let dig_result = std::process::Command::new("dig")
        .args([
            &format!("@{server}"),
            "-p", &port.to_string(),
            hostname,
            "+short",
            "+time=2",
            "+tries=1",
        ])
        .output();

    match dig_result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let answers: Vec<String> = stdout.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with(';'))
                .collect();
            if answers.is_empty() {
                ("nxdomain".to_string(), vec![], None)
            } else {
                ("ok".to_string(), answers, None)
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            ("failed".to_string(), vec![], Some(if stderr.trim().is_empty() { format!("dig exit {}", output.status) } else { stderr }))
        }
        Err(_) => {
            // Try nslookup fallback
            let ns_result = std::process::Command::new("nslookup")
                .args([hostname, server])
                .output();
            match ns_result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let answers: Vec<String> = stdout.lines()
                        .filter(|l| l.contains("Address:") && !l.contains("#"))
                        .map(|l| l.split("Address:").nth(1).unwrap_or("").trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect();
                    if answers.is_empty() {
                        ("failed".to_string(), vec![], Some("dig and nslookup unavailable or returned no answers".to_string()))
                    } else {
                        ("ok".to_string(), answers, None)
                    }
                }
                Err(e) => ("unsupported".to_string(), vec![], Some(format!("dig/nslookup not found: {e}"))),
            }
        }
    }
}

// ── Shared helpers ─────────────────────────────────────────────────────────

#[derive(Debug, Copy, Clone)]
enum DestinationKind {
    Ip,
    Cidr,
    Hostname,
}

fn classify_destination(destination: &str) -> DestinationKind {
    if IpAddr::from_str(destination).is_ok() {
        return DestinationKind::Ip;
    }
    if IpNetwork::from_str(destination).is_ok() {
        return DestinationKind::Cidr;
    }
    DestinationKind::Hostname
}

fn choose_resolver(query: &str, resolvers: &[DnsResolver]) -> Option<DnsResolver> {
    let mut scoped: Vec<&DnsResolver> = resolvers
        .iter()
        .filter(|r| r.scope != "default" && query.ends_with(r.scope.trim_start_matches("*.")))
        .collect();
    scoped.sort_by_key(|r| std::cmp::Reverse(r.scope.len()));
    scoped
        .first()
        .cloned()
        .cloned()
        .or_else(|| resolvers.iter().find(|r| r.scope == "default").cloned())
        .or_else(|| resolvers.first().cloned())
}

fn build_egress(route: &RouteDecision, interfaces: &[NetworkInterface]) -> EgressInterface {
    let matched_name = route
        .matched_interface
        .clone()
        .or_else(|| route.matched_route.as_ref().map(|r| r.interface.clone()));
    let iface = matched_name
        .as_ref()
        .and_then(|name| interfaces.iter().find(|i| &i.name == name));

    let interface_type = iface.map(|i| i.interface_type.clone()).unwrap_or_else(|| "unknown".to_string());
    let mtu = iface.and_then(|i| i.mtu);
    let mtu_warning = mtu.map(|m| m < 1500).unwrap_or(false);
    let protocol = if interface_type == "VPN" {
        iface.and_then(|i| i.tunnel_protocol.clone()).unwrap_or_else(|| "tunnel".to_string())
    } else if interface_type == "Wi-Fi" {
        "Wi-Fi".to_string()
    } else if interface_type == "Eth" {
        "physical Ethernet".to_string()
    } else if interface_type == "Lo" {
        "loopback".to_string()
    } else {
        interface_type.clone()
    };

    EgressInterface {
        name: matched_name.unwrap_or_else(|| "unknown".to_string()),
        interface_type,
        protocol,
        tunnel_endpoint: iface.and_then(|i| i.tunnel_endpoint.clone()),
        source_ip: iface.and_then(|i| i.ipv4.clone().or_else(|| i.ipv6.clone())),
        mtu,
        mtu_warning,
        encapsulation_overhead: iface.and_then(|i| i.encapsulation_overhead),
        last_handshake: iface.and_then(|i| i.last_handshake.clone()),
        ssid: iface.and_then(|i| i.ssid.clone()),
        signal_strength: iface.and_then(|i| i.signal_strength.clone()),
        band: iface.and_then(|i| i.band.clone()),
    }
}
