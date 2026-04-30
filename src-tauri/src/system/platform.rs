use super::models::*;
use regex::Regex;
use std::process::Command;

pub fn snapshot() -> Result<NetworkSnapshot, String> {
    Ok(NetworkSnapshot {
        interfaces: interfaces(),
        dns_resolvers: dns_resolvers(),
        routes: route_table(),
        firewall: firewall_summary(),
        events: vec![ChangeEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            category: "snapshot".to_string(),
            message: "network state refreshed".to_string(),
        }],
        updated_at: chrono::Utc::now().to_rfc3339(),
        platform: std::env::consts::OS.to_string(),
    })
}

pub fn route_lookup(destination: &str) -> Result<RouteDecision, String> {
    platform_route_lookup(destination)
}

pub fn firewall_for_destination(destination: &str) -> Result<FirewallSummary, String> {
    let mut summary = firewall_summary();
    if summary.detectable {
        summary.rules.retain(|rule| {
            rule.destination
                .as_ref()
                .map(|dest| dest.contains(destination) || dest == "any" || dest == "0.0.0.0/0")
                .unwrap_or(true)
        });
        if summary.rules.is_empty() {
            summary.status = "no blocking rules matched".to_string();
        }
    }
    Ok(summary)
}

pub fn ping_once(destination: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    let args = ["-n", "1", "-w", "1000", destination];
    #[cfg(target_os = "macos")]
    let args = ["-c", "1", "-W", "1000", destination];
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let args = ["-c", "1", "-W", "1", destination];

    let output = run("ping", &args)?;
    let lower = output.to_lowercase();
    if lower.contains("ttl=") || lower.contains("ttl ") || lower.contains("1 packets received") || lower.contains("1 received") || lower.contains("0% packet loss") || lower.contains("0.0% packet loss") {
        Ok("reachable".to_string())
    } else {
        Ok("no ping response".to_string())
    }
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("{program}: {err}"))
        .and_then(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if output.status.success() || !stdout.trim().is_empty() {
                Ok(stdout)
            } else {
                Err(if stderr.trim().is_empty() {
                    format!("{program} exited with {}", output.status)
                } else {
                    stderr
                })
            }
        })
}

fn infer_type(name: &str, description: Option<&str>) -> String {
    let lower = format!("{} {}", name, description.unwrap_or("")).to_lowercase();
    if lower == "lo" || lower.starts_with("lo ") || lower.contains("loopback") {
        "Lo".to_string()
    } else if lower.starts_with("utun")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.contains("wireguard")
        || lower.contains("openvpn")
        || lower.contains("vpn")
    {
        "VPN".to_string()
    } else if lower.starts_with("wl") || lower.contains("wi-fi") || lower.contains("wireless") {
        "Wi-Fi".to_string()
    } else if lower.starts_with("en")
        || lower.starts_with("eth")
        || lower.contains("ethernet")
        || lower.contains("realtek")
        || lower.contains("intel")
    {
        "Eth".to_string()
    } else {
        "Other".to_string()
    }
}

fn tunnel_protocol(name: &str, description: Option<&str>) -> Option<String> {
    let lower = format!("{} {}", name, description.unwrap_or("")).to_lowercase();
    if lower.starts_with("wg") || lower.contains("wireguard") {
        Some("WireGuard / UDP".to_string())
    } else if lower.contains("openvpn") || lower.starts_with("tun") || lower.starts_with("tap") {
        Some("OpenVPN / tunnel".to_string())
    } else if lower.starts_with("utun") {
        Some("IPSec / NetworkExtension".to_string())
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn interfaces() -> Vec<NetworkInterface> {
    let ip_addr = run("ip", &["-o", "addr", "show"]).unwrap_or_default();
    let ip_link = run("ip", &["-o", "link", "show"]).unwrap_or_default();
    let wg = run("wg", &["show"]).unwrap_or_default();
    let mut map = std::collections::BTreeMap::<String, NetworkInterface>::new();

    let re_addr = Regex::new(r"^\d+:\s+([^ ]+)\s+inet6?\s+([^/ ]+)").unwrap();
    for line in ip_addr.lines() {
        if let Some(caps) = re_addr.captures(line) {
            let name = caps[1].trim_end_matches(':').split('@').next().unwrap_or("").to_string();
            let ip = caps[2].to_string();
            let entry = map.entry(name.clone()).or_insert_with(|| NetworkInterface {
                name: name.clone(),
                display_name: None,
                status: "up".to_string(),
                interface_type: infer_type(&name, None),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu: None,
                tunnel_protocol: tunnel_protocol(&name, None),
                tunnel_endpoint: None,
                encapsulation_overhead: None,
                last_handshake: None,
                ssid: None,
                signal_strength: None,
                band: None,
            });
            if line.contains(" inet6 ") {
                entry.ipv6 = Some(ip);
            } else {
                entry.ipv4 = Some(ip);
            }
        }
    }

    let re_link = Regex::new(r"^\d+:\s+([^:]+):.*mtu\s+(\d+).*state\s+([A-Z]+)").unwrap();
    let re_mac = Regex::new(r"link/(?:ether|loopback)\s+([0-9a-f:]{2,})").unwrap();
    for line in ip_link.lines() {
        if let Some(caps) = re_link.captures(line) {
            let name = caps[1].split('@').next().unwrap_or("").to_string();
            let mtu = caps[2].parse::<u32>().ok();
            let status = if &caps[3] == "UP" { "up" } else { "down" }.to_string();
            let entry = map.entry(name.clone()).or_insert_with(|| NetworkInterface {
                name: name.clone(),
                display_name: None,
                status: status.clone(),
                interface_type: infer_type(&name, None),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu,
                tunnel_protocol: tunnel_protocol(&name, None),
                tunnel_endpoint: None,
                encapsulation_overhead: None,
                last_handshake: None,
                ssid: None,
                signal_strength: None,
                band: None,
            });
            entry.status = status;
            entry.mtu = mtu;
            entry.mac = re_mac.captures(line).map(|m| m[1].to_string());
        }
    }

    if !wg.trim().is_empty() {
        for block in wg.split("\n\n") {
            let iface = block
                .lines()
                .find_map(|line| line.trim().strip_prefix("interface: "))
                .map(|s| s.to_string());
            if let Some(name) = iface {
                if let Some(entry) = map.get_mut(&name) {
                    entry.interface_type = "VPN".to_string();
                    entry.tunnel_protocol = Some("WireGuard / UDP".to_string());
                    entry.encapsulation_overhead = Some(60);
                    entry.tunnel_endpoint = block
                        .lines()
                        .find_map(|line| line.trim().strip_prefix("endpoint: "))
                        .map(|s| s.to_string());
                    entry.last_handshake = block
                        .lines()
                        .find_map(|line| line.trim().strip_prefix("latest handshake: "))
                        .map(|s| s.to_string());
                }
            }
        }
    }

    map.into_values().collect()
}

#[cfg(target_os = "macos")]
fn interfaces() -> Vec<NetworkInterface> {
    let ifconfig = run("ifconfig", &[]).unwrap_or_default();
    let mut interfaces = Vec::new();
    let mut current: Option<NetworkInterface> = None;
    let header = Regex::new(r"^([a-zA-Z0-9]+):\s+flags=.*mtu\s+(\d+)").unwrap();
    let inet = Regex::new(r"\sinet\s+([0-9.]+)").unwrap();
    let inet6 = Regex::new(r"\sinet6\s+([^%/\s]+)").unwrap();
    let ether = Regex::new(r"\sether\s+([0-9a-f:]+)").unwrap();

    for line in ifconfig.lines() {
        if let Some(caps) = header.captures(line) {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = caps[1].to_string();
            let mtu = caps[2].parse::<u32>().ok();
            let status = if line.contains("UP") { "up" } else { "down" }.to_string();
            current = Some(NetworkInterface {
                name: name.clone(),
                display_name: None,
                status,
                interface_type: infer_type(&name, None),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu,
                tunnel_protocol: tunnel_protocol(&name, None),
                tunnel_endpoint: None,
                encapsulation_overhead: if name.starts_with("utun") { Some(60) } else { None },
                last_handshake: None,
                ssid: None,
                signal_strength: None,
                band: None,
            });
        } else if let Some(iface) = current.as_mut() {
            if let Some(caps) = inet.captures(line) {
                iface.ipv4 = Some(caps[1].to_string());
            }
            if let Some(caps) = inet6.captures(line) {
                iface.ipv6 = Some(caps[1].to_string());
            }
            if let Some(caps) = ether.captures(line) {
                iface.mac = Some(caps[1].to_string());
            }
        }
    }
    if let Some(iface) = current {
        interfaces.push(iface);
    }
    interfaces
}

#[cfg(target_os = "windows")]
fn interfaces() -> Vec<NetworkInterface> {
    let script = "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,IPv4Address,IPv6Address,NetAdapter | ConvertTo-Json -Depth 5";
    let output = run("powershell", &["-NoProfile", "-Command", script]).unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap_or(serde_json::Value::Null);
    let list = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else if value.is_object() {
        vec![value]
    } else {
        vec![]
    };

    list.into_iter()
        .filter_map(|item| {
            let name = item.get("InterfaceAlias")?.as_str()?.to_string();
            let desc = item.get("InterfaceDescription").and_then(|v| v.as_str());
            let adapter = item.get("NetAdapter");
            let status = adapter
                .and_then(|adapter| adapter.get("Status"))
                .and_then(|v| v.as_str())
                .map(|s| if s.eq_ignore_ascii_case("Up") { "up" } else { "down" })
                .unwrap_or("up")
                .to_string();
            let mtu = adapter
                .and_then(|adapter| adapter.get("MtuSize"))
                .and_then(|v| v.as_u64())
                .map(|m| m as u32);
            let ipv4 = item
                .get("IPv4Address")
                .and_then(first_address)
                .map(|s| s.to_string());
            let ipv6 = item
                .get("IPv6Address")
                .and_then(first_address)
                .map(|s| s.to_string());
            Some(NetworkInterface {
                name: name.clone(),
                display_name: desc.map(|s| s.to_string()),
                status,
                interface_type: infer_type(&name, desc),
                ipv4,
                ipv6,
                mac: adapter
                    .and_then(|adapter| adapter.get("MacAddress"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                mtu,
                tunnel_protocol: tunnel_protocol(&name, desc),
                tunnel_endpoint: None,
                encapsulation_overhead: None,
                last_handshake: None,
                ssid: None,
                signal_strength: None,
                band: None,
            })
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn first_address(value: &serde_json::Value) -> Option<&str> {
    if value.is_array() {
        value
            .as_array()?
            .first()?
            .get("IPAddress")
            .and_then(|v| v.as_str())
    } else {
        value.get("IPAddress").and_then(|v| v.as_str())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn interfaces() -> Vec<NetworkInterface> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn dns_resolvers() -> Vec<DnsResolver> {
    let resolved = run("resolvectl", &["status"]).unwrap_or_default();
    if !resolved.trim().is_empty() {
        let mut resolvers = Vec::new();
        let mut current_link: Option<String> = None;
        let mut current_scope = "default".to_string();
        for line in resolved.lines() {
            let trimmed = line.trim();
            if let Some(link) = trimmed.strip_prefix("Link ") {
                current_link = link.split('(').nth(1).map(|s| s.trim_end_matches(')').to_string());
                current_scope = "default".to_string();
            } else if let Some(domains) = trimmed.strip_prefix("DNS Domain:") {
                let domain = domains.split_whitespace().next().unwrap_or("default");
                current_scope = domain.trim_start_matches('~').to_string();
            } else if let Some(servers) = trimmed.strip_prefix("DNS Servers:") {
                for server in servers.split_whitespace() {
                    resolvers.push(DnsResolver {
                        scope: current_scope.clone(),
                        server: server.to_string(),
                        port: Some(53),
                        interface: current_link.clone(),
                        source: "systemd-resolved".to_string(),
                    });
                }
            }
        }
        if !resolvers.is_empty() {
            return resolvers;
        }
    }
    resolv_conf()
}

#[cfg(target_os = "macos")]
fn dns_resolvers() -> Vec<DnsResolver> {
    let output = run("scutil", &["--dns"]).unwrap_or_default();
    let mut resolvers = Vec::new();
    let mut scope = "default".to_string();
    let mut iface: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("resolver #") {
            scope = "default".to_string();
            iface = None;
        } else if let Some(domain) = trimmed.strip_prefix("domain   : ") {
            scope = domain.to_string();
        } else if let Some(if_index) = trimmed.strip_prefix("if_index : ") {
            iface = Some(if_index.to_string());
        } else if let Some(server) = trimmed.strip_prefix("nameserver[") {
            if let Some(addr) = server.split(": ").nth(1) {
                resolvers.push(DnsResolver {
                    scope: scope.clone(),
                    server: addr.trim().to_string(),
                    port: Some(53),
                    interface: iface.clone(),
                    source: "scutil --dns".to_string(),
                });
            }
        }
    }
    if resolvers.is_empty() {
        resolv_conf()
    } else {
        resolvers
    }
}

#[cfg(target_os = "windows")]
fn dns_resolvers() -> Vec<DnsResolver> {
    let servers = run(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | ConvertTo-Json -Depth 4",
        ],
    )
    .unwrap_or_default();
    let nrpt = run(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "Get-DnsClientNrptRule | ConvertTo-Json -Depth 3",
        ],
    )
    .unwrap_or_default();
    let mut resolvers = Vec::new();
    let value: serde_json::Value = serde_json::from_str(&servers).unwrap_or(serde_json::Value::Null);
    let list = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else if value.is_object() {
        vec![value]
    } else {
        vec![]
    };
    for item in list {
        let iface = item.get("InterfaceAlias").and_then(|v| v.as_str()).map(|s| s.to_string());
        if let Some(addresses) = item.get("ServerAddresses").and_then(|v| v.as_array()) {
            for addr in addresses {
                if let Some(server) = addr.as_str() {
                    resolvers.push(DnsResolver {
                        scope: "default".to_string(),
                        server: server.to_string(),
                        port: Some(53),
                        interface: iface.clone(),
                        source: "Get-DnsClientServerAddress".to_string(),
                    });
                }
            }
        }
    }

    let nrpt_value: serde_json::Value = serde_json::from_str(&nrpt).unwrap_or(serde_json::Value::Null);
    let nrpt_list = if nrpt_value.is_array() {
        nrpt_value.as_array().cloned().unwrap_or_default()
    } else if nrpt_value.is_object() {
        vec![nrpt_value]
    } else {
        vec![]
    };
    for item in nrpt_list {
        if let (Some(namespace), Some(addresses)) = (
            item.get("Namespace").and_then(|v| v.as_array()),
            item.get("NameServers").and_then(|v| v.as_array()),
        ) {
            let scope = namespace
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("split-dns")
                .trim_start_matches('.')
                .to_string();
            for addr in addresses {
                if let Some(server) = addr.as_str() {
                    resolvers.push(DnsResolver {
                        scope: scope.clone(),
                        server: server.to_string(),
                        port: Some(53),
                        interface: None,
                        source: "Get-DnsClientNrptRule".to_string(),
                    });
                }
            }
        }
    }
    resolvers
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn dns_resolvers() -> Vec<DnsResolver> {
    resolv_conf()
}

fn resolv_conf() -> Vec<DnsResolver> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed.strip_prefix("nameserver ").map(|server| DnsResolver {
                scope: "default".to_string(),
                server: server.trim().to_string(),
                port: Some(53),
                interface: None,
                source: "/etc/resolv.conf".to_string(),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn route_table() -> Vec<RouteEntry> {
    run("ip", &["route", "show", "table", "all"])
        .unwrap_or_default()
        .lines()
        .filter_map(parse_linux_route)
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_linux_route(line: &str) -> Option<RouteEntry> {
    if line.trim().is_empty() || line.starts_with("broadcast") || line.starts_with("local") {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let destination = if parts.first()? == &"default" {
        "0.0.0.0/0".to_string()
    } else {
        parts[0].to_string()
    };
    let gateway = parts
        .windows(2)
        .find(|w| w[0] == "via")
        .map(|w| w[1].to_string())
        .unwrap_or_else(|| "link#".to_string());
    let interface = parts
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let metric = parts
        .windows(2)
        .find(|w| w[0] == "metric")
        .and_then(|w| w[1].parse::<u32>().ok());
    Some(RouteEntry {
        destination,
        gateway,
        interface,
        metric,
        source: if line.contains("proto dhcp") {
            "DHCP"
        } else if line.contains("proto static") {
            "static"
        } else if line.contains("proto kernel") {
            "local link"
        } else {
            "system"
        }
        .to_string(),
        matched: false,
    })
}

#[cfg(target_os = "macos")]
fn route_table() -> Vec<RouteEntry> {
    run("netstat", &["-rn"])
        .unwrap_or_default()
        .lines()
        .filter_map(parse_macos_route)
        .collect()
}

#[cfg(target_os = "macos")]
fn parse_macos_route(line: &str) -> Option<RouteEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 || parts[0] == "Destination" || parts[0].starts_with("Internet") {
        return None;
    }
    Some(RouteEntry {
        destination: if parts[0] == "default" {
            "0.0.0.0/0".to_string()
        } else {
            parts[0].to_string()
        },
        gateway: parts[1].to_string(),
        interface: parts.last().unwrap_or(&"unknown").to_string(),
        metric: None,
        source: if parts[1].starts_with("link") { "local link" } else { "system" }.to_string(),
        matched: false,
    })
}

#[cfg(target_os = "windows")]
fn route_table() -> Vec<RouteEntry> {
    let script = "Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,Protocol | ConvertTo-Json -Depth 3";
    let output = run("powershell", &["-NoProfile", "-Command", script]).unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap_or(serde_json::Value::Null);
    let list = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else if value.is_object() {
        vec![value]
    } else {
        vec![]
    };
    list.into_iter()
        .map(|item| RouteEntry {
            destination: item
                .get("DestinationPrefix")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            gateway: item
                .get("NextHop")
                .and_then(|v| v.as_str())
                .unwrap_or("link#")
                .to_string(),
            interface: item
                .get("InterfaceAlias")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            metric: item.get("RouteMetric").and_then(|v| v.as_u64()).map(|m| m as u32),
            source: item
                .get("Protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("system")
                .to_string(),
            matched: false,
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn route_table() -> Vec<RouteEntry> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn platform_route_lookup(destination: &str) -> Result<RouteDecision, String> {
    let output = run("ip", &["route", "get", destination])?;
    let line = output.lines().next().unwrap_or_default();
    let parts: Vec<&str> = line.split_whitespace().collect();
    let interface = parts
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string());
    let gateway = parts
        .windows(2)
        .find(|w| w[0] == "via")
        .map(|w| w[1].to_string())
        .unwrap_or_else(|| "link#".to_string());
    let mut routes = route_table();
    let matched_route = interface.as_ref().map(|iface| RouteEntry {
        destination: parts.first().unwrap_or(&destination).to_string(),
        gateway,
        interface: iface.clone(),
        metric: None,
        source: if iface.starts_with("tun") || iface.starts_with("wg") {
            "VPN push"
        } else {
            "kernel lookup"
        }
        .to_string(),
        matched: true,
    });
    for route in &mut routes {
        if Some(&route.interface) == interface.as_ref() && route.destination == "0.0.0.0/0" {
            route.matched = true;
        }
    }
    Ok(RouteDecision {
        status: interface
            .as_ref()
            .map(|iface| {
                if infer_type(iface, None) == "VPN" {
                    format!("tunneled via {iface}")
                } else {
                    format!("egress via {iface}")
                }
            })
            .unwrap_or_else(|| "no interface matched".to_string()),
        matched_interface: interface,
        matched_route,
        routes,
        lookup_error: None,
    })
}

#[cfg(target_os = "macos")]
fn platform_route_lookup(destination: &str) -> Result<RouteDecision, String> {
    let output = run("route", &["get", destination])?;
    let mut interface = None;
    let mut gateway = "link#".to_string();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("interface: ") {
            interface = Some(value.to_string());
        } else if let Some(value) = trimmed.strip_prefix("gateway: ") {
            gateway = value.to_string();
        }
    }
    let mut routes = route_table();
    let matched_route = interface.as_ref().map(|iface| RouteEntry {
        destination: destination.to_string(),
        gateway,
        interface: iface.clone(),
        metric: None,
        source: if iface.starts_with("utun") { "VPN push" } else { "route get" }.to_string(),
        matched: true,
    });
    for route in &mut routes {
        if Some(&route.interface) == interface.as_ref() {
            route.matched = true;
            break;
        }
    }
    Ok(RouteDecision {
        status: interface
            .as_ref()
            .map(|iface| {
                if iface.starts_with("utun") {
                    format!("tunneled via {iface}")
                } else {
                    format!("egress via {iface}")
                }
            })
            .unwrap_or_else(|| "no interface matched".to_string()),
        matched_interface: interface,
        matched_route,
        routes,
        lookup_error: None,
    })
}

#[cfg(target_os = "windows")]
fn platform_route_lookup(destination: &str) -> Result<RouteDecision, String> {
    let script = format!(
        "Find-NetRoute -RemoteIPAddress '{}' | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,Protocol | ConvertTo-Json -Depth 3",
        destination.replace('\'', "''")
    );
    let output = run("powershell", &["-NoProfile", "-Command", &script])?;
    let value: serde_json::Value = serde_json::from_str(&output).unwrap_or(serde_json::Value::Null);
    let route_value = if value.is_array() {
        value.as_array().and_then(|a| a.first()).cloned().unwrap_or(serde_json::Value::Null)
    } else {
        value
    };
    let interface = route_value
        .get("InterfaceAlias")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let matched_route = Some(RouteEntry {
        destination: route_value
            .get("DestinationPrefix")
            .and_then(|v| v.as_str())
            .unwrap_or(destination)
            .to_string(),
        gateway: route_value
            .get("NextHop")
            .and_then(|v| v.as_str())
            .unwrap_or("link#")
            .to_string(),
        interface: interface.clone().unwrap_or_else(|| "unknown".to_string()),
        metric: route_value
            .get("RouteMetric")
            .and_then(|v| v.as_u64())
            .map(|m| m as u32),
        source: route_value
            .get("Protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("Find-NetRoute")
            .to_string(),
        matched: true,
    });
    let mut routes = route_table();
    for route in &mut routes {
        if Some(&route.interface) == interface.as_ref() {
            route.matched = true;
            break;
        }
    }
    Ok(RouteDecision {
        status: interface
            .as_ref()
            .map(|iface| format!("egress via {iface}"))
            .unwrap_or_else(|| "no interface matched".to_string()),
        matched_interface: interface,
        matched_route,
        routes,
        lookup_error: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_route_lookup(_destination: &str) -> Result<RouteDecision, String> {
    Err("route lookup is not implemented for this platform".to_string())
}

#[cfg(target_os = "linux")]
fn firewall_summary() -> FirewallSummary {
    let nft = run("nft", &["list", "ruleset"]).unwrap_or_default();
    if !nft.trim().is_empty() {
        let rules = nft
            .lines()
            .filter(|line| line.contains("drop") || line.contains("reject"))
            .take(20)
            .map(|line| FirewallRule {
                name: "nft rule".to_string(),
                action: if line.contains("reject") { "reject" } else { "drop" }.to_string(),
                direction: if line.contains("input") { "in" } else { "out/forward" }.to_string(),
                protocol: None,
                destination: None,
                source: line.trim().to_string(),
            })
            .collect();
        return FirewallSummary {
            detectable: true,
            rules,
            status: "nftables detected".to_string(),
        };
    }
    let iptables = run("iptables", &["-L", "-n"]).unwrap_or_default();
    if !iptables.trim().is_empty() {
        let rules = iptables
            .lines()
            .filter(|line| line.contains("DROP") || line.contains("REJECT"))
            .take(20)
            .map(|line| FirewallRule {
                name: "iptables rule".to_string(),
                action: if line.contains("REJECT") { "reject" } else { "drop" }.to_string(),
                direction: "filter".to_string(),
                protocol: None,
                destination: None,
                source: line.trim().to_string(),
            })
            .collect();
        return FirewallSummary {
            detectable: true,
            rules,
            status: "iptables detected".to_string(),
        };
    }
    FirewallSummary {
        detectable: false,
        rules: vec![],
        status: "firewall rules not detectable; try running with elevated permissions".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn firewall_summary() -> FirewallSummary {
    let pf = run("sudo", &["/sbin/pfctl", "-sr"]).unwrap_or_default();
    if !pf.trim().is_empty() {
        let rules = pf
            .lines()
            .filter(|line| line.contains("block") || line.contains("pass"))
            .take(20)
            .map(|line| FirewallRule {
                name: "pf rule".to_string(),
                action: if line.contains("block") { "block" } else { "pass" }.to_string(),
                direction: if line.contains(" out ") { "out" } else { "in" }.to_string(),
                protocol: None,
                destination: None,
                source: line.trim().to_string(),
            })
            .collect();
        FirewallSummary {
            detectable: true,
            rules,
            status: "pf detected".to_string(),
        }
    } else {
        FirewallSummary {
            detectable: false,
            rules: vec![],
            status: "pf rules unavailable; pfctl may require elevated permissions".to_string(),
        }
    }
}

#[cfg(target_os = "windows")]
fn firewall_summary() -> FirewallSummary {
    let script = "Get-NetFirewallRule -Enabled True -Direction Outbound | Select-Object -First 20 DisplayName,Action,Direction | ConvertTo-Json -Depth 2";
    let output = run("powershell", &["-NoProfile", "-Command", script]).unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap_or(serde_json::Value::Null);
    let list = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else if value.is_object() {
        vec![value]
    } else {
        vec![]
    };
    if list.is_empty() {
        return FirewallSummary {
            detectable: false,
            rules: vec![],
            status: "Windows Firewall rules unavailable".to_string(),
        };
    }
    FirewallSummary {
        detectable: true,
        rules: list
            .into_iter()
            .map(|item| FirewallRule {
                name: item
                    .get("DisplayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Windows Firewall rule")
                    .to_string(),
                action: item
                    .get("Action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                direction: item
                    .get("Direction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("out")
                    .to_string(),
                protocol: None,
                destination: None,
                source: "Get-NetFirewallRule".to_string(),
            })
            .collect(),
        status: "Windows Firewall detected".to_string(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn firewall_summary() -> FirewallSummary {
    FirewallSummary {
        detectable: false,
        rules: vec![],
        status: "firewall detection is not implemented for this platform".to_string(),
    }
}
