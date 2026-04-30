mod system;

use system::models::*;

// ── existing commands ──────────────────────────────────────────────────────

#[tauri::command]
fn get_network_snapshot() -> Result<NetworkSnapshot, String> {
    system::snapshot()
}

#[tauri::command]
fn analyze_destination(destination: String) -> Result<TraceResult, String> {
    system::trace_destination(destination)
}

#[tauri::command]
fn export_trace_json(trace: TraceResult) -> Result<String, String> {
    serde_json::to_string_pretty(&trace).map_err(|e| e.to_string())
}

// ── Feature 4: Packet test suite ──────────────────────────────────────────

#[tauri::command]
fn run_packet_tests(destination: String) -> Result<PacketTestSuite, String> {
    system::run_packet_tests(destination)
}

// ── Feature 9: Route simulator ────────────────────────────────────────────

#[tauri::command]
fn simulate_route(
    destination: String,
    overrides: SimulatorOverrides,
) -> Result<SimulationResult, String> {
    system::simulate_route(destination, overrides)
}

// ── Feature 10: Resolver-specific DNS testing ─────────────────────────────

#[tauri::command]
fn test_resolvers(hostname: String) -> Result<Vec<ResolverTestResult>, String> {
    system::test_resolvers(hostname)
}

// ── entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_network_snapshot,
            analyze_destination,
            export_trace_json,
            run_packet_tests,
            simulate_route,
            test_resolvers,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PathTrace");
}
