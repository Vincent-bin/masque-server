use std::path::Path;

#[test]
fn grafana_dashboard_is_valid_json_with_unique_panel_ids() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text =
        std::fs::read_to_string(root.join("deploy/monitoring/grafana-dashboard.json")).unwrap();
    let dashboard: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert_eq!(dashboard["uid"], "masque-server");
    let panels = dashboard["panels"].as_array().unwrap();
    assert!(panels.len() >= 10);
    let mut ids: Vec<u64> = panels
        .iter()
        .map(|panel| panel["id"].as_u64().unwrap())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), panels.len(), "panel IDs must be unique");
}

#[test]
fn monitoring_assets_reference_exported_metric_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dashboard =
        std::fs::read_to_string(root.join("deploy/monitoring/grafana-dashboard.json")).unwrap();
    let alerts =
        std::fs::read_to_string(root.join("deploy/monitoring/prometheus-rules.yml")).unwrap();

    for metric in [
        "masque_server_ready",
        "masque_connections_active",
        "masque_quic_receive_bytes_total",
        "masque_quic_send_bytes_total",
        "masque_tunnels_active",
        "masque_auth_attempts_total",
        "masque_packets_dropped_total",
    ] {
        assert!(dashboard.contains(metric), "dashboard omits {metric}");
    }
    for metric in [
        "masque_server_ready",
        "masque_connections_rejected_total",
        "masque_auth_attempts_total",
        "masque_packets_dropped_total",
        "masque_forced_shutdowns_total",
    ] {
        assert!(alerts.contains(metric), "alert rules omit {metric}");
    }
}

#[test]
fn release_packager_includes_operational_assets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(root.join("scripts/package-linux.sh")).unwrap();
    assert!(script.contains("monitoring/prometheus-rules.yml"));
    assert!(script.contains("monitoring/grafana-dashboard.json"));
    assert!(script.contains("bin/masque-probe"));
    assert!(script.contains("maintenance/masque-maintain"));
    assert!(script.contains("maintenance/install-latest.sh"));
}
