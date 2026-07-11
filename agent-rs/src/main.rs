use serde::Serialize;

#[derive(Serialize)]
struct RuntimeEvent<'a> {
    event_id: &'a str,
    event_type: &'a str,
    scan_id: &'a str,
    target_id: &'a str,
    campaign_id: &'a str,
    scenario_id: &'a str,
    correlation_id: &'a str,
    message: &'a str,
}

fn main() {
    let ev = RuntimeEvent {
        event_id: "agent-demo-evt-1",
        event_type: "mock_process_exec",
        scan_id: "scan-demo",
        target_id: "target-demo",
        campaign_id: "campaign-demo",
        scenario_id: "scenario-demo",
        correlation_id: "corr-demo",
        message: "mock runtime event; eBPF loading is intentionally disabled in first version",
    };
    println!("{}", serde_json::to_string(&ev).unwrap());
}
