use std::time::Instant;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub code: String,
    pub detail: String,
    pub duration_ms: u128,
}

impl CheckResult {
    pub fn pass(name: &str, code: &str, detail: impl Into<String>, started: Instant) -> Self {
        Self::new(name, CheckStatus::Pass, code, detail, started)
    }

    pub fn warning(name: &str, code: &str, detail: impl Into<String>, started: Instant) -> Self {
        Self::new(name, CheckStatus::Warning, code, detail, started)
    }

    pub fn fail(name: &str, failure: ProbeFailure, started: Instant) -> Self {
        Self::new(
            name,
            CheckStatus::Fail,
            failure.code,
            failure.detail,
            started,
        )
    }

    pub fn skipped(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: CheckStatus::Skipped,
            code: "SKIPPED".into(),
            detail: detail.into(),
            duration_ms: 0,
        }
    }

    fn new(
        name: &str,
        status: CheckStatus,
        code: &str,
        detail: impl Into<String>,
        started: Instant,
    ) -> Self {
        Self {
            name: name.to_owned(),
            status,
            code: code.to_owned(),
            detail: detail.into(),
            duration_ms: started.elapsed().as_millis(),
        }
    }
}

#[derive(Debug)]
pub struct ProbeFailure {
    pub code: &'static str,
    pub detail: String,
}

impl ProbeFailure {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub schema_version: u8,
    pub probe_version: &'static str,
    pub endpoint: String,
    pub requested_transport: String,
    pub selected_transport: Option<String>,
    pub success: bool,
    pub checks: Vec<CheckResult>,
}

impl ProbeReport {
    pub fn new(endpoint: String, transport: &str) -> Self {
        Self {
            schema_version: 1,
            probe_version: env!("CARGO_PKG_VERSION"),
            endpoint,
            requested_transport: transport.to_owned(),
            selected_transport: None,
            success: false,
            checks: Vec::new(),
        }
    }

    pub fn finish(&mut self) {
        self.success = self.selected_transport.is_some()
            && self
                .checks
                .iter()
                .all(|check| check.status != CheckStatus::Fail);
    }

    pub fn print_human(&self) {
        println!("MASQUE connectivity probe");
        println!("  endpoint:  {}", self.endpoint);
        println!(
            "  transport: {}",
            self.selected_transport
                .as_deref()
                .unwrap_or(&self.requested_transport)
        );
        println!();
        for check in &self.checks {
            let status = match check.status {
                CheckStatus::Pass => "PASS",
                CheckStatus::Warning => "WARN",
                CheckStatus::Fail => "FAIL",
                CheckStatus::Skipped => "SKIP",
            };
            println!(
                "[{status}] {:<20} {:<28} {} ({} ms)",
                check.name, check.code, check.detail, check.duration_ms
            );
        }
        println!();
        println!("result: {}", if self.success { "PASS" } else { "FAIL" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warnings_and_skips_do_not_fail_a_selected_transport() {
        let now = Instant::now();
        let mut report = ProbeReport::new("proxy.example:443".into(), "auto");
        report.selected_transport = Some("http2".into());
        report.checks.push(CheckResult::warning(
            "http3",
            "UDP_BLOCKED",
            "falling back",
            now,
        ));
        report
            .checks
            .push(CheckResult::skipped("connect_ip", "not requested"));
        report.finish();
        assert!(report.success);
    }

    #[test]
    fn any_failed_check_fails_the_report() {
        let mut report = ProbeReport::new("proxy.example:443".into(), "http3");
        report.selected_transport = Some("http3".into());
        report.checks.push(CheckResult::fail(
            "auth",
            ProbeFailure::new("AUTH_REJECTED", "HTTP 407"),
            Instant::now(),
        ));
        report.finish();
        assert!(!report.success);
    }
}
