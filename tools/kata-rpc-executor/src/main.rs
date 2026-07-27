use anyhow::{bail, Context, Result};
use kata_agent::cver_fuzz::{invoke_read_stdout_fields, ReadStdoutCase};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Read};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ReadStdoutInput {
    rpc: String,
    container_id: String,
    exec_id: String,
    len: u32,

    #[serde(default)]
    fixture_profile: Option<String>,

    #[serde(default)]
    hypothesis: Option<String>,

    #[serde(default)]
    expected_security_property: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExecutionOutput {
    schema_version: &'static str,
    harness_status: &'static str,
    rpc: &'static str,

    handler_status: &'static str,
    error_class: Option<&'static str>,
    error_message: Option<String>,
    execution_time_us: u128,

    response_len: Option<usize>,
    response_data_hex: Option<String>,

    input: ReadStdoutInput,
}

fn read_input() -> Result<String> {
    if let Some(path) = env::args_os().nth(1) {
        return fs::read_to_string(&path)
            .with_context(|| format!("failed to read input file {:?}", path));
    }

    let mut input = String::new();

    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read JSON from stdin")?;

    if input.trim().is_empty() {
        bail!("provide a JSON file path or pipe JSON through stdin");
    }

    Ok(input)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let raw = read_input()?;

    let input: ReadStdoutInput =
        serde_json::from_str(&raw).context("invalid ReadStdout JSON input")?;

    if input.rpc != "ReadStdout" {
        bail!(
            "unsupported RPC {:?}; this executor currently \
             supports ReadStdout only",
            input.rpc
        );
    }

    let report = invoke_read_stdout_fields(ReadStdoutCase {
        container_id: input.container_id.clone(),
        exec_id: input.exec_id.clone(),
        len: input.len,
        fixture_profile: input.fixture_profile.clone(),
    })
    .await
    .context("Kata ReadStdout harness execution failed")?;

    let output = ExecutionOutput {
        schema_version: "cver-kata-execution-v1",
        harness_status: "ok",
        rpc: report.rpc,

        handler_status: report.handler_status,
        error_class: report.error_class,
        error_message: report.error_message,
        execution_time_us: report.execution_time_us,

        response_len: report.response_len,
        response_data_hex: report.response_data_hex,

        input,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).context("failed to serialize execution report")?
    );

    Ok(())
}
