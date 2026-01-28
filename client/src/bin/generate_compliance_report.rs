//! Compliance Report Generator CLI Tool
//! 
//! Usage: generate_compliance_report --receipts-dir <dir> --output <report.json> [--format html|json|csv]
//!
//! Generates compliance reports for auditors including:
//! - Summary statistics
//! - Receipt verification results
//! - Timeline of executions
//! - Model usage breakdown

use anyhow::{Context, Result};
use clap::Parser;
use ephemeral_ml_common::AttestationReceipt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "generate_compliance_report")]
#[command(about = "Generate compliance reports from EphemeralML receipts")]
struct Args {
    /// Directory containing receipt JSON files
    #[arg(short, long)]
    receipts_dir: PathBuf,

    /// Output file path
    #[arg(short, long)]
    output: PathBuf,

    /// Output format: json, csv, html
    #[arg(long, default_value = "json")]
    format: String,

    /// Start timestamp filter (Unix epoch)
    #[arg(long)]
    from_timestamp: Option<u64>,

    /// End timestamp filter (Unix epoch)
    #[arg(long)]
    to_timestamp: Option<u64>,

    /// Filter by model ID
    #[arg(long)]
    model_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ComplianceReport {
    /// Report metadata
    generated_at: u64,
    report_version: String,
    
    /// Summary statistics
    summary: ReportSummary,
    
    /// Per-model breakdown
    model_breakdown: Vec<ModelStats>,
    
    /// Execution timeline
    timeline: Vec<TimelineEntry>,
    
    /// Individual receipt details
    receipts: Vec<ReceiptDetail>,
}

#[derive(Serialize, Deserialize)]
struct ReportSummary {
    total_receipts: usize,
    total_models: usize,
    total_execution_time_ms: u64,
    avg_execution_time_ms: u64,
    earliest_timestamp: u64,
    latest_timestamp: u64,
    unique_sessions: usize,
}

#[derive(Serialize, Deserialize)]
struct ModelStats {
    model_id: String,
    model_version: String,
    total_executions: usize,
    total_execution_time_ms: u64,
    avg_execution_time_ms: u64,
    first_seen: u64,
    last_seen: u64,
}

#[derive(Serialize, Deserialize)]
struct TimelineEntry {
    timestamp: u64,
    timestamp_human: String,
    receipt_id: String,
    model_id: String,
    execution_time_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct ReceiptDetail {
    receipt_id: String,
    model_id: String,
    model_version: String,
    execution_timestamp: u64,
    execution_time_ms: u64,
    memory_peak_mb: u64,
    sequence_number: u64,
    policy_version: String,
    has_signature: bool,
    pcr0_hash: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Load all receipts from directory
    let receipts = load_receipts(&args.receipts_dir, &args)?;
    
    if receipts.is_empty() {
        eprintln!("No receipts found in {:?}", args.receipts_dir);
        std::process::exit(1);
    }
    
    // Generate report
    let report = generate_report(receipts)?;
    
    // Output in requested format
    match args.format.as_str() {
        "json" => output_json(&report, &args.output)?,
        "csv" => output_csv(&report, &args.output)?,
        "html" => output_html(&report, &args.output)?,
        _ => {
            eprintln!("Unknown format: {}. Using JSON.", args.format);
            output_json(&report, &args.output)?;
        }
    }
    
    println!("✓ Compliance report generated: {:?}", args.output);
    println!("  Total receipts: {}", report.summary.total_receipts);
    println!("  Total models: {}", report.summary.total_models);
    println!("  Time range: {} - {}", 
        format_timestamp(report.summary.earliest_timestamp),
        format_timestamp(report.summary.latest_timestamp)
    );
    
    Ok(())
}

fn load_receipts(dir: &PathBuf, args: &Args) -> Result<Vec<AttestationReceipt>> {
    let mut receipts = Vec::new();
    
    for entry in fs::read_dir(dir).context("Failed to read receipts directory")? {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {:?}", path))?;
            
            match serde_json::from_str::<AttestationReceipt>(&content) {
                Ok(receipt) => {
                    // Apply filters
                    if let Some(from) = args.from_timestamp {
                        if receipt.execution_timestamp < from {
                            continue;
                        }
                    }
                    if let Some(to) = args.to_timestamp {
                        if receipt.execution_timestamp > to {
                            continue;
                        }
                    }
                    if let Some(ref model) = args.model_id {
                        if &receipt.model_id != model {
                            continue;
                        }
                    }
                    receipts.push(receipt);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to parse {:?}: {}", path, e);
                }
            }
        }
    }
    
    // Sort by timestamp
    receipts.sort_by_key(|r| r.execution_timestamp);
    
    Ok(receipts)
}

fn generate_report(receipts: Vec<AttestationReceipt>) -> Result<ComplianceReport> {
    let now = ephemeral_ml_common::current_timestamp();
    
    // Calculate summary
    let total_receipts = receipts.len();
    let total_execution_time_ms: u64 = receipts.iter().map(|r| r.execution_time_ms).sum();
    let avg_execution_time_ms = if total_receipts > 0 {
        total_execution_time_ms / total_receipts as u64
    } else {
        0
    };
    
    let earliest = receipts.iter().map(|r| r.execution_timestamp).min().unwrap_or(0);
    let latest = receipts.iter().map(|r| r.execution_timestamp).max().unwrap_or(0);
    
    // Count unique models and sessions
    let mut models: HashMap<String, ModelStats> = HashMap::new();
    let mut sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    
    for receipt in &receipts {
        let key = format!("{}@{}", receipt.model_id, receipt.model_version);
        
        let stats = models.entry(key.clone()).or_insert(ModelStats {
            model_id: receipt.model_id.clone(),
            model_version: receipt.model_version.clone(),
            total_executions: 0,
            total_execution_time_ms: 0,
            avg_execution_time_ms: 0,
            first_seen: receipt.execution_timestamp,
            last_seen: receipt.execution_timestamp,
        });
        
        stats.total_executions += 1;
        stats.total_execution_time_ms += receipt.execution_time_ms;
        stats.first_seen = stats.first_seen.min(receipt.execution_timestamp);
        stats.last_seen = stats.last_seen.max(receipt.execution_timestamp);
        
        // Extract session from receipt_id (assuming format: session-xxx-receipt-yyy)
        if let Some(session) = receipt.receipt_id.split('-').next() {
            sessions.insert(session.to_string());
        }
    }
    
    // Finalize model stats
    let model_breakdown: Vec<ModelStats> = models.into_values().map(|mut m| {
        if m.total_executions > 0 {
            m.avg_execution_time_ms = m.total_execution_time_ms / m.total_executions as u64;
        }
        m
    }).collect();
    
    // Generate timeline
    let timeline: Vec<TimelineEntry> = receipts.iter().map(|r| {
        TimelineEntry {
            timestamp: r.execution_timestamp,
            timestamp_human: format_timestamp(r.execution_timestamp),
            receipt_id: r.receipt_id.clone(),
            model_id: r.model_id.clone(),
            execution_time_ms: r.execution_time_ms,
        }
    }).collect();
    
    // Generate receipt details
    let receipt_details: Vec<ReceiptDetail> = receipts.iter().map(|r| {
        ReceiptDetail {
            receipt_id: r.receipt_id.clone(),
            model_id: r.model_id.clone(),
            model_version: r.model_version.clone(),
            execution_timestamp: r.execution_timestamp,
            execution_time_ms: r.execution_time_ms,
            memory_peak_mb: r.memory_peak_mb,
            sequence_number: r.sequence_number,
            policy_version: r.policy_version.clone(),
            has_signature: r.signature.is_some(),
            pcr0_hash: hex::encode(&r.enclave_measurements.pcr0[..8]),
        }
    }).collect();
    
    let summary = ReportSummary {
        total_receipts,
        total_models: model_breakdown.len(),
        total_execution_time_ms,
        avg_execution_time_ms,
        earliest_timestamp: earliest,
        latest_timestamp: latest,
        unique_sessions: sessions.len(),
    };
    
    Ok(ComplianceReport {
        generated_at: now,
        report_version: "1.0.0".to_string(),
        summary,
        model_breakdown,
        timeline,
        receipts: receipt_details,
    })
}

fn output_json(report: &ComplianceReport, path: &PathBuf) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    fs::write(path, json)?;
    Ok(())
}

fn output_csv(report: &ComplianceReport, path: &PathBuf) -> Result<()> {
    let mut csv = String::new();
    
    // Header
    csv.push_str("receipt_id,model_id,model_version,timestamp,execution_time_ms,memory_peak_mb,sequence_number,policy_version,has_signature\n");
    
    // Data
    for r in &report.receipts {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            r.receipt_id,
            r.model_id,
            r.model_version,
            r.execution_timestamp,
            r.execution_time_ms,
            r.memory_peak_mb,
            r.sequence_number,
            r.policy_version,
            r.has_signature
        ));
    }
    
    fs::write(path, csv)?;
    Ok(())
}

fn output_html(report: &ComplianceReport, path: &PathBuf) -> Result<()> {
    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>EphemeralML Compliance Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #2563eb; }}
        .stat-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f9fafb; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        .badge-success {{ background: #d1fae5; color: #065f46; }}
        .badge-warning {{ background: #fef3c7; color: #92400e; }}
    </style>
</head>
<body>
    <h1>🔒 EphemeralML Compliance Report</h1>
    <p>Generated: {}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Receipts</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Models Used</div>
            </div>
            <div class="stat">
                <div class="stat-value">{} ms</div>
                <div class="stat-label">Avg Execution Time</div>
            </div>
        </div>
    </div>
    
    <h2>Model Breakdown</h2>
    <table>
        <tr>
            <th>Model</th>
            <th>Version</th>
            <th>Executions</th>
            <th>Avg Time (ms)</th>
            <th>First Seen</th>
            <th>Last Seen</th>
        </tr>
        {}
    </table>
    
    <h2>Recent Receipts</h2>
    <table>
        <tr>
            <th>Receipt ID</th>
            <th>Model</th>
            <th>Timestamp</th>
            <th>Execution Time</th>
            <th>Signature</th>
        </tr>
        {}
    </table>
</body>
</html>"#,
        format_timestamp(report.generated_at),
        report.summary.total_receipts,
        report.summary.total_models,
        report.summary.avg_execution_time_ms,
        report.model_breakdown.iter().map(|m| format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            m.model_id, m.model_version, m.total_executions, m.avg_execution_time_ms,
            format_timestamp(m.first_seen), format_timestamp(m.last_seen)
        )).collect::<Vec<_>>().join("\n        "),
        report.receipts.iter().take(50).map(|r| format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{} ms</td><td>{}</td></tr>",
            &r.receipt_id[..r.receipt_id.len().min(16)],
            r.model_id,
            format_timestamp(r.execution_timestamp),
            r.execution_time_ms,
            if r.has_signature { "<span class='badge badge-success'>✓ Signed</span>" } else { "<span class='badge badge-warning'>⚠ Unsigned</span>" }
        )).collect::<Vec<_>>().join("\n        ")
    );
    
    fs::write(path, html)?;
    Ok(())
}

fn format_timestamp(ts: u64) -> String {
    use std::time::{UNIX_EPOCH, Duration};
    let d = UNIX_EPOCH + Duration::from_secs(ts);
    format!("{:?}", d)
}
