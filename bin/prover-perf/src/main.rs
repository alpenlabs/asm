//! Prover performance evaluation for ASM SP1 guests.

use anyhow::Result;
use clap::Parser;
use sp1_sdk::utils::setup_logger;
use zkaleido::ZkVm;
use zkaleido_perf_report::{render_report, ZkVmResults};

mod args;
mod programs;

use args::{parse_programs, EvalArgs};

/// Identifies this repository's sticky perf comment on a PR, so a run patches its own report
/// instead of a report posted by some other tool.
const COMMENT_MARKER: &str = "strata-asm-prover-perf";

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();
    let args = EvalArgs::parse();

    let programs = parse_programs(&args.programs).map_err(anyhow::Error::msg)?;

    if args.generate_proof {
        programs::gen_and_save_sp1_proofs(&programs).await;
        return Ok(());
    }

    // Resolve the reporting target up front so a misconfiguration fails before the guests run,
    // not after.
    let reporter = args
        .github
        .as_ref()
        .map(|github| github.reporter(COMMENT_MARKER))
        .transpose()?;

    // Resolve the baseline anchor before running the guests: doing it after would let a PR
    // merging into the base branch during this (long) run shift the walk to a commit whose
    // changes are absent from what was actually measured.
    let mut baseline_lookup_failed = false;
    let baseline_anchor = match &reporter {
        Some(reporter) => match reporter.resolve_baseline_anchor().await {
            Ok(anchor) => anchor,
            Err(err) => {
                eprintln!("warning: failed to resolve baseline anchor: {err:#}");
                baseline_lookup_failed = true;
                None
            }
        },
        None => None,
    };

    let summaries = programs::gen_sp1_execution_summaries(&programs).await;
    let results = vec![ZkVmResults::new(ZkVm::SP1, summaries)];

    // A missing baseline only degrades the report to absolute numbers, so a fetch failure must
    // not block posting it.
    let baseline = match (&reporter, &baseline_anchor) {
        (Some(reporter), Some(anchor)) => match reporter.fetch_baseline(anchor).await {
            Ok(baseline) => baseline,
            Err(err) => {
                eprintln!("warning: failed to fetch baseline report: {err:#}");
                baseline_lookup_failed = true;
                None
            }
        },
        _ => None,
    };

    println!(
        "{}",
        render_report(
            &results,
            baseline.as_ref().map(|baseline| &baseline.payload)
        )
    );

    if let Some(reporter) = reporter {
        reporter
            .post_report(
                &results,
                baseline.as_ref(),
                baseline_lookup_failed,
                baseline_anchor.as_ref(),
            )
            .await?;
    }

    Ok(())
}
