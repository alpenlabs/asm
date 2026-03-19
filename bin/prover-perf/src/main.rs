//! Prover performance evaluation for ASM STF SP1 guest.

use std::process;

use anyhow::Result;
use clap::Parser;
use sp1_sdk::utils::setup_logger;

mod args;
mod format;
mod github;
mod programs;

use args::{parse_programs, EvalArgs};
use format::{format_header, format_results};
use github::{format_github_message, post_to_github_pr};

fn main() -> Result<()> {
    setup_logger();
    let args = EvalArgs::parse();

    let programs = parse_programs(&args.programs).map_err(anyhow::Error::msg)?;

    let mut results_text = vec![format_header(&args)];
    let sp1_reports = programs::run_sp1_programs(&programs);
    results_text.push(format_results(&sp1_reports, "SP1".to_string()));

    println!("{}", results_text.join("\n"));

    if args.post_to_gh {
        let message = format_github_message(&results_text);
        post_to_github_pr(&args, &message)?;
    }

    if !sp1_reports.iter().all(|r| r.success) {
        process::exit(1);
    }

    Ok(())
}
