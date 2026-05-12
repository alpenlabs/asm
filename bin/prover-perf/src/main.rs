//! Prover performance evaluation for ASM SP1 guests.

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

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();
    let args = EvalArgs::parse();

    let programs = parse_programs(&args.programs).map_err(anyhow::Error::msg)?;

    if args.generate_proof {
        let sp1_proofs = programs::gen_sp1_proof(&programs).await;
        for (program, proof) in programs.iter().zip(sp1_proofs) {
            proof
                .save(program.as_str())
                .unwrap_or_else(|e| panic!("failed to save proof for {}: {e}", program.as_str()));
        }
        return Ok(());
    }

    let mut results_text = vec![format_header(&args)];
    let sp1_summaries = programs::gen_sp1_execution_summaries(&programs).await;
    results_text.push(format_results(&programs, &sp1_summaries, "SP1".to_string()));

    println!("{}", results_text.join("\n"));

    if args.post_to_gh {
        let message = format_github_message(&results_text);
        post_to_github_pr(&args, &message).await?;
    }

    Ok(())
}
