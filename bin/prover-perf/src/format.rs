use num_format::{Locale, ToFormattedString};
use zkaleido::ExecutionSummary;

use crate::{args::EvalArgs, programs::GuestProgram};

/// Returns a formatted header for the execution report.
pub(crate) fn format_header(args: &EvalArgs) -> String {
    if args.post_to_gh {
        let short_commit: String = args.commit_hash.chars().take(8).collect();
        format!("*Commit*: {short_commit}")
    } else {
        "*Local execution*".to_string()
    }
}

/// Returns formatted results for the [`ExecutionSummary`]s as a table.
pub(crate) fn format_results(
    programs: &[GuestProgram],
    summaries: &[ExecutionSummary],
    host_name: String,
) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str("| program                | cycles      | gas         |\n");
    table_text.push_str("|------------------------|-------------|-------------|");

    for (program, summary) in programs.iter().zip(summaries) {
        table_text.push_str(&format!(
            "\n| {:<22} | {:>11} | {:>11} |",
            program.as_str(),
            summary.cycles().to_formatted_string(&Locale::en),
            summary
                .gas()
                .map(|g| g.to_formatted_string(&Locale::en))
                .unwrap_or_else(|| "-".to_string()),
        ));
    }
    table_text.push('\n');

    format!("*{host_name} Execution Results*\n {table_text}")
}
