use num_format::{Locale, ToFormattedString};
use zkaleido::PerformanceReport;

use crate::args::EvalArgs;

/// Returns a formatted header for the performance report.
pub(crate) fn format_header(args: &EvalArgs) -> String {
    if args.post_to_gh {
        let short_commit: String = args.commit_hash.chars().take(8).collect();
        format!("*Commit*: {short_commit}")
    } else {
        "*Local execution*".to_string()
    }
}

/// Returns formatted results for the [`PerformanceReport`]s as a table.
pub(crate) fn format_results(results: &[PerformanceReport], host_name: String) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str("| program                | cycles      | success  |\n");
    table_text.push_str("|------------------------|-------------|----------|");

    for result in results {
        table_text.push_str(&format!(
            "\n| {:<22} | {:>11} | {:<7} |",
            result.name,
            result.cycles.to_formatted_string(&Locale::en),
            if result.success { "yes" } else { "no" }
        ));
    }
    table_text.push('\n');

    format!("*{host_name} Execution Results*\n {table_text}")
}
