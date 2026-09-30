use clap::Parser;
use zkaleido_perf_report::GithubReportArgs;

use crate::programs::GuestProgram;

/// Evaluate SP1 prover performance for ASM programs.
#[derive(Debug, Clone, Parser)]
pub(crate) struct EvalArgs {
    /// GitHub reporting options; the report is posted to the PR only when at least one of these is
    /// provided.
    #[command(flatten)]
    pub github: Option<GithubReportArgs>,

    /// Whether to generate the proof. When proof generation is enabled, the performance report is
    /// skipped.
    #[arg(long, default_value_t = false)]
    pub generate_proof: bool,

    /// Programs to run. Supports comma-delimited and repeated values
    /// `--programs asm-stf` or `--programs asm-stf,moho`.
    #[arg(long)]
    pub programs: Vec<String>,
}

/// Parses program strings into [`GuestProgram`] variants.
///
/// Supports comma-separated values and repeated options.
pub(crate) fn parse_programs(raw: &[String]) -> Result<Vec<GuestProgram>, String> {
    if raw.is_empty() {
        return Ok(vec![GuestProgram::AsmStf]);
    }

    raw.iter()
        .flat_map(|s| s.split(','))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<GuestProgram>())
        .collect()
}

// TODO(STR-4523): these tests never run. They live in the binary target, which sets `test = false`
// to keep the heavy sp1-sdk build out of the workspace coverage run. Moving `args` and `programs`
// into a library target would let them run without adding that cost back.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_programs_default() {
        let input: Vec<String> = vec![];
        let result = parse_programs(&input).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], GuestProgram::AsmStf));
    }

    #[test]
    fn test_parse_programs_comma_separated() {
        let input = vec!["asm-stf".to_string()];
        let result = parse_programs(&input).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], GuestProgram::AsmStf));
    }

    #[test]
    fn test_parse_programs_invalid() {
        let input = vec!["invalid-program".to_string()];
        let result = parse_programs(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown program"));
    }
}
