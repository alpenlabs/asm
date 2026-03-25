use std::env;

use clap::Parser;

use crate::programs::GuestProgram;

fn default_github_repo() -> String {
    env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| "alpenlabs/asm".to_string())
}

/// Evaluate SP1 prover performance for ASM programs.
#[derive(Debug, Clone, Parser)]
pub(crate) struct EvalArgs {
    /// Whether to post the results as a GitHub PR comment.
    #[arg(long, default_value_t = false)]
    pub post_to_gh: bool,

    /// GitHub token used to authenticate API requests.
    #[arg(long, default_value_t = String::new())]
    pub github_token: String,

    /// Pull request number to post comment to.
    #[arg(long, default_value_t = String::new())]
    pub pr_number: String,

    /// Commit hash shown in the generated report header.
    #[arg(long, default_value = "local_commit")]
    pub commit_hash: String,

    /// GitHub repository in `owner/repo` format.
    #[arg(long, default_value_t = default_github_repo())]
    pub github_repo: String,

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
