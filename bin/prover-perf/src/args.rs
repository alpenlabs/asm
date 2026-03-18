use clap::Parser;

use crate::programs::GuestProgram;

/// Evaluate SP1 prover performance for ASM programs.
#[derive(Debug, Clone, Parser)]
pub(crate) struct EvalArgs {
    /// Programs to run. Supports comma-delimited and repeated values, e.g.
    /// `--programs asm-stf` or `--programs asm-stf,asm-stf`.
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
