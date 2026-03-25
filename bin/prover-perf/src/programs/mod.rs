use std::str::FromStr;

mod asm_stf;
mod moho;

use zkaleido::PerformanceReport;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum GuestProgram {
    AsmStf,
    Moho,
}

impl FromStr for GuestProgram {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "asm-stf" => Ok(GuestProgram::AsmStf),
            "moho" => Ok(GuestProgram::Moho),
            _ => Err(format!("unknown program: {s}")),
        }
    }
}

/// Runs SP1 programs to generate reports.
pub(crate) fn run_sp1_programs(programs: &[GuestProgram]) -> Vec<PerformanceReport> {
    programs
        .iter()
        .map(|program| match program {
            GuestProgram::AsmStf => asm_stf::gen_perf_report(),
            GuestProgram::Moho => moho::gen_perf_report(),
        })
        .collect()
}
