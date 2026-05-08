use strata_asm_params::AdminTxType;

/// A buffer for the indented sub-fields under the `Action Details:` header line.
///
/// Constructed only by the signing-message renderer, so per-action `render_details`
/// implementors cannot bypass the two-space indent that hardware wallets use to
/// distinguish detail sub-fields from top-level header lines.
#[derive(Debug)]
pub(crate) struct IndentedDetails<'a> {
    lines: &'a mut Vec<String>,
}

impl<'a> IndentedDetails<'a> {
    pub(crate) fn new(lines: &'a mut Vec<String>) -> Self {
        Self { lines }
    }

    pub(crate) fn push(&mut self, line: impl Into<String>) {
        self.lines.push(format!("  {}", line.into()));
    }
}

/// Renders an action variant's contributions to the bitcoin `signMessage` payload.
///
/// Implemented by every action type that participates in the canonical signing message that
/// hardware wallets display and sign. [`tx_type`](RenderSigningMessage::tx_type) supplies the
/// `Action:` line, and [`render_details`](RenderSigningMessage::render_details) pushes the
/// indented sub-fields that appear under `Action Details:`.
pub(crate) trait RenderSigningMessage {
    /// Returns the [`AdminTxType`] used in the `Action:` line.
    fn tx_type(&self) -> AdminTxType;

    /// Pushes the action-specific sub-fields into the indented details buffer.
    fn render_details(&self, details: &mut IndentedDetails<'_>);
}

pub(crate) fn append_indexed_fields(
    details: &mut IndentedDetails<'_>,
    prefix: &str,
    values: impl IntoIterator<Item = String>,
) {
    let values: Vec<String> = values.into_iter().collect();
    details.push(format!("{prefix} Count: {}", values.len()));
    for (idx, value) in values.into_iter().enumerate() {
        details.push(format!("{prefix} {}: {value}", idx + 1));
    }
}
