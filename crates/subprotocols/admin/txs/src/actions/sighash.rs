use strata_asm_params::AdminTxType;

/// Defines a multisig action's contributions to the bitcoin `signMessage` payload.
///
/// Each multisig action implements this trait to render itself into the canonical
/// signing message that hardware wallets display and sign. [`tx_type`](SigningMessage::tx_type)
/// supplies the `action_type:` line, and [`render_details`](SigningMessage::render_details)
/// appends the action-specific lines.
pub trait SigningMessage {
    /// Returns the [`AdminTxType`] used in the `action_type:` line.
    fn tx_type(&self) -> AdminTxType;

    /// Pushes the action-specific lines into the signing message buffer.
    fn render_details(&self, lines: &mut Vec<String>);
}
