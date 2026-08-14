use std::collections::BTreeMap;

use bitcoin::Block;
use strata_asm_common::{SubprotocolId, TxInputRef};
use strata_l1_txfmt::{MagicBytes, ParseConfig};

/// Groups the SPS-50 tagged transactions in `block` by the subprotocol they
/// target.
///
/// Transactions that lack a valid SPS-50 header — wrong magic, no OP_RETURN in
/// the first output, or too short a payload — are filtered out, as is the
/// coinbase at index 0.
///
/// The coinbase is excluded because a miner picks its contents freely: it
/// spends no UTXO and carries no signature, so grouping it would let any miner
/// feed every subprotocol parser an unauthenticated transaction for the cost of
/// mining a block. Leaving it out also means every grouped transaction spends a
/// real UTXO, since Bitcoin consensus allows the null outpoint only in a
/// coinbase. A parser can therefore treat an input's previous output as naming
/// a transaction that exists.
///
/// # Returns
///
/// One entry per subprotocol that has at least one tagged transaction, holding
/// references to the block's transactions wrapped in [`TxInputRef`].
pub fn group_txs_by_subprotocol(
    magic: MagicBytes,
    block: &Block,
) -> BTreeMap<SubprotocolId, Vec<TxInputRef<'_>>> {
    let parser = ParseConfig::new(magic);
    let mut map: BTreeMap<SubprotocolId, Vec<TxInputRef<'_>>> = BTreeMap::new();

    for tx in block.txdata.iter().skip(1) {
        if let Ok(payload) = parser.try_parse_tx(tx) {
            map.entry(payload.subproto_id())
                .or_default()
                .push(TxInputRef::new(tx, payload));
        }
    }

    map
}
