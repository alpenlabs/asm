use std::collections::HashMap;

use bitcoin::{
    Block,
    block::Header,
    consensus::{self, deserialize},
};
use strata_identifiers::L1Height;

/// Inclusive start height of the bundled contiguous mainnet header fixture.
const MAINNET_FIXTURE_START_HEIGHT: L1Height = 40_000;

/// Exclusive end height of the bundled contiguous mainnet header fixture.
const MAINNET_FIXTURE_END_HEIGHT: L1Height = 50_000;

/// A Bitcoin test fixture segment indexed by L1 block height.
///
/// This struct stores a sparse set of full blocks and headers in maps so tests can
/// directly query a known fixture by height.
#[derive(Debug, Default)]
pub struct BtcMainnetSegment {
    pub blocks: HashMap<L1Height, Block>,
    pub headers: HashMap<L1Height, Header>,
}

impl BtcMainnetSegment {
    /// Returns the fixture height bounds as `(start, end)`.
    ///
    /// The range follows Rust's standard half-open convention: `start..end`.
    pub const fn height_bounds(&self) -> (L1Height, L1Height) {
        (MAINNET_FIXTURE_START_HEIGHT, MAINNET_FIXTURE_END_HEIGHT)
    }

    /// Loads a single full mainnet block fixture from disk.
    ///
    /// The fixture file contains block
    /// `000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae`.
    pub fn load_full_block() -> Block {
        let raw_block = include_bytes!(
            "../data/btc_mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw"
        );
        deserialize(&raw_block[..]).expect("valid bundled full block fixture")
    }

    /// Loads fixed full-block fixtures keyed by their L1 heights.
    pub fn load_blocks() -> HashMap<L1Height, Block> {
        // Chosen around the first historical Bitcoin difficulty adjustment boundary.
        [
            (40_320, "010000001a231097b6ab6279c80f24674a2c8ee5b9a848e1d45715ad89b6358100000000a822bafe6ed8600e3ffce6d61d10df1927eafe9bbf677cb44c4d209f143c6ba8db8c784b5746651cce2221180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08045746651c02db02ffffffff0100f2052a010000004341046477f88505bef7e3c1181a7e3975c4cd2ac77ffe23ea9b28162afbb63bd71d3f7c3a07b58cf637f1ec68ed532d5b6112d57a9744010aae100e4a48cd831123b8ac00000000"),
            (40_321, "0100000045720d24eae33ade0d10397a2e02989edef834701b965a9b161e864500000000993239a44a83d5c427fd3d7902789ea1a4d66a37d5848c7477a7cf47c2b071cd7690784b5746651c3af7ca030101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08045746651c02db00ffffffff0100f2052a01000000434104c9f513361104db6a84fb6d5b364ba57a27cd19bd051239bf750d8999c6b437220df8fea6b932a248df3cad1fdebb501791e02b7b893a44718d696542ba92a0acac00000000"),
            (40_322, "01000000fd1133cd53d00919b0bd77dd6ca512c4d552a0777cc716c00d64c60d0000000014cf92c7edbe8a75d1e328b4fec0d6143764ecbd0f5600aba9d22116bf165058e590784b5746651c1623dbe00101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08045746651c020509ffffffff0100f2052a010000004341043eb751f57bd4839a8f2922d5bf1ed15ade9b161774658fb39801f0b9da9c881f226fbe4ee0c240915f17ce5255dd499075ab49b199a7b1f898fb20cc735bc45bac00000000"),
            (40_323, "01000000c579e586b48485b6e263b54949d07dce8660316163d915a35e44eb570000000011d2b66f9794f17393bf90237f402918b61748f41f9b5a2523c482a81a44db1f4f91784b5746651c284557020101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08045746651c024502ffffffff0100f2052a01000000434104597b934f2081e7f0d7fae03ec668a9c69a090f05d4ee7c65b804390d94266ffb90442a1889aaf78b460692a43857638520baa8319cf349b0d5f086dc4d36da8eac00000000"),
            (40_324, "010000001f35c6ea4a54eb0ea718a9e2e9badc3383d6598ff9b6f8acfd80e52500000000a7a6fbce300cbb5c0920164d34c36d2a8bb94586e9889749962b1be9a02bbf3b9194784b5746651c0558e1140101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08045746651c029001ffffffff0100f2052a01000000434104e5d390c21b7d221e6ba15c518444c1aae43d6fb6f721c4a5f71e590288637ca2961be07ee845a795da3fd1204f52d4faa819c167062782590f08cf717475e488ac00000000"),
        ]
        .into_iter()
        .map(|(height, raw_block)| {
            let block = consensus::encode::deserialize_hex(raw_block)
                .expect("valid bundled block hex fixture");
            (height, block)
        })
        .collect()
    }

    /// Loads header fixtures keyed by L1 height.
    ///
    /// Includes the contiguous range `40_000..50_000` from the bundled raw file,
    /// plus one extra custom header at height `38_304`.
    pub fn load_headers() -> HashMap<L1Height, Header> {
        let raw_headers = include_bytes!("../data/btc_mainnet_headers_40000-50000.raw");
        assert_eq!(
            raw_headers.len() % Header::SIZE,
            0,
            "header fixture length must be a multiple of {}",
            Header::SIZE
        );

        let mut headers = HashMap::with_capacity(
            (MAINNET_FIXTURE_END_HEIGHT - MAINNET_FIXTURE_START_HEIGHT) as usize + 1,
        );

        for (idx, chunk) in raw_headers.chunks_exact(Header::SIZE).enumerate() {
            let height = MAINNET_FIXTURE_START_HEIGHT + idx as L1Height;
            let header =
                deserialize(chunk).expect("valid serialized header in bundled fixture range");
            headers.insert(height, header);
        }

        let custom_header: Header = consensus::encode::deserialize_hex(
            "01000000858a5c6d458833aa83f7b7e56d71c604cb71165ebb8104b82f64de8d00000000e408c11029b5fdbb92ea0eeb8dfa138ffa3acce0f69d7deebeb1400c85042e01723f6b4bc38c001d09bd8bd5",
        )
        .expect("valid custom header hex fixture");
        headers.insert(38_304, custom_header);

        headers
    }

    /// Loads the full BTC fixture segment (`blocks` + `headers`).
    pub fn load_full() -> BtcMainnetSegment {
        BtcMainnetSegment {
            blocks: Self::load_blocks(),
            headers: Self::load_headers(),
        }
    }

    /// Backward-compatible alias for [`Self::load_full`].
    pub fn load() -> BtcMainnetSegment {
        Self::load_full()
    }

    /// Retrieves the full block fixture at `height`, if available.
    pub fn get_block_at(&self, height: L1Height) -> Option<Block> {
        self.blocks.get(&height).cloned()
    }

    /// Retrieves the header fixture at `height`, if available.
    pub fn get_block_header_at(&self, height: L1Height) -> Option<Header> {
        self.headers.get(&height).cloned()
    }
}
