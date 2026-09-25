from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from bitcoinlib.keys import Key

from constants import ASM_MAGIC_BYTES

# BOSD-encoded P2TR descriptor used as the default safe harbour address in
# tests. Address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`.
DEFAULT_SAFE_HARBOUR_ADDRESS = "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667"


@dataclass
class Block:
    height: int
    blkid: str


@dataclass
class L1Anchor:
    block: Block
    next_target: int
    epoch_start_timestamp: int
    network: str


@dataclass
class ThresholdConfig:
    signers: list[str]
    threshold: int


@dataclass
class ConfirmationDepths:
    strata_admin_multisig_update: int
    strata_seq_manager_multisig_update: int
    alpen_admin_multisig_update: int
    strata_security_council_multisig_update: int
    operator_update: int
    sequencer_update: int
    ol_stf_vk_update: int
    asm_stf_vk_update: int
    ee_stf_vk_update: int
    defcon3: int
    safe_harbour_address_update: int


@dataclass
class AdminSubprotocol:
    alpen_administrator: ThresholdConfig
    strata_administrator: ThresholdConfig
    strata_sequencer_manager: ThresholdConfig
    strata_security_council: ThresholdConfig
    confirmation_depths: ConfirmationDepths
    max_seqno_gap: int


@dataclass
class CheckpointSubprotocol:
    sequencer_key: str
    checkpoint_predicate: str
    genesis_l1_height: int
    genesis_ol_blkid: str


@dataclass
class BridgeSubprotocol:
    operators: list[str]
    denomination: int
    assignment_duration: int
    operator_fee: int
    recovery_delay: int
    safe_harbour_address: str


@dataclass
class AsmParams:
    magic: str
    anchor: L1Anchor
    subprotocols: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "anchor": asdict(self.anchor),
            "subprotocols": self.subprotocols,
        }


# Bitcoin's difficulty-adjustment epoch length, in blocks. Same on every network.
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016


def parse_bits_to_target(bits: int | str) -> int:
    if isinstance(bits, str):
        return int(bits, 16)
    return int(bits)


def epoch_start_height(anchor_height: int) -> int:
    """Height of the first block of the difficulty epoch containing `anchor_height`."""
    return (anchor_height // DIFFICULTY_ADJUSTMENT_INTERVAL) * DIFFICULTY_ADJUSTMENT_INTERVAL


def build_l1_anchor(
    genesis_height: int,
    block_hash: str,
    header: dict[str, Any],
    epoch_start_header: dict[str, Any],
    network: str = "regtest",
) -> L1Anchor:
    # The worker validates the anchor against L1 at startup, re-deriving every field, so
    # these must match what header verification would compute (see crates/worker state.rs).
    #
    # `epoch_start_timestamp` is the timestamp of the *first* block of the anchor's
    # difficulty epoch, not the anchor block's own timestamp.
    epoch_start_timestamp = int(epoch_start_header["time"])

    # `next_target` is the target the anchor's successor must satisfy. On regtest
    # retargeting is disabled, so it is always the anchor block's own target; the
    # difficulty-boundary retarget branch (genesis at a 2016 multiple) never triggers.
    next_target = parse_bits_to_target(header["bits"])

    return L1Anchor(
        block=Block(height=genesis_height, blkid=block_hash),
        next_target=next_target,
        epoch_start_timestamp=epoch_start_timestamp,
        network=network,
    )


def p2wpkh_address(compressed_key: str, network: str) -> str:
    """P2WPKH address of a compressed public key, on `network`.

    Admin signers are named by address in the params file, and the runner rejects a
    signer whose address prefix disagrees with the anchor's network.
    """
    return Key(import_key=compressed_key, network=network, is_private=False).address(
        encoding="bech32"
    )


def build_subprotocols(
    musig2_keys: list[str],
    genesis_height: int,
    denomination: int = 1_000_000_000,
    assignment_duration: int = 100_000,
    operator_fee: int = 100_000_000,
    recovery_delay: int = 1_008,
    safe_harbour_address: str = DEFAULT_SAFE_HARBOUR_ADDRESS,
    network: str = "regtest",
) -> list[dict[str, Any]]:
    compressed_keys = [f"02{key}" for key in musig2_keys]
    signer_addresses = [p2wpkh_address(key, network) for key in compressed_keys]
    confirmation_depth = 144

    admin = {
        "Admin": asdict(
            AdminSubprotocol(
                alpen_administrator=ThresholdConfig(signers=signer_addresses, threshold=1),
                strata_administrator=ThresholdConfig(signers=signer_addresses, threshold=1),
                strata_sequencer_manager=ThresholdConfig(signers=signer_addresses, threshold=1),
                strata_security_council=ThresholdConfig(signers=signer_addresses, threshold=1),
                confirmation_depths=ConfirmationDepths(
                    strata_admin_multisig_update=confirmation_depth,
                    strata_seq_manager_multisig_update=confirmation_depth,
                    alpen_admin_multisig_update=confirmation_depth,
                    strata_security_council_multisig_update=confirmation_depth,
                    operator_update=confirmation_depth,
                    sequencer_update=confirmation_depth,
                    ol_stf_vk_update=confirmation_depth,
                    asm_stf_vk_update=confirmation_depth,
                    ee_stf_vk_update=confirmation_depth,
                    defcon3=confirmation_depth,
                    safe_harbour_address_update=confirmation_depth,
                ),
                max_seqno_gap=10,
            )
        )
    }

    checkpoint = {
        "Checkpoint": asdict(
            CheckpointSubprotocol(
                # The musig2 keys are already x-only, which is what the
                # sequencer key has to be.
                sequencer_key=musig2_keys[0],
                checkpoint_predicate="AlwaysAccept",
                genesis_l1_height=genesis_height,
                genesis_ol_blkid="0" * 64,
            )
        )
    }

    bridge = {
        "Bridge": asdict(
            BridgeSubprotocol(
                operators=compressed_keys,
                denomination=denomination,
                assignment_duration=assignment_duration,
                operator_fee=operator_fee,
                recovery_delay=recovery_delay,
                safe_harbour_address=safe_harbour_address,
            )
        )
    }

    return [admin, checkpoint, bridge]


def build_asm_params(
    musig2_keys: list[str],
    genesis_height: int,
    block_hash: str,
    header: dict[str, Any],
    epoch_start_header: dict[str, Any],
    magic: str = ASM_MAGIC_BYTES,
    denomination: int = 1_000_000_000,
    assignment_duration: int = 10_000,
    operator_fee: int = 100_000_000,
    recovery_delay: int = 1_008,
    safe_harbour_address: str = DEFAULT_SAFE_HARBOUR_ADDRESS,
    network: str = "regtest",
) -> AsmParams:
    anchor = build_l1_anchor(
        genesis_height, block_hash, header, epoch_start_header, network=network
    )
    subprotocols = build_subprotocols(
        musig2_keys,
        genesis_height,
        denomination=denomination,
        assignment_duration=assignment_duration,
        operator_fee=operator_fee,
        recovery_delay=recovery_delay,
        safe_harbour_address=safe_harbour_address,
        network=network,
    )
    return AsmParams(
        magic=magic,
        anchor=anchor,
        subprotocols=subprotocols,
    )


def write_asm_params_json(output_path: str | Path, asm_params: AsmParams) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asm_params.to_dict(), indent=4) + "\n")
    return path.as_posix()
