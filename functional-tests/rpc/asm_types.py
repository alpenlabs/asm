from __future__ import annotations

from dataclasses import dataclass


@dataclass
class L1BlockCommitment:
    height: int
    blkid: str

    @classmethod
    def from_dict(cls, data: dict) -> L1BlockCommitment:
        return cls(height=data["height"], blkid=data["blkid"])


@dataclass
class AsmWorkerStatus:
    is_initialized: bool
    cur_block: L1BlockCommitment | None
    cur_state: dict | None

    @classmethod
    def from_dict(cls, data: dict) -> AsmWorkerStatus:
        cur_block = None
        if data.get("cur_block") is not None:
            cur_block = L1BlockCommitment.from_dict(data["cur_block"])
        return cls(
            is_initialized=data["is_initialized"],
            cur_block=cur_block,
            cur_state=data.get("cur_state"),
        )


@dataclass
class OLBlockCommitment:
    slot: int
    blkid: str

    @classmethod
    def from_dict(cls, data: dict) -> OLBlockCommitment:
        return cls(slot=data["slot"], blkid=data["blkid"])


@dataclass
class CheckpointTip:
    epoch: int
    l1_height: int
    l2_commitment: OLBlockCommitment

    @classmethod
    def from_dict(cls, data: dict) -> CheckpointTip:
        return cls(
            epoch=data["epoch"],
            l1_height=data["l1_height"],
            l2_commitment=OLBlockCommitment.from_dict(data["l2_commitment"]),
        )
