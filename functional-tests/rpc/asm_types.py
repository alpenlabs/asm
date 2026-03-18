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
