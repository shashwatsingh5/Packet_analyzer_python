from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: int


@dataclass
class PacketInfo:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    payload: bytes


@dataclass
class DPIResult:
    flow: FlowKey
    ts: float
    sni: Optional[str]
    matched_rule: Optional[str]
