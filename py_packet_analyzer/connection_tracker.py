from typing import Dict
from .types import FlowKey
from dataclasses import dataclass


@dataclass
class ConnectionState:
    first_ts: float
    last_ts: float
    packets: int


class ConnectionTracker:
    def __init__(self) -> None:
        self._flows: Dict[FlowKey, ConnectionState] = {}

    def update(self, flow: FlowKey, ts: float) -> None:
        st = self._flows.get(flow)
        if st is None:
            self._flows[flow] = ConnectionState(first_ts=ts, last_ts=ts, packets=1)
        else:
            st.last_ts = ts
            st.packets += 1

    def stats(self) -> Dict[FlowKey, ConnectionState]:
        return self._flows
