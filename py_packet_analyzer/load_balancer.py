from .types import FlowKey


class LoadBalancer:
    """Simple consistent-hash-based flow assignment to worker ids.

    For offline processing this can be used to shard flows across workers.
    """

    def __init__(self, workers: int = 1) -> None:
        self.workers = max(1, int(workers))

    def assign(self, flow: FlowKey) -> int:
        # stable, fast hash over tuple values
        h = hash((flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.proto))
        return (h & 0x7FFFFFFF) % self.workers
