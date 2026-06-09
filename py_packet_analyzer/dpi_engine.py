from multiprocessing import Process, Queue
from typing import Iterator, Optional, List, Dict, Any
from .pcap_reader import PcapReader
from .packet_parser import parse_packet
from .rule_manager import RuleManager
from .sni_extractor import extract_sni_from_tls
from .connection_tracker import ConnectionTracker
from .types import DPIResult, FlowKey
from .load_balancer import LoadBalancer


def _stream_worker(worker_id: int, rules: List[str], task_queue: Queue, result_queue: Queue) -> None:
    rm = RuleManager(rules=rules)
    conn = ConnectionTracker()
    while True:
        item = task_queue.get()
        if item is None:
            break
        ts, src_ip, src_port, dst_ip, dst_port, proto, payload = item
        flow = FlowKey(src_ip, src_port, dst_ip, dst_port, proto)
        conn.update(flow, ts)
        sni = None
        if payload and proto == 6:
            sni = extract_sni_from_tls(payload)
        matched = rm.match(payload)
        result_queue.put({
            'flow': (src_ip, src_port, dst_ip, dst_port, proto),
            'ts': ts,
            'sni': sni,
            'matched_rule': matched,
        })
    result_queue.put({'worker_done': True, 'match_time': rm.match_time_seconds, 'worker_id': worker_id})


class DPIEngine:
    def __init__(self, rule_manager: Optional[RuleManager] = None) -> None:
        self.reader = PcapReader()
        self.rule_manager = rule_manager or RuleManager()
        self.conn_tracker = ConnectionTracker()
    def process_pcap(self, path: str) -> Iterator[DPIResult]:
        for ts, raw in self.reader.iter_packets(path):
            pkt = parse_packet(ts, raw)
            if pkt is None:
                continue
            flow = FlowKey(
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                proto=pkt.proto,
            )
            # update connection state
            self.conn_tracker.update(flow, pkt.ts)

            sni = None
            # if TCP and payload present, try SNI
            if pkt.payload and pkt.proto == 6:
                sni = extract_sni_from_tls(pkt.payload)

            matched = self.rule_manager.match(pkt.payload)

            yield DPIResult(flow=flow, ts=pkt.ts, sni=sni, matched_rule=matched)

    def process_pcap_multi(self, path: str, workers: int = 1, max_packets: Optional[int] = None) -> Iterator[DPIResult]:
        """Stream packets to worker processes while maintaining flow-based sharding."""
        if workers <= 1:
            yield from self.process_pcap(path)
            return

        lb = LoadBalancer(workers=workers)
        task_queues: List[Queue] = [Queue() for _ in range(workers)]
        result_queue: Queue = Queue()
        processes: List[Process] = []
        for worker_id in range(workers):
            p = Process(
                target=_stream_worker,
                args=(worker_id, list(self.rule_manager.rules), task_queues[worker_id], result_queue),
            )
            p.start()
            processes.append(p)

        packet_count = 0
        for ts, raw in self.reader.iter_packets(path):
            pkt = parse_packet(ts, raw)
            if pkt is None:
                continue
            flow = FlowKey(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto)
            worker_idx = lb.assign(flow)
            task_queues[worker_idx].put(
                (ts, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto, pkt.payload)
            )
            packet_count += 1
            if max_packets is not None and packet_count >= max_packets:
                break

        for queue in task_queues:
            queue.put(None)

        done_workers = 0
        total_match_time = 0.0
        while done_workers < workers:
            item = result_queue.get()
            if item.get('worker_done'):
                total_match_time += float(item.get('match_time', 0.0))
                done_workers += 1
                continue
            flow_tuple = item['flow']
            flow = FlowKey(*flow_tuple)
            yield DPIResult(
                flow=flow,
                ts=item['ts'],
                sni=item.get('sni'),
                matched_rule=item.get('matched_rule'),
            )

        for p in processes:
            p.join()

        self.last_shard_match_time = total_match_time
