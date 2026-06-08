from typing import Iterator, Optional, List, Dict, Any
from .pcap_reader import PcapReader
from .packet_parser import parse_packet
from .rule_manager import RuleManager
from .sni_extractor import extract_sni_from_tls
from .connection_tracker import ConnectionTracker
from .types import DPIResult, FlowKey
from .load_balancer import LoadBalancer
import tempfile
import dpkt
import os
from concurrent.futures import ProcessPoolExecutor


def _process_shard(pcap_path: str, rules: List[str]) -> Dict[str, Any]:
    """Worker-level processing for a shard file. Returns list of result dicts."""
    rm = RuleManager(rules=rules)
    conn = ConnectionTracker()
    results: List[Dict[str, Any]] = []
    try:
        with open(pcap_path, 'rb') as f:
            reader = dpkt.pcap.Reader(f)
            for ts, buf in reader:
                pkt = parse_packet(float(ts), buf)
                if pkt is None:
                    continue
                flow = FlowKey(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto)
                conn.update(flow, pkt.ts)
                sni = None
                if pkt.payload and pkt.proto == 6:
                    sni = extract_sni_from_tls(pkt.payload)
                matched = rm.match(pkt.payload)
                results.append({
                    'flow': (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.proto),
                    'ts': pkt.ts,
                    'sni': sni,
                    'matched_rule': matched,
                })
    except Exception:
        pass
    return {'results': results, 'match_time': getattr(rm, 'match_time_seconds', 0.0)}


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

    def process_pcap_multi(self, path: str, workers: int = 1) -> Iterator[DPIResult]:
        """Shard the input pcap into per-worker files, process in parallel, and yield results.

        Note: results returned are not in original packet order; callers should sort if order matters.
        """
        if workers <= 1:
            yield from self.process_pcap(path)
            return

        lb = LoadBalancer(workers=workers)
        # create temporary pcap files for shards
        with tempfile.TemporaryDirectory() as td:
            writers = []
            files = []
            for i in range(workers):
                fp = os.path.join(td, f'shard_{i}.pcap')
                f = open(fp, 'wb')
                w = dpkt.pcap.Writer(f)
                writers.append((f, w))
                files.append(fp)

            # stream and write to shard files
            for ts, raw in self.reader.iter_packets(path):
                pkt = parse_packet(ts, raw)
                if pkt is None:
                    continue
                flow = FlowKey(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto)
                idx = lb.assign(flow)
                f, w = writers[idx]
                w.writepkt(raw, ts=ts)

            # close writers
            for f, w in writers:
                try:
                    w.close()
                except Exception:
                    pass
                try:
                    f.close()
                except Exception:
                    pass

            # process shards in parallel
            results: List[Dict[str, Any]] = []
            total_match_time = 0.0
            rules_copy = list(self.rule_manager.rules)
            with ProcessPoolExecutor(max_workers=workers) as ex:
                futures = [ex.submit(_process_shard, fp, rules_copy) for fp in files]
                for fut in futures:
                    try:
                        res = fut.result()
                        results.extend(res.get('results', []))
                        total_match_time += float(res.get('match_time', 0.0))
                    except Exception:
                        continue

            # yield merged results (sorted by ts)
            # store aggregated match time for caller
            self.last_shard_match_time = total_match_time
            results.sort(key=lambda r: r.get('ts', 0.0))
            for r in results:
                flow_tuple = r['flow']
                flow = FlowKey(*flow_tuple)
                yield DPIResult(flow=flow, ts=r['ts'], sni=r.get('sni'), matched_rule=r.get('matched_rule'))
