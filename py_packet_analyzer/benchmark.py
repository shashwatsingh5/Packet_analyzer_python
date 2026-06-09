from __future__ import annotations

import time
from typing import Dict, Optional

import psutil

from .dpi_engine import DPIEngine
from .rule_manager import RuleManager


def _cpu_seconds(process: psutil.Process) -> float:
    total = process.cpu_times().user + process.cpu_times().system
    for child in process.children(recursive=True):
        try:
            cpu = child.cpu_times()
            total += cpu.user + cpu.system
        except Exception:
            continue
    return total


def _rss_bytes(process: psutil.Process) -> int:
    total = process.memory_info().rss
    for child in process.children(recursive=True):
        try:
            total += child.memory_info().rss
        except Exception:
            continue
    return total


def benchmark(
    pcap_path: str,
    workers: int = 1,
    rules_path: Optional[str] = None,
    max_packets: Optional[int] = None,
    runs: int = 1,
) -> Dict[str, float]:
    rm = RuleManager()
    if rules_path:
        rm.load_rules_from_file(rules_path)
    engine = DPIEngine(rule_manager=rm)
    proc = psutil.Process()
    metrics = {
        'runs': runs,
        'workers': workers,
        'packets': 0,
        'elapsed_seconds': 0.0,
        'throughput_pps': 0.0,
        'cpu_seconds': 0.0,
        'cpu_percent': 0.0,
        'memory_rss_bytes': 0,
        'match_time_seconds': 0.0,
    }
    total_packets = 0
    total_elapsed = 0.0
    total_cpu = 0.0
    peak_memory = 0

    for _ in range(runs):
        start_cpu = _cpu_seconds(proc)
        start_mem = _rss_bytes(proc)
        start_ts = time.perf_counter()
        packet_count = 0

        if workers > 1:
            for _ in engine.process_pcap_multi(pcap_path, workers=workers):
                packet_count += 1
                if max_packets is not None and packet_count >= max_packets:
                    break
        else:
            for _ in engine.process_pcap(pcap_path):
                packet_count += 1
                if max_packets is not None and packet_count >= max_packets:
                    break

        elapsed = time.perf_counter() - start_ts
        end_cpu = _cpu_seconds(proc)
        end_mem = _rss_bytes(proc)
        memory_used = max(start_mem, end_mem)

        total_packets += packet_count
        total_elapsed += elapsed
        total_cpu += max(0.0, end_cpu - start_cpu)
        peak_memory = max(peak_memory, memory_used)

    metrics['runs'] = runs
    metrics['workers'] = workers
    metrics['packets'] = total_packets
    metrics['elapsed_seconds'] = total_elapsed
    metrics['throughput_pps'] = total_packets / total_elapsed if total_elapsed > 0 else 0.0
    metrics['cpu_seconds'] = total_cpu
    metrics['cpu_percent'] = (total_cpu / total_elapsed / psutil.cpu_count(logical=True) * 100.0) if total_elapsed > 0 else 0.0
    metrics['memory_rss_bytes'] = peak_memory
    metrics['match_time_seconds'] = getattr(engine, 'last_shard_match_time', getattr(rm, 'match_time_seconds', 0.0))

    return metrics
