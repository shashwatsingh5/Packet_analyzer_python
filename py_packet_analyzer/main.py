from typing import Optional
import argparse
from .dpi_engine import DPIEngine
from .rule_manager import RuleManager


def run(path: str, rules: Optional[str] = None, max_packets: Optional[int] = None) -> None:
    rm = RuleManager()
    if rules:
        rm.load_rules_from_file(rules)
    engine = DPIEngine(rule_manager=rm)
    count = 0
    for res in engine.process_pcap(path):
        count += 1
        if res.sni or res.matched_rule:
            print(f"{res.ts:.6f} {res.flow.src_ip}:{res.flow.src_port} -> {res.flow.dst_ip}:{res.flow.dst_port} sni={res.sni} rule={res.matched_rule}")
        if max_packets is not None and count >= max_packets:
            break

    print(f"Processed {count} packets")


def main() -> None:
    parser = argparse.ArgumentParser(description='Offline DPI engine (dpkt)')
    parser.add_argument('pcap', nargs='?', default='test_dpi.pcap', help='PCAP file to process')
    parser.add_argument('--rules', help='Rules file (one rule substring per line)')
    parser.add_argument('--max-packets', type=int, help='Limit number of packets to process (for testing)')
    parser.add_argument('--workers', type=int, default=1, help='Number of worker processes to use for sharded processing')
    parser.add_argument('--benchmark', action='store_true', help='Run benchmark measurements instead of printing every packet')
    parser.add_argument('--bench-runs', type=int, default=1, help='Number of benchmark runs to average')
    args = parser.parse_args()

    if args.benchmark:
        from .benchmark import benchmark
        metrics = benchmark(
            args.pcap,
            workers=args.workers,
            rules_path=args.rules,
            max_packets=args.max_packets,
            runs=args.bench_runs,
        )
        print('Benchmark results:')
        print(f"  runs: {metrics['runs']}")
        print(f"  workers: {metrics['workers']}")
        print(f"  packets: {metrics['packets']}")
        print(f"  elapsed_seconds: {metrics['elapsed_seconds']:.6f}")
        print(f"  throughput_pps: {metrics['throughput_pps']:.2f}")
        print(f"  cpu_seconds: {metrics['cpu_seconds']:.6f}")
        print(f"  cpu_percent: {metrics['cpu_percent']:.2f}%")
        print(f"  memory_rss_bytes: {metrics['memory_rss_bytes']}")
        print(f"  match_time_seconds: {metrics['match_time_seconds']:.6f}")
        return

    import time
    start = time.perf_counter()
    if args.workers and args.workers > 1:
        rm_inst = RuleManager()
        if args.rules:
            rm_inst.load_rules_from_file(args.rules)
        engine = DPIEngine(rule_manager=rm_inst)
        count = 0
        for res in engine.process_pcap_multi(args.pcap, workers=args.workers):
            count += 1
            if res.sni or res.matched_rule:
                print(f"{res.ts:.6f} {res.flow.src_ip}:{res.flow.src_port} -> {res.flow.dst_ip}:{res.flow.dst_port} sni={res.sni} rule={res.matched_rule}")
            if args.max_packets is not None and count >= args.max_packets:
                break
        elapsed = time.perf_counter() - start
        print(f"Processed {count} packets in {elapsed:.3f}s ({count/elapsed:.2f} pkt/s)")
        # print rule matching time if available
        mtime = getattr(engine, 'last_shard_match_time', None)
        if mtime is not None:
            print(f"Total rule matching time (sharded workers): {mtime:.6f}s")
    else:
        run(args.pcap, args.rules, args.max_packets)
        elapsed = time.perf_counter() - start
        # print match time for single-worker
        # we can't access RuleManager inside run() here, so create a fresh engine to query time if rules provided
        print(f"Elapsed: {elapsed:.3f}s")


if __name__ == '__main__':
    main()
