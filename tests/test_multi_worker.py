import sys
sys.path.insert(0, r'E:\Packet_analyzer-main')
from py_packet_analyzer.dpi_engine import DPIEngine
from py_packet_analyzer.rule_manager import RuleManager


def collect_results(engine, pcap_path, workers=1, max_packets=None):
    res = []
    if workers > 1:
        it = engine.process_pcap_multi(pcap_path, workers=workers)
    else:
        it = engine.process_pcap(pcap_path)
    c = 0
    for r in it:
        res.append((r.flow.src_ip, r.flow.src_port, r.flow.dst_ip, r.flow.dst_port, r.ts, r.sni, r.matched_rule))
        c += 1
        if max_packets and c >= max_packets:
            break
    return sorted(res)


def test_multi_worker_consistency():
    rm = RuleManager(rules=['example', 'secret'])
    engine = DPIEngine(rule_manager=rm)
    pcap = r'E:\\Packet_analyzer-main\\test_dpi.pcap'
    single = collect_results(engine, pcap, workers=1)
    multi = collect_results(engine, pcap, workers=2)
    assert single == multi
