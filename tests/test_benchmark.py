import sys
sys.path.insert(0, r'E:\Packet_analyzer-main')

from py_packet_analyzer.benchmark import benchmark


def test_benchmark_metrics():
    metrics = benchmark(
        r'E:\\Packet_analyzer-main\\test_dpi.pcap',
        workers=1,
        runs=1,
        max_packets=10,
    )
    assert metrics['packets'] == 10
    assert metrics['elapsed_seconds'] >= 0
    assert metrics['throughput_pps'] >= 0
    assert metrics['memory_rss_bytes'] > 0
