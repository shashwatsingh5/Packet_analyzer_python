import sys
sys.path.insert(0, r'E:\Packet_analyzer-main')
from py_packet_analyzer.connection_tracker import ConnectionTracker
from py_packet_analyzer.types import FlowKey


def test_connection_tracker_counts():
    ct = ConnectionTracker()
    f = FlowKey('1.1.1.1', 1000, '2.2.2.2', 80, 6)
    ct.update(f, 1.0)
    ct.update(f, 2.0)
    stats = ct.stats()
    assert f in stats
    assert stats[f].packets == 2
