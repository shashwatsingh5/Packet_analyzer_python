import sys
sys.path.insert(0, r'E:\Packet_analyzer-main')
from py_packet_analyzer.rule_manager import RuleManager


def test_rule_match():
    rm = RuleManager(rules=['secret', 'password'])
    assert rm.match(b'this contains secret value') == 'secret'
    assert rm.match(b'no match here') is None
