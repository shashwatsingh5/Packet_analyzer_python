import sys
import socket
sys.path.insert(0, r'E:\Packet_analyzer-main')
import dpkt
from py_packet_analyzer.packet_parser import parse_packet


def build_tcp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    ip = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip))
    ip.p = dpkt.ip.IP_PROTO_TCP
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, data=payload)
    ip.data = tcp
    eth = dpkt.ethernet.Ethernet()
    eth.data = ip
    return bytes(eth)


def test_parse_tcp_packet():
    raw = build_tcp_frame('192.168.1.100', '10.0.0.1', 12345, 80, b'hello')
    pkt = parse_packet(1.0, raw)
    assert pkt is not None
    assert pkt.src_ip == '192.168.1.100'
    assert pkt.dst_ip == '10.0.0.1'
    assert pkt.src_port == 12345
    assert pkt.dst_port == 80
    assert pkt.payload.startswith(b'hello')
