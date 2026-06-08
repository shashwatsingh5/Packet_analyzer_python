from typing import Optional
import dpkt

from .types import PacketInfo


def parse_packet(ts: float, raw: bytes) -> Optional[PacketInfo]:
    try:
        eth = dpkt.ethernet.Ethernet(raw)
    except Exception:
        return None

    ip = None
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
    elif isinstance(eth.data, dpkt.ip6.IP6):
        ip = eth.data
    else:
        return None

    proto = ip.p
    src_ip = None
    dst_ip = None
    import socket
    try:
        # IPv4 (4 bytes)
        if len(ip.src) == 4 and len(ip.dst) == 4:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
        else:
            # IPv6 or others
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
    except Exception:
        return None

    src_port = 0
    dst_port = 0
    payload = b""

    if proto == dpkt.ip.IP_PROTO_TCP and hasattr(ip, 'data'):
        tcp = ip.data
        src_port = getattr(tcp, 'sport', 0)
        dst_port = getattr(tcp, 'dport', 0)
        payload = getattr(tcp, 'data', b"") or b""
    elif proto == dpkt.ip.IP_PROTO_UDP and hasattr(ip, 'data'):
        udp = ip.data
        src_port = getattr(udp, 'sport', 0)
        dst_port = getattr(udp, 'dport', 0)
        payload = getattr(udp, 'data', b"") or b""
    else:
        # Other protocols: expose raw payload if present
        payload = getattr(ip, 'data', b"") or b""

    return PacketInfo(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(src_port),
        dst_port=int(dst_port),
        proto=int(proto),
        payload=payload,
    )
