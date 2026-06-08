from typing import Iterator, Tuple
import dpkt


class PcapReader:
    """Stream PCAP reader using dpkt.Reader. Yields (ts, raw_bytes)."""

    def iter_packets(self, path: str) -> Iterator[Tuple[float, bytes]]:
        with open(path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                yield float(ts), buf
