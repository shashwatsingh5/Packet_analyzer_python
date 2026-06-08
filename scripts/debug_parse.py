import sys
from py_packet_analyzer.pcap_reader import PcapReader
from py_packet_analyzer.packet_parser import parse_packet

def main(pcap_path: str) -> None:
    pr = PcapReader()
    for i, (ts, buf) in enumerate(pr.iter_packets(pcap_path)):
        print(f'packet {i} ts={ts} len={len(buf)}')
        pkt = parse_packet(ts, buf)
        print('parsed=', pkt)
        if i >= 5:
            break


if __name__ == '__main__':
    main(sys.argv[1])
