import sys
sys.path.insert(0, r'E:\Packet_analyzer-main')
from py_packet_analyzer.sni_extractor import extract_sni_from_tls


def make_client_hello_with_sni(hostname: str) -> bytes:
    # Build a minimal TLS record with a ClientHello containing a server_name extension
    name_bytes = hostname.encode('utf-8')
    name_len = len(name_bytes)
    # server name entry: name_type(1)=0x00, name_len(2), name
    server_name = b'\x00' + name_len.to_bytes(2, 'big') + name_bytes
    # server_name_list length (2 bytes)
    sn_list = len(server_name).to_bytes(2, 'big') + server_name
    # extension: type 0x0000, length (2 bytes) + sn_list
    ext = b'\x00\x00' + (len(sn_list)).to_bytes(2, 'big') + sn_list
    # minimal ClientHello handshake: place the extensions immediately after the handshake header
    hs_len = len(ext).to_bytes(3, 'big')
    handshake = b'\x01' + hs_len + ext
    record_len = len(handshake).to_bytes(2, 'big')
    # TLS record header: type=0x16, version 0x03 0x03
    record = b'\x16\x03\x03' + record_len + handshake
    return record


def test_extract_sni_simple():
    payload = make_client_hello_with_sni('example.com')
    sni = extract_sni_from_tls(payload)
    assert sni == 'example.com'
