from typing import Optional


def extract_sni_from_tls(payload: bytes) -> Optional[str]:
    """Best-effort SNI extraction from a TLS ClientHello payload bytes.
    This function does not implement full TLS parsing, but extracts SNI
    if present in a typical ClientHello handshake record.
    """
    try:
        if len(payload) < 5:
            return None
        # TLS record header: type(1)=0x16, version(2), length(2)
        record_type = payload[0]
        if record_type != 0x16:
            return None
        # skip record header
        offset = 5
        # handshake header must be present
        if len(payload) < offset + 4:
            return None
        hs_type = payload[offset]
        # 1 == ClientHello
        if hs_type != 0x01:
            return None
        # skip handshake header (1 type + 3 length)
        # find extensions: search for server_name extension (type 0x0000)
        # start searching after the handshake header (offset + 4)
        ext_type = b"\x00\x00"
        idx = payload.find(ext_type, offset + 4)
        if idx == -1:
            return None
        # read extension length (2 bytes after ext_type)
        if idx + 4 > len(payload):
            return None
        ext_len = int.from_bytes(payload[idx+2:idx+4], 'big')
        # server_name list follows; find the server_name length and name
        # search for name type 0x00 (host_name) after ext header
        # simple scan for name length bytes
        pos = idx + 4
        # skip list length if present
        if pos + 2 > len(payload):
            return None
        # server_name_list_length
        sn_list_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + sn_list_len
        if end > len(payload):
            end = len(payload)
        # first server name entry
        if pos + 3 > end:
            return None
        name_type = payload[pos]
        if name_type != 0x00:
            return None
        name_len = int.from_bytes(payload[pos+1:pos+3], 'big')
        pos += 3
        if pos + name_len > end:
            return None
        sni = payload[pos:pos+name_len].decode('utf-8', errors='ignore')
        return sni
    except Exception:
        # structured parse failed; fall through to fallback scanner
        pass

    # Fallback: scan for printable ASCII substrings that look like a hostname
    try:
        import re
        printable = re.findall(rb"[A-Za-z0-9.-]{3,255}", payload)
        for p in printable:
            if b'.' in p:
                try:
                    return p.decode('utf-8', errors='ignore')
                except Exception:
                    continue
    except Exception:
        pass

    return None
