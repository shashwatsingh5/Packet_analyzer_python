from typing import Optional


class FastPath:
    """Simple fast-path heuristics: quick SNI check and payload rule substring check.

    Designed to be cheap and avoid full parsing where possible.
    """

    def __init__(self) -> None:
        # could be extended with compiled patterns or prefix tables
        pass

    def quick_sni_check(self, payload: bytes) -> Optional[str]:
        # look for TLS record header and server_name extension quickly
        if not payload or len(payload) < 5:
            return None
        if payload[0] != 0x16:
            return None
        # naive scan for server_name extension bytes
        idx = payload.find(b"\x00\x00")
        if idx == -1:
            return None
        # attempt light decode near the extension
        try:
            # find possible ascii substring
            start = max(0, idx - 32)
            tail = payload[start: start + 256]
            for b in tail.split(b"\x00"):
                if len(b) >= 3 and all(32 <= ch < 127 for ch in b[:3]):
                    s = b.decode('utf-8', errors='ignore')
                    if '.' in s:
                        return s
        except Exception:
            return None
        return None

    def quick_rule_match(self, payload: bytes, rules: list[str]) -> Optional[str]:
        if not payload:
            return None
        try:
            text = payload.decode('utf-8', errors='ignore')
        except Exception:
            return None
        for r in rules:
            if r in text:
                return r
        return None
