from typing import List, Optional
import re
import time


class RuleManager:
    def __init__(self, rules: Optional[List[str]] = None, compile_regex: bool = True) -> None:
        self.rules = rules or []
        self.compile_regex = compile_regex
        self.compiled: List[re.Pattern] = []
        self.match_time_seconds: float = 0.0
        if self.rules:
            self._compile()

    def _compile(self) -> None:
        self.compiled = []
        for r in self.rules:
            try:
                if self.compile_regex:
                    p = re.compile(r)
                else:
                    p = re.compile(re.escape(r))
                self.compiled.append(p)
            except re.error:
                # fallback to escaped literal
                self.compiled.append(re.compile(re.escape(r)))

    def load_rules_from_file(self, path: str) -> None:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    self.rules.append(s)
        self._compile()

    def match(self, payload: bytes) -> Optional[str]:
        if not payload:
            return None
        start = time.perf_counter()
        try:
            text = payload.decode('utf-8', errors='ignore')
        except Exception:
            return None
        for i, p in enumerate(self.compiled):
            if p.search(text):
                self.match_time_seconds += time.perf_counter() - start
                return self.rules[i]
        self.match_time_seconds += time.perf_counter() - start
        return None

