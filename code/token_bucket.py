from __future__ import annotations

BURST_S = 0.010
MIN_BURST_BYTES = 1522


def parse_rate(text: str) -> int:
    units = {"gbit": 1_000_000_000, "mbit": 1_000_000, "kbit": 1_000, "bit": 1}
    t = text.strip().lower()
    for unit, mult in units.items():
        if t.endswith(unit) and t[: -len(unit)].replace(".", "", 1).isdigit():
            return int(float(t[: -len(unit)]) * mult)
    raise ValueError(f"rate needs a number and a unit, e.g. 300mbit, not {text!r}")


class TokenBucket:
    __slots__ = ("rate_bps", "_bytes_per_ns", "capacity", "tokens", "last_ns")

    def __init__(self, rate_bps: int, *, now_ns: int = 0, burst_s: float = BURST_S) -> None:
        if rate_bps <= 0:
            raise ValueError("rate must be positive")
        self.rate_bps = rate_bps
        self._bytes_per_ns = rate_bps / 8 / 1e9
        self.capacity = max(rate_bps / 8 * burst_s, float(MIN_BURST_BYTES))
        self.tokens = self.capacity
        self.last_ns = now_ns

    def allow(self, nbytes: int, now_ns: int) -> bool:
        elapsed = now_ns - self.last_ns
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self._bytes_per_ns)
            self.last_ns = now_ns
        if self.tokens >= nbytes:
            self.tokens -= nbytes
            return True
        return False


def simulate(rate: str, offered_mbit: float, frame_len: int = 1518, seconds: float = 2.0) -> float:
    bucket = TokenBucket(parse_rate(rate))
    gap_ns = int(frame_len * 8 / (offered_mbit * 1e6) * 1e9)
    passed = 0
    t = 0
    end = int(seconds * 1e9)
    while t < end:
        if bucket.allow(frame_len, t):
            passed += frame_len
        t += gap_ns
    return passed * 8 / seconds / 1e6


if __name__ == "__main__":
    for offered in (50, 100, 500, 900):
        print(f"limit 100mbit, offered {offered:4d} Mbit/s -> passed {simulate('100mbit', offered):6.1f} Mbit/s")
