from __future__ import annotations

import zlib

FCS_LEN = 4


def compute_fcs(frame_without_fcs: bytes) -> bytes:
    return (zlib.crc32(frame_without_fcs) & 0xFFFFFFFF).to_bytes(FCS_LEN, "little")


def append_fcs(frame: bytes) -> bytes:
    return frame + compute_fcs(frame)


def fcs_ok(frame_with_fcs: bytes) -> bool:
    if len(frame_with_fcs) <= FCS_LEN:
        return False
    mv = memoryview(frame_with_fcs)
    return (zlib.crc32(mv[:-FCS_LEN]) & 0xFFFFFFFF) == int.from_bytes(mv[-FCS_LEN:], "little")


def strip_fcs(frame_with_fcs: bytes) -> bytes:
    return frame_with_fcs[:-FCS_LEN]


if __name__ == "__main__":
    frame = bytes.fromhex("e454e82d8fca" "40c2ba50b1b7" "0800") + bytes(46)
    good = append_fcs(frame)
    bad = bytearray(good)
    bad[20] ^= 0x01
    print(f"good frame: {len(good)} bytes, FCS {good[-4:].hex()} -> ok={fcs_ok(good)}")
    print(f"bad frame:  {len(bad)} bytes, FCS {bad[-4:].hex()} -> ok={fcs_ok(bytes(bad))}  (pyfw drops it: reason crc)")
