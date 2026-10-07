#!/usr/bin/env python3
"""V3: third opinion on the CRYPTOGRAPHIC result only, with `openssl cms -verify -noverify`.
Byte-level extraction written here (regex on /ByteRange, hex token read at br[1]); no PDF library.
Output: {file: {"br0,br1,br2,br3": {"openssl_verify_ok": bool|None, "note": str}}}"""
import binascii
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BR = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


def der_len(b):
    """Total length of the first DER TLV in b (definite lengths only)."""
    if len(b) < 2:
        raise ValueError("short")
    n = b[1]
    if n < 0x80:
        return 2 + n
    k = n & 0x7F
    if k == 0 or k > 4 or len(b) < 2 + k:
        raise ValueError("bad length")
    return 2 + k + int.from_bytes(b[2:2 + k], "big")


def check(data, br):
    if data[br[1]:br[1] + 1] != b"<":
        return None, "no '<' at br[1]"
    end = data.find(b">", br[1])
    if end < 0:
        return None, "no '>' after br[1]"
    try:
        raw = binascii.unhexlify(data[br[1] + 1:end])
        raw = raw[:der_len(raw)]
    except Exception as e:  # noqa: BLE001
        return None, "contents not decodable: " + type(e).__name__
    if br[2] + br[3] > len(data):
        return None, "byte range beyond EOF"
    signed = data[br[0]:br[0] + br[1]] + data[br[2]:br[2] + br[3]]
    with tempfile.TemporaryDirectory() as td:
        s, c = Path(td, "sig.der"), Path(td, "content.bin")
        s.write_bytes(raw)
        c.write_bytes(signed)
        p = subprocess.run(["openssl", "cms", "-verify", "-noverify", "-binary", "-inform", "DER",
                            "-in", str(s), "-content", str(c), "-out", "/dev/null"],
                           capture_output=True, text=True)
    note = "" if p.returncode == 0 else (p.stderr.strip().splitlines() or [""])[0][:160]
    return p.returncode == 0, note


def analyse(path):
    data = Path(path).read_bytes()
    out = {}
    for m in BR.finditer(data):
        br = [int(x) for x in m.groups()]
        ok, note = check(data, br)
        out[",".join(map(str, br))] = {"openssl_verify_ok": ok, "note": note}
    return out


if __name__ == "__main__":
    print(json.dumps({Path(p).name: analyse(p) for p in sys.argv[1:]}, indent=1, sort_keys=True))
