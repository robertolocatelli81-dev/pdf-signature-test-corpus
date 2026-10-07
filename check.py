#!/usr/bin/env python3
"""Re-measure the committed corpus with V1/V2/V3 and compare with EXPECTED.json.

  python3 check.py                     # exit 0 = every case matches EXPECTED.json, 1 = any difference
  python3 check.py --positive-control  # also prove the validators and the comparison CAN fail

Needs: pyHanko (see README), java + javac, openssl, jars from tools/fetch_jars.py.
Does not need keys/ or certs/ (only build.py does).
"""
import argparse
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "validators"))
import run as R  # noqa: E402

STRIP = ("file", "sha256", "description")


def compare(expected_cases, merged):
    """Return list of human-readable differences (empty = match)."""
    diffs = []
    by_file = {Path(c["file"]).name: (cid, c) for cid, c in expected_cases.items()}
    if set(by_file) != set(merged):
        diffs.append(f"file set differs: expected {sorted(by_file)} got {sorted(merged)}")
    for fname, m in merged.items():
        if fname not in by_file:
            continue
        cid, c = by_file[fname]
        exp = {k: v for k, v in c.items() if k not in STRIP}
        if exp != m:
            for k in sorted(set(exp) | set(m)):
                if exp.get(k) != m.get(k):
                    diffs.append(f"{cid} {fname}: '{k}' differs")
    return diffs


def check_hashes(expected_cases):
    bad = []
    for cid, c in expected_cases.items():
        h = hashlib.sha256((HERE / c["file"]).read_bytes()).hexdigest()
        if h != c["sha256"]:
            bad.append(f"{cid}: sha256 {h} != {c['sha256']}")
    return bad


def exit_code(diffs):
    """0 = corpus matches EXPECTED.json, 1 = at least one difference."""
    return 0 if not diffs else 1


def crypto_flags(v1, v2, v3, fname):
    s1 = (v1[fname].get("signatures") or {}).get("Signature1", {})
    s2 = (v2[fname].get("signatures") or {}).get("Signature1", {})
    o3 = [x["openssl_verify_ok"] for x in v3[fname].values()]
    return s1.get("crypto_ok"), s2.get("crypto_ok"), (o3[0] if o3 else None)


def positive_control(expected_cases, build_dir):
    ok = True
    a01 = HERE / expected_cases["A01"]["file"]
    with tempfile.TemporaryDirectory() as td:
        good = Path(td) / "pc_good.pdf"
        bad = Path(td) / "pc_bad.pdf"
        shutil.copy(a01, good)
        data = bytearray(a01.read_bytes())
        i = data.index(b"Synthetic test document")
        data[i] ^= 0x01  # one bit, inside the signed page content
        bad.write_bytes(bytes(data))
        files = [good, bad]
        v1, v2, v3 = R.run_v1(files), R.run_v2(files, build_dir), R.run_v3(files)
        g = crypto_flags(v1, v2, v3, good.name)
        b = crypto_flags(v1, v2, v3, bad.name)
        print(f"PC-validators: untouched copy (V1,V2,V3) crypto_ok = {g}; one flipped bit = {b}")
        for name, x, y in zip(("V1", "V2", "V3"), g, b):
            if not (x is True and y is False):
                print(f"  FAIL: {name} did not change its verdict")
                ok = False
    # the comparison itself must be able to fail
    tampered = copy.deepcopy(expected_cases)
    tampered["A01"]["signatures"]["Signature1"]["crypto_ok"]["value"] = False
    merged, _ = R.measure(HERE / "pdf", build_dir)
    d_true, d_false = compare(expected_cases, merged), compare(tampered, merged)
    print(f"PC-comparison: real EXPECTED -> {len(d_true)} differences; tampered EXPECTED -> {len(d_false)}")
    if d_true or not d_false:
        ok = False
        print("  FAIL: comparison cannot discriminate")
    # a wrong sha256 in EXPECTED must be reported, and a difference must give exit code 1
    bad_hash = copy.deepcopy(expected_cases)
    bad_hash["J01"]["sha256"] = "0" * 64
    n_bad = len(check_hashes(bad_hash))
    print(f"PC-hashes: tampered sha256 -> {n_bad} reported; exit codes: "
          f"no diff -> {exit_code([])}, one diff -> {exit_code(['x'])}")
    if n_bad != 1 or exit_code([]) != 0 or exit_code(["x"]) != 1:
        ok = False
        print("  FAIL: hash check or exit code cannot discriminate")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--positive-control", action="store_true")
    ap.add_argument("--build-dir", default=str(Path(tempfile.gettempdir()) / "iped3016_v2build"))
    a = ap.parse_args()
    exp = json.loads((HERE / "EXPECTED.json").read_text(encoding="utf-8"))
    cases = exp["cases"]
    bd = Path(a.build_dir)
    bad = check_hashes(cases)
    merged, _ = R.measure(HERE / "pdf", bd)
    diffs = bad + compare(cases, merged)
    n_agreed = sum(1 for m in merged.values() if m["all_fields_agreed"])
    print(f"cases: {len(merged)}; all-fields-agreed (V1==V2): {n_agreed}; differences vs EXPECTED: {len(diffs)}")
    for d in diffs:
        print("  " + d)
    rc = exit_code(diffs)
    if a.positive_control:
        rc = rc if positive_control(cases, bd) else 1
    print("RESULT:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
