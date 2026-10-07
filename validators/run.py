"""Shared runner: executes V1/V2/V3 on the corpus and merges them under the PREREG agreement rule."""
import hashlib
import json
import os
import tempfile
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
JARS_DIR = Path(os.environ.get("IPED3016_JARS", str(Path(tempfile.gettempdir()) / "iped3016_jars")))
PY = os.environ.get("IPED3016_PY", sys.executable)

# Maven Central artifacts; sha256 measured on download, sha1 checked against Central's .sha1
JARS = {
    "pdfbox-2.0.27.jar": "a25ad2a0be6b0bf9eb0e972abd09c34c0e797a3ce2a980d5ff035ff4cf078037",
    "fontbox-2.0.27.jar": "dc7429868aaf3d313c524b9aab846a405e89ca4927f35762ca4d1a60bce1d7f4",
    "commons-logging-1.2.jar": "daddea1ea0be0f56978ab3006b8ac92834afeefbd9b7e4e6316fca57df0fa636",
    "bcpkix-jdk15on-1.70.jar": "e5b9cb821df57f70b0593358e89c0e8d7266515da9d088af6c646f63d433c07c",
    "bcprov-jdk15on-1.70.jar": "8f3c20e3e2d565d26f33e8d4857a37d0d7f8ac39b62a7026496fcab1bdac30d4",
    "bcutil-jdk15on-1.70.jar": "52dc5551b0257666526c5095424567fed7dc7b00d2b1ba7bd52298411112b1d0",
}

DOC_FIELDS = ["loads", "file_size", "signature_field_count", "signature_count"]
SIG_FIELDS = [
    "field_name", "filter", "subfilter", "name", "reason", "location", "contact_info", "m",
    "byte_range", "covers_whole_file", "gap_is_contents_only", "cms_parsed", "digest_algorithm",
    "signature_algorithm", "cms_signing_time", "digest_match", "signature_valid", "crypto_ok",
    "cert_subject_der_sha256", "cert_subject_cn", "cert_issuer_der_sha256", "cert_issuer_cn",
    "cert_serial_hex", "cert_not_before", "cert_not_after", "cert_sha256_fingerprint",
    "cert_valid_at_m", "ts_present", "ts_gen_time", "ts_imprint_alg", "ts_imprint_hex",
    "ts_imprint_matches_signature", "extraction_status",
]
V2_ONLY = ["bc_signerinfo_verify", "bc_signerinfo_verify_error", "pdfbox_getContents_bytes", "error"]


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def classpath():
    for n, h in JARS.items():
        p = JARS_DIR / n
        if not p.exists():
            sys.exit(f"missing {p}: run tools/fetch_jars.py")
        if sha256(p) != h:
            sys.exit(f"sha256 mismatch for {p}")
    return ":".join(str(JARS_DIR / n) for n in JARS)


def run_v1(files):
    p = subprocess.run([PY, str(HERE / "v1_pyhanko.py"), *map(str, files)], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("V1 crashed:\n" + p.stderr[-2000:])
    return json.loads(p.stdout)


def run_v2(files, build_dir):
    cp = classpath()
    build_dir.mkdir(parents=True, exist_ok=True)
    c = subprocess.run(["javac", "-encoding", "UTF-8", "-cp", cp, "-d", str(build_dir),
                        str(HERE / "V2Probe.java")], capture_output=True, text=True)
    if c.returncode != 0:
        sys.exit("javac failed:\n" + c.stderr)
    p = subprocess.run(["java", "-Djava.util.logging.config.file=/dev/null", "-cp",
                        f"{build_dir}:{cp}", "V2Probe", *map(str, files)],
                       capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0:
        sys.exit("V2 crashed:\n" + p.stderr[-2000:])
    return json.loads(p.stdout)


def run_v3(files):
    p = subprocess.run([PY, str(HERE / "v3_openssl.py"), *map(str, files)], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("V3 crashed:\n" + p.stderr[-2000:])
    return json.loads(p.stdout)


def cmp(a, b):
    if a == b:
        return {"status": "agreed", "value": a}
    return {"status": "disagreement", "v1": a, "v2": b}


def merge_file(v1, v2, v3):
    out = {"document": {k: cmp(v1.get(k), v2.get(k)) for k in DOC_FIELDS}, "signatures": {}}
    s1, s2 = v1.get("signatures") or {}, v2.get("signatures") or {}
    v3 = dict(v3)
    for name in sorted(set(s1) | set(s2)):
        a, b = s1.get(name), s2.get(name)
        if a is None or b is None:
            out["signatures"][name] = {"_presence": cmp(a is not None, b is not None)}
            continue
        sig = {k: cmp(a.get(k), b.get(k)) for k in SIG_FIELDS}
        sig["_v2_only"] = {k: b.get(k) for k in V2_ONLY if k in b}
        brs = {",".join(map(str, x)) for x in (a.get("byte_range"), b.get("byte_range")) if x}
        sig["_v3_openssl"] = {k: v3.pop(k) for k in brs if k in v3}
        out["signatures"][name] = sig
    if v3:
        out["_v3_unmatched"] = v3
    out["_v1_errors"] = {k: v1[k] for k in ("error", "signatures_error") if k in v1}
    out["_v2_errors"] = {k: v2[k] for k in ("error",) if k in v2}

    def all_agreed(o):
        if isinstance(o, dict):
            if o.get("status") == "disagreement":
                return False
            return all(all_agreed(v) for k, v in o.items() if not k.startswith("_") or k == "_presence")
        return True
    out["all_fields_agreed"] = all_agreed({k: out[k] for k in ("document", "signatures")})
    return out


def measure(pdf_dir, build_dir):
    files = sorted(Path(pdf_dir).glob("*.pdf"))
    v1, v2, v3 = run_v1(files), run_v2(files, build_dir), run_v3(files)
    merged = {f.name: merge_file(v1[f.name], v2[f.name], v3[f.name]) for f in files}
    return merged, {"v1": v1, "v2": v2, "v3": v3}


def versions():
    import importlib.metadata as md
    jv = subprocess.run(["java", "-version"], capture_output=True, text=True).stderr.splitlines()[0]
    ov = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    return {
        "pyHanko": md.version("pyHanko"), "pyhanko-certvalidator": md.version("pyhanko-certvalidator"),
        "asn1crypto": md.version("asn1crypto"), "cryptography": md.version("cryptography"),
        "python": sys.version.split()[0], "java": jv, "openssl": ov, "jars_sha256": JARS,
    }
