#!/usr/bin/env python3
"""Build the synthetic signed-PDF corpus for sepinf-inc/IPED#3016.

All keys/certificates are synthetic TEST material generated for this corpus (CC0-1.0).
No network access: the RFC 3161 timestamp comes from pyHanko's local DummyTimestamper.

Determinism: the original keys (not published, see README), fixed times (clock monkeypatched),
seeded os.urandom inside this process only. RSA PKCS#1 v1.5 signatures are deterministic;
ECDSA (M01) uses RFC 6979 deterministic nonces (set in patch_pyhanko_clock).

Usage:  python3 build.py [--out DIR] [--new-keys]
"""
import argparse
import asyncio
import binascii
import datetime as _dt
import hashlib
import os
import tempfile
import random
import sys
from io import BytesIO
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = 3016

# --- deterministic os.urandom for THIS process (PDF /ID, TSA nonce/serial) -----------------
_rng = random.Random(SEED)
_real_urandom = os.urandom


def _seeded_urandom(n):
    return _rng.randbytes(n)


from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

UTC = _dt.timezone.utc


def T(s):
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


# --- fixed clock -----------------------------------------------------------------------------
class _Clock:
    now = T("2026-01-15T10:00:00Z")


class FixedDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return _Clock.now


def patch_pyhanko_clock():
    import pyhanko.sign.signers.pdf_cms as pc
    import pyhanko.sign.signers.pdf_signer as ps
    import pyhanko.pdf_utils.metadata.info as mi
    import pyhanko.pdf_utils.metadata.xmp_xml as mx
    for mod in (ps, pc, mi, mx):
        mod.datetime = FixedDateTime
    # RFC 6979 deterministic ECDSA, so that M01 is reproducible too
    pc.ECDSA = lambda h: ec.ECDSA(h, deterministic_signing=True)


# --- keys ------------------------------------------------------------------------------------
KEYS = {
    "root": "rsa", "alice": "rsa", "bob": "rsa", "expired": "rsa",
    "nonascii": "rsa", "tsa": "rsa", "ecdsa": "ec",
}


def load_or_make_keys(new=False):
    kdir = HERE / "keys"
    if new:
        kdir.mkdir(exist_ok=True)
    out = {}
    for name, kind in KEYS.items():
        p = kdir / f"{name}.key.pem"
        if not new and not p.exists():
            sys.exit(f"build.py: {p} not found. The original test keys are not published (see README); "
                     "use --new-keys --out DIR to build a fresh, non-identical corpus.")
        if new:
            k = (rsa.generate_private_key(65537, 2048) if kind == "rsa"
                 else ec.generate_private_key(ec.SECP256R1()))
            p.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        out[name] = serialization.load_pem_private_key(p.read_bytes(), None)
    return out


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synthetic Test PKI (NOT REAL)"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def make_cert(subject_cn, pub, issuer_cn, issuer_key, serial, nb, na, ca=False, eku=None):
    b = (x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
         .public_key(pub).serial_number(serial).not_valid_before(T(nb)).not_valid_after(T(na))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
    else:
        b = b.add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


ROOT_CN = "Synthetic Test Root CA"
SUBJECTS = {
    "alice": ("Alice Example (TEST)", 0x1001, "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
    "bob": ("Bob Example (TEST)", 0x1002, "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
    "expired": ("Expired Signer (TEST)", 0x1003, "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
    "nonascii": ("José Ñandú Łukasz Øre 测试", 0x1004, "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
    "tsa": ("Synthetic Local TSA (TEST)", 0x1005, "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
    "ecdsa": ("Carol ECDSA (TEST)", 0x1006, "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
}


def build_pki(keys):
    cdir = HERE / "certs"
    cdir.mkdir(exist_ok=True)
    certs = {}
    # the root is self-signed but deliberately also covers 2020 so that H01 is "expired leaf", not "bad chain"
    certs["root"] = make_cert(ROOT_CN, keys["root"].public_key(), ROOT_CN, keys["root"], 0x01,
                              "2019-01-01T00:00:00Z", "2035-01-01T00:00:00Z", ca=True)
    for k, (cn, serial, nb, na) in SUBJECTS.items():
        eku = [ExtendedKeyUsageOID.TIME_STAMPING] if k == "tsa" else None
        certs[k] = make_cert(cn, keys[k].public_key(), ROOT_CN, keys["root"], serial, nb, na, eku=eku)
    for k, c in certs.items():
        (cdir / f"{k}.cert.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return certs


# --- base PDF (hand-written, deterministic) --------------------------------------------------
def base_pdf():
    content = (b"BT /F1 24 Tf 72 720 Td (Synthetic test document) Tj ET\n"
               b"BT /F1 12 Tf 72 690 Td (Corpus for IPED issue 3016 - CC0-1.0 - no real data) Tj ET\n")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Producer (iped_3016_corpus build.py) /CreationDate (D:20260115090000Z) >>",
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs:
        out += b"%010d 00000 n \n" % off
    out += (b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R "
            b"/ID [<00112233445566778899aabbccddeeff> <00112233445566778899aabbccddeeff>] >>\n"
            b"startxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref))
    return bytes(out)


# --- signing helpers -------------------------------------------------------------------------
def to_asn1(cert=None, key=None):
    from asn1crypto import keys as ak, x509 as ax
    if cert is not None:
        return ax.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    return ak.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER,
                                                    serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))


def signer_for(who, keys, certs):
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore
    return signers.SimpleSigner(
        signing_cert=to_asn1(cert=certs[who]), signing_key=to_asn1(key=keys[who]),
        cert_registry=SimpleCertificateStore.from_certs([to_asn1(cert=certs["root"])]))


def sign(data, who, keys, certs, when, field="Signature1", subfilter="pades", md="sha256",
         name=None, reason="Synthetic test signature", location="Nowhere (test)",
         contact="test@example.invalid", tsa_time=None):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers
    _Clock.now = T(when)
    sf = {"pades": fields.SigSeedSubFilter.PADES,
          "adbe": fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED}[subfilter]
    meta = signers.PdfSignatureMetadata(
        field_name=field, md_algorithm=md, subfilter=sf, name=name or SUBJECTS[who][0],
        reason=reason, location=location, contact_info=contact)
    ts = None
    if tsa_time:
        from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper as DummyTimestamper
        ts = DummyTimestamper(tsa_cert=to_asn1(cert=certs["tsa"]), tsa_key=to_asn1(key=keys["tsa"]),
                              certs_to_embed=[to_asn1(cert=certs["root"])], fixed_dt=T(tsa_time))
    w = IncrementalPdfFileWriter(BytesIO(data))
    out = signers.PdfSigner(meta, signer=signer_for(who, keys, certs), timestamper=ts).sign_pdf(w)
    return out.getvalue()


def contents_span(data, occurrence=0):
    """(start of '<', end after '>') of the /Contents hex string of the n-th /ByteRange."""
    import re
    ms = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data))
    m = ms[occurrence]
    br = [int(x) for x in m.groups()]
    return m, br


def craft_wider_gap(data, keys, certs, K=24):
    """E02: rewrite /ByteRange so the gap excludes K bytes after /Contents, then sign those ranges."""
    m, br = contents_span(data)
    nbr = [0, br[1], br[2] + K, br[3] - K]
    old = m.group(0)
    new = b"/ByteRange [%d %d %d %d]" % tuple(nbr)
    assert len(new) <= len(old)
    new = new[:-1] + b" " * (len(old) - len(new)) + b"]"
    d = bytearray(data)
    d[m.start():m.end()] = new
    signed = bytes(d[0:nbr[1]]) + bytes(d[nbr[2]:nbr[2] + nbr[3]])
    digest = hashlib.sha256(signed).digest()
    from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
    _Clock.now = T("2026-01-15T10:00:00Z")
    s = signer_for("alice", keys, certs)
    ci = asyncio.run(s.async_sign(digest, "sha256", use_pades=True,
                                  signed_attr_settings=PdfCMSSignedAttributes()))
    hexsig = binascii.hexlify(ci.dump())
    room = br[2] - br[1] - 2
    assert len(hexsig) <= room
    d[br[1] + 1:br[2] - 1] = hexsig + b"0" * (room - len(hexsig))
    return bytes(d)


def flip_sigvalue(data):
    """G01: change one hex digit in the middle of the RSA signature value inside /Contents."""
    from asn1crypto import cms
    _, br = contents_span(data)
    raw = binascii.unhexlify(data[br[1] + 1:br[2] - 1])
    ci = cms.ContentInfo.load(raw, strict=False)
    sigval = ci["content"]["signer_infos"][0]["signature"].native
    off = raw.find(sigval)
    assert off > 0 and raw.count(sigval) == 1
    pos = br[1] + 1 + 2 * (off + len(sigval) // 2)
    d = bytearray(data)
    d[pos] = ord("1") if d[pos] != ord("1") else ord("2")
    return bytes(d)


def break_der(data):
    _, br = contents_span(data)
    d = bytearray(data)
    assert d[br[1] + 1:br[1] + 3] == b"30"
    d[br[1] + 1:br[1] + 3] = b"31"
    return bytes(d)


def add_text_after_signing(data):
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    w = IncrementalPdfFileWriter(BytesIO(data))
    page_ref = w.root["/Pages"].raw_get("/Kids")[0]
    page = page_ref.get_object()
    stream = generic.StreamObject(stream_data=b"BT /F1 18 Tf 72 600 Td (TEXT ADDED AFTER SIGNING) Tj ET\n")
    sref = w.add_object(stream)
    page["/Contents"] = generic.ArrayObject([page.raw_get("/Contents"), sref])
    w.update_container(page)
    out = BytesIO()
    w.write(out)
    return out.getvalue()


def empty_sig_field(data):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields
    w = IncrementalPdfFileWriter(BytesIO(data))
    fields.append_signature_field(w, fields.SigFieldSpec(sig_field_name="Signature1"))
    out = BytesIO()
    w.write(out)
    return out.getvalue()


CASES = [
    ("A01", "pades_bb_single", "PAdES B-B (ETSI.CAdES.detached), RSA-2048/SHA-256, all dictionary fields set"),
    ("A02", "pkcs7_detached_single", "adbe.pkcs7.detached; CMS signingTime attribute present and equal to /M"),
    ("B01", "pades_bt", "PAdES B-T: RFC 3161 token from a LOCAL test TSA (genTime fixed)"),
    ("C01", "two_signatures", "Two successive signatures (Alice, then Bob incrementally)"),
    ("D01", "incremental_after_signing", "A01 followed by an incremental update that adds visible page text"),
    ("E01", "trailing_bytes", "A01 with bytes appended after %%EOF (no new revision)"),
    ("E02", "byterange_gap_wider", "Crafted /ByteRange: gap excludes 24 bytes beyond /Contents; CMS signed over those ranges"),
    ("F01", "signed_content_byte_flipped", "A01 with one byte of the signed page content changed"),
    ("G01", "contents_sigvalue_flipped", "A01 with one hex digit of the RSA signature value inside /Contents changed"),
    ("G02", "contents_der_broken", "A01 with the first CMS DER byte changed 0x30->0x31 (CMS unparsable)"),
    ("H01", "expired_cert", "Signer certificate valid 2020-01-01..2021-01-01, /M = 2026-01-15"),
    ("I01", "non_ascii_signer", "Signer CN and /Name with non-ASCII characters; non-ASCII /Reason"),
    ("J01", "unsigned", "Plain unsigned PDF"),
    ("K01", "truncated", "A01 truncated to half its length"),
    ("K02", "not_a_pdf", "%PDF-1.7 header followed by 4096 seeded random bytes"),
    ("L01", "empty_signature_field", "Unsigned (empty) signature field, no /V"),
    ("M01", "ecdsa_p256_sha384", "PAdES B-B with ECDSA P-256 and SHA-384"),
]


def build(outdir: Path, new_keys=False):
    keys = load_or_make_keys(new_keys)  # key generation uses the library RNG, not os.urandom
    os.urandom = _seeded_urandom
    patch_pyhanko_clock()
    certs = build_pki(keys)
    outdir.mkdir(parents=True, exist_ok=True)
    base = base_pdf()
    f = {}
    f["J01"] = base
    f["A01"] = sign(base, "alice", keys, certs, "2026-01-15T10:00:00Z")
    f["A02"] = sign(base, "alice", keys, certs, "2026-01-15T11:00:00Z", subfilter="adbe")
    f["B01"] = sign(base, "alice", keys, certs, "2026-01-15T12:00:00Z", tsa_time="2026-01-15T12:00:05Z")
    c1 = sign(base, "alice", keys, certs, "2026-01-16T09:00:00Z", field="Signature1")
    f["C01"] = sign(c1, "bob", keys, certs, "2026-01-16T10:00:00Z", field="Signature2")
    f["D01"] = add_text_after_signing(f["A01"])
    f["E01"] = f["A01"] + b"\n% appended after signing, no new revision\n" + b"X" * 64 + b"\n"
    f["E02"] = craft_wider_gap(f["A01"], keys, certs)
    a = f["A01"]
    i = a.index(b"(Synthetic test document)")
    f["F01"] = a[:i + 1] + b"T" + a[i + 2:]
    f["G01"] = flip_sigvalue(a)
    f["G02"] = break_der(a)
    f["H01"] = sign(base, "expired", keys, certs, "2026-01-15T10:00:00Z")
    f["I01"] = sign(base, "nonascii", keys, certs, "2026-01-15T10:00:00Z",
                    reason="Conformità – verificação – Prüfung", location="São Paulo / Zürich")
    f["K01"] = a[:len(a) // 2]
    f["K02"] = b"%PDF-1.7\n" + random.Random(SEED + 1).randbytes(4096)
    f["L01"] = empty_sig_field(base)
    f["M01"] = sign(base, "ecdsa", keys, certs, "2026-01-15T10:00:00Z", md="sha384")
    paths = {}
    for cid, fname, _ in CASES:
        p = outdir / f"{cid}_{fname}.pdf"
        p.write_bytes(f[cid])
        paths[cid] = p
    return paths


def write_expected():
    """Run V1/V2/V3 on pdf/ and write EXPECTED.json, measurements/, SHA256SUMS."""
    import json
    sys.path.insert(0, str(HERE / "validators"))
    import run as R
    merged, raw = R.measure(HERE / "pdf", Path(tempfile.gettempdir()) / "iped3016_v2build")
    (HERE / "measurements").mkdir(exist_ok=True)
    for k, v in raw.items():
        (HERE / "measurements" / f"raw_{k}.json").write_text(
            json.dumps(v, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    desc = {f"{cid}_{fn}.pdf": (cid, d) for cid, fn, d in CASES}
    cases = {}
    for fname, m in merged.items():
        cid, d = desc[fname]
        cases[cid] = {"file": "pdf/" + fname, "sha256": R.sha256(HERE / "pdf" / fname),
                      "description": d, **m}
    # PREREG.sha256 is not in the public repository: keep the value already in EXPECTED.json
    pfile = HERE / "PREREG.sha256"
    prereg = (pfile.read_text().split()[0] if pfile.exists()
              else json.loads((HERE / "EXPECTED.json").read_text(encoding="utf-8"))["prereg_sha256"])
    exp = {"corpus": "iped_3016_corpus", "license": "CC0-1.0", "prereg_sha256": prereg,
           "agreement_rule": "field agreed iff V1 (pyHanko) == V2 (PDFBox 2.0.27 + BC 1.70) after "
                             "normalisation; otherwise both values recorded, no choice made; "
                             "V3 (openssl cms -verify -noverify) recorded, not used as tie-break",
           "versions": R.versions(), "cases": cases}
    (HERE / "EXPECTED.json").write_text(json.dumps(exp, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                        encoding="utf-8")
    write_sums()


def write_sums():
    import hashlib as _h
    lines = []
    for p in sorted(HERE.rglob("*")):
        rel = p.relative_to(HERE).as_posix()
        internal = (rel == "SHA256SUMS" or "__pycache__" in rel
                    or rel.split("/")[0] in (".git", "keys", "venv"))
        if p.is_file() and not internal:
            lines.append(f"{_h.sha256(p.read_bytes()).hexdigest()}  {rel}")
    (HERE / "SHA256SUMS").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "pdf"))
    ap.add_argument("--no-measure", action="store_true", help="only build the PDFs")
    ap.add_argument("--new-keys", action="store_true", help="regenerate keys (breaks reproducibility)")
    ap.add_argument("--sums-only", action="store_true", help="only rewrite SHA256SUMS")
    a = ap.parse_args()
    if a.sums_only:
        write_sums()
        sys.exit(0)
    ap_out = Path(a.out)
    ps = build(ap_out, a.new_keys)
    for cid, p in ps.items():
        print(cid, hashlib.sha256(p.read_bytes()).hexdigest(), p.name)
    if ap_out.resolve() == (HERE / "pdf").resolve() and not a.no_measure:
        os.urandom = _real_urandom
        write_expected()
    sys.exit(0)
