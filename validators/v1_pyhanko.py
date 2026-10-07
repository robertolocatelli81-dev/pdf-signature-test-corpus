#!/usr/bin/env python3
"""V1: pyHanko-based extractor. Prints one JSON object {file: result} for the PDFs given.
Verification is OFFLINE, against the embedded signer certificate only (trust is not evaluated:
the synthetic root is passed only so that pyHanko runs its integrity/validity checks)."""
import hashlib
import json
import sys
import unicodedata
from pathlib import Path


# Errors that mean "this harness is broken", never "this PDF is bad": they must crash, not
# be reported as extraction_status FAILED.
HARNESS_ERRORS = (ImportError, NameError, AttributeError, TypeError, KeyError)


def iso(dt):
    if dt is None:
        return None
    import datetime as d
    return dt.astimezone(d.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def s(v):
    if v is None:
        return None
    return unicodedata.normalize("NFC", str(v))


def cert_fields(c):
    out = {}
    if c is None:
        return out
    subj, iss = c.subject, c.issuer
    out["cert_subject_der_sha256"] = hashlib.sha256(subj.dump()).hexdigest()
    out["cert_subject_cn"] = s(subj.native.get("common_name"))
    out["cert_issuer_der_sha256"] = hashlib.sha256(iss.dump()).hexdigest()
    out["cert_issuer_cn"] = s(iss.native.get("common_name"))
    out["cert_serial_hex"] = format(c.serial_number, "x")
    v = c["tbs_certificate"]["validity"]
    out["cert_not_before"] = iso(v["not_before"].native)
    out["cert_not_after"] = iso(v["not_after"].native)
    out["cert_sha256_fingerprint"] = hashlib.sha256(c.dump()).hexdigest()
    return out


def pdf_date(v):
    if v is None:
        return None
    from pyhanko.pdf_utils.generic import parse_pdf_date
    try:
        return iso(parse_pdf_date(str(v)))
    except HARNESS_ERRORS:
        raise
    except Exception as e:  # noqa: BLE001
        return "UNPARSABLE:" + type(e).__name__


def dict_fields(field_name, so, data):
    r = {"field_name": s(field_name)}
    for k, key in (("filter", "/Filter"), ("subfilter", "/SubFilter")):
        r[k] = str(so[key])[1:] if key in so else None
    for k, key in (("name", "/Name"), ("reason", "/Reason"), ("location", "/Location"),
                   ("contact_info", "/ContactInfo")):
        r[k] = s(so[key]) if key in so else None
    r["m"] = pdf_date(so.get("/M"))
    br = [int(x) for x in so["/ByteRange"]]
    r["byte_range"] = br
    r["covers_whole_file"] = br[0] == 0 and br[2] + br[3] == len(data)
    raw_contents = so.raw_get("/Contents")
    r["gap_is_contents_only"] = (br[2] - br[1]) == 2 * len(bytes(raw_contents)) + 2
    return r


def one_sig(es, data):
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    r = dict_fields(es.field_name, es.sig_object, data)
    try:
        si = es.signer_info
        sd = es.signed_data
        r["cms_parsed"] = True
    except HARNESS_ERRORS:
        raise
    except Exception as e:  # noqa: BLE001
        r["cms_parsed"] = False
        r["extraction_status"] = "FAILED"
        r["error"] = type(e).__name__
        return r
    r["digest_algorithm"] = si["digest_algorithm"]["algorithm"].dotted
    r["signature_algorithm"] = si["signature_algorithm"]["algorithm"].dotted
    st = None
    if si["signed_attrs"].native is not None:
        for a in si["signed_attrs"]:
            if a["type"].native == "signing_time":
                st = iso(a["values"][0].native)
    r["cms_signing_time"] = st
    cert = es.signer_cert
    r.update(cert_fields(cert))
    try:
        # trust anchors = the certificates embedded in the CMS itself (signer + any others, e.g. the
        # synthetic root); nothing is read from certs/, so check.py works without keys/ or certs/.
        roots = [cert] + [c for c in es.other_embedded_certs if c.sha256 != cert.sha256]
        vc = ValidationContext(trust_roots=roots, allow_fetching=False)
        st_ = validate_pdf_signature(es, signer_validation_context=vc, skip_diff=True)
        r["digest_match"] = bool(st_.intact)
        r["signature_valid"] = bool(st_.valid)
    except HARNESS_ERRORS:
        raise
    except Exception as e:  # noqa: BLE001
        r["digest_match"] = None
        r["signature_valid"] = None
        r["validation_error"] = type(e).__name__ + ": " + str(e)[:200]
    r["crypto_ok"] = bool(r["digest_match"] and r["signature_valid"])
    if cert is not None and r["m"] and not r["m"].startswith("UNPARSABLE"):
        r["cert_valid_at_m"] = r["cert_not_before"] <= r["m"] <= r["cert_not_after"]
    else:
        r["cert_valid_at_m"] = None
    # RFC 3161 signature timestamp (unsigned attribute) — recorded for future work
    r["ts_present"] = False
    ua = si["unsigned_attrs"]
    if ua.native is not None:
        for a in ua:
            if a["type"].native == "signature_time_stamp_token":
                tok = a["values"][0]
                tst = tok["content"]["encap_content_info"]["content"].parsed
                mi = tst["message_imprint"]
                r["ts_present"] = True
                r["ts_gen_time"] = iso(tst["gen_time"].native)
                r["ts_imprint_alg"] = mi["hash_algorithm"]["algorithm"].dotted
                r["ts_imprint_hex"] = mi["hashed_message"].native.hex()
                h = hashlib.new(mi["hash_algorithm"]["algorithm"].native, si["signature"].native)
                r["ts_imprint_matches_signature"] = h.hexdigest() == r["ts_imprint_hex"]
    r["extraction_status"] = "OK" if cert is not None else "FAILED"
    return r


def analyse(path):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.fields import enumerate_sig_fields
    data = Path(path).read_bytes()
    res = {"file_size": len(data)}
    try:
        rd = PdfFileReader(__import__("io").BytesIO(data), strict=False)
        fields = list(enumerate_sig_fields(rd, filled_status=None))
        res["loads"] = True
    except HARNESS_ERRORS:
        raise
    except Exception as e:  # noqa: BLE001
        res["loads"] = False
        res["error"] = type(e).__name__
        return res
    res["signature_field_count"] = len(fields)
    res["signature_count"] = sum(1 for _, v, _ in fields if v is not None)
    sigs = {}
    try:
        embedded = rd.embedded_signatures
    except HARNESS_ERRORS:
        raise
    except Exception as e:  # noqa: BLE001
        # pyHanko refuses to build ANY EmbeddedPdfSignature if one CMS blob is unparsable.
        # Fall back to the signature dictionaries themselves (still read by pyHanko).
        res["signatures_error"] = type(e).__name__ + ": " + str(e)[:200]
        for fname, v, _ in fields:
            if v is None:
                continue
            r = dict_fields(fname, v.get_object() if hasattr(v, "get_object") else v, data)
            r.update({"cms_parsed": False, "extraction_status": "FAILED", "crypto_ok": False})
            sigs[fname] = r
        embedded = []
    for es in embedded:
        sigs[es.field_name] = one_sig(es, data)
    res["signatures"] = sigs
    return res


def main(argv):
    out = {Path(p).name: analyse(p) for p in argv}
    print(json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1:])
