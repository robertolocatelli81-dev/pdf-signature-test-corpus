# Synthetic signed-PDF test corpus (for sepinf-inc/IPED#3016)

17 small PDFs (14 signatures) for testing a parser that extracts PDF digital-signature metadata,
such as the `DigitalSignatureParser` proposed in sepinf-inc/IPED#3016. Each file comes with expected values
measured by two independent validators.

**Everything here is synthetic.** All keys, certificates and documents were generated for this corpus.
`certs/` holds the synthetic test certificates (a test root CA, five signers and a test TSA). The
matching private keys are not published: they are not needed to use or re-check the corpus (see
[Rebuilding](#rebuilding)). No real person, organisation or
document is involved. Nothing in this corpus says anything about legal validity.

License: **CC0-1.0** (public domain dedication) for the PDFs, certificates, scripts and expected
values. See `LICENSE`.

## Cases

| id | file | what it exercises |
|---|---|---|
| A01 | pades_bb_single | PAdES B-B (ETSI.CAdES.detached), RSA-2048/SHA-256, /Name /Reason /Location /ContactInfo set |
| A02 | pkcs7_detached_single | adbe.pkcs7.detached; CMS signingTime attribute present and equal to /M |
| B01 | pades_bt | PAdES B-T: RFC 3161 token from a local test TSA (genTime fixed) |
| C01 | two_signatures | two successive signatures; the first one no longer covers the whole file |
| D01 | incremental_after_signing | incremental update adding visible page text after signing |
| E01 | trailing_bytes | bytes appended after %%EOF, no new revision |
| E02 | byterange_gap_wider | /ByteRange gap excludes 24 bytes beyond /Contents; CMS signed over exactly those ranges |
| F01 | signed_content_byte_flipped | one signed byte changed: messageDigest no longer matches |
| G01 | contents_sigvalue_flipped | one hex digit of the RSA signature value changed: CMS parses, signature invalid |
| G02 | contents_der_broken | first CMS byte 0x30→0x31: CMS cannot be parsed |
| H01 | expired_cert | signer certificate expired (2021) before /M (2026); signature itself valid |
| I01 | non_ascii_signer | non-ASCII CN, /Name, /Reason, /Location (UTF-8 / UTF-16BE) |
| J01 | unsigned | plain PDF |
| K01 | truncated | A01 cut at half its length |
| K02 | not_a_pdf | `%PDF-1.7` header + random bytes |
| L01 | empty_signature_field | signature field with no /V |
| M01 | ecdsa_p256_sha384 | ECDSA P-256 with SHA-384 |

## Expected values

`EXPECTED.json` has, per case: file, sha256, description, document fields (`loads`,
`signature_field_count`, `signature_count`, `file_size`) and, per signature, 33 fields: dictionary
entries, /M, /ByteRange, whole-file coverage, whether the /ByteRange gap is exactly the /Contents
string, digest and signature algorithm OIDs, CMS signingTime, `digest_match`, `signature_valid`,
`crypto_ok`, signer certificate (subject/issuer CN and DER sha256, serial, validity, sha256
fingerprint), whether /M lies inside the certificate validity, RFC 3161 token fields (genTime,
messageImprint), extraction status. The top-level `prereg_sha256` is the sha256 of the pre-registration
written before the corpus was generated; that document is not part of this repository.

Each field is either `{"status": "agreed", "value": ...}` or `{"status": "disagreement", "v1": ..., "v2": ...}`.
Disagreements are kept as they are; no value was chosen.

- **V1**: pyHanko 0.37.0 (Python).
- **V2**: PDFBox 2.0.27 + BouncyCastle jdk15on 1.70 (the versions in IPED's poms at master
  `eeb340f5`), via `validators/V2Probe.java`.
- **V3**: `openssl cms -verify -noverify` on the CMS blob and the /ByteRange bytes. It is recorded
  next to `crypto_ok` and is not used to break ties.

The PDFs were signed with pyHanko, so V1 shares a library with the generator. V2 shares no code
with either.

Measured on 2026-10-07: 530 field values were compared. 527 agree and 3 disagree, all three in K01
(pyHanko does not load the truncated file; PDFBox recovers it, sees 1 field and 0 signatures).
V3 matches the agreed `crypto_ok` for all 14 signatures. Other measured observations:
- Only A02 carries a CMS signingTime attribute in the signer's SignerInfo. In the PAdES files the only signer-declared signing time is /M. In B01 the RFC 3161 token is itself a CMS SignedData, and the TSA's SignerInfo inside it carries a signingTime equal to genTime.
- In E02, PDFBox 2.0.27 `PDSignature.getContents(byte[])` throws an IOException
  (`Invalid hex string`), because it decodes the whole /ByteRange gap. V2 falls back to the /Contents string and
  records the failure in `_v2_only.pdfbox_getContents_bytes`.
- In F01, BouncyCastle `SignerInformation.verify` throws `CMSSignerDigestMismatchException`
  instead of returning false.

## Commands

```
python3 -m venv venv && venv/bin/pip install pyHanko==0.37.0 pyhanko-certvalidator==0.32.1
venv/bin/python tools/fetch_jars.py           # Maven Central, sha1 + pinned sha256 checked
venv/bin/python check.py --positive-control   # exit 0 = matches EXPECTED.json
```

`check.py` re-runs V1, V2 and V3 and compares the results with `EXPECTED.json`. It needs `pdf/`,
`EXPECTED.json`, `validators/` and the jars; it does not read `keys/` or `certs/` (trust anchors for V1 are
the certificates embedded in each CMS).
`--positive-control` also checks that flipping one bit of A01 changes `crypto_ok` in all three
validators, that a wrong EXPECTED entry (value or sha256) is reported, and that a difference gives exit
code 1. Tested
with Python 3.11.2, OpenJDK 17.0.20.1 and OpenSSL 3.0.22. Jar location: `IPED3016_JARS`
(default: `iped3016_jars` in the system temporary directory; `tools/fetch_jars.py` downloads them there).

## Using the files in IPED's tests

IPED keeps parser test files in `iped-parsers/iped-parsers-impl/src/test/resources/test-files/`,
and its own PDFs there are named `test_<name>.pdf` (for example `test_pdfImages.pdf`). The 17 PDFs are
about 150 KB together (about 210 KB with `EXPECTED.json`), so they can be copied there as they are, or
renamed to that pattern. `EXPECTED.json` is keyed by case id (`A01` to `M01`), and each case records the
file's sha256, so a renamed copy can still be matched to its expected values. To pin a version of the
corpus, use the tag `v1.0.0` or the commit hash.

## Rebuilding

`build.py` generated the corpus. With the original keys, rebuilding reproduced all 17 PDFs byte for
byte (fixed clock, seeded randomness, RFC 6979 ECDSA). Those keys are not in this repository, so
`build.py` stops if the key files are missing. To make a fresh corpus with the same cases, run it in a
separate copy of the repository:

```
venv/bin/python build.py --new-keys --out /some/other/dir
```

It writes new keys to `keys/` and new certificates to `certs/` of that copy and the PDFs to `--out`.
All files except J01, K02 and L01 will differ from the published ones (new keys, new
certificates, new signatures), so compare them with your own measurements, not with `EXPECTED.json`.
J01, K02 and L01 do not depend on the keys and come out identical. The original keys are available
on request.

## Not covered

Trust chains, revocation (OCSP/CRL), full PAdES baseline or LTV validation, validation of the
timestamp token's own signature or of its TSA, DocMDP/FieldMDP permissions, encrypted PDFs,
CAdES/XAdES outside PDF, object streams/compressed xref, and PDFs from real-world signing software.
This is a small synthetic corpus, not a conformance suite.
