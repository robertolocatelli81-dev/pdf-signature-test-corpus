// V2: independent extractor on the stack IPED uses (PDFBox 2.0.27 + BouncyCastle jdk15on 1.70).
// Prints {file: result} JSON. Offline; verification only against the certificate embedded in the CMS.
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

public class V2Probe {
    static String iso(Date d) {
        if (d == null) return null;
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(d);
    }
    static String nfc(String s) { return s == null ? null : Normalizer.normalize(s, Normalizer.Form.NFC); }
    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static String sha256(byte[] b) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(b)); }

    // --- minimal JSON writer ---
    static String q(Object o) {
        if (o == null) return "null";
        if (o instanceof Boolean || o instanceof Number) return o.toString();
        if (o instanceof Map) {
            StringBuilder sb = new StringBuilder("{"); boolean first = true;
            for (Object e : new TreeMap<>((Map<?, ?>) o).entrySet()) {
                Map.Entry<?, ?> me = (Map.Entry<?, ?>) e;
                if (!first) sb.append(","); first = false;
                sb.append(q(me.getKey().toString())).append(":").append(q(me.getValue()));
            }
            return sb.append("}").toString();
        }
        if (o instanceof List) {
            StringBuilder sb = new StringBuilder("["); boolean first = true;
            for (Object e : (List<?>) o) { if (!first) sb.append(","); first = false; sb.append(q(e)); }
            return sb.append("]").toString();
        }
        String s = o.toString(); StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') sb.append('\\').append(c);
            else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else sb.append(c);
        }
        return sb.append("\"").toString();
    }

    static String cn(X500Name n) {
        RDN[] r = n.getRDNs(BCStyle.CN);
        if (r.length == 0) return null;
        ASN1Encodable v = r[0].getFirst().getValue();
        return nfc(v instanceof ASN1String ? ((ASN1String) v).getString() : v.toString());
    }

    static String digestName(String oid) {
        switch (oid) {
            case "2.16.840.1.101.3.4.2.1": return "SHA-256";
            case "2.16.840.1.101.3.4.2.2": return "SHA-384";
            case "2.16.840.1.101.3.4.2.3": return "SHA-512";
            case "1.3.14.3.2.26": return "SHA-1";
            default: return oid;
        }
    }

    static Map<String, Object> analyseSig(PDSignatureField f, PDSignature sig, byte[] data) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("field_name", nfc(f.getFullyQualifiedName()));
        r.put("filter", sig.getFilter());
        r.put("subfilter", sig.getSubFilter());
        r.put("name", nfc(sig.getName()));
        r.put("reason", nfc(sig.getReason()));
        r.put("location", nfc(sig.getLocation()));
        r.put("contact_info", nfc(sig.getContactInfo()));
        Calendar m = sig.getSignDate();
        r.put("m", m == null ? null : iso(m.getTime()));
        int[] br = sig.getByteRange();
        List<Integer> brl = new ArrayList<>(); for (int x : br) brl.add(x);
        r.put("byte_range", brl);
        r.put("covers_whole_file", br.length == 4 && br[0] == 0 && (long) br[2] + br[3] == data.length);
        // raw-byte check of the gap: '<' hex-digits '>' and nothing else
        boolean gapOk = br.length == 4 && br[1] < br[2] && br[2] <= data.length
                && data[br[1]] == '<' && data[br[2] - 1] == '>';
        if (gapOk) for (int i = br[1] + 1; i < br[2] - 1; i++) {
            if (Character.digit((char) data[i], 16) < 0) { gapOk = false; break; }
        }
        r.put("gap_is_contents_only", gapOk);

        // What a PDFBox-based parser typically calls: contents re-read from the file via /ByteRange.
        byte[] contents;
        try {
            contents = sig.getContents(data);
            r.put("pdfbox_getContents_bytes", "OK");
        } catch (java.io.IOException e) {
            // PDFBox 2.0.27 parses the WHOLE /ByteRange gap as hex; fall back to the /Contents string itself
            r.put("pdfbox_getContents_bytes", "FAILED: " + e.getClass().getSimpleName());
            contents = sig.getContents();
        }
        byte[] signed = sig.getSignedContent(data);
        CMSSignedData cms;
        SignerInformation si;
        try {
            cms = new CMSSignedData(new CMSProcessableByteArray(signed), contents);
            si = cms.getSignerInfos().getSigners().iterator().next();
            r.put("cms_parsed", true);
        } catch (Exception e) {
            r.put("cms_parsed", false); r.put("extraction_status", "FAILED"); r.put("crypto_ok", false);
            r.put("error", e.getClass().getSimpleName());
            return r;
        }
        r.put("digest_algorithm", si.getDigestAlgOID());
        r.put("signature_algorithm", si.getEncryptionAlgOID());
        AttributeTable sa = si.getSignedAttributes();
        String st = null;
        if (sa != null) {
            Attribute a = sa.get(CMSAttributes.signingTime);
            if (a != null) st = iso(org.bouncycastle.asn1.cms.Time.getInstance(a.getAttrValues().getObjectAt(0)).getDate());
        }
        r.put("cms_signing_time", st);

        @SuppressWarnings("unchecked")
        Store<X509CertificateHolder> store = cms.getCertificates();
        Collection<X509CertificateHolder> matches = store.getMatches(si.getSID());
        if (matches.isEmpty()) { r.put("extraction_status", "FAILED"); r.put("crypto_ok", false); return r; }
        X509CertificateHolder h = matches.iterator().next();
        X509Certificate c = new JcaX509CertificateConverter().getCertificate(h);
        r.put("cert_subject_der_sha256", sha256(c.getSubjectX500Principal().getEncoded()));
        r.put("cert_subject_cn", cn(h.getSubject()));
        r.put("cert_issuer_der_sha256", sha256(c.getIssuerX500Principal().getEncoded()));
        r.put("cert_issuer_cn", cn(h.getIssuer()));
        r.put("cert_serial_hex", c.getSerialNumber().toString(16));
        r.put("cert_not_before", iso(c.getNotBefore()));
        r.put("cert_not_after", iso(c.getNotAfter()));
        r.put("cert_sha256_fingerprint", sha256(c.getEncoded()));
        if (m != null) {
            Date md = m.getTime();
            r.put("cert_valid_at_m", !md.before(c.getNotBefore()) && !md.after(c.getNotAfter()));
        } else r.put("cert_valid_at_m", null);

        // digest_match: messageDigest attribute vs our own digest of the ByteRange bytes
        Boolean digestMatch = null;
        if (sa != null && sa.get(CMSAttributes.messageDigest) != null) {
            byte[] md = ASN1OctetString.getInstance(sa.get(CMSAttributes.messageDigest).getAttrValues().getObjectAt(0)).getOctets();
            byte[] calc = MessageDigest.getInstance(digestName(si.getDigestAlgOID())).digest(signed);
            digestMatch = MessageDigest.isEqual(md, calc);
        }
        r.put("digest_match", digestMatch);
        // signature_valid: raw signature over the DER signed attributes, with JCA directly
        String alg = digestName(si.getDigestAlgOID()).replace("-", "") + "with"
                + (c.getPublicKey().getAlgorithm().equals("EC") ? "ECDSA" : "RSA");
        java.security.Signature js = java.security.Signature.getInstance(alg);
        js.initVerify(c.getPublicKey());
        js.update(si.getEncodedSignedAttributes());
        boolean sigValid;
        try { sigValid = js.verify(si.getSignature()); } catch (java.security.SignatureException e) { sigValid = false; }
        r.put("signature_valid", sigValid);
        // the call a BouncyCastle-based parser would make
        Boolean bc;
        String bcErr = null;
        try {
            bc = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(c));
        } catch (CMSSignerDigestMismatchException e) { bc = false; bcErr = "CMSSignerDigestMismatchException"; }
        catch (CMSException e) { bc = false; bcErr = "CMSException: " + e.getMessage(); }
        r.put("bc_signerinfo_verify", bc);
        r.put("bc_signerinfo_verify_error", bcErr);
        r.put("crypto_ok", Boolean.TRUE.equals(digestMatch) && sigValid);

        // RFC 3161 token (unsigned attribute 1.2.840.113549.1.9.16.2.14)
        r.put("ts_present", false);
        AttributeTable ua = si.getUnsignedAttributes();
        if (ua != null) {
            Attribute ta = ua.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if (ta != null) {
                TimeStampToken tst = new TimeStampToken(new CMSSignedData(
                        ta.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                r.put("ts_present", true);
                r.put("ts_gen_time", iso(tst.getTimeStampInfo().getGenTime()));
                String ialg = tst.getTimeStampInfo().getMessageImprintAlgOID().getId();
                r.put("ts_imprint_alg", ialg);
                byte[] imp = tst.getTimeStampInfo().getMessageImprintDigest();
                r.put("ts_imprint_hex", hex(imp));
                byte[] calc = MessageDigest.getInstance(digestName(ialg)).digest(si.getSignature());
                r.put("ts_imprint_matches_signature", MessageDigest.isEqual(imp, calc));
            }
        }
        r.put("extraction_status", "OK");
        return r;
    }

    static Map<String, Object> analyse(File file) throws Exception {
        byte[] data = Files.readAllBytes(file.toPath());
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("file_size", data.length);
        PDDocument doc;
        try {
            doc = PDDocument.load(data);
            res.put("loads", true);
        } catch (Exception e) {
            res.put("loads", false); res.put("error", e.getClass().getSimpleName());
            return res;
        }
        try {
            List<PDSignatureField> fields = doc.getSignatureFields();
            res.put("signature_field_count", fields.size());
            int n = 0;
            Map<String, Object> sigs = new LinkedHashMap<>();
            for (PDSignatureField f : fields) {
                PDSignature s = f.getSignature();
                if (s == null) continue;
                n++;
                Map<String, Object> r;
                try { r = analyseSig(f, s, data); }
                catch (RuntimeException e) { throw e; }   // harness bugs must crash, not become data
                catch (Exception e) {
                    r = new LinkedHashMap<>(); r.put("field_name", f.getFullyQualifiedName());
                    r.put("extraction_status", "FAILED"); String msg = e.getClass().getSimpleName() + ": " + e.getMessage();
                    r.put("error", msg.length() > 200 ? msg.substring(0, 200) : msg);
                }
                sigs.put(f.getFullyQualifiedName(), r);
            }
            res.put("signature_count", n);
            res.put("signatures", sigs);
        } finally { doc.close(); }
        return res;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Map<String, Object> out = new TreeMap<>();
        for (String a : args) { File f = new File(a); out.put(f.getName(), analyse(f)); }
        new java.io.PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8").println(q(out));
    }
}
