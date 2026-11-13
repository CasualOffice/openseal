package org.openseal.dss;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CRLFirstRevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates PDFs with EU DSS against one or more trust roots, and prints one TSV line per
 * signature: file, indication, sub-indication, format, signature intact, signature valid,
 * undefined changes after signing, then the indications of its timestamps and how many
 * revocation answers DSS used for the signing certificate.
 *
 * <p>Usage: {@code Validate [--online [--crl-first]] [--rewrite FROM=TO] [--trust ROOT.pem]... <trust-root.pem>
 * <file.pdf>...}.
 *
 * <p>By default nothing is fetched: AIA, OCSP and CRL sources are left unset, so a seal with no
 * revocation data is INDETERMINATE at best; the caller judges intactness from the cryptographic
 * columns (docs/31 §7, F-006). {@code --online} turns on the AIA, OCSP and CRL sources, so DSS
 * fetches what the certificates name (HRD-02: the interop PKI serves them during the test).
 * {@code --rewrite} replaces a URL prefix before any fetch: on Docker Desktop a container
 * reaches the host's loopback as {@code host.docker.internal}, so the interop run passes
 * {@code http://127.0.0.1:=http://host.docker.internal:} there; DSS still validates the
 * certificates and answers exactly as received. {@code --crl-first} asks CRLs before OCSP: EU
 * DSS 6.5.1 refuses DigiCert's OCSP answer for its timestamping CA ("The ResponderId does not
 * match the OCSP issuer certificate!") and does not fall back, so the interop run's opt-in
 * production-TSA mode validates that chain by its CRLs (HRD-02, docs/31).
 */
public final class Validate {
    private Validate() {}

    /** A URL prefix rewrite, or none. */
    private static String[] rewrite;

    private static String rewritten(String url) {
        if (rewrite != null && url != null && url.startsWith(rewrite[0])) {
            return rewrite[1] + url.substring(rewrite[0].length());
        }
        return url;
    }

    /** CRL and AIA fetches, through the rewrite. */
    private static final class Loader extends CommonsDataLoader {
        @Override
        public byte[] get(String url) {
            return super.get(rewritten(url));
        }

        @Override
        public byte[] post(String url, byte[] content) {
            return super.post(rewritten(url), content);
        }
    }

    /** OCSP requests, through the rewrite. */
    private static final class OcspLoader extends OCSPDataLoader {
        @Override
        public byte[] get(String url) {
            return super.get(rewritten(url));
        }

        @Override
        public byte[] post(String url, byte[] content) {
            return super.post(rewritten(url), content);
        }
    }

    private static void usage() {
        System.err.println("usage: Validate [--online [--crl-first]] [--rewrite FROM=TO] [--trust ROOT.pem]... <trust-root.pem> <file.pdf>...");
        System.exit(2);
    }

    public static void main(String[] args) {
        boolean online = false;
        boolean crlFirst = false;
        List<String> roots = new ArrayList<>();
        int at = 0;
        while (at < args.length && args[at].startsWith("--")) {
            switch (args[at]) {
                case "--online" -> online = true;
                case "--crl-first" -> crlFirst = true;
                case "--rewrite" -> {
                    if (at + 1 >= args.length || !args[at + 1].contains("=")) {
                        usage();
                    }
                    rewrite = args[++at].split("=", 2);
                }
                case "--trust" -> {
                    if (at + 1 >= args.length) {
                        usage();
                    }
                    roots.add(args[++at]);
                }
                default -> usage();
            }
            at++;
        }
        if (args.length - at < 2) {
            usage();
        }
        roots.add(0, args[at++]);
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        for (String root : roots) {
            trusted.addCertificate(DSSUtils.loadCertificate(new File(root)));
        }
        System.out.println("file\tindication\tsubindication\tformat\tintact\tvalid\tundefined_changes\ttimestamps\trevocation");
        int failures = 0;
        for (int i = at; i < args.length; i++) {
            String name = new File(args[i]).getName();
            try {
                DSSDocument doc = new FileDocument(args[i]);
                SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
                CommonCertificateVerifier verifier = new CommonCertificateVerifier();
                verifier.setTrustedCertSources(trusted);
                if (online) {
                    Loader loader = new Loader();
                    verifier.setAIASource(new DefaultAIASource(loader));
                    verifier.setCrlSource(new OnlineCRLSource(loader));
                    verifier.setOcspSource(new OnlineOCSPSource(new OcspLoader()));
                    if (crlFirst) {
                        verifier.setRevocationDataLoadingStrategyFactory(
                                new CRLFirstRevocationDataLoadingStrategyFactory());
                    }
                } else {
                    verifier.setAIASource(null);
                    verifier.setOcspSource(null);
                    verifier.setCrlSource(null);
                }
                validator.setCertificateVerifier(verifier);
                Reports reports = validator.validateDocument();
                SimpleReport simple = reports.getSimpleReport();
                DiagnosticData diag = reports.getDiagnosticData();
                if (simple.getSignatureIdList().isEmpty()) {
                    System.out.println(name + "\tNO_SIGNATURE\t-\t-\tfalse\tfalse\t-\t-\t-");
                }
                for (String id : simple.getSignatureIdList()) {
                    SignatureWrapper sig = diag.getSignatureById(id);
                    int undefined = sig.getPdfUndefinedChanges() == null ? 0 : sig.getPdfUndefinedChanges().size();
                    List<String> ts = new ArrayList<>();
                    for (TimestampWrapper t : sig.getTimestampList()) {
                        String sub = String.valueOf(simple.getSubIndication(t.getId()));
                        ts.add(t.getType() + ":" + simple.getIndication(t.getId())
                                + ("null".equals(sub) ? "" : "/" + sub));
                        if (!"null".equals(sub)) {
                            // Why, on stderr: DSS's own messages (no document content).
                            List<String> why = new ArrayList<>();
                            for (eu.europa.esig.dss.jaxb.object.Message m : simple.getAdESValidationErrors(t.getId())) {
                                why.add(m.getValue());
                            }
                            System.err.println(name + " " + t.getType() + ": " + String.join("; ", why));
                        }
                    }
                    CertificateWrapper signer = sig.getSigningCertificate();
                    int revocation = signer == null ? 0 : signer.getCertificateRevocationData().size();
                    System.out.println(String.join("\t", name,
                            String.valueOf(simple.getIndication(id)),
                            String.valueOf(simple.getSubIndication(id)),
                            String.valueOf(simple.getSignatureFormat(id)),
                            String.valueOf(sig.isSignatureIntact()),
                            String.valueOf(sig.isSignatureValid()),
                            String.valueOf(undefined),
                            ts.isEmpty() ? "-" : String.join(",", ts),
                            String.valueOf(revocation)));
                }
            } catch (Exception | LinkageError e) {
                failures++;
                System.err.println(name + ": " + e);
                System.out.println(name + "\tERROR\t" + e.getClass().getSimpleName() + "\t-\tfalse\tfalse\t-\t-\t-");
            }
        }
        System.exit(failures == 0 ? 0 : 1);
    }
}
