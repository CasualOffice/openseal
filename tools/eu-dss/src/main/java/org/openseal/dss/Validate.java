package org.openseal.dss;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;

/**
 * Validates PDFs with EU DSS, offline, against one trust root, and prints one TSV line per
 * signature: file, indication, sub-indication, format, signature intact, signature valid,
 * undefined changes after signing.
 *
 * <p>Usage: {@code Validate <trust-root.pem> <file.pdf>...}. Nothing is fetched: AIA, OCSP and
 * CRL sources are left unset, so a seal with no revocation data is INDETERMINATE at best; the
 * caller judges intactness from the cryptographic columns (docs/31 §7, F-006).
 */
public final class Validate {
    private Validate() {}

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: Validate <trust-root.pem> <file.pdf>...");
            System.exit(2);
        }
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(DSSUtils.loadCertificate(new File(args[0])));
        System.out.println("file\tindication\tsubindication\tformat\tintact\tvalid\tundefined_changes");
        int failures = 0;
        for (int i = 1; i < args.length; i++) {
            String name = new File(args[i]).getName();
            try {
                DSSDocument doc = new FileDocument(args[i]);
                SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
                CommonCertificateVerifier verifier = new CommonCertificateVerifier();
                verifier.setTrustedCertSources(trusted);
                verifier.setAIASource(null);
                verifier.setOcspSource(null);
                verifier.setCrlSource(null);
                validator.setCertificateVerifier(verifier);
                Reports reports = validator.validateDocument();
                SimpleReport simple = reports.getSimpleReport();
                DiagnosticData diag = reports.getDiagnosticData();
                if (simple.getSignatureIdList().isEmpty()) {
                    System.out.println(name + "\tNO_SIGNATURE\t-\t-\tfalse\tfalse\t-");
                }
                for (String id : simple.getSignatureIdList()) {
                    SignatureWrapper sig = diag.getSignatureById(id);
                    int undefined = sig.getPdfUndefinedChanges() == null ? 0 : sig.getPdfUndefinedChanges().size();
                    System.out.println(String.join("\t", name,
                            String.valueOf(simple.getIndication(id)),
                            String.valueOf(simple.getSubIndication(id)),
                            String.valueOf(simple.getSignatureFormat(id)),
                            String.valueOf(sig.isSignatureIntact()),
                            String.valueOf(sig.isSignatureValid()),
                            String.valueOf(undefined)));
                }
            } catch (Exception | LinkageError e) {
                failures++;
                System.err.println(name + ": " + e);
                System.out.println(name + "\tERROR\t" + e.getClass().getSimpleName() + "\t-\tfalse\tfalse\t-");
            }
        }
        System.exit(failures == 0 ? 0 : 1);
    }
}
