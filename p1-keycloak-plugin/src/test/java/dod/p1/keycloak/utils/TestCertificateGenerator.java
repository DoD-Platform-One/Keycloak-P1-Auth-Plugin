package dod.p1.keycloak.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestCertificateGenerator {

    static {
        // Ensure the BC provider is added
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates a valid self‐signed certificate for testing purposes.
     *
     * @return a valid self‐signed X509Certificate
     * @throws Exception if any error occurs during certificate generation.
     */
    public static X509Certificate generateSelfSignedCertificate() throws Exception {
        // Generate a key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Set certificate attributes
        X500Name issuer = new X500Name("CN=Test Certificate,O=ExampleOrg,L=TestCity,ST=TestState,C=US");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60);
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60);
        X500Name subject = issuer;  // Self-signed: issuer equals subject

        // Create the certificate builder
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );

        // Build the certificate using SHA256withRSA
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
        certificate.verify(keyPair.getPublic(), "BC");
        return certificate;
    }
}
