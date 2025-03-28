package dod.p1.keycloak.utils;

import java.math.BigInteger;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERSequence;

/**
 * A test implementation of X509Certificate that returns dummy but non‑null values
 * for methods required by the OCSP logic.
 */
public class TestX509Certificate extends X509CertificateImpl {

    @Override
    public BigInteger getSerialNumber() {
        return BigInteger.ONE;
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        // Return a dummy non-empty byte array.
        return new byte[] { 1, 2, 3 };
    }

    @Override
    public PublicKey getPublicKey() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair kp = keyGen.generateKeyPair();
            return kp.getPublic();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        try {
            // Return a dummy DER-encoded certificate: an empty DER sequence.
            return new DERSequence().getEncoded();
        } catch (IOException e) {
            throw new CertificateEncodingException(e);
        }
    }
}
