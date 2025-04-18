package dod.p1.keycloak.utils;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

/**
 * Minimal no-op X509Certificate implementation for test stubbing.
 *
 * Note: This is NOT a valid certificate implementation for production usage.
 * It should only be used as a placeholder or mock in tests.
 */
public class X509CertificateImpl extends X509Certificate {

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        // No-op for tests
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        // No-op for tests
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public BigInteger getSerialNumber() {
        return null;
    }

    @Override
    public Principal getIssuerDN() {
        return null;
    }

    @Override
    public Principal getSubjectDN() {
        return null;
    }

    @Override
    public Date getNotBefore() {
        return null;
    }

    @Override
    public Date getNotAfter() {
        return null;
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return new byte[0];
    }

    @Override
    public byte[] getSignature() {
        return new byte[0];
    }

    @Override
    public String getSigAlgName() {
        return null;
    }

    @Override
    public String getSigAlgOID() {
        return null;
    }

    @Override
    public byte[] getSigAlgParams() {
        return new byte[0];
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return new boolean[0];
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return new boolean[0];
    }

    @Override
    public boolean[] getKeyUsage() {
        return new boolean[0];
    }

    @Override
    public int getBasicConstraints() {
        return 0;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return new byte[0];
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        // No-op for tests
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        // No-op for tests
    }

    @Override
    public String toString() {
        return null;
    }

    @Override
    public PublicKey getPublicKey() {
        return null;
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return false;
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return null;
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return null;
    }

    /**
     * Example of returning a mock extension value (e.g., to simulate a policy OID).
     * In a real certificate, this would parse the actual extension bytes.
     */
    @Override
    public byte[] getExtensionValue(String oid) {
        // Example: returning a hardcoded byte array for a test policy extension
        String inputString = "#30433037060a6086480186fa6c0a01053029302706082b06010505070201161b68747470733a2f2f7777772e656e74727573742e6e65742f7270613008060667810c010202";
        return inputString.getBytes();
    }
}
