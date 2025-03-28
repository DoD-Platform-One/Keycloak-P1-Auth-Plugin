package dod.p1.keycloak.utils;

import dod.p1.keycloak.common.YAMLConfig;
import dod.p1.keycloak.registration.X509Tools;
import org.apache.commons.io.FilenameUtils;
import org.keycloak.authentication.FormContext;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * A utility class for Keycloak tests that can:
 * <ul>
 *     <li>Provide a mock X509 certificate from a hard-coded PEM string</li>
 *     <li>Simulate basic file mocking without PowerMock</li>
 *     <li>Build YAML config from a test string</li>
 * </ul>
 *
 * <strong>Note:</strong> This code is for test scenarios only and shouldn't be used in production.
 */
public class Utils {

    /**
     * Sets up X509-related mocks.
     *
     * <p>In a JUnit 5 environment, tests should use
     * {@code Mockito.mockStatic(X509Tools.class)} directly.
     * This method is provided as a placeholder for legacy calls.</p>
     */
    public static void setupX509Mocks() {
        // No-op in this updated version.
        // In your tests, use:
        // try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class)) { ... }
    }

    /**
     * Sets up file-related mocks.
     *
     * <p>Without PowerMock, this method simply parses a configuration string
     * into a YAMLConfig object. You may refactor your production code to accept
     * dependencies rather than intercepting constructor calls.</p>
     *
     * @throws Exception if parsing fails.
     */
    public static void setupFileMocks() throws Exception {
        final String fileContent = ""
            + "x509:\n"
            + "  userIdentityAttribute: \"usercertificate\"\n"
            + "  userActive509Attribute: \"activecac\"\n"
            + "  autoJoinGroup:\n"
            + "    - \"/test-group\"\n"
            + "  requiredCertificatePolicies:\n"
            + "    - \"2.16.840.1.101.2.1.11.36\"\n"
            + "    - \"2.16.840.1.114028.10.1.5\"\n"
            + "groupProtectionIgnoreClients:\n"
            + "  - \"test-client\"\n"
            + "noEmailMatchAutoJoinGroup:\n"
            + "  - \"/randos-test-group\"\n"
            + "emailMatchAutoJoinGroup:\n"
            + "  - description: Test thing 1\n"
            + "    groups:\n"
            + "      - \"/test-group-1-a\"\n"
            + "      - \"/test-group-1-b\"\n"
            + "    domains:\n"
            + "      - \".gov\"\n"
            + "      - \".mil\"\n"
            + "      - \"@afit.edu\"\n"
            + "  - description: Test thing 2\n"
            + "    groups:\n"
            + "      - \"/test-group-2-a\"\n"
            + "    domains:\n"
            + "      - \"@unicorns.com\"\n"
            + "      - \"@merica.test\"";

        InputStream stream = new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8));
        LoaderOptions loaderOptions = new LoaderOptions();
        Yaml yaml = new Yaml(new Constructor(YAMLConfig.class, loaderOptions));
        YAMLConfig yamlConfig = yaml.load(stream);
        // Optionally, store yamlConfig or pass it on to code under test.
    }

    /**
     * Builds a test X509 certificate from a hard-coded PEM string.
     * This certificate is the one exported from login.dso.mil.
     *
     * @return A Java X509Certificate parsed from the embedded PEM data.
     * @throws Exception if parsing the certificate fails.
     */
    public static X509Certificate buildTestCertificate() throws Exception {
        String certPem = ""
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIH1TCCBr2gAwIBAgIQJI3UKNbRu9YSNYT1XVNjsjANBgkqhkiG9w0BAQsFADCB\n"
            + "ujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsT\n"
            + "H1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAy\n"
            + "MDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwG\n"
            + "A1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxSzAeFw0y\n"
            + "MjAxMTAyMTU5MjVaFw0yMzAxMTMyMTU5MjVaMHMxCzAJBgNVBAYTAlVTMREwDwYD\n"
            + "VQQIEwhDb2xvcmFkbzEZMBcGA1UEBxMQQ29sb3JhZG8gU3ByaW5nczEeMBwGA1UE\n"
            + "ChMVRGVwYXJ0bWVudCBvZiBEZWZlbnNlMRYwFAYDVQQDEw1sb2dpbi5kc28ubWls\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAymUXk7STDlepS5HJu0ca\n"
            + "B57S5dfLp7zxYmcsGjo10YkHy3m9LASQCTyiioDrlwo2b+n8oZ7esGLv3RgggMwf\n"
            + "xvLVyx1+lZDswxdQoXmjArTdbqpcSoq3Y1rvVp33/jGb3slBjQtcMt2QvaFv3fxy\n"
            + "cwwINvJFEqsQS7zGUgpolJ3smKdcVpUSGZmzpYposuDlPUGeOJaQRMAACW5arWiT\n"
            + "VkDhJD+OVOYEHW8uCQfghD3JJXu6Xp9SwlWe6UNOdxo9cq3s/XE4ZwEgffdLXP2A\n"
            + "wuJF/7B7CFdZjIMptmOODyCeatC344iyubU0MiGCOm4W4wn0pQ0XJtAzWeYFKATL\n"
            + "9BquNOzPUR6pMSFMvIEiS96zbVFuOYt2XKgPryWEYji3Oky082WWYOcXt0NnqnCj\n"
            + "SafVU+2fQi4jQ0att5YXagEEPz83lQZdSKb2+grDeFg78VrEZAe+Y0mVu4/G93he\n"
            + "UOqfZ9jdCnFXq8sEMG9bJJFKeOXkb1Da8Y0amfOw4hFd4UslrbvC5ZCUZNh6roOk\n"
            + "8kast9QWtWFIGPC3f+Uq3gvx3GBHzIG9QPOq1CjSSAF3tWKuMTxK4zaS33mriJo0\n"
            + "Dv1CMX3FCmjT/qG3422guBL02hbGHveDSWk0/saY7ZWFifxnvKEdOi4ItnpMuQhE\n"
            + "zx6/+t7FWuzBTPAeVqV1l2sCAwEAAaOCAxswggMXMAwGA1UdEwEB/wQCMAAwHQYD\n"
            + "VR0OBBYEFCLwpnkje7QKLWok+nWIeBEnIGfmMB8GA1UdIwQYMBaAFIKicHTdvFM/\n"
            + "z3vU981/p2DGCky/MGgGCCsGAQUFBwEBBFwwWjAjBggrBgEFBQcwAYYXaHR0cDov\n"
            + "L29jc3AuZW50cnVzdC5uZXQwMwYIKwYBBQUHMAKGJ2h0dHA6Ly9haWEuZW50cnVz\n"
            + "dC5uZXQvbDFrLWNoYWluMjU2LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8v\n"
            + "Y3JsLmVudHJ1c3QubmV0L2xldmVsMWsuY3JsMCcGA1UdEQQgMB6CDWxvZ2luLmRz\n"
            + "by5taWyCDWxvZ2luLmRzb3AuaW8wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG\n"
            + "CCsGAQUFBwMBBggrBgEFBQcDAjBMBgNVHSAERTBDMDcGCmCGSAGG+mwKAQUwKTAn\n"
            + "BggrBgEFBQcCARYbaHR0cHM6Ly93d3cuZW50cnVzdC5uZXQvcnBhMAgGBmeBDAEC\n"
            + "AjCCAYAGCisGAQQB1nkCBAIEggFwBIIBbAFqAHYAtz77JN+cTbp18jnFulj0bF38\n"
            + "Qs96nzXEnh0JgSXttJkAAAF+RgDXCAAABAMARzBFAiEAjJj5KvxiOvlcsc326ttI\n"
            + "snrtX3qeg1NKaXg253zxuyICIB6uaYu7qZvww1unlvhIkcm2WG5LdjBgf0w7ueqA\n"
            + "57pgAHcAs3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZoAAAF+RgDXLQAA\n"
            + "BAMASDBGAiEApZarmlBvc3HEtu+GbctG2TcPlN9rodFSr8cfQ4nak9MCIQCrKiN3\n"
            + "JFjK8CM6xACN27pJyPFsRh0nzrjadwcdTud/PgB3AOg+0No+9QY1MudXKLyJa8kD\n"
            + "08vREWvs62nhd31tBr1uAAABfkYA1uQAAAQDAEgwRgIhAKJNhQx+xc/bgSvGEsAv\n"
            + "kjeguXlN+GU3uKRL9daPvXwEAiEAhkjxQx8I40hAN9mQ37Tw9lmKazdvkIeforcF\n"
            + "5tqxzN4wDQYJKoZIhvcNAQELBQADggEBAGSn1AAnLNs/EECk5tBBlE+r8rktCQBo\n"
            + "zA2AbX0EvNMrJWb6M6iB9bIlXYAByFRfPG4UgRQoaqoAwtX4mnF9S3sEweCNgOqQ\n"
            + "rdzi9e9ePvHGZcRUKnizFm0FpAJ2NiywezpWX+9muSpl1e9TZy6fBEPyk2M1xScw\n"
            + "h7ffh5F4gt4OBQ31F2FIIcd5ud+5rsI5QGq2+fUeiOxJ6n2yAjr6ywF0lz8semer\n"
            + "OOSFtSTn1ZG4EryV5/79iAkftQWdmz/4dtWhj+Nyufq891unwuFL3oDRBT/21JIk\n"
            + "N8iM5Bydlmc/qlTTYu4bN9pVxEyPZT06Q8wnmEPbaOBRnc0NE9yRkTc=\n"
            + "-----END CERTIFICATE-----\n";
        ByteArrayInputStream in = new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }
}
