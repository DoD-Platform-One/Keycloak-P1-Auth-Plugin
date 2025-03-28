package dod.p1.keycloak.authentication;

import dod.p1.keycloak.utils.OCSPUtils;
import dod.p1.keycloak.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.*;
import jakarta.ws.rs.core.Response;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link OCSPCheckAuthenticator} to improve code coverage.
 * This test class focuses on more edge cases and configuration variations.
 */
class OCSPCheckAuthenticatorTest2 {

    private OCSPCheckAuthenticator ocspCheckAuthenticator;
    private X509Certificate[] mockedCertificates;

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    @Mock
    private KeycloakSession session;

    @Mock
    private Config.Scope scope;

    @Mock
    private X509ClientCertificateLookup x509ClientCertificateLookup;

    @Mock
    private HttpRequest httpRequest;

    @Mock
    private AuthenticationSessionModel authenticationSession;

    @Mock
    private LoginFormsProvider formMock;

    @Mock
    private Response challengeResponseMock;

    @Mock
    private EventBuilder eventBuilderMock;

    // Map to store user attributes for testing
    private Map<String, String> userAttributes;

    @BeforeEach
    void setup() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Initialize the authenticator
        ocspCheckAuthenticator = new OCSPCheckAuthenticator();

        // Prepare a test certificate
        X509Certificate certificate = Utils.buildTestCertificate();
        mockedCertificates = new X509Certificate[]{certificate};

        // Initialize user attributes map
        userAttributes = new HashMap<>();

        // Common context stubs
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);
        when(context.form()).thenReturn(formMock);
        when(formMock.setError(anyString())).thenReturn(formMock); // chaining
        when(formMock.createErrorPage(any(Response.Status.class))).thenReturn(challengeResponseMock);
        when(context.getEvent()).thenReturn(eventBuilderMock);
        when(context.getUser()).thenReturn(user);
        when(user.getUsername()).thenReturn("testUser");
        when(context.getRealm()).thenReturn(realm);
        when(context.getSession()).thenReturn(session);
        when(context.getHttpRequest()).thenReturn(httpRequest);

        // Setup user attribute mocking
        doAnswer(invocation -> {
            String attrName = invocation.getArgument(0);
            String attrValue = invocation.getArgument(1);
            userAttributes.put(attrName, attrValue);
            return null;
        }).when(user).setSingleAttribute(anyString(), anyString());

        doAnswer(invocation -> {
            String attrName = invocation.getArgument(0);
            return userAttributes.get(attrName);
        }).when(user).getFirstAttribute(anyString());
    }

    @Test
    void testAuthenticate_OCSPEnabled_CaseInsensitiveConfig() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with mixed case "TRUE" instead of "true"
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("TRUE");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Mock the OCSP check result
            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(true);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_BooleanParsingVariations() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with "TRUE" for cache enabled
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("TRUE");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status and timestamp
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000));

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));

            // Verify we didn't perform a new OCSP check (used cache)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(any(), any()), never());
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_ZeroTTL() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with zero TTL
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("0");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status and timestamp (should be ignored due to zero TTL)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000));

            // Mock the OCSP check result
            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(true);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));

            // Verify we performed a new OCSP check (cache should be ignored due to zero TTL)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)), times(1));

            // Verify cache was updated
            verify(user).setSingleAttribute("ocsp_cache_status", "GOOD");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_NegativeTTL() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with negative TTL (should use default)
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("-5");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status and timestamp
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000));

            // Mock the OCSP check result in case cache is not used
            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(true);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));

            // Verify we didn't perform a new OCSP check (used cache)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(any(), any()), times(1));
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_VeryLargeTTL() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with very large TTL
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("8760"); // 1 year
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status and old timestamp (6 months ago)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 180 * 24 * 3_600_000L));

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));

            // Verify we didn't perform a new OCSP check (used cache)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(any(), any()), never());
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_MissingCachedStatus() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up timestamp but no status
            userAttributes.put("ocsp_cache_status", null);
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000));

            // Mock the OCSP check result
            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(true);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));

            // Verify we performed a new OCSP check
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)), times(1));

            // Verify cache was updated
            verify(user).setSingleAttribute("ocsp_cache_status", "GOOD");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_OCSPEnabled_BadResult_WithFailureReason() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Mock the OCSP check result with specific failure reason
            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(false);
            when(ocspResult.getFailureReason()).thenReturn("Certificate has been explicitly revoked");

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);
            verify(formMock).setError("Certificate validation failed. Please ensure you are using a valid certificate and try again.");
            verify(context).failureChallenge(eq(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR), any(Response.class));

            // Verify cache was updated
            verify(user).setSingleAttribute("ocsp_cache_status", "REVOKED");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_OCSPEnabled_ExceptionWithDetailedMessage() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Throw exception with detailed message
            GeneralSecurityException exception = new GeneralSecurityException("OCSP responder at https://ocsp.example.com is unreachable");
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenThrow(exception);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);
            verify(formMock).setError("Certificate validation failed, possibly due to an unreachable OCSP server. Please remove CAC/PIV and try again later.");
            verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any(Response.class));
        }
    }

    @Test
    void testAuthenticate_OCSPEnabled_WithNestedExceptionCause() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Create nested exception
            Exception innerException = new java.net.ConnectException("Connection refused");
            GeneralSecurityException outerException = new GeneralSecurityException("OCSP check failed");
            outerException.initCause(innerException);
            
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenThrow(outerException);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);
            verify(formMock).setError("Certificate validation failed, possibly due to an unreachable OCSP server. Please remove CAC/PIV and try again later.");
            verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any(Response.class));
        }
    }
}