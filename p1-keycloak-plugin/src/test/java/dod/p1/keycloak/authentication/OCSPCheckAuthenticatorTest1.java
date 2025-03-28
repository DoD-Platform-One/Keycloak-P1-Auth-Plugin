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
 * This test class focuses on cache-related functionality and edge cases.
 */
class OCSPCheckAuthenticatorTest1 {

    private OCSPCheckAuthenticator ocspCheckAuthenticator;
    private X509Certificate[] mockedCertificates;
    private X509Certificate[] emptyCertificates;

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
        emptyCertificates = new X509Certificate[0];

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
    void testAuthenticate_NullUser() {
        // Setup
        when(context.getUser()).thenReturn(null);

        // Execute
        ocspCheckAuthenticator.authenticate(context);

        // Verify
        verify(context).failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS);
        verifyNoMoreInteractions(user);
    }

    @Test
    void testAuthenticate_EmptyCertificateChain() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            // Return empty certificate chain
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(AuthenticationFlowContext.class)))
                    .thenReturn(emptyCertificates);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);
            verify(formMock).setError("No certificate chain found. Please ensure you are using a valid certificate.");
            verify(context).failureChallenge(eq(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR), any(Response.class));
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_ValidCachedGoodStatus() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status (GOOD) and timestamp (recent)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000)); // 1 second ago

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession).setAuthNote("authenticated_via_x509", "true");
            verify(context).success();
            verify(eventBuilderMock, never()).error(anyString());
            verify(formMock, never()).setError(anyString());
            verify(context, never()).failureChallenge(any(AuthenticationFlowError.class), any(Response.class));

            // Verify we didn't perform a new OCSP check
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(any(), any()), never());
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_ValidCachedRevokedStatus() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status (REVOKED) and timestamp (recent)
            userAttributes.put("ocsp_cache_status", "REVOKED");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000)); // 1 second ago

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);
            verify(formMock).setError("Certificate validation failed. Please ensure you are using a valid certificate and try again.");
            verify(context).failureChallenge(eq(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR), any(Response.class));

            // Verify we didn't perform a new OCSP check
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(any(), any()), never());
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_ExpiredCachedStatus() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status (GOOD) but with expired timestamp (25 hours ago)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 25 * 3_600_000L));

            // Mock the OCSP check result (since cache is expired, a new check will be performed)
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
    void testAuthenticate_CacheEnabled_UnknownCachedStatus() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up unknown cached OCSP status and recent timestamp
            userAttributes.put("ocsp_cache_status", "UNKNOWN");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 1000));

            // Mock the OCSP check result (since cache status is unknown, a new check will be performed)
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
    void testAuthenticate_CacheEnabled_InvalidTimestampFormat() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status but with invalid timestamp format
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", "not-a-number");

            // Mock the OCSP check result (since timestamp is invalid, a new check will be performed)
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
    void testAuthenticate_InvalidTTLValue() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("not-a-number");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

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

            // Verify we performed a new OCSP check
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)), times(1));

            // Verify cache was updated with default TTL
            verify(user).setSingleAttribute("ocsp_cache_status", "GOOD");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_CacheDisabled_ConfigurationVariations() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("48"); // Different TTL
            when(scope.get("CacheEnabled", "false")).thenReturn("false"); // Cache disabled

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status (should be ignored since cache is disabled)
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

            // Verify we performed a new OCSP check (cache should be ignored)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)), times(1));

            // Verify cache was not updated (since cache is disabled)
            verify(user, never()).setSingleAttribute(eq("ocsp_cache_status"), anyString());
            verify(user, never()).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_MissingCachedTimestamp() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status but no timestamp
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", null);

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
}