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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link OCSPCheckAuthenticator} to improve code coverage.
 * This test class focuses on the CacheResult inner class and more edge cases.
 */
class OCSPCheckAuthenticatorTest3 {

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

    /**
     * Test the CacheResult inner class directly using reflection.
     * This tests the constructor and getter methods.
     */
    @Test
    void testCacheResultInnerClass() throws Exception {
        // Get the CacheResult class
        Class<?> cacheResultClass = Class.forName("dod.p1.keycloak.authentication.OCSPCheckAuthenticator$CacheResult");
        
        // Get the constructor
        Constructor<?> constructor = cacheResultClass.getDeclaredConstructor(boolean.class, boolean.class, boolean.class);
        constructor.setAccessible(true);
        
        // Create instances with different combinations
        Object cacheResult1 = constructor.newInstance(true, true, true);
        Object cacheResult2 = constructor.newInstance(true, false, true);
        Object cacheResult3 = constructor.newInstance(false, false, false);
        
        // Get the getter methods
        Method isValidMethod = cacheResultClass.getDeclaredMethod("isValid");
        Method isOCSPGoodMethod = cacheResultClass.getDeclaredMethod("isOCSPGood");
        Method isUsedCacheMethod = cacheResultClass.getDeclaredMethod("isUsedCache");
        
        // Test the getters
        assertTrue((Boolean) isValidMethod.invoke(cacheResult1));
        assertTrue((Boolean) isOCSPGoodMethod.invoke(cacheResult1));
        assertTrue((Boolean) isUsedCacheMethod.invoke(cacheResult1));
        
        assertTrue((Boolean) isValidMethod.invoke(cacheResult2));
        assertFalse((Boolean) isOCSPGoodMethod.invoke(cacheResult2));
        assertTrue((Boolean) isUsedCacheMethod.invoke(cacheResult2));
        
        assertFalse((Boolean) isValidMethod.invoke(cacheResult3));
        assertFalse((Boolean) isOCSPGoodMethod.invoke(cacheResult3));
        assertFalse((Boolean) isUsedCacheMethod.invoke(cacheResult3));
    }

    @Test
    void testAuthenticate_ConfigWithWhitespace() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with whitespace in configuration values
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn(" true ");
            when(scope.get("CacheTTLHours", "24")).thenReturn(" 24 ");
            when(scope.get("CacheEnabled", "false")).thenReturn(" true ");

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
    void testAuthenticate_VeryLargeTTLValue() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup with very large TTL value
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("2147483647"); // Integer.MAX_VALUE
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status and old timestamp (1 year ago)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 365 * 24 * 3_600_000L));

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
    void testAuthenticate_NullCertificateChain() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            // Return null certificate chain
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(AuthenticationFlowContext.class)))
                    .thenReturn(null);

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
    void testAuthenticate_CacheEnabled_ExactlyAtTTLBoundary() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status with timestamp exactly at TTL boundary (24 hours ago)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 24 * 3_600_000L));

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

            // Verify we performed a new OCSP check (cache should be expired)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)), times(1));

            // Verify cache was updated
            verify(user).setSingleAttribute("ocsp_cache_status", "GOOD");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_CacheEnabled_JustBeforeTTLBoundary() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status with timestamp just before TTL boundary (23.99 hours ago)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 23 * 3_600_000L - 59 * 60_000L));

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
    void testAuthenticate_CacheEnabled_JustAfterTTLBoundary() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Set up cached OCSP status with timestamp just after TTL boundary (24.01 hours ago)
            userAttributes.put("ocsp_cache_status", "GOOD");
            userAttributes.put("ocsp_cache_timestamp", String.valueOf(System.currentTimeMillis() - 24 * 3_600_000L - 1 * 60_000L));

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

            // Verify we performed a new OCSP check (cache should be expired)
            ocspUtilsMock.verify(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)), times(1));

            // Verify cache was updated
            verify(user).setSingleAttribute("ocsp_cache_status", "GOOD");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }

    @Test
    void testAuthenticate_OCSPEnabled_BadResult_UpdatesCache() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            // Setup
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("true");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            // Mock the OCSP check result
            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(false);

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);
            verify(formMock).setError("Certificate validation failed. Please ensure you are using a valid certificate and try again.");
            verify(context).failureChallenge(eq(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR), any(Response.class));

            // Verify cache was updated with REVOKED status
            verify(user).setSingleAttribute("ocsp_cache_status", "REVOKED");
            verify(user).setSingleAttribute(eq("ocsp_cache_timestamp"), anyString());
        }
    }
}