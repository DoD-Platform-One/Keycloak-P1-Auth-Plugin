package dod.p1.keycloak.authentication;

import dod.p1.keycloak.registration.X509Tools;
import dod.p1.keycloak.utils.OCSPUtils;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Refactored test for {@link OCSPCheckAuthenticator}, removing PowerMock
 * and switching to JUnit 5 + Mockito static mocking if needed.
 */
class OCSPCheckAuthenticatorTest {

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

    @BeforeEach
    void setup() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Initialize the authenticator
        ocspCheckAuthenticator = new OCSPCheckAuthenticator();

        // Prepare a test certificate
        X509Certificate certificate = Utils.buildTestCertificate();
        mockedCertificates = new X509Certificate[]{certificate};

        // Common context stubs
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);
        when(context.form()).thenReturn(formMock);
        when(formMock.setError(anyString())).thenReturn(formMock); // chaining
        when(formMock.createErrorPage(any(Response.Status.class))).thenReturn(challengeResponseMock);
        when(context.getEvent()).thenReturn(eventBuilderMock);
        when(context.getUser()).thenReturn(user);
        when(user.getUsername()).thenReturn("someUsername");
        when(context.getRealm()).thenReturn(realm);
        when(context.getSession()).thenReturn(session);
        when(context.getHttpRequest()).thenReturn(httpRequest);
    }

    @Test
    void testAuthenticate_OCSPDisabled() throws Exception {
        // We want to mock Config.scope("babyYodaOcsp") => scope
        // and scope.get("enabled", "false") => "false"
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("false");

            // Run
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
    void testAuthenticate_OCSPEnabled_NoCertChain() throws Exception {
        String expectedErrorMessage = "No certificate chain found. Please ensure you are using a valid certificate.";

        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            // Stub additional configuration if needed (not used since chain is null)
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            // Return null from OCSPUtils.getCertificateChain(context)
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(AuthenticationFlowContext.class)))
                    .thenReturn(null);

            // Run
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(context).failureChallenge(eq(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR),
                    responseCaptor.capture());
            assertSame(challengeResponseMock, responseCaptor.getValue());

            verify(formMock).setError(expectedErrorMessage);
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    void testAuthenticate_OCSPEnabled_WithCertChain_Good() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            // Stub cache configuration to avoid NPE
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

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
    void testAuthenticate_OCSPEnabled_WithCertChain_Bad() throws Exception {
        String expectedErrorMessage = "Certificate validation failed. Please ensure you are using a valid certificate and try again.";

        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            // Stub cache configuration to avoid NPE
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);

            OCSPUtils.OCSPResult ocspResult = mock(OCSPUtils.OCSPResult.class);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenReturn(ocspResult);
            when(ocspResult.isOCSPGood()).thenReturn(false);
            when(ocspResult.getFailureReason()).thenReturn("Certificate revoked");

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(context).failureChallenge(eq(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR),
                    responseCaptor.capture());
            assertSame(challengeResponseMock, responseCaptor.getValue());

            verify(formMock).setError(expectedErrorMessage);
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    void testAuthenticate_OCSPEnabled_Exception() throws Exception {
        String expectedErrorMessage = "Certificate validation failed, possibly due to an unreachable OCSP server. "
            + "Please remove CAC/PIV and try again later.";

        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {

            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            // Stub cache configuration to avoid NPE
            when(scope.get("CacheTTLHours", "24")).thenReturn("24");
            when(scope.get("CacheEnabled", "false")).thenReturn("false");

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(context)).thenReturn(mockedCertificates);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(eq(session), eq(mockedCertificates)))
                    .thenThrow(new GeneralSecurityException("OCSP service down"));

            // Execute
            ocspCheckAuthenticator.authenticate(context);

            // Verify
            verify(eventBuilderMock).error(Errors.IDENTITY_PROVIDER_ERROR);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR),
                    responseCaptor.capture());
            assertSame(challengeResponseMock, responseCaptor.getValue());

            verify(formMock).setError(expectedErrorMessage);
            verify(authenticationSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    void testAction() {
        // No static mocking needed; action does nothing
        ocspCheckAuthenticator.action(context);
        verifyNoInteractions(context, realm, user, session, scope, x509ClientCertificateLookup,
                             httpRequest, authenticationSession, formMock, eventBuilderMock, challengeResponseMock);
    }

    @Test
    void testClose() {
        // close does nothing
        ocspCheckAuthenticator.close();
        verifyNoInteractions(context, realm, user, session, scope, x509ClientCertificateLookup,
                             httpRequest, authenticationSession, formMock, eventBuilderMock, challengeResponseMock);
    }

    @Test
    void testRequiresUser() {
        assertTrue(ocspCheckAuthenticator.requiresUser());
    }

    @Test
    void testConfiguredFor() {
        assertTrue(ocspCheckAuthenticator.configuredFor(session, realm, user));
    }

    @Test
    void testSetRequiredActions() {
        ocspCheckAuthenticator.setRequiredActions(session, realm, user);
        verifyNoInteractions(session, realm, user);
    }
}
