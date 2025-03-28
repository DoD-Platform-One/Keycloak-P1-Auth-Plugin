package dod.p1.keycloak.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OCSPCheckAuthenticatorFactoryTest {

    private OCSPCheckAuthenticatorFactory ocspCheckAuthenticatorFactory;

    @Mock
    private KeycloakSessionFactory keycloakSessionFactory;
    @Mock
    private Config.Scope scope;
    @Mock
    private KeycloakSession session;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        ocspCheckAuthenticatorFactory = new OCSPCheckAuthenticatorFactory();
        // Alternatively, you can just mock them without field injection:
        // keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        // scope = mock(Config.Scope.class);
        // session = mock(KeycloakSession.class);
    }

    @Test
    void testGetID() {
        String EXPECTED_ID = "p1-ocsp-check";
        assertEquals(EXPECTED_ID, ocspCheckAuthenticatorFactory.getId());
    }

    @Test
    void testCreate() {
        assertNotNull(ocspCheckAuthenticatorFactory.create(session));
    }

    @Test
    void testInit() {
        ocspCheckAuthenticatorFactory.init(scope);
        // No assertion needed; ensure no exceptions are thrown
    }

    @Test
    void testPostInit() {
        ocspCheckAuthenticatorFactory.postInit(keycloakSessionFactory);
        // No assertion needed; ensure no exceptions are thrown
    }

    @Test
    void testClose() {
        ocspCheckAuthenticatorFactory.close();
        // No assertion needed; ensure no exceptions are thrown
    }

    @Test
    void testGetDisplayType() {
        String EXPECTED_DISPLAY_TYPE = "Platform One OCSP Check";
        assertEquals(EXPECTED_DISPLAY_TYPE, ocspCheckAuthenticatorFactory.getDisplayType());
    }

    @Test
    void testGetReferenceCategory() {
        assertNull(ocspCheckAuthenticatorFactory.getReferenceCategory());
    }

    @Test
    void testIsConfigurable() {
        assertFalse(ocspCheckAuthenticatorFactory.isConfigurable());
    }

    @Test
    void testGetRequirementChoices() {
        assertNotNull(ocspCheckAuthenticatorFactory.getRequirementChoices());
    }

    @Test
    void testIsUserSetupAllowed() {
        assertFalse(ocspCheckAuthenticatorFactory.isUserSetupAllowed());
    }

    @Test
    void testGetHelpText() {
        String EXPECTED_HELP_TEXT = "Performs OCSP verification on the user's X.509 certificate.";
        assertEquals(EXPECTED_HELP_TEXT, ocspCheckAuthenticatorFactory.getHelpText());
    }

    @Test
    void testGetConfigProperties() {
        assertTrue(ocspCheckAuthenticatorFactory.getConfigProperties().isEmpty());
    }
}
