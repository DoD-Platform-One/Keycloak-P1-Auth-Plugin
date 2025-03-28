package dod.p1.keycloak.authentication;

import dod.p1.keycloak.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Refactored unit test for {@link RequireGroupAuthenticatorFactory}, removing PowerMock
 * and using JUnit 5 + Mockito.
 */
class RequireGroupAuthenticatorFactoryTest {

    public static final String EXPECTED_ID = "p1-group-restriction";
    public static final String EXPECTED_NAME = "Platform One Group Authentication Validation";

    private RequireGroupAuthenticatorFactory subjectUnderTest;

    @BeforeEach
    void setup() throws Exception {
        // If your setupFileMocks() references static methods, you may need to replicate
        // that with mockStatic(...) blocks, or adapt as needed.
        Utils.setupFileMocks(); // If this doesn't rely on PowerMock

        subjectUnderTest = new RequireGroupAuthenticatorFactory();
    }

    @Test
    void testShouldCreateExpectedEndpoint() {
        String actualEndpoint = subjectUnderTest.getId();
        assertEquals(EXPECTED_ID, actualEndpoint);
    }

    @Test
    void testShouldCreateAuthenticatorProvider() {
        KeycloakSession mockSession = mock(KeycloakSession.class);
        Authenticator actualProvider = subjectUnderTest.create(mockSession);
        assertEquals(RequireGroupAuthenticator.class, actualProvider.getClass());
    }

    @Test
    void testShouldNameTheModuleProperly() {
        String actualName = subjectUnderTest.getDisplayType();
        assertEquals(EXPECTED_NAME, actualName);
    }

    @Test
    void testShouldForceAuthenticatorAsRequired() {
        AuthenticationExecutionModel.Requirement[] actualRequirementChoices =
                subjectUnderTest.getRequirementChoices();
        AuthenticationExecutionModel.Requirement firstChoice =
                Arrays.stream(actualRequirementChoices).findFirst().orElse(null);

        // We expect exactly one choice: REQUIRED
        assertEquals(1, actualRequirementChoices.length);
        assertEquals(AuthenticationExecutionModel.Requirement.REQUIRED, firstChoice);
    }

    @Test
    void testShouldSetupOverrides() {
        // Void overrides, just ensure they do not throw exceptions
        subjectUnderTest.init(null);
        subjectUnderTest.postInit(null);
        subjectUnderTest.close();

        assertNull(subjectUnderTest.getReferenceCategory(),
                "Reference category should be null");
        assertFalse(subjectUnderTest.isConfigurable(),
                "Factory should not be configurable");
        assertFalse(subjectUnderTest.isUserSetupAllowed(),
                "User setup should not be allowed");
        assertNull(subjectUnderTest.getHelpText(),
                "Help text should be null if not defined");
        assertEquals(new ArrayList<ProviderConfigProperty>(),
                subjectUnderTest.getConfigProperties(),
                "No config properties should be defined");
    }
}
