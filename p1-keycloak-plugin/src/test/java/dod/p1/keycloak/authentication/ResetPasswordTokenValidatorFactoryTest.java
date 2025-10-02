package dod.p1.keycloak.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for ResetPasswordTokenValidatorFactory.
 */
@ExtendWith(MockitoExtension.class)
class ResetPasswordTokenValidatorFactoryTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory sessionFactory;

    @Mock
    private Config.Scope config;

    private ResetPasswordTokenValidatorFactory factory;

    @BeforeEach
    void setUp() {
        factory = new ResetPasswordTokenValidatorFactory();
    }

    @Test
    void testGetDisplayType() {
        String displayType = factory.getDisplayType();
        assertEquals("Reset Password Token Validator", displayType);
    }

    @Test
    void testGetReferenceCategory() {
        String referenceCategory = factory.getReferenceCategory();
        assertEquals("Reset Password", referenceCategory);
    }

    @Test
    void testIsConfigurable() {
        assertFalse(factory.isConfigurable());
    }

    @Test
    void testGetRequirementChoices() {
        AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();
        assertNotNull(requirements);
        assertEquals(2, requirements.length);
        assertEquals(AuthenticationExecutionModel.Requirement.REQUIRED, requirements[0]);
        assertEquals(AuthenticationExecutionModel.Requirement.DISABLED, requirements[1]);
    }

    @Test
    void testIsUserSetupAllowed() {
        assertFalse(factory.isUserSetupAllowed());
    }

    @Test
    void testGetHelpText() {
        String helpText = factory.getHelpText();
        assertEquals("Validates that the reset password token is the most recent one for the user.", helpText);
    }

    @Test
    void testGetConfigProperties() {
        List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
        assertNotNull(configProperties);
        assertTrue(configProperties.isEmpty());
    }

    @Test
    void testCreate() {
        Authenticator authenticator = factory.create(session);
        assertNotNull(authenticator);
        assertInstanceOf(ResetPasswordTokenValidator.class, authenticator);
    }

    @Test
    void testInit() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.init(config));
    }

    @Test
    void testPostInit() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.postInit(sessionFactory));
    }

    @Test
    void testClose() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.close());
    }

    @Test
    void testGetId() {
        String id = factory.getId();
        assertEquals("reset-password-token-validator", id);
        assertEquals(ResetPasswordTokenValidatorFactory.PROVIDER_ID, id);
    }

    @Test
    void testProviderIdConstant() {
        assertEquals("reset-password-token-validator", ResetPasswordTokenValidatorFactory.PROVIDER_ID);
    }

    @Test
    void testCreateMultipleInstances() {
        Authenticator authenticator1 = factory.create(session);
        Authenticator authenticator2 = factory.create(session);
        
        assertNotNull(authenticator1);
        assertNotNull(authenticator2);
        assertNotSame(authenticator1, authenticator2);
        assertInstanceOf(ResetPasswordTokenValidator.class, authenticator1);
        assertInstanceOf(ResetPasswordTokenValidator.class, authenticator2);
    }

    @Test
    void testFactoryLifecycle() {
        // Test the complete lifecycle
        assertDoesNotThrow(() -> {
            factory.init(config);
            factory.postInit(sessionFactory);
            
            Authenticator authenticator = factory.create(session);
            assertNotNull(authenticator);
            
            factory.close();
        });
    }
}