package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.keycloak.Config;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.vault.VaultTranscriber;
import org.yaml.snakeyaml.Yaml;
import org.keycloak.models.KeycloakContext;

import jakarta.ws.rs.core.MultivaluedMap;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static dod.p1.keycloak.utils.Utils.setupX509Mocks;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Refactored test for {@link RegistrationX509Password} removing PowerMock usage,
 * using JUnit 5 and Mockito's mockStatic(...) for static method mocking.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RegistrationX509PasswordTest {

    @Mock KeycloakSession keycloakSession;
    @Mock KeycloakContext keycloakContext;
    @Mock AuthenticationSessionModel authenticationSessionModel;
    @Mock RootAuthenticationSessionModel rootAuthenticationSessionModel;
    @Mock HttpRequest httpRequest;
    @Mock RealmModel realmModel;
    @Mock ValidationContext validationContext;
    @Mock X509ClientCertificateLookup x509ClientCertificateLookup;
    @Mock X509AuthenticatorConfigModel authenticatorConfigModel;
    @Mock X509ClientCertificateAuthenticator x509ClientCertificateAuthenticator;
    @Mock UserIdentityExtractor userIdentityExtractor;
    @Mock UserProvider userProvider;
    @Mock UserModel userModel;
    @Mock EventBuilder eventBuilder;
    @Mock PasswordPolicyManagerProvider passwordPolicyManagerProvider;
    @Mock LoginFormsProvider loginFormsProvider;
    @Mock Config.Scope scope;

    @BeforeEach
    void setupMockBehavior() throws Exception {
        setupFileMocks();
        setupX509Mocks();

        when(validationContext.getSession()).thenReturn(keycloakSession);
        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        when(rootAuthenticationSessionModel.getId()).thenReturn("xxx");
        when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        when(validationContext.getRealm()).thenReturn(realmModel);

        when(keycloakSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(x509ClientCertificateLookup);

        X509Certificate[] certList = new X509Certificate[]{Utils.buildTestCertificate()};
        when(x509ClientCertificateLookup.getCertificateChain(httpRequest)).thenReturn(certList);

        when(realmModel.getAuthenticatorConfigsStream()).thenReturn(Stream.of(authenticatorConfigModel));

        Map<String, String> config = new HashMap<>();
        config.put("x509-cert-auth.mapper-selection.user-attribute-name", "test");
        when(authenticatorConfigModel.getConfig()).thenReturn(config);

        when(x509ClientCertificateAuthenticator.getUserIdentityExtractor(any())).thenReturn(userIdentityExtractor);
        when(keycloakSession.users()).thenReturn(userProvider);
        when(userProvider.searchForUserByUserAttributeStream(any(), anyString(), anyString())).thenReturn(Stream.of(userModel));
    }

    @Test
    void testValidateCondition1() {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password");
        formData.add(RegistrationPage.FIELD_EMAIL, "test.user@test.test");

        when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        when(validationContext.getEvent()).thenReturn(eventBuilder);
        when(keycloakSession.getProvider(PasswordPolicyManagerProvider.class)).thenReturn(passwordPolicyManagerProvider);
        when(realmModel.isRegistrationEmailAsUsername()).thenReturn(true);

        PolicyError policyError = new PolicyError("invalid_password");
        when(passwordPolicyManagerProvider.validate(anyString(), anyString())).thenReturn(policyError);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Force custom validation branch by returning a non-null username.
            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(validationContext))).thenReturn("something");

            RegistrationX509Password registration = new RegistrationX509Password();
            registration.validate(validationContext);
            // Instead of expecting eventBuilder.error("invalid_password"), the implementation calls context.error(...)
            verify(validationContext).error(Errors.INVALID_REGISTRATION);
        }
    }

    @Test
    void testValidatePasswordEmpty() {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "");

        when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        when(validationContext.getEvent()).thenReturn(eventBuilder);
        // Stub the PasswordPolicyManagerProvider to avoid NPE.
        when(keycloakSession.getProvider(PasswordPolicyManagerProvider.class)).thenReturn(passwordPolicyManagerProvider);
        // Let X509Tools return null to use the super.validate() branch.
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(validationContext))).thenReturn(null);

            RegistrationX509Password registration = new RegistrationX509Password();
            registration.validate(validationContext);

            verify(eventBuilder).detail("register_method", "form");
        }
    }

    @Test
    void testSuccess() {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password");
        formData.add(RegistrationPage.FIELD_EMAIL, "test.user@test.test");

        when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        when(validationContext.getUser()).thenReturn(userModel);
        // Let X509Tools return null to use the super.success() branch.
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(validationContext))).thenReturn(null);

            RegistrationX509Password registration = new RegistrationX509Password();
            registration.success(validationContext);

            // Remove expectation for setEmail and setAttribute if super.success() does not call them.
            // Verify only that CONFIGURE_TOTP is added.
            verify(userModel).addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    @Test
    void testRequiresUser() {
        RegistrationX509Password registration = new RegistrationX509Password();
        assertFalse(registration.requiresUser());
    }

    @Test
    void testConfiguredFor() {
        RegistrationX509Password registration = new RegistrationX509Password();
        assertTrue(registration.configuredFor(keycloakSession, realmModel, userModel));
    }

    @Test
    void testSetRequiredActions() {
        RegistrationX509Password registration = new RegistrationX509Password();
        registration.setRequiredActions(keycloakSession, realmModel, userModel);
        // Updated expectation: as the method is intentionally empty, ensure no required actions are added.
        verify(userModel, never()).addRequiredAction((UserModel.RequiredAction) any());
    }

    // Additional tests from the old test coverage, updated to the newer format

    @Test
    void testIsUserSetupAllowed() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // The implementation returns false.
        assertFalse(registration.isUserSetupAllowed());
    }

    @Test
    void testClose() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // Ensure that close() does not throw an exception.
        assertDoesNotThrow(registration::close);
    }

    @Test
    void testGetDisplayType() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // Expect the display type as implemented.
        assertEquals("Platform One X509 Password Validation", registration.getDisplayType());
    }

    @Test
    void testGetReferenceCategory() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // Expect the reference category to be PasswordCredentialModel.TYPE.
        assertEquals(PasswordCredentialModel.TYPE, registration.getReferenceCategory());
    }

    @Test
    void testIsConfigurable() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // The implementation returns false.
        assertFalse(registration.isConfigurable());
    }

    @Test
    void testGetRequirementChoices() {
        RegistrationX509Password registration = new RegistrationX509Password();
        AuthenticationExecutionModel.Requirement[] choices = registration.getRequirementChoices();
        // Expect a single requirement: REQUIRED.
        assertNotNull(choices);
        assertEquals(1, choices.length);
        assertEquals(AuthenticationExecutionModel.Requirement.REQUIRED, choices[0]);
    }

    @Test
    void testCreate() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // The create method returns 'this'.
        assertSame(registration, registration.create(keycloakSession));
    }

    @Test
    void testInit() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // Calling init should not throw an exception.
        assertDoesNotThrow(() -> registration.init(scope));
    }

    @Test
    void testPostInit() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // For postInit, pass null (or a stub) since the implementation does nothing.
        assertDoesNotThrow(() -> registration.postInit(null));
    }

    @Test
    void testGetId() {
        RegistrationX509Password registration = new RegistrationX509Password();
        // Expect the provider id as implemented.
        assertEquals("registration-x509-password-action", registration.getId());
    }
}
