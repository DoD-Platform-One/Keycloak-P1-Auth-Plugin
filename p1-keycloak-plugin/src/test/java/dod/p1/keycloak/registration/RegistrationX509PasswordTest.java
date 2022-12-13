package dod.p1.keycloak.registration;
import org.keycloak.*;

import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.Config;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;


@RunWith(PowerMockRunner.class)
@PrepareForTest({ FilenameUtils.class, NewObjectProvider.class })
@PowerMockIgnore("javax.management.*")
class RegistrationX509PasswordTest {

    @Mock
    KeycloakSession keycloakSession;
    @Mock
    KeycloakContext keycloakContext;
    @Mock
    AuthenticationSessionModel authenticationSessionModel;
    @Mock
    RootAuthenticationSessionModel rootAuthenticationSessionModel;
    @Mock
    HttpRequest httpRequest;
    @Mock
    RealmModel realmModel;
    @Mock
    ValidationContext validationContext;
    @Mock
    X509ClientCertificateLookup x509ClientCertificateLookup;
    @Mock
    AuthenticatorConfigModel authenticatorConfigModel;
    @Mock
    X509ClientCertificateAuthenticator x509ClientCertificateAuthenticator;
    @Mock
    UserIdentityExtractor userIdentityExtractor;
    @Mock
    UserProvider userProvider;
    @Mock
    UserModel userModel;
    @Mock
    EventBuilder eventBuilder;
    @Mock
    PasswordPolicyManagerProvider passwordPolicyManagerProvider;
    @Mock
    LoginFormsProvider loginFormsProvider;
    @Mock
    Config.Scope scope;

    public RegistrationX509PasswordTest() {}

    @Before
    public void setupMockBehavior() throws Exception {

        setupFileMocks();

        // common mock implementations
        PowerMockito.when(validationContext.getSession()).thenReturn(keycloakSession);
        PowerMockito.when(keycloakSession.getContext()).thenReturn(keycloakContext);
        PowerMockito.when(keycloakSession.getContext().getAuthenticationSession()).thenReturn(authenticationSessionModel);
        PowerMockito.when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        PowerMockito.when(rootAuthenticationSessionModel.getId()).thenReturn("xxx");
        PowerMockito.when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        PowerMockito.when(validationContext.getRealm()).thenReturn(realmModel);

        // setup X509Tools
        PowerMockito.when(keycloakSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(x509ClientCertificateLookup);

        // create cert array and add the cert
        X509Certificate[] certList = new X509Certificate[1];
        X509Certificate x509Certificate2 = Utils.buildTestCertificate();
        certList[0] = x509Certificate2;
        PowerMockito.when(x509ClientCertificateLookup.getCertificateChain(httpRequest)).thenReturn(certList);

        PowerMockito.when(realmModel.getAuthenticatorConfigsStream()).thenAnswer((stream) -> {
            return Stream.of(authenticatorConfigModel);
        });

        // create map
        Map<String, String> mapSting = new HashMap<>();
        mapSting.put("x509-cert-auth.mapper-selection.user-attribute-name", "test");
        PowerMockito.when(authenticatorConfigModel.getConfig()).thenReturn(mapSting);

        PowerMockito.when(x509ClientCertificateAuthenticator
                .getUserIdentityExtractor(any(X509AuthenticatorConfigModel.class))).thenReturn(userIdentityExtractor);
        PowerMockito.when(keycloakSession.users()).thenReturn(userProvider);
        PowerMockito.when(userProvider.searchForUserByUserAttributeStream(any(RealmModel.class), anyString(), anyString()))
                .thenAnswer((stream) -> {
                    return Stream.of(userModel);
                });

        CryptoIntegration.init(this.getClass().getClassLoader());
    }

    @Test
    public void testGetHelpText() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.getHelpText();
    }

    @Test
    public void testGetConfigProperties() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.getConfigProperties();
    }

    @Test
    public void testValidatePasswordEmpty() {

        MultivaluedMapImpl<String, String>  formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "");

        PowerMockito.when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        PowerMockito.when(validationContext.getEvent()).thenReturn(eventBuilder);

        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.validate(validationContext);

    }

    @Test
    public void testValidate() {

        MultivaluedMapImpl<String, String>  formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password");
        formData.add(RegistrationPage.FIELD_EMAIL, "test.user@test.test");

        PowerMockito.when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        PowerMockito.when(validationContext.getEvent()).thenReturn(eventBuilder);
        PowerMockito.when(validationContext.getSession()).thenReturn(keycloakSession);
        PowerMockito.when(validationContext.getSession().getProvider(PasswordPolicyManagerProvider.class))
            .thenReturn(passwordPolicyManagerProvider);
        PowerMockito.when(validationContext.getRealm().isRegistrationEmailAsUsername()).thenReturn(true);
        PolicyError policyError = new PolicyError("anything", new Object[0]);
        PowerMockito.when(validationContext.getSession().getProvider(PasswordPolicyManagerProvider.class)
             .validate(any(String.class), any(String.class))).thenReturn(policyError);

        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.validate(validationContext);

    }

    @Test
    public void testSuccess() {
        MultivaluedMapImpl<String, String>  formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password");
        formData.add(RegistrationPage.FIELD_EMAIL, "test.user@test.test");

        PowerMockito.when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        PowerMockito.when(validationContext.getUser()).thenReturn(userModel);

        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.success(validationContext);
    }

    @Test
    public void testBuildPage() {
        // force to null
        PowerMockito.when(validationContext.getSession()).thenReturn(null);

        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.buildPage(validationContext, loginFormsProvider );
    }

    @Test
    public void testRequiresUser() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.requiresUser();
    }

    @Test
    public void testconfiguredFor() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.configuredFor(keycloakSession, realmModel, userModel);
    }

    @Test
    public void testSetRequiredActions() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.setRequiredActions(keycloakSession, realmModel, userModel);
    }

    @Test
    public void testIsUserSetupAllowed() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.isUserSetupAllowed();
    }

    @Test
    public void testClose() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.close();
    }

    @Test
    public void testgetDisplayType() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.getDisplayType();
    }

    @Test
    public void testGetReferenceCategory() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.getReferenceCategory();
    }

    @Test
    public void testIsConfigurable() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.isConfigurable();
    }

    @Test
    public void testGetRequirementChoices() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.getRequirementChoices();
    }

    @Test
    public void testCreate() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.create(keycloakSession);
    }

    @Test
    public void testInit() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.init(scope);
    }

    @Test
    public void testPostInit() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.postInit(keycloakSession.getKeycloakSessionFactory());
    }

    @Test
    public void testGetId() {
        RegistrationX509Password registrationX509Password = new RegistrationX509Password();
        registrationX509Password.getId();
    }
}
