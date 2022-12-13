package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.UserModelDefaultMethodsImpl;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.models.*;
import org.keycloak.services.validation.Validation;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;


@RunWith(PowerMockRunner.class)
@PrepareForTest({ Yaml.class, FileInputStream.class, File.class, CommonConfig.class, FilenameUtils.class, NewObjectProvider.class})
@PowerMockIgnore("javax.management.*")
class RegistrationValidation2Test {

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

    public RegistrationValidation2Test() {}

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
    public void testSuccess() {

        UserModelDefaultMethodsImpl userModelDefaultMethodsImpl = new UserModelDefaultMethodsImpl();
        PowerMockito.when(validationContext.getUser()).thenReturn(userModelDefaultMethodsImpl);
        PowerMockito.when(validationContext.getRealm()).thenReturn(realmModel);

        MultivaluedMapImpl<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(Validation.FIELD_EMAIL, "test.user@test.bad");

        PowerMockito.when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        RegistrationValidation registrationValidation = new RegistrationValidation();
        registrationValidation.success(validationContext);
    }

    @Test
    public void testSuccessNoX509() throws GeneralSecurityException {

        // force no cert
        PowerMockito.when(x509ClientCertificateLookup.getCertificateChain(httpRequest)).thenReturn(null);

        UserModelDefaultMethodsImpl userModelDefaultMethodsImpl = new UserModelDefaultMethodsImpl();
        PowerMockito.when(validationContext.getUser()).thenReturn(userModelDefaultMethodsImpl);
        PowerMockito.when(validationContext.getRealm()).thenReturn(realmModel);

        MultivaluedMapImpl<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(Validation.FIELD_EMAIL, "test.user@test.bad");

        PowerMockito.when(validationContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        RegistrationValidation registrationValidation = new RegistrationValidation();
        registrationValidation.success(validationContext);
    }
}
