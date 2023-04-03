package dod.p1.keycloak.registration;
import org.keycloak.*;

import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.http.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.common.crypto.*;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
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
class UpdateX509Test {

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
    RequiredActionContext requiredActionContext;
    @Mock
    LoginFormsProvider loginFormsProvider;
    @Mock
    Config.Scope scope;

    public UpdateX509Test() {}

    @Before
    public void setupMockBehavior() throws Exception {

        setupFileMocks();

        // common mock implementations
        PowerMockito.when(requiredActionContext.getSession()).thenReturn(keycloakSession);
        PowerMockito.when(keycloakSession.getContext()).thenReturn(keycloakContext);
        PowerMockito.when(keycloakSession.getContext().getAuthenticationSession()).thenReturn(authenticationSessionModel);
        PowerMockito.when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        PowerMockito.when(rootAuthenticationSessionModel.getId()).thenReturn("xxx");
        PowerMockito.when(requiredActionContext.getHttpRequest()).thenReturn(httpRequest);
        PowerMockito.when(requiredActionContext.getRealm()).thenReturn(realmModel);

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
    public void testEvaluateTriggers() throws Exception {
        PowerMockito.when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        PowerMockito.when(requiredActionContext.getAuthenticationSession().getAuthNote("IGNORE_X509")).thenReturn("authNote");

        // create cert array and add the cert
        X509Certificate[] certList = new X509Certificate[1];
        X509Certificate x509Certificate2 = Utils.buildTestCertificate();
        certList[0] = x509Certificate2;

        PowerMockito.when(requiredActionContext.getHttpRequest().getClientCertificateChain())
            .thenReturn(certList);
        PowerMockito.when(requiredActionContext.getUser()).thenReturn(userModel);

        UpdateX509 updateX509 = new UpdateX509();
        updateX509.evaluateTriggers(requiredActionContext);
    }

    @Test
    public void testRequiredActionChallenge() throws Exception {
        PowerMockito.when(requiredActionContext.form()).thenReturn(loginFormsProvider);

        UpdateX509 updateX509 = new UpdateX509();
        updateX509.requiredActionChallenge(requiredActionContext);
    }

    @Test
    public void testProcessActionCancel() throws Exception {
        MultivaluedMapImpl<String, String> formData = new MultivaluedMapImpl<>();
        formData.add("cancel", "");

        PowerMockito.when(requiredActionContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        PowerMockito.when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);

        UpdateX509 updateX509 = new UpdateX509();
        updateX509.processAction(requiredActionContext);
    }

    @Test
    public void testProcessAction() throws Exception {
        MultivaluedMapImpl<String, String> formData = new MultivaluedMapImpl<>();

        PowerMockito.when(requiredActionContext.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);
        PowerMockito.when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        PowerMockito.when(requiredActionContext.getUser()).thenReturn(userModel);

        UpdateX509 updateX509 = new UpdateX509();
        updateX509.processAction(requiredActionContext);
    }

    @Test
    public void testGetDisplayText() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.getDisplayText();
    }

    @Test
    public void testIsOneTimeAction() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.isOneTimeAction();
    }

    @Test
    public void testCreate() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.create(keycloakSession);
    }

    @Test
    public void testPostInit() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.postInit(keycloakSession.getKeycloakSessionFactory());
    }

    @Test
    public void testClose() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.close();
    }

    @Test
    public void testGetId() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.getId();
    }

}
