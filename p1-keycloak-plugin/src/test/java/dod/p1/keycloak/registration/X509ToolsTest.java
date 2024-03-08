package dod.p1.keycloak.registration;
import dod.p1.keycloak.utils.ZacsOCSPProvider;
import org.keycloak.*;

import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.keycloak.crypto.def.BCOCSPProvider;
import org.keycloak.http.HttpRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.common.crypto.*;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.models.*;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static dod.p1.keycloak.registration.X509Tools.isX509Registered;
import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.whenNew;


@RunWith(PowerMockRunner.class)
@PrepareForTest({ FilenameUtils.class, NewObjectProvider.class, BCOCSPProvider.class, ZacsOCSPProvider.class })
@PowerMockIgnore("javax.management.*")
class X509ToolsTest {

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
    GroupProvider groupProvider;
//    @Mock
//    ZacsOCSPProvider ocspProvider;

    public X509ToolsTest(){};

    @Before
    public void setupMockBehavior() throws Exception {

        setupFileMocks();

        // Vars
        List<String> stringList = new ArrayList<>();
        stringList.add("value1");
        stringList.add("value2");

//        List<URI> uriList = new ArrayList<>();
//        stringList.add("http://redirect1.com");
//        stringList.add("http://redirect2.com");

//        // ZacsOCSPProvider
//        mockStatic(ZacsOCSPProvider.class);
//        PowerMockito.whenNew(ZacsOCSPProvider.class).withNoArguments().thenReturn(ocspProvider);
//        PowerMockito.when(ocspProvider.getResponderURIsPublic(any())).thenReturn(stringList);

        // common mock implementations
        PowerMockito.when(validationContext.getSession()).thenReturn(keycloakSession);
        PowerMockito.when(keycloakSession.getContext()).thenReturn(keycloakContext);
        PowerMockito.when(keycloakSession.getContext().getAuthenticationSession()).thenReturn(authenticationSessionModel);
        PowerMockito.when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        PowerMockito.when(rootAuthenticationSessionModel.getId()).thenReturn("xxx");
        PowerMockito.when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        PowerMockito.when(validationContext.getRealm()).thenReturn(realmModel);
        PowerMockito.when(keycloakSession.groups()).thenReturn(groupProvider);

        CryptoIntegration.init(this.getClass().getClassLoader());
    }

    @Test
    public void testIsX509RegisteredFalse() {

        boolean isRegistered = isX509Registered(validationContext);
        Assert.assertFalse(isRegistered);

    }

    @Test
    public void testIsX509RegisteredTrue() throws Exception {

        PowerMockito.when(keycloakSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(x509ClientCertificateLookup);

        // create cert array and add the cert
        X509Certificate[] certList = new X509Certificate[1];
        X509Certificate x509Certificate2 = Utils.buildTestCertificate();
        certList[0] = x509Certificate2;
        PowerMockito.when(x509ClientCertificateLookup.getCertificateChain(httpRequest)).thenReturn(certList);

//        PowerMockito.when(realmModel.getAuthenticatorConfigsStream()).thenAnswer( (stream) -> {
//            return Stream.of(authenticatorConfigModel);
//        });
//
//        // create map
//        Map<String, String> mapSting = new HashMap<>();
//        mapSting.put("x509-cert-auth.mapper-selection.user-attribute-name","test");
//        PowerMockito.when(authenticatorConfigModel.getConfig()).thenReturn(mapSting);
//
//        PowerMockito.when(x509ClientCertificateAuthenticator
//                .getUserIdentityExtractor(any(X509AuthenticatorConfigModel.class))).thenReturn(userIdentityExtractor);
//        PowerMockito.when(keycloakSession.users()).thenReturn(userProvider);
//        PowerMockito.when(userProvider.searchForUserByUserAttributeStream( any(RealmModel.class), anyString(), anyString() ))
//                .thenAnswer( (stream) -> {
//                    return Stream.of(userModel);
//                });

//        boolean isRegistered = isX509Registered(validationContext);
//        Assert.assertTrue(isRegistered);
//        Assert.assertFalse(isRegistered);
    }
}
