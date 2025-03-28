package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.OCSPUtils;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import java.util.List;
import java.util.ArrayList;
import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static dod.p1.keycloak.utils.Utils.setupX509Mocks;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class UpdateX509Test {

    // Disable FIPS mode to avoid loading the FIPS provider.
    static {
        System.setProperty("keycloak.crypto.fips-mode", "false");
        System.setProperty("keycloak.fips", "false");
    }

    // Global stub for Config.scope("babyYodaOcsp")
    private MockedStatic<Config> globalConfigMock;
    private Config.Scope globalMockScope;

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
    X509AuthenticatorConfigModel authenticatorConfigModel;
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

    public UpdateX509Test() {
    }

    @BeforeEach
    public void globalConfigStub() {
        globalConfigMock = Mockito.mockStatic(Config.class);
        globalMockScope = Mockito.mock(Config.Scope.class);
        globalConfigMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(globalMockScope);
        // Default value; tests can override as needed.
        when(globalMockScope.get("enabled", "false")).thenReturn("false");
    }

    @AfterEach
    public void closeGlobalConfigStub() {
        globalConfigMock.close();
    }

    @BeforeEach
    public void setupMockBehavior() throws Exception {
        setupFileMocks();

        // Global stub: always return userModel from requiredActionContext.getUser()
        when(requiredActionContext.getUser()).thenReturn(userModel);

        // Common mock implementations
        when(requiredActionContext.getSession()).thenReturn(keycloakSession);
        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        when(rootAuthenticationSessionModel.getId()).thenReturn("xxx");
        when(requiredActionContext.getHttpRequest()).thenReturn(httpRequest);
        when(requiredActionContext.getRealm()).thenReturn(realmModel);

        // Setup X509 tools
        when(keycloakSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(x509ClientCertificateLookup);

        // Create cert array and add the cert
        X509Certificate[] certList = new X509Certificate[1];
        X509Certificate x509Certificate2 = Utils.buildTestCertificate();
        certList[0] = x509Certificate2;
        when(x509ClientCertificateLookup.getCertificateChain(httpRequest)).thenReturn(certList);

        // Realm config
        when(realmModel.getAuthenticatorConfigsStream()).thenAnswer((stream) -> Stream.of(authenticatorConfigModel));

        // Create map for authenticator config
        Map<String, String> mapString = new HashMap<>();
        mapString.put("x509-cert-auth.mapper-selection.user-attribute-name", "test");
        when(authenticatorConfigModel.getConfig()).thenReturn(mapString);

        when(x509ClientCertificateAuthenticator.getUserIdentityExtractor(any(X509AuthenticatorConfigModel.class)))
                .thenReturn(userIdentityExtractor);
        when(keycloakSession.users()).thenReturn(userProvider);
        when(userProvider.searchForUserByUserAttributeStream(any(RealmModel.class), anyString(), anyString()))
                .thenAnswer(inv -> Stream.of(userModel));

        // Removed CryptoIntegration.init(...) call to avoid FIPS provider initialization.
    }

    @Test
    public void testEvaluateTriggersCondition1() throws Exception {
        try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = Mockito.mockStatic(CommonConfig.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = Mockito.mockStatic(OCSPUtils.class)) {

            // Stub X509Tools.getX509Username
            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(requiredActionContext)))
                    .thenReturn("something");

            // Stub CommonConfig.getInstance(...)
            CommonConfig commonConfig = Mockito.mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(eq(keycloakSession), eq(realmModel)))
                    .thenReturn(commonConfig);

            when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
            when(authenticationSessionModel.getAuthNote("IGNORE_X509")).thenReturn("authNote");

            // Create cert array
            X509Certificate[] certList = new X509Certificate[1];
            X509Certificate x509Certificate2 = Utils.buildTestCertificate();
            certList[0] = x509Certificate2;
            when(requiredActionContext.getHttpRequest().getClientCertificateChain())
                    .thenReturn(certList);

            // Stub user attributes
            Map<String, List<String>> mapString = new HashMap<>();
            List<String> listString = new ArrayList<>();
            listString.add("some value");
            mapString.put("usercertificate", listString);
            when(userModel.getAttributes()).thenReturn(mapString);

            UpdateX509 updateX509 = new UpdateX509();
            updateX509.evaluateTriggers(requiredActionContext);

            // Now change stubs for different conditions
            mapString = new HashMap<>();
            mapString.put("usercertificate", new ArrayList<>());
            when(authenticationSessionModel.getAuthNote("IGNORE_X509")).thenReturn(null);
            when(userModel.getAttributes()).thenReturn(mapString);
            updateX509.evaluateTriggers(requiredActionContext);

            mapString = new HashMap<>();
            mapString.put("usercertificate", null);
            when(userModel.getAttributes()).thenReturn(mapString);
            updateX509.evaluateTriggers(requiredActionContext);

            mapString = new HashMap<>();
            mapString.put("no valid value", new ArrayList<>());
            when(userModel.getAttributes()).thenReturn(mapString);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(eq(requiredActionContext))).thenReturn(true);
            updateX509.evaluateTriggers(requiredActionContext);

            x509ToolsMock.when(() -> X509Tools.extractUPN(x509Certificate2)).thenReturn("extractUPN");
            updateX509.evaluateTriggers(requiredActionContext);

            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(x509Certificate2, 0, 0))
                    .thenReturn("policyID");
            updateX509.evaluateTriggers(requiredActionContext);

            x509ToolsMock.when(() -> X509Tools.extractURN(x509Certificate2)).thenReturn("urn");
            updateX509.evaluateTriggers(requiredActionContext);

            // Override global config stub to return "true" for babyYodaOcsp.enabled
            when(globalMockScope.get("enabled", "false")).thenReturn("true");
            updateX509.evaluateTriggers(requiredActionContext);

            // Reuse the same ocspUtilsMock to change its behavior:
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(null);
            updateX509.evaluateTriggers(requiredActionContext);

            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(new X509Certificate[]{});
            updateX509.evaluateTriggers(requiredActionContext);
        }
    }

    @Test
    public void testEvaluateTriggersCondition2() throws Exception {
        try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class)) {

            when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
            when(requiredActionContext.getUser()).thenReturn(userModel);
            when(userModel.getUsername()).thenReturn("an awesome username");

            // #1: getX509Username -> null, authNote -> "authNote"
            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(requiredActionContext))).thenReturn(null);
            when(authenticationSessionModel.getAuthNote("IGNORE_X509")).thenReturn("authNote");
            UpdateX509 updateX509 = new UpdateX509();
            updateX509.evaluateTriggers(requiredActionContext);

            // #2: getX509Username -> null, authNote -> null
            when(authenticationSessionModel.getAuthNote("IGNORE_X509")).thenReturn(null);
            updateX509.evaluateTriggers(requiredActionContext);

            // #3: getX509Username -> null, authNote -> "true"
            when(authenticationSessionModel.getAuthNote("IGNORE_X509")).thenReturn("true");
            updateX509.evaluateTriggers(requiredActionContext);

            // #4: getX509Username -> "something", authNote -> "true"
            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(requiredActionContext))).thenReturn("something");
            updateX509.evaluateTriggers(requiredActionContext);
        }
    }

    @Test
    public void testRequiredActionChallengeCondition1() throws Exception {
        setupX509Mocks();
        when(requiredActionContext.form()).thenReturn(loginFormsProvider);
        when(requiredActionContext.getUser()).thenReturn(userModel);
        when(userModel.getUsername()).thenReturn("an awesome username");
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.requiredActionChallenge(requiredActionContext);
    }

    @Test
    public void testRequiredActionChallengeCondition2() throws Exception {
        setupX509Mocks();
        when(requiredActionContext.form()).thenReturn(loginFormsProvider);
        when(requiredActionContext.getUser()).thenReturn(userModel);
        when(userModel.getUsername()).thenReturn("an awesome username");
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.requiredActionChallenge(requiredActionContext);
    }

    @Test
    public void testProcessActionCancel() throws Exception {
        setupX509Mocks();
        MultivaluedMapImpl<String, String> formData = new MultivaluedMapImpl<>();
        formData.add("cancel", "");
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        when(requiredActionContext.getUser()).thenReturn(userModel);
        when(userModel.getUsername()).thenReturn("an awesome username");
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.processAction(requiredActionContext);
    }

    @Test
    public void testProcessAction() throws Exception {
        setupX509Mocks();
        // CONDITION 1
        MultivaluedMapImpl<String, String> formData = new MultivaluedMapImpl<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        when(requiredActionContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.processAction(requiredActionContext);

        // CONDITION 2
        try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = Mockito.mockStatic(CommonConfig.class)) {

            x509ToolsMock.when(() -> X509Tools.getX509Username(eq(requiredActionContext)))
                    .thenReturn("something");
            CommonConfig commonConfig = Mockito.mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(eq(keycloakSession), eq(realmModel)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(eq(realmModel))).thenReturn("an attribute");
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.empty());
            updateX509.processAction(requiredActionContext);
        }
    }

    @Test
    public void testInit() {
        UpdateX509 updateX509 = new UpdateX509();
        updateX509.init(scope);
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
