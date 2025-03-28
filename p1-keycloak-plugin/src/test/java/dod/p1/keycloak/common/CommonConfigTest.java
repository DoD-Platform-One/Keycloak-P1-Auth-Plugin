package dod.p1.keycloak.common;

import dod.p1.keycloak.utils.NewObjectProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.ConstructorException;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import org.keycloak.Config.Scope;

class CommonConfigTest {

    private RealmModel realmModel;
    private KeycloakSession keycloakSession;
    private KeycloakSessionFactory sessionFactory;

    // Static mocks
    private MockedStatic<NewObjectProvider> newObjectProviderMock;
    private MockedStatic<KeycloakModelUtils> keycloakModelUtilsMock;
    private MockedStatic<Config> configMock;
    private AutoCloseable mocks;

    // Test YAML content for default (original) configuration.
    private final String fileContent =
            "x509:\n" +
            "  userIdentityAttribute: \"usercertificate\"\n" +
            "  userActive509Attribute: \"activecac\"\n" +
            "  autoJoinGroup:\n" +
            "    - \"/test-group\"\n" +
            "  requiredCertificatePolicies:\n" +
            "    - \"policy1\"\n" +
            "    - \"policy2\"\n" +
            "groupProtectionIgnoreClients:\n" +
            "  - \"test-client\"\n" +
            "noEmailMatchAutoJoinGroup:\n" +
            "  - \"/randos-test-group\"\n" +
            "emailMatchAutoJoinGroup:\n" +
            "  - description: Test thing 1\n" +
            "    groups:\n" +
            "      - \"/test-group-1-a\"\n" +
            "      - \"/test-group-1-b\"\n" +
            "    domains:\n" +
            "      - \".gov\"\n" +
            "      - \".mil\"\n" +
            "      - \"@afit.edu\"\n" +
            "  - description: Test thing 2\n" +
            "    groups:\n" +
            "      - \"/test-group-2-a\"\n" +
            "    domains:\n" +
            "      - \"@unicorns.com\"\n" +
            "      - \"@merica.test\"\n";

    // Extra valid YAML sample for additional tests (with multi‑realm and group information).
    private final String validYaml =
            "x509:\n" +
            "  userIdentityAttribute: \"usercertificate\"\n" +
            "  userActive509Attribute: \"activecac\"\n" +
            "  autoJoinGroup:\n" +
            "    - \"/group1\"\n" +
            "  requiredCertificatePolicies:\n" +
            "    - \"policy1\"\n" +
            "    - \"policy2\"\n" +
            "groupProtectionIgnoreClients:\n" +
            "  - \"client1\"\n" +
            "noEmailMatchAutoJoinGroup:\n" +
            "  - \"/group2\"\n" +
            "emailMatchAutoJoinGroup:\n" +
            "  - description: \"Email group\"\n" +
            "    groups:\n" +
            "      - \"/group3\"\n" +
            "    domains:\n" +
            "      - \"@example.com\"\n";

    // Malformed YAML sample (missing expected x509 key)
    private final String malformedYaml = "notX509:\n  someKey: value";

    @BeforeEach
    void setup() {
        mocks = MockitoAnnotations.openMocks(this);

        // Create dummy mocks for Keycloak session and realm.
        realmModel = mock(RealmModel.class);
        keycloakSession = mock(KeycloakSession.class);
        sessionFactory = mock(KeycloakSessionFactory.class);
        when(realmModel.getName()).thenReturn("testRealm");
        when(keycloakSession.getKeycloakSessionFactory()).thenReturn(sessionFactory);

        // Static mock for NewObjectProvider – default using fileContent.
        newObjectProviderMock = mockStatic(NewObjectProvider.class);
        newObjectProviderMock.when(() -> NewObjectProvider.getFile(any(String.class)))
                .thenReturn(new File("dummy"));
        newObjectProviderMock.when(() -> NewObjectProvider.getFileInputStream(any(File.class)))
                .thenAnswer(invocation -> new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8)));
        newObjectProviderMock.when(NewObjectProvider::getYaml).thenReturn(new Yaml());

        // Static mock for KeycloakModelUtils.findGroupByPath – return null by default.
        keycloakModelUtilsMock = mockStatic(KeycloakModelUtils.class);
        keycloakModelUtilsMock.when(() -> KeycloakModelUtils.findGroupByPath(any(), any(), anyString()))
                .thenReturn(null);

        // Stub Config.scope(...) for multi‑realm behavior.
        configMock = mockStatic(Config.class);
        Scope scopeMock = mock(Scope.class);
        when(scopeMock.get("enabled", "false")).thenReturn("true");
        configMock.when(() -> Config.scope("multiRealm")).thenReturn(scopeMock);
    }

    @AfterEach
    void tearDown() throws Exception {
        newObjectProviderMock.close();
        keycloakModelUtilsMock.close();
        configMock.close();
        mocks.close();
        CommonConfig.clearInstances();
    }

    // Original tests

    @Test
    void testCommonConfig() {
        CommonConfig commonConfigInstance = CommonConfig.getInstance(keycloakSession, realmModel);
        assertNotNull(commonConfigInstance, "CommonConfig instance should not be null");
    }

    @Test
    void getUserActive509AttributeTest() {
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        assertEquals("activecac", commonConfig.getUserActive509Attribute());
    }

    @Test
    void getNoEmailMatchAutoJoinGroupTest() {
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        List<?> list = commonConfig.getNoEmailMatchAutoJoinGroup().toList();
        assertTrue(list.isEmpty(), "Expected no groups when lookup returns null");
    }

    @Test
    void getUserIdentityAttributeTest() {
        // For realm "baby-yoda", no suffix is appended.
        when(realmModel.getName()).thenReturn("baby-yoda");
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        assertEquals("usercertificate", commonConfig.getUserIdentityAttribute(realmModel));
    }

    @Test
    void getAutoJoinGroupX509Test() {
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        List<?> list = commonConfig.getAutoJoinGroupX509().toList();
        assertTrue(list.isEmpty(), "Expected empty list as group lookup returns null");
    }

    @Test
    void getEmailMatchAutoJoinGroupTest() {
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        List<?> list = commonConfig.getEmailMatchAutoJoinGroup().toList();
        assertEquals(2, list.size(), "Expected two emailMatchAutoJoinGroup entries");
    }

    @Test
    void getIgnoredGroupProtectionClientsTest() {
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        assertEquals(Collections.singletonList("test-client"), commonConfig.getIgnoredGroupProtectionClients());
    }

    @Test
    void getRequiredCertificatePoliciesTest() {
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        List<?> policies = commonConfig.getRequiredCertificatePolicies().toList();
        assertEquals(List.of("policy1", "policy2"), policies);
    }

    // Extra tests for additional scenarios

    @Test
    void testMissingEnvironmentVariable() {
        // Simulate missing env variable by returning null for file lookup.
        newObjectProviderMock.when(() -> NewObjectProvider.getFile(any(String.class))).thenReturn(null);
        Exception ex = assertThrows(NullPointerException.class,
                () -> CommonConfig.getInstance(keycloakSession, realmModel),
                "Expected exception when env var is not set");
        assertNotNull(ex);
    }

    @Test
    void testMalformedYamlParsing() {
        // Use malformed YAML.
        newObjectProviderMock.when(() -> NewObjectProvider.getFileInputStream(any(File.class)))
                .thenAnswer(invocation -> new ByteArrayInputStream(malformedYaml.getBytes(StandardCharsets.UTF_8)));
        Exception ex = assertThrows(ConstructorException.class,
                () -> CommonConfig.getInstance(keycloakSession, realmModel),
                "Expected ConstructorException due to malformed YAML");
        assertNotNull(ex);
    }

    @Test
    void testMultiRealmUserIdentityAttribute() {
        // Use validYaml for this test.
        newObjectProviderMock.when(() -> NewObjectProvider.getFileInputStream(any(File.class)))
                .thenAnswer(invocation -> new ByteArrayInputStream(validYaml.getBytes(StandardCharsets.UTF_8)));
        when(realmModel.getName()).thenReturn("testRealm");
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        String attr = commonConfig.getUserIdentityAttribute(realmModel);
        assertEquals("usercertificate_testRealm", attr, "Expected identity attribute with realm suffix");
    }

    @Test
    void testNonNullGroupConversion() {
        // For autoJoinGroup in validYaml, stub group lookups accordingly.
        newObjectProviderMock.when(() -> NewObjectProvider.getFileInputStream(any(File.class)))
                .thenAnswer(invocation -> new ByteArrayInputStream(validYaml.getBytes(StandardCharsets.UTF_8)));
        keycloakModelUtilsMock.when(() -> KeycloakModelUtils.findGroupByPath(any(), any(), eq("/group1")))
                .thenReturn(mock(GroupModel.class));
        keycloakModelUtilsMock.when(() -> KeycloakModelUtils.findGroupByPath(any(), any(), eq("/group2")))
                .thenReturn(null);
        keycloakModelUtilsMock.when(() -> KeycloakModelUtils.findGroupByPath(any(), any(), eq("/group3")))
                .thenReturn(mock(GroupModel.class));
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        List<GroupModel> groups = commonConfig.getAutoJoinGroupX509().toList();
        // validYaml autoJoinGroup contains "/group1" only.
        assertEquals(1, groups.size(), "Expected one group in autoJoinGroup conversion");
    }

    @Test
    void testValidConfigParsing() {
        newObjectProviderMock.when(() -> NewObjectProvider.getFileInputStream(any(File.class)))
                .thenAnswer(invocation -> new ByteArrayInputStream(validYaml.getBytes(StandardCharsets.UTF_8)));
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        assertEquals("activecac", commonConfig.getUserActive509Attribute());
        assertEquals(Collections.singletonList("client1"), commonConfig.getIgnoredGroupProtectionClients());
        List<?> emailGroups = commonConfig.getEmailMatchAutoJoinGroup().toList();
        // validYaml defines one emailMatchAutoJoinGroup entry.
        assertEquals(1, emailGroups.size(), "Expected one emailMatchAutoJoinGroup entry in validYaml");
        List<?> policies = commonConfig.getRequiredCertificatePolicies().toList();
        assertEquals(List.of("policy1", "policy2"), policies);
    }
}
