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
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Additional tests for CommonConfig to increase code coverage.
 */
class CommonConfigAdditionalTest {

    private RealmModel realmModel;
    private KeycloakSession keycloakSession;
    private KeycloakSessionFactory sessionFactory;

    // Static mocks
    private MockedStatic<NewObjectProvider> newObjectProviderMock;
    private MockedStatic<KeycloakModelUtils> keycloakModelUtilsMock;
    private MockedStatic<Config> configMock;
    private AutoCloseable mocks;

    // YAML with invalid email domain format
    private final String yamlWithInvalidEmailDomain =
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
            "  - description: Test thing with invalid domain\n" +
            "    groups:\n" +
            "      - \"/test-group-1-a\"\n" +
            "    domains:\n" +
            "      - \"invalid-domain\"\n" +  // Invalid domain without . or @ prefix
            "      - \".valid-domain.com\"\n";

    @BeforeEach
    void setup() {
        mocks = MockitoAnnotations.openMocks(this);

        // Create dummy mocks for Keycloak session and realm
        realmModel = mock(RealmModel.class);
        keycloakSession = mock(KeycloakSession.class);
        sessionFactory = mock(KeycloakSessionFactory.class);
        when(realmModel.getName()).thenReturn("testRealm");
        when(keycloakSession.getKeycloakSessionFactory()).thenReturn(sessionFactory);

        // Static mock for NewObjectProvider
        newObjectProviderMock = mockStatic(NewObjectProvider.class);
        newObjectProviderMock.when(() -> NewObjectProvider.getFile(any(String.class)))
                .thenReturn(new File("dummy"));
        newObjectProviderMock.when(() -> NewObjectProvider.getFileInputStream(any(File.class)))
                .thenAnswer(invocation -> new ByteArrayInputStream(yamlWithInvalidEmailDomain.getBytes(StandardCharsets.UTF_8)));
        newObjectProviderMock.when(NewObjectProvider::getYaml).thenReturn(new Yaml());

        // Static mock for KeycloakModelUtils.findGroupByPath
        keycloakModelUtilsMock = mockStatic(KeycloakModelUtils.class);
        keycloakModelUtilsMock.when(() -> KeycloakModelUtils.findGroupByPath(any(), any(), anyString()))
                .thenReturn(null);

        // Stub Config.scope
        configMock = mockStatic(Config.class);
    }

    @AfterEach
    void tearDown() throws Exception {
        newObjectProviderMock.close();
        keycloakModelUtilsMock.close();
        configMock.close();
        mocks.close();
        CommonConfig.clearInstances();
    }

    /**
     * Test for invalid email domain format (lines 72-73, 75).
     */
    @Test
    void testInvalidEmailDomainFormat() {
        // The setup already uses yamlWithInvalidEmailDomain
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        
        // Get email match auto join groups
        List<?> emailGroups = commonConfig.getEmailMatchAutoJoinGroup().toList();
        
        // Should be empty because the invalid domain should have been filtered out
        assertTrue(emailGroups.isEmpty(), "Email groups with invalid domains should be filtered out");
    }

    /**
     * Test config file path from Config.scope (lines 96, 98-99).
     *
     * Note: We can't directly mock System.getenv, but we can test the Config.scope path
     * by ensuring our mock is properly set up and called.
     */
    @Test
    void testConfigFilePathFromScope() {
        // Mock Config.scope to return a non-null scope
        Config.Scope scopeMock = mock(Config.Scope.class);
        when(scopeMock.get(eq("configFilePath"), anyString())).thenReturn("/custom/path/config.yaml");
        configMock.when(() -> Config.scope("customRegistration")).thenReturn(scopeMock);
        
        // Create a new instance to trigger the code path
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        assertNotNull(commonConfig, "CommonConfig should be created successfully");
        
        // Verify that our Config.scope mock was called
        configMock.verify(() -> Config.scope("customRegistration"));
    }

    /**
     * Note: We can't directly test the IOException handling in loadConfigFile (lines 113-116)
     * because it calls System.exit(1), which would terminate the test process.
     *
     * Instead, we'll focus on testing other parts of the code that are more testable.
     */

    /**
     * Test multi-realm configuration in getUserIdentityAttribute when scope is null (line 167).
     */
    @Test
    void testMultiRealmConfigurationWithNullScope() {
        // Mock Config.scope for multiRealm to return null
        configMock.when(() -> Config.scope("multiRealm")).thenReturn(null);
        
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        String attribute = commonConfig.getUserIdentityAttribute(realmModel);
        
        // Should return the plain attribute without realm suffix
        assertEquals("usercertificate", attribute, "Should return plain attribute when multi-realm scope is null");
    }

    /**
     * Test multi-realm configuration in getUserIdentityAttribute when disabled (lines 167, 171).
     */
    @Test
    void testMultiRealmConfigurationDisabled() {
        // Mock Config.scope for multiRealm to return disabled
        Config.Scope scopeMock = mock(Config.Scope.class);
        when(scopeMock.get(eq("enabled"), eq("false"))).thenReturn("false");
        configMock.when(() -> Config.scope("multiRealm")).thenReturn(scopeMock);
        
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        String attribute = commonConfig.getUserIdentityAttribute(realmModel);
        
        // Should return the plain attribute without realm suffix
        assertEquals("usercertificate", attribute, "Should return plain attribute when multi-realm is disabled");
    }

    /**
     * Test multi-realm configuration with non-baby-yoda realm.
     */
    @Test
    void testMultiRealmConfigurationEnabled() {
        // Mock Config.scope for multiRealm to return enabled
        Config.Scope scopeMock = mock(Config.Scope.class);
        when(scopeMock.get(eq("enabled"), eq("false"))).thenReturn("true");
        configMock.when(() -> Config.scope("multiRealm")).thenReturn(scopeMock);
        
        // Use a non-baby-yoda realm
        when(realmModel.getName()).thenReturn("other-realm");
        
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);
        String attribute = commonConfig.getUserIdentityAttribute(realmModel);
        
        // Should return the attribute with realm suffix
        assertEquals("usercertificate_other-realm", attribute, 
                "Should return attribute with realm suffix when multi-realm is enabled and realm is not baby-yoda");
    }

    /**
     * Test singleton pattern with different realms.
     */
    @Test
    void testSingletonPatternWithDifferentRealms() {
        // Create two different realm models
        RealmModel realm1 = mock(RealmModel.class);
        when(realm1.getName()).thenReturn("realm1");
        
        RealmModel realm2 = mock(RealmModel.class);
        when(realm2.getName()).thenReturn("realm2");
        
        // Get instances for both realms
        CommonConfig config1 = CommonConfig.getInstance(keycloakSession, realm1);
        CommonConfig config2 = CommonConfig.getInstance(keycloakSession, realm2);
        
        // Should be different instances
        assertNotSame(config1, config2, "Different realms should have different CommonConfig instances");
        
        // Get instance for realm1 again
        CommonConfig config1Again = CommonConfig.getInstance(keycloakSession, realm1);
        
        // Should be the same instance
        assertSame(config1, config1Again, "Same realm should return the same CommonConfig instance");
    }
}