package dod.p1.keycloak.common;

import dod.p1.keycloak.utils.NewObjectProvider;
import org.apache.commons.io.FilenameUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ Yaml.class, File.class, FileInputStream.class, FilenameUtils.class, NewObjectProvider.class })
@PowerMockIgnore("javax.management.*")
public class CommonConfigTest {

    @Mock
    RealmModel realmModel;
    @Mock
    KeycloakSession keycloakSession;
    @Mock
    File fileMock;
    @Mock
    FileInputStream fileInputStreamMock;
    @Mock
    GroupProvider groupProvider;

    @Before
    public void setupMockBehavior() throws Exception {

        final String fileContent = "x509:\n" +
                "  userIdentityAttribute: \"usercertificate\"\n" +
                "  userActive509Attribute: \"activecac\"\n" +
                "  autoJoinGroup:\n" +
                "    - \"/test-group\"\n" +
                "  requiredCertificatePolicies:\n" +
                "    - \"2.16.840.1.101.2.1.11.36\"\n" +
                "    - \"2.16.840.1.114028.10.1.5\"\n" +
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
                "      - \"@merica.test\"";

        InputStream stream = new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8));

        PowerMockito.whenNew(File.class).withAnyArguments().thenReturn(fileMock);
        PowerMockito.whenNew(FileInputStream.class).withAnyArguments().thenReturn(fileInputStreamMock);

        Yaml yaml = new Yaml();
        YAMLConfig yamlConfig = yaml.loadAs(stream, YAMLConfig.class);

        final Yaml yamlMock = PowerMockito.mock(Yaml.class);
        PowerMockito.whenNew(Yaml.class).withAnyArguments().thenReturn(yamlMock);

        PowerMockito.when(yamlMock.load(any(InputStream.class))).thenReturn(yamlConfig);
        PowerMockito.when(keycloakSession.groups()).thenReturn(groupProvider);
    }

    @Test
    public void testCommonConfig() {

        PowerMockito.mockStatic(FilenameUtils.class);
        PowerMockito.when(FilenameUtils.normalize(System.getenv("CUSTOM_REGISTRATION_CONFIG")))
            .thenReturn("test/filepath/file");

        CommonConfig commonConfigInstance = CommonConfig.getInstance(keycloakSession, realmModel);
    }

    @Test
    public void getEmailMatchAutoJoinGroupTest(){
        // CommonConfig
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);

        // getEmailMatchAutoJoinGroup
        assertNotNull(commonConfig.getEmailMatchAutoJoinGroup());
    }

    @Test
    public void getUserActive509AttributeTest(){
        // CommonConfig
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);

        // getUserActive509Attribute
        assertNotNull(commonConfig.getUserActive509Attribute());
    }

    @Test
    public void getAutoJoinGroupX509Test(){
        // CommonConfig
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);

        // getAutoJoinGroupX509
        assertNotNull(commonConfig.getAutoJoinGroupX509());
    }

    @Test
    public void getNoEmailMatchAutoJoinGroupTest(){
        // CommonConfig
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);

        // getNoEmailMatchAutoJoinGroup
        assertNotNull(commonConfig.getNoEmailMatchAutoJoinGroup());
    }

    @Test
    public void getIgnoredGroupProtectionClientsTest(){
        // CommonConfig
        CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realmModel);

        // getIgnoredGroupProtectionClients
        assertNotNull(commonConfig.getIgnoredGroupProtectionClients());
    }

}
