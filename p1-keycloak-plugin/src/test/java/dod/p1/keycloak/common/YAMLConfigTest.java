package dod.p1.keycloak.common;

import org.junit.jupiter.api.Test;
import org.keycloak.models.GroupModel;
import org.yaml.snakeyaml.Yaml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Test class for YAMLConfig.
 *
 * @see dod.p1.keycloak.common.YAMLConfig
 */
class YAMLConfig_Test {

    @Test
    void testYAMLConfigConstructorAndGettersSetters() {
        // Create a new YAMLConfig instance
        YAMLConfig config = new YAMLConfig();
        
        // Test that it was created successfully
        assertNotNull(config, "YAMLConfig instance should not be null");
        
        // Create and set YAMLConfigX509
        YAMLConfigX509 x509 = new YAMLConfigX509();
        x509.setUserIdentityAttribute("testAttribute");
        config.setX509(x509);
        
        // Test getter
        assertEquals(x509, config.getX509(), "X509 getter should return the set value");
        assertEquals("testAttribute", config.getX509().getUserIdentityAttribute(), 
                "Should be able to access nested properties");
        
        // Test list properties
        List<String> clients = Arrays.asList("client1", "client2");
        config.setGroupProtectionIgnoreClients(clients);
        assertEquals(clients, config.getGroupProtectionIgnoreClients(), 
                "GroupProtectionIgnoreClients getter should return the set value");
        
        List<String> noEmailGroups = Arrays.asList("/group1", "/group2");
        config.setNoEmailMatchAutoJoinGroup(noEmailGroups);
        assertEquals(noEmailGroups, config.getNoEmailMatchAutoJoinGroup(), 
                "NoEmailMatchAutoJoinGroup getter should return the set value");
        
        // Test email match auto join group
        List<YAMLConfigEmailAutoJoin> emailGroups = new ArrayList<>();
        YAMLConfigEmailAutoJoin emailGroup = new YAMLConfigEmailAutoJoin();
        emailGroup.setDescription("Test Email Group");
        emailGroup.setDomains(Arrays.asList("@example.com", ".gov"));
        emailGroup.setGroups(Arrays.asList("/email-group1", "/email-group2"));
        emailGroups.add(emailGroup);
        
        config.setEmailMatchAutoJoinGroup(emailGroups);
        assertEquals(emailGroups, config.getEmailMatchAutoJoinGroup(), 
                "EmailMatchAutoJoinGroup getter should return the set value");
        assertEquals("Test Email Group", config.getEmailMatchAutoJoinGroup().get(0).getDescription(), 
                "Should be able to access nested email group properties");
    }
    
    @Test
    void testYAMLDeserialization() {
        // Create a YAML string
        String yamlStr = 
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
                "      - \".mil\"\n";
        
        // Parse YAML
        Yaml yaml = new Yaml();
        YAMLConfig config = yaml.loadAs(yamlStr, YAMLConfig.class);
        
        // Verify parsed values
        assertNotNull(config, "Parsed config should not be null");
        assertNotNull(config.getX509(), "X509 config should not be null");
        assertEquals("usercertificate", config.getX509().getUserIdentityAttribute(), 
                "UserIdentityAttribute should match YAML value");
        assertEquals("activecac", config.getX509().getUserActive509Attribute(), 
                "UserActive509Attribute should match YAML value");
        
        assertEquals(1, config.getX509().getAutoJoinGroup().size(), 
                "AutoJoinGroup should have 1 entry");
        assertEquals("/test-group", config.getX509().getAutoJoinGroup().get(0), 
                "AutoJoinGroup entry should match YAML value");
        
        assertEquals(2, config.getX509().getRequiredCertificatePolicies().size(), 
                "RequiredCertificatePolicies should have 2 entries");
        assertEquals("policy1", config.getX509().getRequiredCertificatePolicies().get(0), 
                "First policy should match YAML value");
        
        assertEquals(1, config.getGroupProtectionIgnoreClients().size(), 
                "GroupProtectionIgnoreClients should have 1 entry");
        assertEquals("test-client", config.getGroupProtectionIgnoreClients().get(0), 
                "GroupProtectionIgnoreClients entry should match YAML value");
        
        assertEquals(1, config.getNoEmailMatchAutoJoinGroup().size(), 
                "NoEmailMatchAutoJoinGroup should have 1 entry");
        assertEquals("/randos-test-group", config.getNoEmailMatchAutoJoinGroup().get(0), 
                "NoEmailMatchAutoJoinGroup entry should match YAML value");
        
        assertEquals(1, config.getEmailMatchAutoJoinGroup().size(), 
                "EmailMatchAutoJoinGroup should have 1 entry");
        YAMLConfigEmailAutoJoin emailGroup = config.getEmailMatchAutoJoinGroup().get(0);
        assertEquals("Test thing 1", emailGroup.getDescription(), 
                "EmailMatchAutoJoinGroup description should match YAML value");
        assertEquals(2, emailGroup.getGroups().size(), 
                "EmailMatchAutoJoinGroup groups should have 2 entries");
        assertEquals(2, emailGroup.getDomains().size(), 
                "EmailMatchAutoJoinGroup domains should have 2 entries");
    }
}