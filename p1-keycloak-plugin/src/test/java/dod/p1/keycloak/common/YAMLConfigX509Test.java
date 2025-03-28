package dod.p1.keycloak.common;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for YAMLConfigX509.
 *
 * @see dod.p1.keycloak.common.YAMLConfigX509
 */
class YAMLConfigX509_Test {

    @Test
    void testYAMLConfigX509ConstructorAndGettersSetters() {
        // Create a new YAMLConfigX509 instance
        YAMLConfigX509 x509 = new YAMLConfigX509();
        
        // Test that it was created successfully
        assertNotNull(x509, "YAMLConfigX509 instance should not be null");
        
        // Test string properties
        x509.setUserIdentityAttribute("testIdentityAttribute");
        assertEquals("testIdentityAttribute", x509.getUserIdentityAttribute(), 
                "UserIdentityAttribute getter should return the set value");
        
        x509.setUserActive509Attribute("testActiveAttribute");
        assertEquals("testActiveAttribute", x509.getUserActive509Attribute(), 
                "UserActive509Attribute getter should return the set value");
        
        // Test list properties
        List<String> autoJoinGroup = Arrays.asList("/group1", "/group2", "/group3");
        x509.setAutoJoinGroup(autoJoinGroup);
        assertEquals(autoJoinGroup, x509.getAutoJoinGroup(), 
                "AutoJoinGroup getter should return the set value");
        assertEquals(3, x509.getAutoJoinGroup().size(), 
                "AutoJoinGroup should have the correct number of entries");
        
        List<String> policies = Arrays.asList("policy1", "policy2");
        x509.setRequiredCertificatePolicies(policies);
        assertEquals(policies, x509.getRequiredCertificatePolicies(), 
                "RequiredCertificatePolicies getter should return the set value");
        assertEquals(2, x509.getRequiredCertificatePolicies().size(), 
                "RequiredCertificatePolicies should have the correct number of entries");
    }
    
    @Test
    void testYAMLDeserialization() {
        // Create a YAML string
        String yamlStr = 
                "userIdentityAttribute: \"usercertificate\"\n" +
                "userActive509Attribute: \"activecac\"\n" +
                "autoJoinGroup:\n" +
                "  - \"/test-group-1\"\n" +
                "  - \"/test-group-2\"\n" +
                "requiredCertificatePolicies:\n" +
                "  - \"policy1\"\n" +
                "  - \"policy2\"\n" +
                "  - \"policy3\"\n";
        
        // Parse YAML
        Yaml yaml = new Yaml();
        YAMLConfigX509 x509 = yaml.loadAs(yamlStr, YAMLConfigX509.class);
        
        // Verify parsed values
        assertNotNull(x509, "Parsed x509 should not be null");
        assertEquals("usercertificate", x509.getUserIdentityAttribute(), 
                "UserIdentityAttribute should match YAML value");
        assertEquals("activecac", x509.getUserActive509Attribute(), 
                "UserActive509Attribute should match YAML value");
        
        assertEquals(2, x509.getAutoJoinGroup().size(), 
                "AutoJoinGroup should have 2 entries");
        assertEquals("/test-group-1", x509.getAutoJoinGroup().get(0), 
                "First AutoJoinGroup entry should match YAML value");
        assertEquals("/test-group-2", x509.getAutoJoinGroup().get(1), 
                "Second AutoJoinGroup entry should match YAML value");
        
        assertEquals(3, x509.getRequiredCertificatePolicies().size(), 
                "RequiredCertificatePolicies should have 3 entries");
        assertEquals("policy1", x509.getRequiredCertificatePolicies().get(0), 
                "First policy should match YAML value");
        assertEquals("policy2", x509.getRequiredCertificatePolicies().get(1), 
                "Second policy should match YAML value");
        assertEquals("policy3", x509.getRequiredCertificatePolicies().get(2), 
                "Third policy should match YAML value");
    }
}