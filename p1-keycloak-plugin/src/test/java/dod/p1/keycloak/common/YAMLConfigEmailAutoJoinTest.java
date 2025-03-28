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
 * Test class for YAMLConfigEmailAutoJoin.
 *
 * @see dod.p1.keycloak.common.YAMLConfigEmailAutoJoin
 */
class YAMLConfigEmailAutoJoin_Test {

    @Test
    void testYAMLConfigEmailAutoJoinConstructorAndGettersSetters() {
        // Create a new YAMLConfigEmailAutoJoin instance
        YAMLConfigEmailAutoJoin emailAutoJoin = new YAMLConfigEmailAutoJoin();
        
        // Test that it was created successfully
        assertNotNull(emailAutoJoin, "YAMLConfigEmailAutoJoin instance should not be null");
        
        // Test string property
        emailAutoJoin.setDescription("Test Email Auto Join Group");
        assertEquals("Test Email Auto Join Group", emailAutoJoin.getDescription(), 
                "Description getter should return the set value");
        
        // Test list properties
        List<String> groups = Arrays.asList("/group1", "/group2");
        emailAutoJoin.setGroups(groups);
        assertEquals(groups, emailAutoJoin.getGroups(), 
                "Groups getter should return the set value");
        assertEquals(2, emailAutoJoin.getGroups().size(), 
                "Groups should have the correct number of entries");
        
        List<String> domains = Arrays.asList(".gov", "@example.com");
        emailAutoJoin.setDomains(domains);
        assertEquals(domains, emailAutoJoin.getDomains(), 
                "Domains getter should return the set value");
        assertEquals(2, emailAutoJoin.getDomains().size(), 
                "Domains should have the correct number of entries");
        
        // Test GroupModel list
        List<GroupModel> groupModels = new ArrayList<>();
        GroupModel group1 = mock(GroupModel.class);
        GroupModel group2 = mock(GroupModel.class);
        groupModels.add(group1);
        groupModels.add(group2);
        
        emailAutoJoin.setGroupModels(groupModels);
        assertEquals(groupModels, emailAutoJoin.getGroupModels(), 
                "GroupModels getter should return the set value");
        assertEquals(2, emailAutoJoin.getGroupModels().size(), 
                "GroupModels should have the correct number of entries");
    }
    
    @Test
    void testYAMLDeserialization() {
        // Create a YAML string
        String yamlStr = 
                "description: \"Test Email Group\"\n" +
                "groups:\n" +
                "  - \"/email-group-1\"\n" +
                "  - \"/email-group-2\"\n" +
                "domains:\n" +
                "  - \".gov\"\n" +
                "  - \"@example.com\"\n";
        
        // Parse YAML
        Yaml yaml = new Yaml();
        YAMLConfigEmailAutoJoin emailAutoJoin = yaml.loadAs(yamlStr, YAMLConfigEmailAutoJoin.class);
        
        // Verify parsed values
        assertNotNull(emailAutoJoin, "Parsed emailAutoJoin should not be null");
        assertEquals("Test Email Group", emailAutoJoin.getDescription(), 
                "Description should match YAML value");
        
        assertEquals(2, emailAutoJoin.getGroups().size(), 
                "Groups should have 2 entries");
        assertEquals("/email-group-1", emailAutoJoin.getGroups().get(0), 
                "First group should match YAML value");
        assertEquals("/email-group-2", emailAutoJoin.getGroups().get(1), 
                "Second group should match YAML value");
        
        assertEquals(2, emailAutoJoin.getDomains().size(), 
                "Domains should have 2 entries");
        assertEquals(".gov", emailAutoJoin.getDomains().get(0), 
                "First domain should match YAML value");
        assertEquals("@example.com", emailAutoJoin.getDomains().get(1), 
                "Second domain should match YAML value");
        
        // GroupModels is not part of the YAML, so it should be null
        assertNull(emailAutoJoin.getGroupModels(), 
                "GroupModels should be null after deserialization");
    }
}