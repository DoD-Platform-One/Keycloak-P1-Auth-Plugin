package dod.p1.keycloak.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class MattermostEventListenerProviderFactoryTest1 {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory keycloakSessionFactory;

    @Mock
    private Config.Scope config;

    @Test
    public void testCreateReturnsValidProvider() {
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Create provider
        Object provider = factory.create(session);
        
        // Verify provider is not null
        assertNotNull(provider);
    }

    @Test
    public void testInitWithNoConfiguration() {
        // Setup config to return null for all arrays
        when(config.getArray(anyString())).thenReturn(null);
        when(config.get(eq("serverUri"), any())).thenReturn(null);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize with no configuration
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithExcludedEvents() {
        // Setup excluded events
        String[] excludedEvents = {"LOGIN", "LOGOUT", "CODE_TO_TOKEN"};
        when(config.getArray("exclude-events")).thenReturn(excludedEvents);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize with excluded events
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithIncludedAdminEvents() {
        // Setup included admin events
        String[] includedAdminEvents = {"USER", "GROUP", "CLIENT"};
        when(config.getArray("include-admin-events")).thenReturn(includedAdminEvents);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize with included admin events
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithGroupMembershipValues() {
        // Setup group membership values
        String[] groupMembershipValues = {"/group1", "/group2", "/group3"};
        when(config.getArray("group-membership-values")).thenReturn(groupMembershipValues);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize with group membership values
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithServerUri() {
        // Setup server URI
        String serverUri = "https://mattermost.example.com/hooks/webhook-token";
        when(config.get("serverUri", null)).thenReturn(serverUri);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize with server URI
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithAllConfiguration() {
        // Setup all configuration
        String[] excludedEvents = {"LOGIN", "LOGOUT"};
        String[] includedAdminEvents = {"USER", "GROUP"};
        String[] groupMembershipValues = {"/group1", "/group2"};
        String serverUri = "https://mattermost.example.com/hooks/webhook-token";
        
        when(config.getArray("exclude-events")).thenReturn(excludedEvents);
        when(config.getArray("include-admin-events")).thenReturn(includedAdminEvents);
        when(config.getArray("group-membership-values")).thenReturn(groupMembershipValues);
        when(config.get("serverUri", null)).thenReturn(serverUri);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize with all configuration
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testPostInitDoesNothing() {
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Call postInit
        factory.postInit(keycloakSessionFactory);
        
        // No assertions needed as postInit is empty, but we're ensuring code coverage
    }

    @Test
    public void testCloseDoesNothing() {
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Call close
        factory.close();
        
        // No assertions needed as close is empty, but we're ensuring code coverage
    }

    @Test
    public void testGetIdReturnsCorrectValue() {
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Verify ID matches expected value
        assertEquals("Mattermost", factory.getId());
        assertEquals(MattermostEventListenerProviderFactory.ID, factory.getId());
    }

    @Test
    public void testFullLifecycle() {
        // Setup all configuration
        String[] excludedEvents = {"LOGIN", "LOGOUT"};
        String[] includedAdminEvents = {"USER", "GROUP"};
        String[] groupMembershipValues = {"/group1", "/group2"};
        String serverUri = "https://mattermost.example.com/hooks/webhook-token";
        
        when(config.getArray("exclude-events")).thenReturn(excludedEvents);
        when(config.getArray("include-admin-events")).thenReturn(includedAdminEvents);
        when(config.getArray("group-membership-values")).thenReturn(groupMembershipValues);
        when(config.get("serverUri", null)).thenReturn(serverUri);
        
        // Create factory
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();
        
        // Initialize
        factory.init(config);
        
        // Post-initialize
        factory.postInit(keycloakSessionFactory);
        
        // Create provider
        Object provider = factory.create(session);
        assertNotNull(provider);
        
        // Get ID
        assertEquals("Mattermost", factory.getId());
        
        // Close
        factory.close();
    }
}