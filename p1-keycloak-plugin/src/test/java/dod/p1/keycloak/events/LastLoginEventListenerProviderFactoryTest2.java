package dod.p1.keycloak.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class LastLoginEventListenerProviderFactoryTest2 {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory keycloakSessionFactory;

    @Mock
    private Config.Scope config;

    @Mock
    private RealmProvider realmProvider;

    @Test
    public void testCreateReturnsValidProvider() {
        // Stub session.realms() to avoid NPE in provider constructor
        when(session.realms()).thenReturn(realmProvider);
        
        // Create factory
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();
        
        // Create provider
        Object provider = factory.create(session);
        
        // Verify provider is not null and is of correct type
        assertNotNull(provider);
        assertTrue(provider instanceof LastLoginEventListenerProvider);
    }

    @Test
    public void testInitWithEmptyConfig() {
        // Create factory
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();
        
        // Initialize with empty config
        factory.init(config);
        
        // Stub session.realms() to avoid NPE in provider constructor
        when(session.realms()).thenReturn(realmProvider);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testPostInitDoesNothing() {
        // Create factory
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();
        
        // Call postInit
        factory.postInit(keycloakSessionFactory);
        
        // No assertions needed as postInit is empty, but we're ensuring code coverage
    }

    @Test
    public void testCloseDoesNothing() {
        // Create factory
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();
        
        // Call close
        factory.close();
        
        // No assertions needed as close is empty, but we're ensuring code coverage
    }

    @Test
    public void testGetIdReturnsCorrectValue() {
        // Create factory
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();
        
        // Verify ID matches expected value
        assertEquals("Lastlogin", factory.getId());
        assertEquals(LastLoginEventListenerProviderFactory.ID, factory.getId());
    }

    @Test
    public void testFullLifecycle() {
        // Stub session.realms() to avoid NPE in provider constructor
        when(session.realms()).thenReturn(realmProvider);
        
        // Create factory
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();
        
        // Initialize
        factory.init(config);
        
        // Post-initialize
        factory.postInit(keycloakSessionFactory);
        
        // Create provider
        Object provider = factory.create(session);
        assertNotNull(provider);
        assertTrue(provider instanceof LastLoginEventListenerProvider);
        
        // Get ID
        assertEquals("Lastlogin", factory.getId());
        
        // Close
        factory.close();
    }
}