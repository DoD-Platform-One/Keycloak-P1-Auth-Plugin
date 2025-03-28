package dod.p1.keycloak.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class JBossLoggingExtEventListenerProviderFactoryTest2 {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory keycloakSessionFactory;

    @Mock
    private Config.Scope config;

    @Test
    public void testInitWithCustomLogLevels() {
        // Setup custom log levels
        when(config.get("success-level", "debug")).thenReturn("info");
        when(config.get("error-level", "warn")).thenReturn("error");
        
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Initialize with custom log levels
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithNoExcludedEvents() {
        // Setup default log levels
        when(config.get("success-level", "debug")).thenReturn("debug");
        when(config.get("error-level", "warn")).thenReturn("warn");
        
        // Setup no excluded events
        when(config.getArray("exclude-events")).thenReturn(null);
        
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Initialize with no excluded events
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithMultipleExcludedEvents() {
        // Setup default log levels
        when(config.get("success-level", "debug")).thenReturn("debug");
        when(config.get("error-level", "warn")).thenReturn("warn");
        
        // Setup multiple excluded events
        String[] excludedEvents = {"LOGIN", "LOGOUT", "CODE_TO_TOKEN", "REFRESH_TOKEN"};
        when(config.getArray("exclude-events")).thenReturn(excludedEvents);
        
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Initialize with multiple excluded events
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testInitWithInvalidLogLevel() {
        // Setup invalid log level that will be converted to uppercase
        when(config.get("success-level", "debug")).thenReturn("trace");
        when(config.get("error-level", "warn")).thenReturn("fatal");
        when(config.getArray("exclude-events")).thenReturn(null);
        
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Initialize with invalid log level
        factory.init(config);
        
        // Create provider and verify it's not null
        assertNotNull(factory.create(session));
    }

    @Test
    public void testGetIdReturnsCorrectValue() {
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Verify ID matches expected value
        assertEquals("jboss-logging-ext", factory.getId());
        assertEquals(JBossLoggingExtEventListenerProviderFactory.ID, factory.getId());
    }

    @Test
    public void testPostInitAndClose() {
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Call postInit and close
        factory.postInit(keycloakSessionFactory);
        factory.close();
        
        // No assertions needed as these methods are empty, but we're ensuring code coverage
    }

    @Test
    public void testCreateWithDifferentConfigurations() {
        // Create factory
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();
        
        // Test create without initialization
        assertNotNull(factory.create(session));
        
        // Initialize with some configuration
        when(config.get("success-level", "debug")).thenReturn("info");
        when(config.get("error-level", "warn")).thenReturn("error");
        String[] excludedEvents = {"LOGIN"};
        when(config.getArray("exclude-events")).thenReturn(excludedEvents);
        factory.init(config);
        
        // Test create after initialization
        assertNotNull(factory.create(session));
    }
}