package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for ResetPasswordProviderFactory.
 */
@ExtendWith(MockitoExtension.class)
class ResetPasswordProviderFactoryTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory sessionFactory;

    @Mock
    private Config.Scope config;

    private ResetPasswordProviderFactory factory;

    @BeforeEach
    void setUp() {
        factory = new ResetPasswordProviderFactory();
    }

    @Test
    void testCreate() {
        EventListenerProvider provider = factory.create(session);
        
        assertNotNull(provider);
        assertInstanceOf(ResetPasswordProvider.class, provider);
    }

    @Test
    void testCreateMultipleInstances() {
        EventListenerProvider provider1 = factory.create(session);
        EventListenerProvider provider2 = factory.create(session);
        
        assertNotNull(provider1);
        assertNotNull(provider2);
        assertNotSame(provider1, provider2);
        assertInstanceOf(ResetPasswordProvider.class, provider1);
        assertInstanceOf(ResetPasswordProvider.class, provider2);
    }

    @Test
    void testInit() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.init(config));
    }

    @Test
    void testPostInit() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.postInit(sessionFactory));
    }

    @Test
    void testClose() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.close());
    }

    @Test
    void testGetId() {
        String id = factory.getId();
        assertEquals("reset-password", id);
    }

    @Test
    void testFactoryLifecycle() {
        // Test the complete lifecycle
        assertDoesNotThrow(() -> {
            factory.init(config);
            factory.postInit(sessionFactory);
            
            EventListenerProvider provider = factory.create(session);
            assertNotNull(provider);
            
            factory.close();
        });
    }

    @Test
    void testCreateWithNullSession() {
        EventListenerProvider provider = factory.create(null);
        
        assertNotNull(provider);
        assertInstanceOf(ResetPasswordProvider.class, provider);
    }

    @Test
    void testInitWithNullConfig() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.init(null));
    }

    @Test
    void testPostInitWithNullFactory() {
        // Should not throw any exception
        assertDoesNotThrow(() -> factory.postInit(null));
    }

    @Test
    void testMultipleInitCalls() {
        // Multiple init calls should not cause issues
        assertDoesNotThrow(() -> {
            factory.init(config);
            factory.init(config);
            factory.init(null);
        });
    }

    @Test
    void testMultiplePostInitCalls() {
        // Multiple postInit calls should not cause issues
        assertDoesNotThrow(() -> {
            factory.postInit(sessionFactory);
            factory.postInit(sessionFactory);
            factory.postInit(null);
        });
    }

    @Test
    void testMultipleCloseCalls() {
        // Multiple close calls should not cause issues
        assertDoesNotThrow(() -> {
            factory.close();
            factory.close();
        });
    }

    @Test
    void testCreateAfterClose() {
        factory.close();
        
        EventListenerProvider provider = factory.create(session);
        
        assertNotNull(provider);
        assertInstanceOf(ResetPasswordProvider.class, provider);
    }

    @Test
    void testFactoryState() {
        // Factory should be stateless and reusable
        EventListenerProvider provider1 = factory.create(session);
        factory.init(config);
        EventListenerProvider provider2 = factory.create(session);
        factory.postInit(sessionFactory);
        EventListenerProvider provider3 = factory.create(session);
        factory.close();
        EventListenerProvider provider4 = factory.create(session);
        
        assertNotNull(provider1);
        assertNotNull(provider2);
        assertNotNull(provider3);
        assertNotNull(provider4);
        
        assertNotSame(provider1, provider2);
        assertNotSame(provider2, provider3);
        assertNotSame(provider3, provider4);
    }
}