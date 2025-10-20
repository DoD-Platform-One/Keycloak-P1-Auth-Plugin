package dod.p1.keycloak.events;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for MattermostProvisioningEventListenerProviderFactory.
 */
@ExtendWith(MockitoExtension.class)
class MattermostProvisioningEventListenerProviderFactoryTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private Config.Scope config;

    @Mock
    private KeycloakSessionFactory sessionFactory;

    private MattermostProvisioningEventListenerProviderFactory factory;

    @BeforeEach
    void setUp() {
        factory = new MattermostProvisioningEventListenerProviderFactory();
    }

    @Test
    void testGetId() {
        // Test that the ID is correct
        assertEquals("mattermost-provisioning", factory.getId());
        assertEquals(MattermostProvisioningEventListenerProviderFactory.ID, factory.getId());
    }

    @Test
    void testCreate() {
        // Mock the session context to return null realm (simplest case)
        org.keycloak.models.KeycloakContext context = mock(org.keycloak.models.KeycloakContext.class);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(null);

        // Create provider
        EventListenerProvider provider = factory.create(session);

        // Verify provider is created
        assertNotNull(provider);
        assertInstanceOf(MattermostProvisioningEventListenerProvider.class, provider);
    }

    @Test
    void testInit() {
        // Call init - should log a message but not throw
        assertDoesNotThrow(() -> factory.init(config));

        // Verify no interactions with config (we just log)
        verifyNoInteractions(config);
    }

    @Test
    void testPostInit() {
        // Call postInit - should do nothing
        assertDoesNotThrow(() -> factory.postInit(sessionFactory));

        // Verify no interactions
        verifyNoInteractions(sessionFactory);
    }

    @Test
    void testClose() {
        // Call close - should do nothing
        assertDoesNotThrow(() -> factory.close());
    }

    @Test
    void testCompleteLifecycle() {
        // Mock the session context
        org.keycloak.models.KeycloakContext context = mock(org.keycloak.models.KeycloakContext.class);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(null);

        // Test complete lifecycle
        factory.init(config);
        factory.postInit(sessionFactory);
        
        EventListenerProvider provider = factory.create(session);
        assertNotNull(provider);
        
        factory.close();

        // Verify everything works without errors
        assertEquals("mattermost-provisioning", factory.getId());
    }
}