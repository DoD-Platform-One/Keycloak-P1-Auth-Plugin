package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for {@link ClientSpecificLoginEventListenerProviderFactory}.
 */
@ExtendWith(MockitoExtension.class)
public class ClientSpecificLoginEventListenerProviderFactoryTest {

    @Mock
    private KeycloakSession keycloakSession;

    @Mock
    private Config.Scope scope;

    @Mock
    private KeycloakSessionFactory keycloakSessionFactory;

    private ClientSpecificLoginEventListenerProviderFactory factory;

    @BeforeEach
    public void setup() {
        factory = new ClientSpecificLoginEventListenerProviderFactory();
    }

    /**
     * Test that the create method returns a non-null instance of ClientSpecificLoginEventListenerProvider.
     */
    @Test
    public void testCreate() {
        ClientSpecificLoginEventListenerProvider provider = factory.create(keycloakSession);
        
        assertNotNull(provider, "Provider should not be null");
        assertTrue(provider instanceof ClientSpecificLoginEventListenerProvider, 
                "Provider should be an instance of ClientSpecificLoginEventListenerProvider");
    }

    /**
     * Test that the init method doesn't throw any exceptions.
     */
    @Test
    public void testInit() {
        // This method doesn't do anything in the implementation, but we should test it doesn't throw
        assertDoesNotThrow(() -> factory.init(scope), "Init method should not throw any exceptions");
    }

    /**
     * Test that the postInit method doesn't throw any exceptions.
     */
    @Test
    public void testPostInit() {
        // This method doesn't do anything in the implementation, but we should test it doesn't throw
        assertDoesNotThrow(() -> factory.postInit(keycloakSessionFactory), 
                "PostInit method should not throw any exceptions");
    }

    /**
     * Test that the close method doesn't throw any exceptions.
     */
    @Test
    public void testClose() {
        // This method doesn't do anything in the implementation, but we should test it doesn't throw
        assertDoesNotThrow(() -> factory.close(), "Close method should not throw any exceptions");
    }

    /**
     * Test that the getId method returns the correct ID.
     */
    @Test
    public void testGetId() {
        String id = factory.getId();
        
        assertEquals("ClientSpecificLogin", id, "ID should be 'ClientSpecificLogin'");
        assertEquals(ClientSpecificLoginEventListenerProviderFactory.ID, id, 
                "ID should match the static ID constant");
    }
}