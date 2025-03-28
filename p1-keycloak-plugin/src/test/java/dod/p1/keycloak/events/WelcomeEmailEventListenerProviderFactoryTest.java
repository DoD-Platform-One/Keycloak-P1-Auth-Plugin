package dod.p1.keycloak.events;

import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

public class WelcomeEmailEventListenerProviderFactoryTest {

    @Test
    public void testWelcomeEmailEventListenerProviderFactoryDefault() {
        // Mocks
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        Config.Scope config = mock(Config.Scope.class);

        // Constructor
        WelcomeEmailEventListenerProviderFactory factory = new WelcomeEmailEventListenerProviderFactory();

        // create
        assertNotNull(factory.create(session));

        // init
        factory.init(config);

        // postInit
        factory.postInit(keycloakSessionFactory);

        // getId
        assertEquals("WelcomeEmail", factory.getId());

        // close
        factory.close();
    }
}
