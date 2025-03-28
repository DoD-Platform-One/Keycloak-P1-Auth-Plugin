package dod.p1.keycloak.events;

import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JBossLoggingExtEventListenerProviderFactoryTest {

    @Test
    public void JBossLoggingExtEventListenerProviderFactoryDefaultTest() {
        // Mocks
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        Config.Scope config = mock(Config.Scope.class);

        // Mock config returns
        when(config.get("success-level", "debug")).thenReturn("debug");
        when(config.get("error-level", "warn")).thenReturn("warn");

        // Instantiate
        JBossLoggingExtEventListenerProviderFactory factory =
                new JBossLoggingExtEventListenerProviderFactory();

        // create
        assertNotNull(factory.create(session));

        // init
        factory.init(config);

        // init condition 2
        when(config.getArray("exclude-events")).thenReturn(new String[]{"LOGIN", "LOGOUT"});
        factory.init(config);

        // postInit
        factory.postInit(keycloakSessionFactory);

        // getId
        assertEquals("jboss-logging-ext", factory.getId());

        // close
        factory.close();
    }
}
