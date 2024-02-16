package dod.p1.keycloak.events;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({})
public class JBossLoggingExtEventListenerProviderFactoryTest {

    @Test
    public void JBossLoggingExtEventListenerProviderFactoryDefaultTest(){

        // Mocks
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        Config.Scope config = mock(Config.Scope.class);

        // Scope
        when(config.get("success-level", "debug")).thenReturn("debug");
        when(config.get("error-level", "warn")).thenReturn("warn");

        // Constructor
        JBossLoggingExtEventListenerProviderFactory factory = new JBossLoggingExtEventListenerProviderFactory();

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
