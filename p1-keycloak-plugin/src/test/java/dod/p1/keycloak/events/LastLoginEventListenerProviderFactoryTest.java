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
import static org.powermock.api.mockito.PowerMockito.*;
@RunWith(PowerMockRunner.class)
@PrepareForTest({})
public class LastLoginEventListenerProviderFactoryTest {

    @Test
    public void LastLoginEventListenerProviderFactoryDefault(){

        // Mocks
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        Config.Scope config = mock(Config.Scope.class);

        // Constructor
        LastLoginEventListenerProviderFactory factory = new LastLoginEventListenerProviderFactory();

        // create
        assertNotNull(factory.create(session));

        // init
        factory.init(config);

        // postInit
        factory.postInit(keycloakSessionFactory);

        // getId
        assertEquals("Lastlogin", factory.getId());

        // close
        factory.close();
    }

}
