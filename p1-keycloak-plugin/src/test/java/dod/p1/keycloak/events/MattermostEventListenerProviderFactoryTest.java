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
import static org.mockito.ArgumentMatchers.*;
import static org.powermock.api.mockito.PowerMockito.*;


@RunWith(PowerMockRunner.class)
@PrepareForTest({})
public class MattermostEventListenerProviderFactoryTest {

    @Test
    public void MattermostEventListenerProviderFactoryDefault() throws Exception {
        // variables
        String[] events = {"LOGIN"};
        String[] resource = {"REALM"};
        String[] values = {"value1", "value2" };

        // Mocks
        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);
        Config.Scope config = mock(Config.Scope.class);

        // Constructor
        MattermostEventListenerProviderFactory factory = new MattermostEventListenerProviderFactory();

        // init (default)
        factory.init(config);

        // mock conditions
        when(config.getArray(eq("exclude-events"))).thenReturn(events);
        when(config.getArray(eq("include-admin-events"))).thenReturn(resource);
        when(config.getArray(eq("group-membership-values"))).thenReturn(values);

        // init (all conditions)
        factory.init(config);

        // postInit
        factory.postInit(keycloakSessionFactory);

        // getId
        assertEquals("Mattermost", factory.getId());

        // create
        assertNotNull(factory.create(session));

        // close
        factory.close();
    }
}
