package dod.p1.keycloak.events;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MattermostEventListenerProviderFactoryTest {

    @Test
    public void MattermostEventListenerProviderFactoryDefault() throws Exception {
        // variables
        String[] events = {"LOGIN"};
        String[] resource = {"REALM"};
        String[] values = {"value1", "value2"};

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
