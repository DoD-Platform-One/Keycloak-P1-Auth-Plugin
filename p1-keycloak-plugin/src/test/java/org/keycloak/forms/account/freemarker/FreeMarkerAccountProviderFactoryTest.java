package org.keycloak.forms.account.freemarker;

import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class FreeMarkerAccountProviderFactoryTest {

    @Test
    public void testCreate() {
        FreeMarkerAccountProviderFactory factory = new FreeMarkerAccountProviderFactory();
        KeycloakSession session = mock(KeycloakSession.class);

        // Ensure that the create method returns a non-null instance of FreeMarkerAccountProvider
        assertEquals(FreeMarkerAccountProvider.class, factory.create(session).getClass(),
                "Expected an instance of FreeMarkerAccountProvider");
    }

    @Test
    public void testInit() {
        FreeMarkerAccountProviderFactory factory = new FreeMarkerAccountProviderFactory();
        Config.Scope config = mock(Config.Scope.class);

        // Ensure that the init method does not throw any exceptions
        factory.init(config);
    }

    @Test
    public void testPostInit() {
        FreeMarkerAccountProviderFactory factory = new FreeMarkerAccountProviderFactory();
        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);

        // Ensure that the postInit method does not throw any exceptions
        factory.postInit(keycloakSessionFactory);
    }

    @Test
    public void testClose() {
        FreeMarkerAccountProviderFactory factory = new FreeMarkerAccountProviderFactory();

        // Ensure that the close method does not throw any exceptions
        factory.close();
    }

    @Test
    public void testGetId() {
        FreeMarkerAccountProviderFactory factory = new FreeMarkerAccountProviderFactory();

        // Ensure that the getId method returns "freemarker"
        assertEquals("freemarker", factory.getId(), "Expected factory ID to be 'freemarker'");
    }
}
