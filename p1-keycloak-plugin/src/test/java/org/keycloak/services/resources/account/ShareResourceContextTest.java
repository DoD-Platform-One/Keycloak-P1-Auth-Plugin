package org.keycloak.services.resources.account;

import org.junit.Test;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ScopeStore;
import jakarta.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

/**
 * Tests for the ShareResourceContext class.
 */
public class ShareResourceContextTest {

    /**
     * Tests the constructor with an error response.
     */
    @Test
    public void testConstructorWithErrorResponse() {
        // Arrange
        Response errorResponse = mock(Response.class);

        // Act
        ShareResourceContext context = new ShareResourceContext(errorResponse);

        // Assert
        assertEquals(errorResponse, context.getErrorResponse());
        assertNull(context.getAuthorization());
        assertNull(context.getTicketStore());
        assertNull(context.getScopeStore());
        assertNull(context.getResource());
        assertNull(context.getResourceServer());
    }

    /**
     * Tests the constructor with components.
     */
    @Test
    public void testConstructorWithComponents() {
        // Arrange
        AuthorizationProvider authorization = mock(AuthorizationProvider.class);
        PermissionTicketStore ticketStore = mock(PermissionTicketStore.class);
        ScopeStore scopeStore = mock(ScopeStore.class);
        Resource resource = mock(Resource.class);
        ResourceServer resourceServer = mock(ResourceServer.class);

        // Act
        ShareResourceContext context = new ShareResourceContext(
            authorization, ticketStore, scopeStore, resource, resourceServer);

        // Assert
        assertNull(context.getErrorResponse());
        assertEquals(authorization, context.getAuthorization());
        assertEquals(ticketStore, context.getTicketStore());
        assertEquals(scopeStore, context.getScopeStore());
        assertEquals(resource, context.getResource());
        assertEquals(resourceServer, context.getResourceServer());
    }
}