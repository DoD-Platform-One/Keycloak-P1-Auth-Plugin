package org.keycloak.services.resources.account;

import org.junit.Test;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Resource;
import jakarta.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

/**
 * Tests for the PermissionValidationResult class.
 */
public class PermissionValidationResultTest {

    /**
     * Tests the constructor with an error response.
     */
    @Test
    public void testConstructorWithErrorResponse() {
        // Arrange
        Response errorResponse = mock(Response.class);

        // Act
        PermissionValidationResult result = new PermissionValidationResult(errorResponse);

        // Assert
        assertEquals(errorResponse, result.getErrorResponse());
        assertNull(result.getAuthorization());
        assertNull(result.getResource());
    }

    /**
     * Tests the constructor with authorization and resource.
     */
    @Test
    public void testConstructorWithAuthorizationAndResource() {
        // Arrange
        AuthorizationProvider authorization = mock(AuthorizationProvider.class);
        Resource resource = mock(Resource.class);

        // Act
        PermissionValidationResult result = new PermissionValidationResult(authorization, resource);

        // Assert
        assertNull(result.getErrorResponse());
        assertEquals(authorization, result.getAuthorization());
        assertEquals(resource, result.getResource());
    }
}