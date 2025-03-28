package org.keycloak.services.resources.account;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Resource;
import jakarta.ws.rs.core.Response;

/**
 * Class to hold the result of permission request validation.
 */
public class PermissionValidationResult {
  /** The error response, or null if validation succeeded. */
  private final Response validationErrorResponse;
  /** The authorization provider. */
  private final AuthorizationProvider validationAuthorization;
  /** The resource. */
  private final Resource validationResource;

  /**
   * Constructs a PermissionValidationResult with an error response.
   *
   * @param errorResponse The error response.
   */
  public PermissionValidationResult(final Response errorResponse) {
    this.validationErrorResponse = errorResponse;
    this.validationAuthorization = null;
    this.validationResource = null;
  }

  /**
   * Constructs a PermissionValidationResult with authorization and resource.
   *
   * @param authorization The authorization provider.
   * @param resource The resource.
   */
  public PermissionValidationResult(
      final AuthorizationProvider authorization, final Resource resource) {
    this.validationErrorResponse = null;
    this.validationAuthorization = authorization;
    this.validationResource = resource;
  }

  /**
   * Gets the error response.
   *
   * @return The error response, or null if validation succeeded.
   */
  public Response getErrorResponse() {
    return validationErrorResponse;
  }

  /**
   * Gets the authorization provider.
   *
   * @return The authorization provider.
   */
  public AuthorizationProvider getAuthorization() {
    return validationAuthorization;
  }

  /**
   * Gets the resource.
   *
   * @return The resource.
   */
  public Resource getResource() {
    return validationResource;
  }
}
