package org.keycloak.services.resources.account;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ScopeStore;
import jakarta.ws.rs.core.Response;

/**
 * Class to hold the context for share resource operations.
 */
public class ShareResourceContext {
  /** The error response, or null if validation succeeded. */
  private final Response contextErrorResponse;
  /** The authorization provider. */
  private final AuthorizationProvider contextAuthorization;
  /** The permission ticket store. */
  private final PermissionTicketStore contextTicketStore;
  /** The scope store. */
  private final ScopeStore contextScopeStore;
  /** The resource. */
  private final Resource contextResource;
  /** The resource server. */
  private final ResourceServer contextResourceServer;

  /**
   * Constructs a ShareResourceContext with an error response.
   *
   * @param errorResponse The error response.
   */
  public ShareResourceContext(final Response errorResponse) {
    this.contextErrorResponse = errorResponse;
    this.contextAuthorization = null;
    this.contextTicketStore = null;
    this.contextScopeStore = null;
    this.contextResource = null;
    this.contextResourceServer = null;
  }

  /**
   * Constructs a ShareResourceContext with components.
   *
   * @param authorization The authorization provider.
   * @param ticketStore The permission ticket store.
   * @param scopeStore The scope store.
   * @param resource The resource.
   * @param resourceServer The resource server.
   */
  public ShareResourceContext(
      final AuthorizationProvider authorization,
      final PermissionTicketStore ticketStore,
      final ScopeStore scopeStore,
      final Resource resource,
      final ResourceServer resourceServer) {
    this.contextErrorResponse = null;
    this.contextAuthorization = authorization;
    this.contextTicketStore = ticketStore;
    this.contextScopeStore = scopeStore;
    this.contextResource = resource;
    this.contextResourceServer = resourceServer;
  }

  /**
   * Gets the error response.
   *
   * @return The error response, or null if validation succeeded.
   */
  public Response getErrorResponse() {
    return contextErrorResponse;
  }

  /**
   * Gets the authorization provider.
   *
   * @return The authorization provider.
   */
  public AuthorizationProvider getAuthorization() {
    return contextAuthorization;
  }

  /**
   * Gets the permission ticket store.
   *
   * @return The permission ticket store.
   */
  public PermissionTicketStore getTicketStore() {
    return contextTicketStore;
  }

  /**
   * Gets the scope store.
   *
   * @return The scope store.
   */
  public ScopeStore getScopeStore() {
    return contextScopeStore;
  }

  /**
   * Gets the resource.
   *
   * @return The resource.
   */
  public Resource getResource() {
    return contextResource;
  }

  /**
   * Gets the resource server.
   *
   * @return The resource server.
   */
  public ResourceServer getResourceServer() {
    return contextResourceServer;
  }
}
