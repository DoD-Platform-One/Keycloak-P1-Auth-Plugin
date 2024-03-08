/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.forms.account.freemarker.model;

import jakarta.ws.rs.core.UriInfo;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.services.util.ResolveRelative;

/**
 * The `AuthorizationBean` class provides functionality to manage and retrieve authorization-related information for
 * a user.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthorizationBean {

  /** The Keycloak session associated with the authorization. */
  private final KeycloakSession session;

  /** The realm to which the user belongs. */
  private final RealmModel realm;

  /** The user for whom authorization operations are performed. */
  private final UserModel user;

  /** The provider for handling authorization operations. */
  private final AuthorizationProvider authorization;

  /** The information about the URI being processed. */
  private final UriInfo uriInfo;

  /** The specific resource associated with the current authorization operation. */
  private ResourceBean resource;

  /** The list of resources associated with the user and authorization. */
  private List<ResourceBean> resources;

  /** The collection of resources shared with the user. */
  private Collection<ResourceBean> userSharedResources;

  /** The collection of resources for which permission is requested. */
  private Collection<ResourceBean> requestsWaitingPermission;

  /** The collection of resources waiting for approval from others. */
  private Collection<ResourceBean> resourcesWaitingOthersApproval;

  /**
   * Constructs an `AuthorizationBean` instance.
   *
   * @param kcSession    The Keycloak session.
   * @param realmModel   The realm model.
   * @param userModel    The user model.
   * @param uri          The URI information.
   */
  public AuthorizationBean(
      final KeycloakSession kcSession,
      final RealmModel realmModel,
      final UserModel userModel,
      final UriInfo uri) {
    this.session = kcSession;
    this.realm = realmModel;
    this.user = userModel;
    this.uriInfo = uri;
    authorization = kcSession.getProvider(AuthorizationProvider.class);
    List<String> pathParameters = uri.getPathParameters().get("resource_id");

    if (pathParameters != null && !pathParameters.isEmpty()) {
      Resource resourceInfo =
          authorization
              .getStoreFactory()
              .getResourceStore()
              .findById(realmModel, null, pathParameters.get(0));

      if (resourceInfo != null && !resourceInfo.getOwner().equals(userModel.getId())) {
        throw new IllegalStateException(
            "User [" + userModel.getUsername() + "] can not access resource [" + resourceInfo.getId() + "]");
      }
    }
  }

  /**
   * Retrieves a collection of resources for which the user has shared access, waiting for others' approval.
   *
   * @return A collection of resources waiting for others' approval.
   */
  public Collection<ResourceBean> getResourcesWaitingOthersApproval() {
    if (resourcesWaitingOthersApproval == null) {
      Map<PermissionTicket.FilterOption, String> filters =
          new EnumMap<>(PermissionTicket.FilterOption.class);

      filters.put(PermissionTicket.FilterOption.REQUESTER, user.getId());
      filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.FALSE.toString());

      resourcesWaitingOthersApproval = toResourceRepresentation(findPermissions(filters));
    }

    return resourcesWaitingOthersApproval;
  }

  /**
   * Retrieves a collection of resources for which the user has requested access, waiting for approval.
   *
   * @return A collection of resources waiting for approval.
   */
  public Collection<ResourceBean> getResourcesWaitingApproval() {
    if (requestsWaitingPermission == null) {
      Map<PermissionTicket.FilterOption, String> filters =
          new EnumMap<>(PermissionTicket.FilterOption.class);

      filters.put(PermissionTicket.FilterOption.OWNER, user.getId());
      filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.FALSE.toString());

      requestsWaitingPermission = toResourceRepresentation(findPermissions(filters));
    }

    return requestsWaitingPermission;
  }

  /**
   * Retrieves a list of resources owned by the user.
   *
   * @return A list of user-owned resources.
   */
  public List<ResourceBean> getResources() {
    if (resources == null) {
      resources =
          authorization
              .getStoreFactory()
              .getResourceStore()
              .findByOwner(realm, null, user.getId())
              .stream()
              .filter(Resource::isOwnerManagedAccess)
              .map(ResourceBean::new)
              .collect(Collectors.toList());
    }
    return resources;
  }

  /**
   * Retrieves a collection of resources shared with the user.
   *
   * @return A collection of shared resources.
   */
  public Collection<ResourceBean> getSharedResources() {
    if (userSharedResources == null) {
      Map<PermissionTicket.FilterOption, String> filters =
          new EnumMap<>(PermissionTicket.FilterOption.class);

      filters.put(PermissionTicket.FilterOption.REQUESTER, user.getId());
      filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.TRUE.toString());

      PermissionTicketStore ticketStore =
          authorization.getStoreFactory().getPermissionTicketStore();

      userSharedResources =
          toResourceRepresentation(ticketStore.find(realm, null, filters, null, null));
    }
    return userSharedResources;
  }

  /**
   * Retrieves information about a specific resource.
   *
   * @return The resource information.
   */
  public ResourceBean getResource() {
    if (resource == null) {
      String resourceId = uriInfo.getPathParameters().getFirst("resource_id");

      if (resourceId != null) {
        resource = getResource(resourceId);
      }
    }

    return resource;
  }

  /**
   * Retrieves a {@code ResourceBean} instance based on the provided resource ID.
   *
   * @param id The unique identifier of the resource to retrieve.
   * @return A {@code ResourceBean} representing the resource with the given ID.
   */
  private ResourceBean getResource(final String id) {
    return new ResourceBean(
        authorization.getStoreFactory().getResourceStore().findById(realm, null, id));
  }

  /**
   * Represents a requester associated with a {@link PermissionTicket}.
   */
  public static class RequesterBean {

    /** The timestamp when the permission was created. */
    private final Long createdTimestamp;

    /** The timestamp when the permission was granted. */
    private final Long grantedTimestamp;

    /** The user associated with the requester. */
    private UserModel requester;

    /** The list of permission scopes associated with the requester. */
    private List<PermissionScopeBean> scopes = new ArrayList<>();

    /** A flag indicating whether the permission is granted. */
    private boolean granted;

    /**
     * Constructs a {@code RequesterBean} based on the provided {@link PermissionTicket}
     * and {@link AuthorizationProvider}.
     *
     * @param ticket The permission ticket.
     * @param authorization The authorization provider.
     */
    public RequesterBean(final PermissionTicket ticket, final AuthorizationProvider authorization) {
      this.requester =
          authorization
              .getKeycloakSession()
              .users()
              .getUserById(authorization.getRealm(), ticket.getRequester());
      granted = ticket.isGranted();
      createdTimestamp = ticket.getCreatedTimestamp();
      grantedTimestamp = ticket.getGrantedTimestamp();
    }

    /**
     * Gets the user associated with the requester.
     *
     * @return The user associated with the requester.
     */
    public UserModel getRequester() {
      return requester;
    }

    /**
     * Gets the list of permission scopes associated with the requester.
     *
     * @return The list of permission scopes.
     */
    public List<PermissionScopeBean> getScopes() {
      return scopes;
    }

    /**
     * Adds a permission scope associated with the requester.
     *
     * @param ticket The permission ticket.
     */
    private void addScope(final PermissionTicket ticket) {
      if (ticket != null) {
        scopes.add(new PermissionScopeBean(ticket));
      }
    }

    /**
     * Checks if the permission is granted.
     *
     * @return {@code true} if the permission is granted, otherwise {@code false}.
     */
    public boolean isGranted() {
      return (granted && scopes.isEmpty())
          || scopes.stream().filter(permissionScopeBean -> permissionScopeBean.isGranted()).count()
              > 0;
    }

    /**
     * Gets the date when the permission was created.
     *
     * @return The date of creation.
     */
    public Date getCreatedDate() {
      return Time.toDate(createdTimestamp);
    }

    /**
     * Gets the date when the permission was granted.
     *
     * @return The date of granting, or {@code null} if not granted.
     */
    public Date getGrantedDate() {
      if (grantedTimestamp == null) {
        PermissionScopeBean permission =
            scopes.stream()
                .filter(permissionScopeBean -> permissionScopeBean.isGranted())
                .findFirst()
                .orElse(null);

        if (permission == null) {
          return null;
        }

        return permission.getGrantedDate();
      }
      return Time.toDate(grantedTimestamp);
    }
  }

  /**
   * Represents a permission scope associated with a {@link PermissionTicket}.
   */
  public static class PermissionScopeBean {

    /** The scope associated with the permission. */
    private final Scope scope;

    /** The permission ticket. */
    private final PermissionTicket ticket;

    /**
     * Constructs a {@code PermissionScopeBean} based on the provided {@link PermissionTicket}.
     *
     * @param permissionTicket The permission ticket.
     */
    public PermissionScopeBean(final PermissionTicket permissionTicket) {
      this.ticket = permissionTicket;
      scope = permissionTicket.getScope();
    }

    /**
     * Gets the ID of the permission scope.
     *
     * @return The ID of the permission scope.
     */
    public String getId() {
      return ticket.getId();
    }

    /**
     * Gets the scope associated with the permission.
     *
     * @return The scope associated with the permission.
     */
    public Scope getScope() {
      return scope;
    }

    /**
     * Checks if the permission is granted.
     *
     * @return {@code true} if the permission is granted, otherwise {@code false}.
     */
    public boolean isGranted() {
      return ticket.isGranted();
    }

    /**
     * Gets the date when the permission was granted.
     *
     * @return The date of granting, or {@code null} if not granted.
     */
    private Date getGrantedDate() {
      if (isGranted()) {
        return Time.toDate(ticket.getGrantedTimestamp());
      }
      return null;
    }
  }

  /**
   * Represents a resource and its associated information.
   */
  public class ResourceBean {

    /** The associated resource server. */
    private final ResourceServerBean resourceServer;

    /** The name of the resource owner. */
    private final String ownerName;

    /** The user owner of the resource. */
    private final UserModel userOwner;

    /** The client owner of the resource. */
    private ClientModel clientOwner;

    /** The resource itself. */
    private Resource resource;

    /** Map of requesters and their associated permissions. */
    private Map<String, RequesterBean> permissions = new HashMap<>();

    /** Collection of requesters who have been granted shares. */
    private Collection<RequesterBean> shares;

    /**
     * Constructs a {@code ResourceBean} based on the provided {@link Resource}.
     *
     * @param resourceInfo The resource information.
     */
    public ResourceBean(final Resource resourceInfo) {
      RealmModel realmModel = authorization.getRealm();
      ResourceServer resourceServerModel = resourceInfo.getResourceServer();
      resourceServer =
          new ResourceServerBean(
              realmModel.getClientById(resourceServerModel.getClientId()), resourceServerModel);
      this.resource = resourceInfo;
      userOwner =
          authorization.getKeycloakSession().users().getUserById(realmModel, resourceInfo.getOwner());
      if (userOwner == null) {
        clientOwner = realmModel.getClientById(resourceInfo.getOwner());
        ownerName = clientOwner.getClientId();
      } else if (userOwner.getEmail() != null) {
        ownerName = userOwner.getEmail();
      } else {
        ownerName = userOwner.getUsername();
      }
    }

    /**
     * Gets the ID of the resource.
     *
     * @return The ID of the resource.
     */
    public String getId() {
      return resource.getId();
    }

    /**
     * Gets the name of the resource.
     *
     * @return The name of the resource.
     */
    public String getName() {
      return resource.getName();
    }

    /**
     * Gets the display name of the resource.
     *
     * @return The display name of the resource.
     */
    public String getDisplayName() {
      return resource.getDisplayName();
    }

    /**
     * Gets the URI for the icon of the resource.
     *
     * @return The URI for the icon of the resource.
     */
    public String getIconUri() {
      return resource.getIconUri();
    }

    /**
     * Gets the name of the resource owner.
     *
     * @return The name of the resource owner.
     */
    public String getOwnerName() {
      return ownerName;
    }

    /**
     * Gets the user owner of the resource.
     *
     * @return The user owner of the resource.
     */
    public UserModel getUserOwner() {
      return userOwner;
    }

    /**
     * Gets the client owner of the resource.
     *
     * @return The client owner of the resource.
     */
    public ClientModel getClientOwner() {
      return clientOwner;
    }

    /**
     * Gets the scopes associated with the resource.
     *
     * @return List of scopes associated with the resource.
     */
    public List<ScopeRepresentation> getScopes() {
      return resource.getScopes().stream()
          .map(ModelToRepresentation::toRepresentation)
          .collect(Collectors.toList());
    }

    /**
     * Gets the requesters who have been granted shares for this resource.
     *
     * @return Collection of requesters who have been granted shares.
     */
    public Collection<RequesterBean> getShares() {
      if (shares == null) {
        Map<PermissionTicket.FilterOption, String> filters =
            new EnumMap<>(PermissionTicket.FilterOption.class);

        filters.put(PermissionTicket.FilterOption.RESOURCE_ID, this.resource.getId());
        filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.TRUE.toString());

        shares = toPermissionRepresentation(findPermissions(filters));
      }

      return shares;
    }

    /**
     * Gets the policies associated with the resource.
     *
     * @return Collection of managed permissions associated with the resource.
     */
    public Collection<ManagedPermissionBean> getPolicies() {
      ResourceServer resourceServerModel = getResourceServer().getResourceServerModel();
      RealmModel realmModel = resourceServerModel.getRealm();
      Map<Policy.FilterOption, String[]> filters = new EnumMap<>(Policy.FilterOption.class);

      filters.put(Policy.FilterOption.TYPE, new String[] {"uma"});
      filters.put(Policy.FilterOption.RESOURCE_ID, new String[] {this.resource.getId()});
      if (getUserOwner() != null) {
        filters.put(Policy.FilterOption.OWNER, new String[] {getUserOwner().getId()});
      } else {
        filters.put(Policy.FilterOption.OWNER, new String[] {getClientOwner().getId()});
      }

      List<Policy> policies =
          authorization
              .getStoreFactory()
              .getPolicyStore()
              .find(realmModel, resourceServerModel, filters, null, null);

      if (policies.isEmpty()) {
        return Collections.emptyList();
      }

      return policies.stream()
          .filter(
              policy -> {
                Map<PermissionTicket.FilterOption, String> filters1 =
                    new EnumMap<>(PermissionTicket.FilterOption.class);

                filters1.put(PermissionTicket.FilterOption.POLICY_ID, policy.getId());

                return authorization
                    .getStoreFactory()
                    .getPermissionTicketStore()
                    .find(realmModel, resourceServerModel, filters1, -1, 1)
                    .isEmpty();
              })
          .map(ManagedPermissionBean::new)
          .collect(Collectors.toList());
    }

    /**
     * Gets the associated resource server.
     *
     * @return The associated resource server.
     */
    public ResourceServerBean getResourceServer() {
      return resourceServer;
    }

    /**
     * Gets the permissions associated with the resource.
     *
     * @return Collection of requesters and their associated permissions.
     */
    public Collection<RequesterBean> getPermissions() {
      return permissions.values();
    }

    /**
     * Adds a permission for the resource.
     *
     * @param ticket                    The permission ticket.
     */
    private void addPermission(final PermissionTicket ticket) {
      permissions
          .computeIfAbsent(ticket.getRequester(), key -> new RequesterBean(ticket, authorization))
          .addScope(ticket);
    }
  }

  /**
   * Converts a list of {@link PermissionTicket} instances into a collection of {@link RequesterBean}s,
   * representing requesters and their associated permissions.
   *
   * @param permissionRequests The list of permission tickets to convert.
   * @return A collection of {@link RequesterBean}s representing requesters and their permissions.
   */
  private Collection<RequesterBean> toPermissionRepresentation(
      final List<PermissionTicket> permissionRequests) {
    Map<String, RequesterBean> requests = new HashMap<>();

    for (PermissionTicket ticket : permissionRequests) {
      Resource resourceModel = ticket.getResource();

      if (!resourceModel.isOwnerManagedAccess()) {
        continue;
      }

      requests
          .computeIfAbsent(
              ticket.getRequester(), resourceId -> new RequesterBean(ticket, authorization))
          .addScope(ticket);
    }

    return requests.values();
  }

  /**
   * Converts a list of {@link PermissionTicket} instances into a collection of {@link ResourceBean}s,
   * representing resources and their associated permissions.
   *
   * @param tickets The list of permission tickets to convert.
   * @return A collection of {@link ResourceBean}s representing resources and their associated permissions.
   */
  private Collection<ResourceBean> toResourceRepresentation(final List<PermissionTicket> tickets) {
    Map<String, ResourceBean> requests = new HashMap<>();

    for (PermissionTicket ticket : tickets) {
      Resource resourceModel = ticket.getResource();

      if (!resourceModel.isOwnerManagedAccess()) {
        continue;
      }

      requests
          .computeIfAbsent(resourceModel.getId(), resourceId -> getResource(resourceId))
          .addPermission(ticket);
    }

    return requests.values();
  }

  /**
   * Finds and retrieves a list of {@link PermissionTicket} instances based on the specified filters.
   *
   * @param filters The filters to apply when searching for permission tickets.
   * @return A list of {@link PermissionTicket} instances that match the specified filters.
   */
  private List<PermissionTicket> findPermissions(
      final Map<PermissionTicket.FilterOption, String> filters) {
    return authorization
        .getStoreFactory()
        .getPermissionTicketStore()
        .find(realm, null, filters, null, null);
  }

  /**
   * Represents a resource server and its associated information.
   */
  public class ResourceServerBean {

    /** The client model associated with the resource server. */
    private ClientModel clientModel;

    /** The resource server model. */
    private ResourceServer resourceServer;

    /**
     * Constructs a {@code ResourceServerBean} based on the provided client and resource server.
     *
     * @param client   The client model.
     * @param resourceSrv The resource server model.
     */
    public ResourceServerBean(final ClientModel client, final ResourceServer resourceSrv) {
      this.clientModel = client;
      this.resourceServer = resourceSrv;
    }

    /**
     * Gets the ID of the resource server.
     *
     * @return The ID of the resource server.
     */
    public String getId() {
      return resourceServer.getId();
    }

    /**
     * Gets the name of the resource server.
     *
     * @return The name of the resource server, or the client ID if the name is null.
     */
    public String getName() {
      String name = clientModel.getName();

      if (name != null) {
        return name;
      }

      return clientModel.getClientId();
    }

    /**
     * Gets the client ID associated with the resource server.
     *
     * @return The client ID associated with the resource server.
     */
    public String getClientId() {
      return clientModel.getClientId();
    }

    /**
     * Gets the redirect URI associated with the resource server.
     *
     * @return The redirect URI associated with the resource server, or null if not available.
     */
    public String getRedirectUri() {
      Set<String> redirectUris = clientModel.getRedirectUris();

      if (redirectUris.isEmpty()) {
        return null;
      }

      return redirectUris.iterator().next();
    }

    /**
     * Gets the base URI associated with the resource server.
     *
     * @return The base URI associated with the resource server.
     */
    public String getBaseUri() {
      return ResolveRelative.resolveRelativeUri(
          session, clientModel.getRootUrl(), clientModel.getBaseUrl());
    }

    /**
     * Gets the resource server model.
     *
     * @return The resource server model.
     */
    public ResourceServer getResourceServerModel() {
      return resourceServer;
    }
  }

  /**
   * The `ManagedPermissionBean` class represents a managed permission associated with a policy.
   */
  public class ManagedPermissionBean {

    /** The policy model associated with the managed permission. */
    private final Policy policy;

    /** The list of managed permissions associated with policies. */
    private List<ManagedPermissionBean> policies;

    /**
     * Constructs a `ManagedPermissionBean` instance.
     *
     * @param policyModel The policy model associated with the managed permission.
     */
    public ManagedPermissionBean(final Policy policyModel) {
      this.policy = policyModel;
    }

    /**
     * Retrieves the unique identifier of the managed permission.
     *
     * @return The ID of the managed permission.
     */
    public String getId() {
      return policy.getId();
    }

    /**
     * Retrieves the scopes associated with the managed permission.
     *
     * @return A collection of scope representations.
     */
    public Collection<ScopeRepresentation> getScopes() {
      return policy.getScopes().stream()
          .map(ModelToRepresentation::toRepresentation)
          .collect(Collectors.toList());
    }

    /**
     * Retrieves the description of the managed permission.
     *
     * @return The description of the managed permission.
     */
    public String getDescription() {
      return this.policy.getDescription();
    }

    /**
     * Retrieves the policies associated with the managed permission.
     *
     * @return A collection of managed permissions associated with policies.
     */
    public Collection<ManagedPermissionBean> getPolicies() {
      if (this.policies == null) {
        this.policies =
            policy.getAssociatedPolicies().stream()
                .map(ManagedPermissionBean::new)
                .collect(Collectors.toList());
      }

      return this.policies;
    }
  }
}
