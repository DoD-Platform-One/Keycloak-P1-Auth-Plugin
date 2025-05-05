/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrderedModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.storage.StorageId;

/**
 * Represents information about applications associated with a user in the account management.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ApplicationsBean {

  /** The list of applications for the user. */
  private List<ApplicationEntry> applications = new LinkedList<>();

  /**
   * Constructs an ApplicationsBean for the specified Keycloak session, realm, and user.
   *
   * @param session The Keycloak session.
   * @param realm   The realm of the user.
   * @param user    The user for whom application information is retrieved.
   */
  public ApplicationsBean(final KeycloakSession session, final RealmModel realm, final UserModel user) {
    Set<ClientModel> offlineClients = new UserSessionManager(session).findClientsWithOfflineToken(realm, user);

    this.applications = this.getApplications(session, realm, user)
        .filter(Objects::nonNull)
        .filter(client -> !isAdminClient(client) || userIsAdminForClient(session, realm, user, client))
        .map(client -> toApplicationEntry(session, realm, user, client, offlineClients))
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }

  /**
   * Checks if the user is an admin for the specified client.
   *
   * @param session The Keycloak session.
   * @param realm   The realm of the user.
   * @param user    The user to check.
   * @param client  The client to check.
   * @return {@code true} if the user is an admin for the client, otherwise
   *         {@code false}.
   */
  public static boolean userIsAdminForClient(final KeycloakSession session, final RealmModel realm,
      final UserModel user, final ClientModel client) {
    AdminAuth adminAuth = new AdminAuth(realm, null, user, client);
    return AdminPermissions.evaluator(session, realm, adminAuth).clients().canView(client);
  }

  /**
   * Checks if the client is an admin client.
   *
   * @param client The client to check.
   * @return {@code true} if the client is an admin client, otherwise {@code false}.
   */
  public static boolean isAdminClient(final ClientModel client) {
    return client.getClientId().equals(Constants.ADMIN_CLI_CLIENT_ID)
        || client.getClientId().equals(Constants.ADMIN_CONSOLE_CLIENT_ID);
  }

  private Stream<ClientModel> getApplications(
      final KeycloakSession session, final RealmModel realm, final UserModel user) {
    Predicate<ClientModel> bearerOnly = ClientModel::isBearerOnly;
    Stream<ClientModel> clients = realm.getClientsStream().filter(bearerOnly.negate());

    Predicate<ClientModel> isLocal = client -> new StorageId(client.getId()).isLocal();
    return Stream.concat(
            clients,
            session
                .users()
                .getConsentsStream(realm, user.getId())
                .map(UserConsentModel::getClient)
                .filter(isLocal.negate()))
        .distinct();
  }

  private void processRoles(
      final Set<RoleModel> inputRoles,
      final List<RoleModel> realmRoles,
      final MultivaluedHashMap<String, ClientRoleEntry> clientRoles) {
    for (RoleModel role : inputRoles) {
      if (role.getContainer() instanceof RealmModel) {
        realmRoles.add(role);
      } else {
        ClientModel currentClient = (ClientModel) role.getContainer();
        ClientRoleEntry clientRole =
            new ClientRoleEntry(
                currentClient.getClientId(),
                currentClient.getName(),
                role.getName(),
                role.getDescription());
        clientRoles.add(currentClient.getClientId(), clientRole);
      }
    }
  }

  /**
   * Gets the list of applications associated with the user.
   *
   * @return The list of application entries.
   */
  public List<ApplicationEntry> getApplications() {
    return applications;
  }

  /**
   * Represents an entry for an application associated with a user.
   */
  public static class ApplicationEntry {

    /** Reference to the Keycloak session. */
    private KeycloakSession session;

    /** List of realm roles available for the application. */
    private final List<RoleModel> realmRolesAvailable;

    /** Map of client roles available for the application. */
    private final MultivaluedHashMap<String, ClientRoleEntry> resourceRolesAvailable;

    /** The client representing the application. */
    private final ClientModel client;

    /** List of client scopes granted for the application. */
    private final List<String> clientScopesGranted;

    /** List of additional grants for the application. */
    private final List<String> additionalGrants;

    /**
     * Constructs an ApplicationEntry with the specified parameters.
     *
     * @param kcSession              The Keycloak session.
     * @param realmRolesAvailableList The list of realm roles available.
     * @param resourceRolesAvailableMap The map of client roles available.
     * @param clientModel            The client representing the application.
     * @param clientScopesGrantedList List of client scopes granted.
     * @param additionalGrantsList   List of additional grants.
     */
    public ApplicationEntry(
        final KeycloakSession kcSession,
        final List<RoleModel> realmRolesAvailableList,
        final MultivaluedHashMap<String, ClientRoleEntry> resourceRolesAvailableMap,
        final ClientModel clientModel,
        final List<String> clientScopesGrantedList,
        final List<String> additionalGrantsList) {
      this.session = kcSession;
      this.realmRolesAvailable = realmRolesAvailableList;
      this.resourceRolesAvailable = resourceRolesAvailableMap;
      this.client = clientModel;
      this.clientScopesGranted = clientScopesGrantedList;
      this.additionalGrants = additionalGrantsList;
    }

    /**
     * Gets the list of realm roles available for the application.
     *
     * @return List of realm roles.
     */
    public List<RoleModel> getRealmRolesAvailable() {
      return realmRolesAvailable;
    }

    /**
     * Gets the multivalued map containing client roles available for the application.
     *
     * @return Multivalued map of client roles.
     */
    public MultivaluedHashMap<String, ClientRoleEntry> getResourceRolesAvailable() {
      return resourceRolesAvailable;
    }

    /**
     * Gets the list of client scopes granted for the application.
     *
     * @return List of client scopes.
     */
    public List<String> getClientScopesGranted() {
      return clientScopesGranted;
    }

    /**
     * Gets the effective URL for the application.
     *
     * @return The effective URL for the application.
     */
    public String getEffectiveUrl() {
      return ResolveRelative.resolveRelativeUri(
          session, getClient().getRootUrl(), getClient().getBaseUrl());
    }

    /**
     * Gets the client associated with the application.
     *
     * @return The client associated with the application.
     */
    public ClientModel getClient() {
      return client;
    }

    /**
     * Gets the list of additional grants for the application.
     *
     * @return The list of additional grants for the application.
     */
    public List<String> getAdditionalGrants() {
      return additionalGrants;
    }
  }

  /**
   * Represents an entry for a client role associated with an application.
   * Same class used in OAuthGrantBean as well. Maybe should be merged into common-freemarker...
   */
  public static class ClientRoleEntry {

    /** The client ID. */
    private final String clientId;

    /** The client name. */
    private final String clientName;

    /** The role name. */
    private final String roleName;

    /** The role description. */
    private final String roleDescription;

    /**
     * Constructs a ClientRoleEntry with the specified parameters.
     *
     * @param clientIdEntry       The client ID.
     * @param clientNameEntry     The client name.
     * @param roleNameEntry       The role name.
     * @param roleDescriptionEntry The role description.
     */
    public ClientRoleEntry(
        final String clientIdEntry,
        final String clientNameEntry,
        final String roleNameEntry,
        final String roleDescriptionEntry) {
      this.clientId = clientIdEntry;
      this.clientName = clientNameEntry;
      this.roleName = roleNameEntry;
      this.roleDescription = roleDescriptionEntry;
    }

    /**
     * Gets the client ID associated with the client role entry.
     *
     * @return The client ID.
     */
    public String getClientId() {
      return clientId;
    }

    /**
     * Gets the client name associated with the client role entry.
     *
     * @return The client name.
     */
    public String getClientName() {
      return clientName;
    }

    /**
     * Gets the role name associated with the client role entry.
     *
     * @return The role name.
     */
    public String getRoleName() {
      return roleName;
    }

    /**
     * Gets the role description associated with the client role entry.
     *
     * @return The role description.
     */
    public String getRoleDescription() {
      return roleDescription;
    }
  }

  /**
   * Constructs a {@link ApplicationEntry} from the specified parameters.
   *
   * @param session a reference to the {@code Keycloak} session.
   * @param realm a reference to the realm.
   * @param user a reference to the user.
   * @param client a reference to the client that contains the applications.
   * @param offlineClients a {@link Set} containing the offline clients.
   * @return the constructed {@link ApplicationEntry} instance or {@code null} if the user can't
   *     access the applications in the specified client.
   */
  private ApplicationEntry toApplicationEntry(
      final KeycloakSession session,
      final RealmModel realm,
      final UserModel user,
      final ClientModel client,
      final Set<ClientModel> offlineClients) {

    // Construct scope parameter with all optional scopes to see all potentially available roles
    Stream<ClientScopeModel> allClientScopes =
        Stream.concat(
            client.getClientScopes(true).values().stream(),
            client.getClientScopes(false).values().stream());
    allClientScopes = Stream.concat(allClientScopes, Stream.of(client)).distinct();

    Set<RoleModel> availableRoles = TokenManager.getAccess(user, client, allClientScopes);

    // Don't show applications, which user doesn't have access into (any available roles)
    // unless this is can be changed by approving/revoking consent
    if (!isAdminClient(client) && availableRoles.isEmpty() && !client.isConsentRequired()) {
      return null;
    }

    List<RoleModel> realmRolesAvailable = new LinkedList<>();
    MultivaluedHashMap<String, ClientRoleEntry> resourceRolesAvailable = new MultivaluedHashMap<>();
    processRoles(availableRoles, realmRolesAvailable, resourceRolesAvailable);

    List<ClientScopeModel> orderedScopes = new LinkedList<>();
    if (client.isConsentRequired()) {
      UserConsentModel consent =
          session.users().getConsentByClient(realm, user.getId(), client.getId());

      if (consent != null) {
        orderedScopes.addAll(consent.getGrantedClientScopes());
      }
    }
    List<String> clientScopesGranted =
        orderedScopes.stream()
            .sorted(OrderedModel.OrderedModelComparator.getInstance())
            .map(ClientScopeModel::getConsentScreenText)
            .collect(Collectors.toList());

    List<String> additionalGrants = new ArrayList<>();
    if (offlineClients.contains(client)) {
      additionalGrants.add("${offlineToken}");
    }
    return new ApplicationEntry(
        session,
        realmRolesAvailable,
        resourceRolesAvailable,
        client,
        clientScopesGranted,
        additionalGrants);
  }
}
