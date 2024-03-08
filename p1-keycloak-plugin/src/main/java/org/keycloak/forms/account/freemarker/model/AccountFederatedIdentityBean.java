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

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrderedModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.account.AccountFormService;

/**
 * Represents federated identity information for a user in the account management.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:velias@redhat.com">Vlastimil Elias</a>
 */
public class AccountFederatedIdentityBean {

  /** A comparator instance for ordering federated identity entries. */
  private static OrderedModel.OrderedModelComparator<FederatedIdentityEntry>
      idpComparatorInstance = new OrderedModel.OrderedModelComparator<>();

  /** The list of federated identity entries. */
  private final List<FederatedIdentityEntry> identities;

  /** Indicates whether removing the federated identity link is possible. */
  private final boolean removeLinkPossible;

  /** The Keycloak session. */
  private final KeycloakSession session;

  /**
   * Constructs an AccountFederatedIdentityBean for the specified user and realm.
   *
   * @param kcSession     The Keycloak session.
   * @param realm         The realm of the user.
   * @param user          The user for whom federated identity information is retrieved.
   * @param baseUri       The base URI.
   * @param stateChecker  The state checker.
   */
  public AccountFederatedIdentityBean(
      final KeycloakSession kcSession,
      final RealmModel realm,
      final UserModel user,
      final URI baseUri,
      final String stateChecker) {
    this.session = kcSession;

    AtomicInteger availableIdentities = new AtomicInteger(0);
    this.identities =
        realm
            .getIdentityProvidersStream()
            .filter(IdentityProviderModel::isEnabled)
            .map(
                provider -> {
                  String providerId = provider.getAlias();

                  FederatedIdentityModel identity =
                      getIdentity(
                          session.users().getFederatedIdentitiesStream(realm, user), providerId);

                  if (identity != null) {
                    availableIdentities.getAndIncrement();
                  }

                  String displayName =
                      KeycloakModelUtils.getIdentityProviderDisplayName(session, provider);
                  return new FederatedIdentityEntry(
                      identity,
                      displayName,
                      provider.getAlias(),
                      provider.getAlias(),
                      provider.getConfig() != null ? provider.getConfig().get("guiOrder") : null);
                })
            .sorted(idpComparatorInstance)
            .collect(Collectors.toList());

    // Removing last social provider is not possible if you don't have other possibility to
    // authenticate
    this.removeLinkPossible =
        availableIdentities.get() > 1
            || user.getFederationLink() != null
            || AccountFormService.isPasswordSet(user);
  }

  private FederatedIdentityModel getIdentity(
      final Stream<FederatedIdentityModel> identityModels, final String providerId) {
    return identityModels
        .filter(
            federatedIdentityModel ->
                Objects.equals(federatedIdentityModel.getIdentityProvider(), providerId))
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets the list of federated identity entries.
   *
   * @return List of federated identity entries.
   */
  public List<FederatedIdentityEntry> getIdentities() {
    return identities;
  }

  /**
   * Checks if removing the federated identity link is possible.
   *
   * @return True if removing the link is possible, false otherwise.
   */
  public boolean isRemoveLinkPossible() {
    return removeLinkPossible;
  }

  /**
   * Represents a federated identity entry.
   */
  public static class FederatedIdentityEntry implements OrderedModel {

    /** The federated identity model. */
    private FederatedIdentityModel federatedIdentityModel;

    /** The provider ID. */
    private final String providerId;

    /** The provider name. */
    private final String providerName;

    /** The GUI order. */
    private final String guiOrder;

    /** The display name. */
    private final String displayName;

    /**
     * Constructs a FederatedIdentityEntry with the specified parameters.
     *
     * @param federatedIdentityModelEntry  The federated identity model.
     * @param displayNameEntry             The display name.
     * @param providerIdEntry              The provider ID.
     * @param providerNameEntry            The provider name.
     * @param guiOrderEntry                The GUI order.
     */
    public FederatedIdentityEntry(
        final FederatedIdentityModel federatedIdentityModelEntry,
        final String displayNameEntry,
        final String providerIdEntry,
        final String providerNameEntry,
        final String guiOrderEntry) {
      this.federatedIdentityModel = federatedIdentityModelEntry;
      this.displayName = displayNameEntry;
      this.providerId = providerIdEntry;
      this.providerName = providerNameEntry;
      this.guiOrder = guiOrderEntry;
    }

    /**
     * Gets the provider ID.
     *
     * @return The provider ID.
     */
    public String getProviderId() {
      return providerId;
    }

    /**
     * Gets the provider name.
     *
     * @return The provider name.
     */
    public String getProviderName() {
      return providerName;
    }

    /**
     * Gets the user ID associated with the federated identity.
     *
     * @return The user ID.
     */
    public String getUserId() {
      return federatedIdentityModel != null ? federatedIdentityModel.getUserId() : null;
    }

    /**
     * Gets the user name associated with the federated identity.
     *
     * @return The user name.
     */
    public String getUserName() {
      return federatedIdentityModel != null ? federatedIdentityModel.getUserName() : null;
    }

    /**
     * Checks if the federated identity is connected.
     *
     * @return True if connected, false otherwise.
     */
    public boolean isConnected() {
      return federatedIdentityModel != null;
    }

    /**
     * Gets the GUI order.
     *
     * @return The GUI order.
     */
    @Override
    public String getGuiOrder() {
      return guiOrder;
    }

    /**
     * Gets the display name.
     *
     * @return The display name.
     */
    public String getDisplayName() {
      return displayName;
    }
  }
}
