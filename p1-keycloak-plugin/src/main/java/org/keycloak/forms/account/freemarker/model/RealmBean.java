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

import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.models.RealmModel;

/**
 * This class represents information about a Keycloak realm, providing various details about
 * its configuration.
 *
 * @author <a href="mailto:gerbermichi@me.com">Michael Gerber</a>
 */
public class RealmBean {

  /** The underlying realm model. */
  private RealmModel realm;

  /**
   * Constructs a {@code RealmBean} object with the specified realm model.
   *
   * @param realmModel The realm model.
   */
  public RealmBean(final RealmModel realmModel) {
    realm = realmModel;
  }

  /**
   * Gets the name of the realm.
   *
   * @return The name of the realm.
   */
  public String getName() {
    return realm.getName();
  }

  /**
   * Gets the display name of the realm. If no display name is set, the realm name is returned.
   *
   * @return The display name of the realm.
   */
  public String getDisplayName() {
    String displayName = realm.getDisplayName();
    if (displayName != null && !displayName.isEmpty()) {
      return displayName;
    } else {
      return getName();
    }
  }

  /**
   * Gets the HTML-formatted display name of the realm. If no HTML display name is set, the regular
   * display name is returned.
   *
   * @return The HTML-formatted display name of the realm.
   */
  public String getDisplayNameHtml() {
    String displayNameHtml = realm.getDisplayNameHtml();
    if (displayNameHtml != null && !displayNameHtml.isEmpty()) {
      return displayNameHtml;
    } else {
      return getDisplayName();
    }
  }

  /**
   * Checks if internationalization is enabled for the realm.
   *
   * @return {@code true} if internationalization is enabled; otherwise, {@code false}.
   */
  public boolean isInternationalizationEnabled() {
    return realm.isInternationalizationEnabled();
  }

  /**
   * Gets the set of supported locales for the realm.
   *
   * @return The set of supported locales.
   */
  public Set<String> getSupportedLocales() {
    return realm.getSupportedLocalesStream().collect(Collectors.toSet());
  }

  /**
   * Checks if editing the username is allowed for users in the realm.
   *
   * @return {@code true} if editing the username is allowed; otherwise, {@code false}.
   */
  public boolean isEditUsernameAllowed() {
    return realm.isEditUsernameAllowed();
  }

  /**
   * Checks if registration email is used as the username for users in the realm.
   *
   * @return {@code true} if registration email is used as the username; otherwise, {@code false}.
   */
  public boolean isRegistrationEmailAsUsername() {
    return realm.isRegistrationEmailAsUsername();
  }

  /**
   * Checks if user-managed access is allowed in the realm.
   *
   * @return {@code true} if user-managed access is allowed; otherwise, {@code false}.
   */
  public boolean isUserManagedAccessAllowed() {
    return realm.isUserManagedAccessAllowed();
  }
}
