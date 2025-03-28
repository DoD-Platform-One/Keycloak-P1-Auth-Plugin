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

import java.io.IOException;
import java.net.URI;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.services.AccountUrls;
import org.keycloak.theme.Theme;

/**
 * This class represents a bean for managing URLs related to account operations.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class UrlBean {

  /** Logger for capturing log information. */
  private static final Logger LOGGER = Logger.getLogger(UrlBean.class);

  /** The name of the realm. */
  private String realm;

  /** The selected theme. */
  private Theme theme;

  /** The base URI. */
  private URI baseURI;

  /** The base query URI. */
  private URI baseQueryURI;

  /** The current URI. */
  private URI currentURI;

  /** The ID token hint. */
  private String idTokenHint;

  /**
   * Constructs a new {@code UrlBean} instance.
   *
   * @param realmModel   The realm model.
   * @param selectedTheme The selected theme.
   * @param baseUri       The base URI.
   * @param baseQueryUri  The base query URI.
   * @param currentUri    The current URI.
   * @param tokenHint     The ID token hint.
   */
  public UrlBean(
      final RealmModel realmModel,
      final Theme selectedTheme,
      final URI baseUri,
      final URI baseQueryUri,
      final URI currentUri,
      final String tokenHint) {
    this.realm = realmModel.getName();
    this.theme = selectedTheme;
    this.baseURI = baseUri;
    this.baseQueryURI = baseQueryUri;
    this.currentURI = currentUri;
    this.idTokenHint = tokenHint;
  }

  /**
   * Gets the applications URL.
   *
   * @return The applications URL.
   */
  public String getApplicationsUrl() {
    return AccountUrls.accountApplicationsPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the account URL.
   *
   * @return The account URL.
   */
  public String getAccountUrl() {
    return AccountUrls.accountPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the password URL.
   *
   * @return The password URL.
   */
  public String getPasswordUrl() {
    return AccountUrls.accountPasswordPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the social URL.
   *
   * @return The social URL.
   */
  public String getSocialUrl() {
    return AccountUrls.accountFederatedIdentityPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the TOTP URL.
   *
   * @return The TOTP URL.
   */
  public String getTotpUrl() {
    return AccountUrls.accountTotpPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the log URL.
   *
   * @return The log URL.
   */
  public String getLogUrl() {
    return AccountUrls.accountLogPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the sessions URL.
   *
   * @return The sessions URL.
   */
  public String getSessionsUrl() {
    return AccountUrls.accountSessionsPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the logout URL.
   *
   * @return The logout URL.
   */
  public String getLogoutUrl() {
    return AccountUrls.accountLogout(baseQueryURI, currentURI, realm, idTokenHint).toString();
  }

  /**
   * Gets the resource URL.
   *
   * @return The resource URL.
   */
  public String getResourceUrl() {
    return AccountUrls.accountResourcesPage(baseQueryURI, realm).toString();
  }

  /**
   * Gets the resource detail URL.
   *
   * @param id The resource ID.
   * @return The resource detail URL.
   */
  public String getResourceDetailUrl(final String id) {
    return AccountUrls.accountResourceDetailPage(id, baseQueryURI, realm).toString();
  }

  /**
   * Gets the resource grant URL.
   *
   * @param id The resource ID.
   * @return The resource grant URL.
   */
  public String getResourceGrant(final String id) {
    return AccountUrls.accountResourceGrant(id, baseQueryURI, realm).toString();
  }

  /**
   * Gets the resource share URL.
   *
   * @param id The resource ID.
   * @return The resource share URL.
   */
  public String getResourceShare(final String id) {
    return AccountUrls.accountResourceShare(id, baseQueryURI, realm).toString();
  }

  /**
   * Gets the path for resources based on the theme.
   *
   * @return The path for resources.
   */
  public String getResourcesPath() {
    URI uri = AccountUrls.themeRoot(baseURI);
    return uri.getPath() + "/" + theme.getType().toString().toLowerCase() + "/" + theme.getName();
  }

  /**
   * Gets the common path for resources based on the theme.
   *
   * @return The common path for resources.
   */
  public String getResourcesCommonPath() {
    URI uri = AccountUrls.themeRoot(baseURI);
    String commonPath = "";
    try {
      commonPath = theme.getProperties().getProperty("import");
    } catch (IOException ex) {
      LOGGER.warn("Failed to load properties", ex);
    }
    if (commonPath == null || commonPath.isEmpty()) {
      // Get default common path from theme properties or system property
      commonPath = System.getProperty("keycloak.theme.common.path", "/common/keycloak");
    }
    return uri.getPath() + "/" + commonPath;
  }
}
