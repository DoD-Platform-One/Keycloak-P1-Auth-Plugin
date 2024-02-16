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

/**
 * Represents a bean encapsulating various features and their states.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class FeaturesBean {

  /** Represents the state of identity federation. */
  private final boolean identityFederation;

  /** Represents the logging status. */
  private final boolean log;

  /** Indicates whether password updates are supported. */
  private final boolean passwordUpdateSupported;

  /** Represents the authorization status. */
  private boolean authorization;

  /**
   * Constructs a new FeaturesBean with the specified feature states.
   *
   * @param isIdentityFederationEnabled True if identity federation is enabled, false otherwise.
   * @param isLoggingEnabled True if logging is enabled, false otherwise.
   * @param isPasswordUpdateSupported True if password updates are supported, false otherwise.
   * @param isAuthorizationEnabled True if authorization is enabled, false otherwise.
   */
  public FeaturesBean(
      final boolean isIdentityFederationEnabled,
      final boolean isLoggingEnabled,
      final boolean isPasswordUpdateSupported,
      final boolean isAuthorizationEnabled) {
    this.identityFederation = isIdentityFederationEnabled;
    this.log = isLoggingEnabled;
    this.passwordUpdateSupported = isPasswordUpdateSupported;
    this.authorization = isAuthorizationEnabled;
  }

  /**
   * Gets the state of identity federation.
   *
   * @return True if identity federation is enabled, false otherwise.
   */
  public boolean isIdentityFederation() {
    return identityFederation;
  }

  /**
   * Gets the logging status.
   *
   * @return True if logging is enabled, false otherwise.
   */
  public boolean isLog() {
    return log;
  }

  /**
   * Checks if password updates are supported.
   *
   * @return True if password updates are supported, false otherwise.
   */
  public boolean isPasswordUpdateSupported() {
    return passwordUpdateSupported;
  }

  /**
   * Gets the authorization status.
   *
   * @return True if authorization is enabled, false otherwise.
   */
  public boolean isAuthorization() {
    return authorization;
  }
}
