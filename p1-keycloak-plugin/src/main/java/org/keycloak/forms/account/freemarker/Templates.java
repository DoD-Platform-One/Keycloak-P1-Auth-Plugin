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

package org.keycloak.forms.account.freemarker;

import org.keycloak.forms.account.AccountPages;

/**
 * Utility class for retrieving template names based on account pages.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public final class Templates {

  // Private constructor to prevent instantiation
  private Templates() {
    // This class should not be instantiated
    throw new AssertionError("Utility class Templates should not be instantiated");
  }

  /**
   * Gets the template name for the specified account page.
   *
   * @param page The account page.
   * @return The template name associated with the given account page.
   * @throws IllegalArgumentException If an invalid account page is provided.
   */
  public static String getTemplate(final AccountPages page) {
    switch (page) {
      case ACCOUNT:
        return "account.ftl";
      case PASSWORD:
        return "password.ftl";
      case TOTP:
        return "totp.ftl";
      case FEDERATED_IDENTITY:
        return "federatedIdentity.ftl";
      case LOG:
        return "log.ftl";
      case SESSIONS:
        return "sessions.ftl";
      case APPLICATIONS:
        return "applications.ftl";
      case RESOURCES:
        return "resources.ftl";
      case RESOURCE_DETAIL:
        return "resource-detail.ftl";
      default:
        throw new IllegalArgumentException();
    }
  }
}
