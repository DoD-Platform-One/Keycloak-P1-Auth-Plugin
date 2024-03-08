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

import jakarta.ws.rs.core.MultivaluedMap;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;

/**
 * Represents user account information, providing access to common attributes like first name, last name, username,
 * and email. Additionally, it includes a map of custom attributes associated with the user.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AccountBean {

  /** Logger for logging messages. */
  private static final Logger LOGGER = Logger.getLogger(AccountBean.class);

  /** The user model containing account information. */
  private final UserModel user;

  /** The form data containing profile information. */
  private final MultivaluedMap<String, String> profileFormData;

  // Potential Update: More proper multi-value attribute support
  /** A map to store custom attributes associated with the user. */
  private final Map<String, String> attributes = new HashMap<>();

  /**
   * Constructs an AccountBean with user model and profile form data.
   *
   * @param userModel        The user model containing account information.
   * @param profileFormDataMap  The form data containing profile information.
   */
  public AccountBean(final UserModel userModel, final MultivaluedMap<String, String> profileFormDataMap) {
    this.user = userModel;
    this.profileFormData = profileFormDataMap;

    for (Map.Entry<String, List<String>> attr : userModel.getAttributes().entrySet()) {
      List<String> attrValue = attr.getValue();
      if (!attrValue.isEmpty()) {
        attributes.put(attr.getKey(), attrValue.get(0));
      }

      if (attrValue.size() > 1) {
        LOGGER.warnf(
            "There are more values for attribute '%s' of user '%s' . Will display just first value",
            attr.getKey(), userModel.getUsername());
      }
    }

    if (profileFormDataMap != null) {
      for (String key : profileFormDataMap.keySet()) {
        if (key.startsWith(Constants.USER_ATTRIBUTES_PREFIX)) {
          String attribute = key.substring(Constants.USER_ATTRIBUTES_PREFIX.length());
          attributes.put(attribute, profileFormDataMap.getFirst(key));
        } else {
          attributes.put(key, profileFormDataMap.getFirst(key));
        }
      }
    }
  }

  /**
   * Gets the first name of the user.
   *
   * @return The first name.
   */
  public String getFirstName() {
    return profileFormData != null ? profileFormData.getFirst("firstName") : user.getFirstName();
  }

  /**
   * Gets the last name of the user.
   *
   * @return The last name.
   */
  public String getLastName() {
    return profileFormData != null ? profileFormData.getFirst("lastName") : user.getLastName();
  }

  /**
   * Gets the username of the user.
   *
   * @return The username.
   */
  public String getUsername() {
    if (profileFormData != null && profileFormData.containsKey("username")) {
      return profileFormData.getFirst("username");
    } else {
      return user.getUsername();
    }
  }

  /**
   * Gets the email address of the user.
   *
   * @return The email address.
   */
  public String getEmail() {
    return profileFormData != null ? profileFormData.getFirst("email") : user.getEmail();
  }

  /**
   * Gets the custom attributes associated with the user.
   *
   * @return A map of custom attributes.
   */
  public Map<String, String> getAttributes() {
    // attributes is never null, it can be empty, but it will never be null (check line 49)
    return !attributes.isEmpty() ? attributes : Collections.emptyMap();
  }
}
