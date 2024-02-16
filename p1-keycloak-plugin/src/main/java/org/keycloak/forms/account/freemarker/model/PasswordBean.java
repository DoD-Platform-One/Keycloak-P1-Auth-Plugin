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
 * This class represents information about the password, indicating whether it is set.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class PasswordBean {

  /** Indicates whether the password is set. */
  private boolean passwordSet;

  /**
   * Constructs a {@code PasswordBean} object with the given information about the password.
   *
   * @param isPasswordSet {@code true} if the password is set; otherwise, {@code false}.
   */
  public PasswordBean(final boolean isPasswordSet) {
    this.passwordSet = isPasswordSet;
  }

  /**
   * Checks if the password is set.
   *
   * @return {@code true} if the password is set; otherwise, {@code false}.
   */
  public boolean isPasswordSet() {
    return passwordSet;
  }
}
