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

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.account.AccountProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory class for creating instances of {@link FreeMarkerAccountProvider}.
 *
 * <p>This factory is responsible for creating and managing instances of the
 * FreeMarker-based account provider, {@link FreeMarkerAccountProvider}.
 * It implements the {@link AccountProviderFactory} interface and is registered as
 * a service provider using the {@link AutoService} annotation.
 * </p>
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@AutoService(AccountProviderFactory.class)
public class FreeMarkerAccountProviderFactory implements AccountProviderFactory {

  /**
   * Creates a new instance of {@link FreeMarkerAccountProvider}.
   *
   * @param session The Keycloak session.
   * @return A new instance of {@link FreeMarkerAccountProvider}.
   */
  @Override
  public AccountProvider create(final KeycloakSession session) {
    return new FreeMarkerAccountProvider(session);
  }

  /**
   * Initializes the factory with configuration.
   *
   * @param config The configuration scope.
   */
  @Override
  public void init(final Config.Scope config) {
    // Initializes the factory with configuration.
  }

  /**
   * Performs post-initialization tasks.
   *
   * @param factory The Keycloak session factory.
   */
  @Override
  public void postInit(final KeycloakSessionFactory factory) {
    // Performs post-initialization tasks.
  }

  /**
   * Cleans up resources associated with the factory.
   */
  @Override
  public void close() {
    // Cleans up resources associated with the factory.
  }

  /**
   * Gets the identifier for this factory.
   *
   * @return The identifier for this factory ("freemarker").
   */
  @Override
  public String getId() {
    return "freemarker";
  }
}
