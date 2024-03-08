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

import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;

/**
 * This class represents information about user sessions within a realm, providing details about
 * each session.
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class SessionsBean {

  /** A list containing user session information. */
  private List<UserSessionBean> events;

  /**
   * Constructs a {@code SessionsBean} object with the specified realm and list of user sessions.
   *
   * @param realmModel   The realm associated with the user sessions.
   * @param sessionList  The list of user sessions.
   */
  public SessionsBean(final RealmModel realmModel, final List<UserSessionModel> sessionList) {
    this.events = new LinkedList<>();
    for (UserSessionModel session : sessionList) {
      this.events.add(new UserSessionBean(realmModel, session));
    }
  }

  /**
   * Gets the list of user session information.
   *
   * @return The list of user session information.
   */
  public List<UserSessionBean> getSessions() {
    return events;
  }

  /**
   * This class represents information about a user session within a realm, providing details about the session.
   */
  public static class UserSessionBean {

    /** The user session model. */
    private UserSessionModel session;

    /** The realm associated with the user session. */
    private RealmModel realm;

    /**
     * Constructs a {@code UserSessionBean} object with the specified realm and user session.
     *
     * @param realmModel     The realm associated with the user session.
     * @param sessionModel   The user session model.
     */
    public UserSessionBean(final RealmModel realmModel, final UserSessionModel sessionModel) {
      this.realm = realmModel;
      this.session = sessionModel;
    }

    /**
     * Gets the ID of the user session.
     *
     * @return The ID of the user session.
     */
    public String getId() {
      return session.getId();
    }

    /**
     * Gets the IP address associated with the user session.
     *
     * @return The IP address associated with the user session.
     */
    public String getIpAddress() {
      return session.getIpAddress();
    }

    /**
     * Gets the start time of the user session.
     *
     * @return The start time of the user session.
     */
    public Date getStarted() {
      return Time.toDate(session.getStarted());
    }

    /**
     * Gets the last access time of the user session.
     *
     * @return The last access time of the user session.
     */
    public Date getLastAccess() {
      return Time.toDate(session.getLastSessionRefresh());
    }

    /**
     * Gets the expiration time of the user session.
     *
     * @return The expiration time of the user session.
     */
    public Date getExpires() {
      int maxLifespan =
          session.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0
              ? realm.getSsoSessionMaxLifespanRememberMe()
              : realm.getSsoSessionMaxLifespan();
      int max = session.getStarted() + maxLifespan;
      return Time.toDate(max);
    }

    /**
     * Gets the set of client IDs associated with the user session.
     *
     * @return The set of client IDs associated with the user session.
     */
    public Set<String> getClients() {
      Set<String> clients = new HashSet<>();
      for (String clientUUID : session.getAuthenticatedClientSessions().keySet()) {
        ClientModel client = realm.getClientById(clientUUID);
        clients.add(client.getClientId());
      }
      return clients;
    }
  }
}
