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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.keycloak.events.Event;

/**
 * Represents a bean encapsulating a log and its events.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class LogBean {

  /** The list of events in the log. */
  private List<EventBean> events;

  /**
   * Constructs a LogBean from a list of events.
   *
   * @param eventList The list of events to populate the LogBean.
   */
  public LogBean(final List<Event> eventList) {
    this.events = new LinkedList<>();
    for (Event e : eventList) {
      this.events.add(new EventBean(e));
    }
  }

  /**
   * Gets the list of events in the log.
   *
   * @return The list of events.
   */
  public List<EventBean> getEvents() {
    return events;
  }

  /**
   * Represents a bean encapsulating an event within a log.
   */
  public static class EventBean {

    /** The event being represented. */
    private Event event;

    /**
     * Constructs an EventBean from an event model.
     *
     * @param eventModel The event model to populate the EventBean.
     */
    public EventBean(final Event eventModel) {
      this.event = eventModel;
    }

    /**
     * Gets the date of the event.
     *
     * @return The date of the event.
     */
    public Date getDate() {
      return new Date(event.getTime());
    }

    /**
     * Gets the type of the event.
     *
     * @return The type of the event.
     */
    public String getEvent() {
      return event.getType().toString().toLowerCase().replace("_", " ");
    }

    /**
     * Gets the client associated with the event.
     *
     * @return The client associated with the event.
     */
    public String getClient() {
      return event.getClientId();
    }

    /**
     * Gets the IP address associated with the event.
     *
     * @return The IP address associated with the event.
     */
    public String getIpAddress() {
      return event.getIpAddress();
    }

    /**
     * Gets the details associated with the event.
     *
     * @return The list of details associated with the event.
     */
    public List<DetailBean> getDetails() {
      List<DetailBean> details = new LinkedList<>();
      if (event.getDetails() != null) {
        for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
          details.add(new DetailBean(e));
        }
      }
      return details;
    }
  }

  /**
   * Represents a bean encapsulating details of an event.
   */
  public static class DetailBean {

    /** The detail entry. */
    private Map.Entry<String, String> entry;

    /**
     * Constructs a DetailBean from a map entry.
     *
     * @param entryMap The map entry to populate the DetailBean.
     */
    public DetailBean(final Map.Entry<String, String> entryMap) {
      this.entry = entryMap;
    }

    /**
     * Gets the key of the detail.
     *
     * @return The key of the detail.
     */
    public String getKey() {
      return entry.getKey();
    }

    /**
     * Gets the value of the detail.
     *
     * @return The value of the detail.
     */
    public String getValue() {
      return entry.getValue().replace("_", " ");
    }
  }
}
