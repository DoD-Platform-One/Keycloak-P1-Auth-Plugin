package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.mockito.Mockito;

import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class LogBeanTest {

    @Test
    void testLogBeanConstruction() {
        Map<String, String> map = new HashMap<>();
        // Add values to the map
        map.put("key1", "value1");
        map.put("key2", "value2");
        map.put("key3", "value3");

        // Mock some Event objects
        Event event1 = Mockito.mock(Event.class);
        Mockito.when(event1.getTime()).thenReturn(System.currentTimeMillis());
        Mockito.when(event1.getType()).thenReturn(EventType.LOGIN);
        Mockito.when(event1.getClientId()).thenReturn("client1");
        Mockito.when(event1.getIpAddress()).thenReturn("192.168.1.1");
        Mockito.when(event1.getDetails()).thenReturn(map);

        Event event2 = Mockito.mock(Event.class);
        Mockito.when(event2.getTime()).thenReturn(System.currentTimeMillis());
        Mockito.when(event2.getType()).thenReturn(EventType.LOGOUT);
        Mockito.when(event2.getClientId()).thenReturn("client2");
        Mockito.when(event2.getIpAddress()).thenReturn("192.168.1.2");
        Mockito.when(event2.getDetails()).thenReturn(null);

        // Create a list of mocked Event objects
        List<Event> eventList = Arrays.asList(event1, event2);

        // Create a LogBean from the list of mocked Event objects
        LogBean logBean = new LogBean(eventList);

        // Get the list of EventBean objects from the LogBean
        List<LogBean.EventBean> eventBeans = logBean.getEvents();

        // Assert the size of the EventBean list
        assertEquals(2, eventBeans.size(), "Expected two events in the log");

        // Assert the transformation of Event to EventBean
        assertEquals(new Date(event1.getTime()), eventBeans.get(0).getDate(),
                "EventBean date should match the mock event's date");
        assertEquals("login", eventBeans.get(0).getEvent(),
                "EventBean event should match the mock event's type");
        assertEquals("client1", eventBeans.get(0).getClient(),
                "EventBean client should match the mock event's clientId");
        assertEquals("192.168.1.1", eventBeans.get(0).getIpAddress(),
                "EventBean IP address should match the mock event's IP address");
        assertNotNull(eventBeans.get(0).getDetails(),
                "EventBean details should not be null when the event has details");

        assertEquals(new Date(event2.getTime()), eventBeans.get(1).getDate(),
                "EventBean date should match the second mock event's date");
        assertEquals("logout", eventBeans.get(1).getEvent(),
                "EventBean event should match the second mock event's type");
        assertEquals("client2", eventBeans.get(1).getClient(),
                "EventBean client should match the second mock event's clientId");
        assertEquals("192.168.1.2", eventBeans.get(1).getIpAddress(),
                "EventBean IP address should match the second mock event's IP address");
        assertEquals(Collections.emptyList(), eventBeans.get(1).getDetails(),
                "EventBean details should be an empty list when the event has no details");

        // Test DetailBean
        Map.Entry<String, String> entryMap = new AbstractMap.SimpleEntry<>("key1", "value1");
        LogBean.DetailBean detailBean = new LogBean.DetailBean(entryMap);

        assertEquals("key1", detailBean.getKey(),
                "DetailBean key should match the entry's key");
        assertEquals("value1", detailBean.getValue(),
                "DetailBean value should match the entry's value");
    }
}
