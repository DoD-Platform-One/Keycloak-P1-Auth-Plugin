package org.keycloak.forms.account.freemarker.model;

import org.junit.Test;
import org.mockito.Mockito;

import java.util.*;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.forms.account.freemarker.model.LogBean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LogBeanTest {

    @Test
    public void testLogBeanConstruction() {
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
        assertEquals(2, eventBeans.size());

        // Assert the transformation of Event to EventBean
        assertEquals(new Date(event1.getTime()), eventBeans.get(0).getDate());
        assertEquals("login", eventBeans.get(0).getEvent());
        assertEquals("client1", eventBeans.get(0).getClient());
        assertEquals("192.168.1.1", eventBeans.get(0).getIpAddress());
        assertNotNull(eventBeans.get(0).getDetails());

        assertEquals(new Date(event2.getTime()), eventBeans.get(1).getDate());
        assertEquals("logout", eventBeans.get(1).getEvent());
        assertEquals("client2", eventBeans.get(1).getClient());
        assertEquals("192.168.1.2", eventBeans.get(1).getIpAddress());
        assertEquals(Collections.emptyList(), eventBeans.get(1).getDetails());

        // Test DetailBean
        Map.Entry<String, String> entryMap = new AbstractMap.SimpleEntry<>("key1", "value1");

        LogBean.DetailBean detailBean = new LogBean.DetailBean(entryMap);

        assertEquals("key1", detailBean.getKey());
        assertEquals("value1", detailBean.getValue());
    }
}
