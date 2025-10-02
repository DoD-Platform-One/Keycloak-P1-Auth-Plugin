package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.common.YAMLConfigClientLogin;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for the methods in {@link ClientSpecificLoginEventListenerProvider}.
 * Uses reflection to test private methods.
 */
@ExtendWith(MockitoExtension.class)
public class ClientSpecificLoginEventListenerProviderMethodsTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmProvider realmProvider;

    @Mock
    private UserProvider userProvider;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    @Mock
    private CommonConfig commonConfig;

    private ClientSpecificLoginEventListenerProvider provider;
    private Event loginEvent;
    private Event nonLoginEvent;

    @BeforeEach
    public void setup() {
        // Use lenient() to avoid UnnecessaryStubbingException for stubbings that might not be used in every test
        lenient().when(session.realms()).thenReturn(realmProvider);
        lenient().when(session.users()).thenReturn(userProvider);
        
        provider = new ClientSpecificLoginEventListenerProvider(session);
        
        loginEvent = new Event();
        loginEvent.setType(EventType.LOGIN);
        loginEvent.setRealmId("test-realm");
        loginEvent.setUserId("test-user-id");
        loginEvent.setClientId("abc-client");
        
        nonLoginEvent = new Event();
        nonLoginEvent.setType(EventType.LOGOUT);
        
        lenient().when(realmProvider.getRealm("test-realm")).thenReturn(realm);
        lenient().when(userProvider.getUserById(realm, "test-user-id")).thenReturn(user);
        lenient().when(user.getUsername()).thenReturn("testuser");
    }

    /**
     * Test that non-login events are ignored.
     */
    @Test
    public void testNonLoginEventIgnored() {
        provider.onEvent(nonLoginEvent);
        
        // Verify that no user attributes were set
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    /**
     * Test that null user or client ID is handled properly.
     */
    @Test
    public void testNullUserOrClientId() {
        // Create events with null user or client ID
        Event nullUserEvent = new Event();
        nullUserEvent.setType(EventType.LOGIN);
        nullUserEvent.setRealmId("test-realm");
        nullUserEvent.setClientId("abc-client");
        // No user ID set
        
        Event nullClientEvent = new Event();
        nullClientEvent.setType(EventType.LOGIN);
        nullClientEvent.setRealmId("test-realm");
        nullClientEvent.setUserId("test-user-id");
        // No client ID set
        
        lenient().when(userProvider.getUserById(realm, null)).thenReturn(null);
        
        // Test with null user
        provider.onEvent(nullUserEvent);
        verify(user, never()).setSingleAttribute(anyString(), anyString());
        
        // Test with null client ID
        provider.onEvent(nullClientEvent);
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    /**
     * Test the getCurrentTimestamp method.
     */
    @Test
    public void testGetCurrentTimestamp() throws Exception {
        Method getCurrentTimestamp = ClientSpecificLoginEventListenerProvider.class
                .getDeclaredMethod("getCurrentTimestamp");
        getCurrentTimestamp.setAccessible(true);
        
        String timestamp = (String) getCurrentTimestamp.invoke(provider);
        
        assertNotNull(timestamp, "Timestamp should not be null");
        // The ISO format from DateTimeFormatter.ISO_INSTANT is: yyyy-MM-dd'T'HH:mm:ss.SSSZ
        // But the Z at the end is a literal 'Z', not a timezone pattern
        assertTrue(timestamp.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z"),
                "Timestamp should be in ISO format");
    }

    /**
     * Test the buildClientToAttributeMap method.
     */
    @Test
    public void testBuildClientToAttributeMap() throws Exception {
        Method buildClientToAttributeMap = ClientSpecificLoginEventListenerProvider.class
                .getDeclaredMethod("buildClientToAttributeMap", List.class);
        buildClientToAttributeMap.setAccessible(true);
        
        List<YAMLConfigClientLogin> configs = new ArrayList<>();
        
        // First config
        YAMLConfigClientLogin config1 = new YAMLConfigClientLogin();
        config1.setAttributeName("ABCGroupLastLogin");
        List<String> clientIds1 = new ArrayList<>();
        clientIds1.add("abc-client");
        clientIds1.add("abc-admin");
        config1.setClientIds(clientIds1);
        configs.add(config1);
        
        // Second config
        YAMLConfigClientLogin config2 = new YAMLConfigClientLogin();
        config2.setAttributeName("DEFGroupLastLogin");
        List<String> clientIds2 = new ArrayList<>();
        clientIds2.add("def-client");
        config2.setClientIds(clientIds2);
        configs.add(config2);
        
        // Config with null client IDs (should be skipped)
        YAMLConfigClientLogin config3 = new YAMLConfigClientLogin();
        config3.setAttributeName("XYZGroupLastLogin");
        config3.setClientIds(null);
        configs.add(config3);
        
        @SuppressWarnings("unchecked")
        Map<String, String> result = (Map<String, String>) buildClientToAttributeMap.invoke(provider, configs);
        
        // Verify the map contains expected mappings
        assertEquals("ABCGroupLastLogin", result.get("abc-client"), "Should map abc-client to ABCGroupLastLogin");
        assertEquals("ABCGroupLastLogin", result.get("abc-admin"), "Should map abc-admin to ABCGroupLastLogin");
        assertEquals("DEFGroupLastLogin", result.get("def-client"), "Should map def-client to DEFGroupLastLogin");
        assertNull(result.get("xyz-client"), "Should not contain unmapped client");
        
        // Verify size
        assertEquals(3, result.size(), "Map should contain exactly 3 entries");
    }

    /**
     * Test the preservePriorValue method.
     */
    @Test
    public void testPreservePriorValue() throws Exception {
        Method preservePriorValue = ClientSpecificLoginEventListenerProvider.class
                .getDeclaredMethod("preservePriorValue", UserModel.class, String.class);
        preservePriorValue.setAccessible(true);
        
        // Setup user attributes
        Map<String, List<String>> attributes = new HashMap<>();
        List<String> values = new ArrayList<>();
        values.add("2023-01-01T00:00:00.000Z");
        attributes.put("testAttribute", values);
        when(user.getAttributes()).thenReturn(attributes);
        
        // Test with existing attribute
        preservePriorValue.invoke(provider, user, "testAttribute");
        verify(user).setSingleAttribute("priortestAttribute", "2023-01-01T00:00:00.000Z");
        
        // Test with non-existing attribute
        preservePriorValue.invoke(provider, user, "nonExistingAttribute");
        verify(user, never()).setSingleAttribute(eq("priornonExistingAttribute"), anyString());
        
        // Test with empty values
        attributes.put("emptyAttribute", new ArrayList<>());
        preservePriorValue.invoke(provider, user, "emptyAttribute");
        verify(user, never()).setSingleAttribute(eq("prioremptyAttribute"), anyString());
        
        // Test with null values
        attributes.put("nullAttribute", null);
        preservePriorValue.invoke(provider, user, "nullAttribute");
        verify(user, never()).setSingleAttribute(eq("priornullAttribute"), anyString());
    }

    /**
     * Test the updateUserAttribute method.
     */
    @Test
    public void testUpdateUserAttribute() throws Exception {
        Method updateUserAttribute = ClientSpecificLoginEventListenerProvider.class
                .getDeclaredMethod("updateUserAttribute", UserModel.class, String.class, String.class);
        updateUserAttribute.setAccessible(true);
        
        // Setup user attributes
        Map<String, List<String>> attributes = new HashMap<>();
        when(user.getAttributes()).thenReturn(attributes);
        
        // Test updating an attribute
        updateUserAttribute.invoke(provider, user, "testAttribute", "new-value");
        verify(user).setSingleAttribute("testAttribute", "new-value");
    }

    /**
     * Test exception handling in the processLoginEvent method.
     */
    @Test
    public void testExceptionHandling() {
        try (MockedStatic<CommonConfig> mockedStatic = Mockito.mockStatic(CommonConfig.class)) {
            // Mock the static getInstance method to throw an exception
            mockedStatic.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenThrow(new RuntimeException("Test exception"));
            
            // This should not throw an exception
            assertDoesNotThrow(() -> provider.onEvent(loginEvent), 
                    "Exception should be caught and logged, not thrown");
        }
    }
}