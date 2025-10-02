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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ClientSpecificLoginEventListenerProviderTest {

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

    @BeforeEach
    public void setup() {
        when(session.realms()).thenReturn(realmProvider);
        when(session.users()).thenReturn(userProvider);
        
        provider = new ClientSpecificLoginEventListenerProvider(session);
        
        loginEvent = new Event();
        loginEvent.setType(EventType.LOGIN);
        loginEvent.setRealmId("test-realm");
        loginEvent.setUserId("test-user-id");
        loginEvent.setClientId("abc-client");
        
        when(realmProvider.getRealm("test-realm")).thenReturn(realm);
        when(userProvider.getUserById(realm, "test-user-id")).thenReturn(user);
        // Removed unnecessary stubbing that was causing UnnecessaryStubbingException
    }

    @Test
    public void testOnEventWithMatchingClient() {
        try (MockedStatic<CommonConfig> mockedStatic = Mockito.mockStatic(CommonConfig.class)) {
            // Mock the static getInstance method
            mockedStatic.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            
            // Create client login config
            List<YAMLConfigClientLogin> clientLoginConfigs = new ArrayList<>();
            YAMLConfigClientLogin config = new YAMLConfigClientLogin();
            config.setAttributeName("ABCGroupLastLogin");
            config.setDescription("ABC Group Last Login");
            List<String> clientIds = new ArrayList<>();
            clientIds.add("abc-client");
            config.setClientIds(clientIds);
            clientLoginConfigs.add(config);
            
            when(commonConfig.getClientLoginAttributes()).thenReturn(clientLoginConfigs);
            
            // Mock user attributes
            Map<String, List<String>> attributes = new HashMap<>();
            when(user.getAttributes()).thenReturn(attributes);
            
            // Execute the event
            provider.onEvent(loginEvent);
            
            // Verify that the attribute was set
            verify(user).setSingleAttribute(eq("ABCGroupLastLogin"), anyString());
        }
    }
    
    @Test
    public void testOnEventWithNonMatchingClient() {
        try (MockedStatic<CommonConfig> mockedStatic = Mockito.mockStatic(CommonConfig.class)) {
            // Mock the static getInstance method
            mockedStatic.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            
            // Create client login config
            List<YAMLConfigClientLogin> clientLoginConfigs = new ArrayList<>();
            YAMLConfigClientLogin config = new YAMLConfigClientLogin();
            config.setAttributeName("DEFGroupLastLogin");
            config.setDescription("DEF Group Last Login");
            List<String> clientIds = new ArrayList<>();
            clientIds.add("def-client");
            config.setClientIds(clientIds);
            clientLoginConfigs.add(config);
            
            when(commonConfig.getClientLoginAttributes()).thenReturn(clientLoginConfigs);
            
            // Execute the event
            provider.onEvent(loginEvent);
            
            // Verify that the attribute was not set
            verify(user, never()).setSingleAttribute(eq("DEFGroupLastLogin"), anyString());
        }
    }
    
    @Test
    public void testOnEventWithExistingAttribute() {
        try (MockedStatic<CommonConfig> mockedStatic = Mockito.mockStatic(CommonConfig.class)) {
            // Mock the static getInstance method
            mockedStatic.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            
            // Create client login config
            List<YAMLConfigClientLogin> clientLoginConfigs = new ArrayList<>();
            YAMLConfigClientLogin config = new YAMLConfigClientLogin();
            config.setAttributeName("ABCGroupLastLogin");
            config.setDescription("ABC Group Last Login");
            List<String> clientIds = new ArrayList<>();
            clientIds.add("abc-client");
            config.setClientIds(clientIds);
            clientLoginConfigs.add(config);
            
            when(commonConfig.getClientLoginAttributes()).thenReturn(clientLoginConfigs);
            
            // Mock user attributes with existing value
            Map<String, List<String>> attributes = new HashMap<>();
            List<String> existingValue = new ArrayList<>();
            existingValue.add("2023-01-01T00:00:00Z");
            attributes.put("ABCGroupLastLogin", existingValue);
            when(user.getAttributes()).thenReturn(attributes);
            
            // Execute the event
            provider.onEvent(loginEvent);
            
            // Verify that the prior attribute was set
            verify(user).setSingleAttribute(eq("priorABCGroupLastLogin"), eq("2023-01-01T00:00:00Z"));
            
            // Verify that the attribute was updated
            verify(user).setSingleAttribute(eq("ABCGroupLastLogin"), anyString());
        }
    }
}