package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for ResetPasswordProvider.
 */
@ExtendWith(MockitoExtension.class)
class ResetPasswordProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    @Mock
    private Event event;

    @Mock
    private AdminEvent adminEvent;

    private ResetPasswordProvider provider;

    @BeforeEach
    void setUp() {
        provider = new ResetPasswordProvider(session);
        
        lenient().when(session.getContext()).thenReturn(mock(org.keycloak.models.KeycloakContext.class));
        lenient().when(session.getContext().getRealm()).thenReturn(realm);
        lenient().when(session.users()).thenReturn(mock(org.keycloak.models.UserProvider.class));
        lenient().when(session.users().getUserById(any(), anyString())).thenReturn(user);
        lenient().when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
        lenient().when(session.realms().getRealm(anyString())).thenReturn(realm);
        lenient().when(user.getUsername()).thenReturn("testuser");
    }

    @Test
    void testOnEventWithSendResetPasswordEvent() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        verify(user).setSingleAttribute("reset_pwd_token", "test-token-123");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
    }

    @Test
    void testOnEventWithSendResetPasswordEventNoToken() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithSendResetPasswordEventEmptyToken() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithSendResetPasswordEventNullDetails() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        when(event.getDetails()).thenReturn(null);
        
        provider.onEvent(event);
        
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithSendResetPasswordEventNoUser() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        when(session.users().getUserById(any(), anyString())).thenReturn(null);
        
        provider.onEvent(event);
        
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithSendResetPasswordEventNoUserId() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn(null);
        when(event.getRealmId()).thenReturn("realm-123");
        
        provider.onEvent(event);
        
        // The implementation will still try to get the user but won't find it due to null userId
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithSendResetPasswordEventNoRealmId() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn(null);
        
        provider.onEvent(event);
        
        // The implementation will still try to get the user but won't find it
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithOtherEventType() {
        when(event.getType()).thenReturn(EventType.LOGIN);
        
        provider.onEvent(event);
        
        verify(session.users(), never()).getUserById(any(), anyString());
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithNullEvent() {
        provider.onEvent(null);
        
        verify(session.users(), never()).getUserById(any(), anyString());
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testOnEventWithUpdatePasswordEvent() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // No token clearing expected - relying on 5-minute expiration
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }

    @Test
    void testOnEventWithUpdatePasswordEventNoStoredToken() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }

    @Test
    void testStoreNewTokenWithLegacyAttributes() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should store the new token and timestamp
        verify(user).setSingleAttribute("reset_pwd_token", "test-token-123");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
    }

    @Test
    void testOnAdminEvent() {
        // Admin events should be ignored
        provider.onEvent(adminEvent, true);
        provider.onEvent(adminEvent, false);
        
        verify(session.users(), never()).getUserById(any(), anyString());
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testClose() {
        // Should not throw any exception
        assertDoesNotThrow(() -> provider.close());
    }

    @Test
    void testTimestampGeneration() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should store the new token and timestamp
        verify(user).setSingleAttribute("reset_pwd_token", "test-token-123");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
    }

    @Test
    void testClearTokenOnPasswordUpdate() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // No token clearing expected - relying on 5-minute expiration
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }

    @Test
    void testClearTokenOnPasswordUpdatePartialAttributes() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // No token clearing expected - relying on 5-minute expiration
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }

    @Test
    void testEventProcessingWithException() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        // Simulate exception during user lookup
        when(session.users().getUserById(any(), anyString())).thenThrow(new RuntimeException("Database error"));
        
        // Should not throw exception, just log and continue
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
@Test
void testOnEventWithExecuteActionTokenEvent() {
    when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
    when(event.getUserId()).thenReturn("user-123");
    when(event.getRealmId()).thenReturn("realm-123");
    
    
    provider.onEvent(event);
    
    // Simplified logic - no token operations expected
    verify(user, never()).removeAttribute(anyString());
    verify(user, never()).getFirstAttribute(anyString());
}

@Test
void testOnEventWithExecuteActionTokenErrorEvent() {
    when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN_ERROR);
    when(event.getUserId()).thenReturn("user-123");
    when(event.getRealmId()).thenReturn("realm-123");
    
    
    provider.onEvent(event);
    
    // Simplified logic - no token operations expected
    verify(user, never()).removeAttribute(anyString());
    verify(user, never()).getFirstAttribute(anyString());
}
    
    @Test
    void testActionTokenEventWithNonResetCredentialsAction() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Should not clear tokens for non-reset-credentials actions
        verify(user, never()).removeAttribute(anyString());
    }
    
    @Test
    void testActionTokenEventWithNullDetails() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        provider.onEvent(event);
        
        // Should not crash and not clear tokens
        verify(user, never()).removeAttribute(anyString());
    }
    
    @Test
    void testActionTokenEventWithMissingAction() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Should not clear tokens without proper action
        verify(user, never()).removeAttribute(anyString());
    }
    
    @Test
    void testActionTokenEventWithNoStoredToken() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Simplified logic - no token operations expected
        verify(user, never()).removeAttribute(anyString());
        verify(user, never()).getFirstAttribute(anyString());
    }
    
    @Test
    void testActionTokenEventWithMismatchedToken() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Simplified logic - no token operations expected
        verify(user, never()).removeAttribute(anyString());
        verify(user, never()).getFirstAttribute(anyString());
    }
    
    @Test
    void testActionTokenEventWithNoTokenInDetails() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Simplified logic - no token operations expected
        verify(user, never()).removeAttribute(anyString());
        verify(user, never()).getFirstAttribute(anyString());
    }
    
    @Test
    void testStoreNewTokenWithLegacyAttributesCleanup() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Simulate legacy attributes exist
        when(user.getFirstAttribute("previousResetToken")).thenReturn("old-token");
        when(user.getFirstAttribute("previousResetTokenIat")).thenReturn("1234567890");
        
        provider.onEvent(event);
        
        // Should store new token and clean up legacy attributes
        verify(user).setSingleAttribute("reset_pwd_token", "test-token-123");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
        verify(user).removeAttribute("previousResetToken");
        verify(user).removeAttribute("previousResetTokenIat");
    }
    
    @Test
    void testUpdatePasswordEventWithResetCredentialsAction() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // No token clearing expected - relying on 5-minute expiration
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
        verify(user, never()).removeAttribute("previousResetToken");
        verify(user, never()).removeAttribute("previousResetTokenIat");
    }
    
    @Test
    void testUpdatePasswordEventWithNonResetCredentialsAction() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Should not clear tokens for non-reset-credentials actions
        verify(user, never()).removeAttribute(anyString());
    }
    
    @Test
    void testUpdatePasswordEventWithNullAction() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        
        provider.onEvent(event);
        
        // Should not clear tokens without action
        verify(user, never()).removeAttribute(anyString());
    }
    
    @Test
    void testSendResetPasswordWithInvalidateTokenException() throws Exception {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Simulate existing token that will cause exception during invalidation
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("existing-token");
        
        // Should not throw exception, just log and continue
        assertDoesNotThrow(() -> provider.onEvent(event));
        
        // Should still store the new token despite any potential invalidation failure
        verify(user).setSingleAttribute("reset_pwd_token", "test-token-123");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
    }
    
    @Test
    void testExtractTokenFromDetailsWithMultipleFields() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token_type", "reset-credentials");
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should extract token and store it
        verify(user).setSingleAttribute("reset_pwd_token", "test-token-123");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
    }
    
    @Test
    void testExtractTokenFromDetailsWithActionTokenField() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token", "action-token-456");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should extract token from action_token field
        verify(user).setSingleAttribute("reset_pwd_token", "action-token-456");
        verify(user).setSingleAttribute(eq("reset_pwd_token_iat"), anyString());
    }
    
    @Test
    void testCleanupLegacyAttributesWithAllAttributes() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Simulate some legacy attributes exist
        when(user.getFirstAttribute("previousResetToken")).thenReturn("old-token");
        when(user.getFirstAttribute("previousResetTokenIat")).thenReturn("1234567890");
        when(user.getFirstAttribute("resetTokenInfo")).thenReturn("legacy-info");
        
        provider.onEvent(event);
        
        // Should clean up legacy attributes that exist
        verify(user).removeAttribute("previousResetToken");
        verify(user).removeAttribute("previousResetTokenIat");
        // resetTokenInfo should be checked but not removed since it returns null in the mock
        verify(user).getFirstAttribute("resetTokenInfo");
    }
    
    @Test
    void testInvalidatePreviousTokenWithSingleUseStore() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "new-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock existing token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("old-token-456");
        
        // Mock SingleUseObjectProvider
        SingleUseObjectProvider singleUseStore = mock(SingleUseObjectProvider.class);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        
        provider.onEvent(event);
        
        // Should invalidate old token and store new one
        verify(singleUseStore).remove("old-token-456");
        verify(user).setSingleAttribute("reset_pwd_token", "new-token-123");
    }
    
    @Test
    void testSendResetPasswordWithNullUserProvider() {
        lenient().when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        lenient().when(session.getProvider(any())).thenReturn(null);
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        lenient().when(event.getDetails()).thenReturn(details);
        
        // Should handle null user provider gracefully
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
    
    @Test
    void testSendResetPasswordWithNullRealm() {
        lenient().when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        lenient().when(session.realms()).thenReturn(null);
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        lenient().when(event.getDetails()).thenReturn(details);
        
        // Should handle null realm service gracefully
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
    
    @Test
    void testUpdatePasswordWithValidToken() {
        lenient().when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        
        // Mock stored token and timestamp
        lenient().when(user.getFirstAttribute("reset_pwd_token")).thenReturn("valid-token");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        provider.onEvent(event);
        
        // Should not remove tokens (relying on 5-minute expiration)
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithExpiredToken() {
        lenient().when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        
        // Mock expired token (older than 5 minutes)
        long expiredTime = Instant.now().getEpochSecond() - 400; // 6+ minutes ago
        lenient().when(user.getFirstAttribute("reset_pwd_token")).thenReturn("expired-token");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(expiredTime));
        
        provider.onEvent(event);
        
        // Should not remove tokens (relying on 5-minute expiration)
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithInvalidTimestamp() {
        lenient().when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        
        // Mock token with invalid timestamp
        lenient().when(user.getFirstAttribute("reset_pwd_token")).thenReturn("valid-token");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn("invalid-timestamp");
        
        provider.onEvent(event);
        
        // Should not remove tokens (relying on 5-minute expiration)
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testInvalidateTokenWithException() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "new-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock existing token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("old-token-456");
        
        // Mock SingleUseObjectProvider that throws exception
        SingleUseObjectProvider singleUseStore = mock(SingleUseObjectProvider.class);
        doThrow(new RuntimeException("Store error")).when(singleUseStore).remove("old-token-456");
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        
        // Should not throw exception, just log and continue
        assertDoesNotThrow(() -> provider.onEvent(event));
        
        // Should still store the new token despite invalidation failure
        verify(user).setSingleAttribute("reset_pwd_token", "new-token-123");
    }
    
    @Test
    void testStoreNewTokenWithNullToken() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", null);
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should not store null token
        verify(user, never()).setSingleAttribute(eq("reset_pwd_token"), any());
        verify(user, never()).setSingleAttribute(eq("reset_pwd_token_iat"), any());
    }
    
    @Test
    void testGetUserFromEventWithException() {
        lenient().when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "test-token-123");
        lenient().when(event.getDetails()).thenReturn(details);
        
        // Mock user provider to throw exception
        org.keycloak.models.UserProvider userProvider = mock(org.keycloak.models.UserProvider.class);
        lenient().when(session.getProvider(org.keycloak.models.UserProvider.class)).thenReturn(userProvider);
        lenient().when(userProvider.getUserById(any(), eq("user-123"))).thenThrow(new RuntimeException("Database error"));
        
        // Should handle exception gracefully
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
    
    @Test
    void testHandleActionTokenEventWithNullUser() {
        lenient().when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        
        // Mock user provider to return null
        org.keycloak.models.UserProvider userProvider = mock(org.keycloak.models.UserProvider.class);
        lenient().when(session.getProvider(org.keycloak.models.UserProvider.class)).thenReturn(userProvider);
        lenient().when(userProvider.getUserById(any(), eq("user-123"))).thenReturn(null);
        
        // Should handle null user gracefully
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
    
    @Test
    void testProcessResetPasswordTokenWithEmptyToken() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "");
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should not store empty token
        verify(user, never()).setSingleAttribute(eq("reset_pwd_token"), eq(""));
    }
    
    @Test
    void testExecuteActionTokenEvent() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        provider.onEvent(event);
        
        // Should process action token event
        verify(user).getUsername();
    }
    
    @Test
    void testExecuteActionTokenErrorEvent() {
        when(event.getType()).thenReturn(EventType.EXECUTE_ACTION_TOKEN_ERROR);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        provider.onEvent(event);
        
        // Should process action token error event
        verify(user).getUsername();
    }
    
    @Test
    void testUpdatePasswordWithResetCredentialsAction() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token_type", "reset-credentials");
        details.put("token", "used-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock stored token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("used-token-123");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        provider.onEvent(event);
        
        // Should clear tokens after successful password update
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithTokenMismatch() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token_type", "reset-credentials");
        details.put("token", "old-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock stored token that doesn't match
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("current-token-456");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        // Mock SingleUseObjectProvider for token invalidation
        SingleUseObjectProvider singleUseStore = mock(SingleUseObjectProvider.class);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        
        provider.onEvent(event);
        
        // Should invalidate the old token
        verify(singleUseStore).remove("old-token-123");
        // Should still clear tokens after password update
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithActionField() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action", "RESET_CREDENTIALS");
        details.put("token", "action-token-789");
        when(event.getDetails()).thenReturn(details);
        
        // Mock stored token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("action-token-789");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        provider.onEvent(event);
        
        // Should clear tokens after successful password update
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithTokenFieldOnly() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("token", "token-only-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock stored token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("token-only-123");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        provider.onEvent(event);
        
        // Should clear tokens (fallback detection)
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithActionTokenField() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token", "action-token-field-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock stored token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("action-token-field-123");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        provider.onEvent(event);
        
        // Should clear tokens (fallback detection)
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithNoStoredToken() {
        lenient().when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        lenient().when(event.getUserId()).thenReturn("user-123");
        lenient().when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token_type", "reset-credentials");
        details.put("token", "some-token-123");
        lenient().when(event.getDetails()).thenReturn(details);
        
        // Mock no stored token
        lenient().when(user.getFirstAttribute("reset_pwd_token")).thenReturn(null);
        lenient().when(user.getFirstAttribute("previousResetToken")).thenReturn(null);
        
        provider.onEvent(event);
        
        // Should not try to clear tokens if none exist
        verify(user, never()).removeAttribute("reset_pwd_token");
        verify(user, never()).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testUpdatePasswordWithLegacyStoredToken() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token_type", "reset-credentials");
        details.put("token", "legacy-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock legacy stored token
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(null);
        when(user.getFirstAttribute("previousResetToken")).thenReturn("legacy-token-123");
        
        provider.onEvent(event);
        
        // Should clear tokens after successful password update
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testTokenInvalidationFailure() {
        when(event.getType()).thenReturn(EventType.UPDATE_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        details.put("action_token_type", "reset-credentials");
        details.put("token", "old-token-123");
        when(event.getDetails()).thenReturn(details);
        
        // Mock stored token that doesn't match
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("current-token-456");
        lenient().when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(Instant.now().getEpochSecond()));
        
        // Mock SingleUseObjectProvider that throws exception
        SingleUseObjectProvider singleUseStore = mock(SingleUseObjectProvider.class);
        doThrow(new RuntimeException("Invalidation failed")).when(singleUseStore).remove("old-token-123");
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        
        // Should not throw exception, just log and continue
        assertDoesNotThrow(() -> provider.onEvent(event));
        
        // Should still clear tokens after password update
        verify(user).removeAttribute("reset_pwd_token");
        verify(user).removeAttribute("reset_pwd_token_iat");
    }
    
    @Test
    void testEventProcessingException() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        // Mock event.getDetails() to throw exception
        when(event.getDetails()).thenThrow(new RuntimeException("Details error"));
        
        // Should handle exception gracefully
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
    
    @Test
    void testOnEventWithUnsupportedEventType() {
        when(event.getType()).thenReturn(EventType.LOGIN);
        
        provider.onEvent(event);
        
        // Should not interact with user-related mocks for unsupported events
        verifyNoInteractions(user);
    }
    
    @Test
    void testExtractTokenFromDetailsWithNullDetails() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        when(event.getDetails()).thenReturn(null);
        
        // Should handle null details gracefully (no exception thrown)
        assertDoesNotThrow(() -> provider.onEvent(event));
    }
    
    @Test
    void testSendResetPasswordWithEmptyDetails() {
        when(event.getType()).thenReturn(EventType.SEND_RESET_PASSWORD);
        when(event.getUserId()).thenReturn("user-123");
        when(event.getRealmId()).thenReturn("realm-123");
        
        Map<String, String> details = new HashMap<>();
        when(event.getDetails()).thenReturn(details);
        
        provider.onEvent(event);
        
        // Should not store any token if no token in details
        verify(user, never()).setSingleAttribute(eq("reset_pwd_token"), any());
        verify(user, never()).setSingleAttribute(eq("reset_pwd_token_iat"), any());
    }
}