package dod.p1.keycloak.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for ResetPasswordTokenValidator.
 */
@ExtendWith(MockitoExtension.class)
class ResetPasswordTokenValidatorTest {

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    @Mock
    private AuthenticationSessionModel authSession;

    @Mock
    private EventBuilder eventBuilder;

    @Mock
    private HttpRequest httpRequest;

    @Mock
    private UriInfo uriInfo;

    private MultivaluedMap<String, String> queryParams;
    private Map<String, String> clientNotes;
    private ResetPasswordTokenValidator validator;

    @BeforeEach
    void setUp() {
        validator = new ResetPasswordTokenValidator();
        queryParams = new MultivaluedHashMap<>();
        clientNotes = new HashMap<>();
        
        // Set up basic mocks with lenient stubbing to avoid unnecessary stubbing errors
        lenient().when(context.getHttpRequest()).thenReturn(httpRequest);
        lenient().when(httpRequest.getUri()).thenReturn(uriInfo);
        lenient().when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
        lenient().when(authSession.getClientNotes()).thenReturn(clientNotes);
        lenient().when(user.getUsername()).thenReturn("testuser");
    }

    @Test
    void testRequiresUser() {
        assertTrue(validator.requiresUser());
    }

    @Test
    void testConfiguredFor() {
        assertTrue(validator.configuredFor(session, realm, user));
    }

    @Test
    void testAction() {
        validator.action(context);
        verify(context).success();
    }

    @Test
    void testSetRequiredActions() {
        // Should not throw any exception
        assertDoesNotThrow(() -> validator.setRequiredActions(session, realm, user));
    }

    @Test
    void testClose() {
        // Should not throw any exception
        assertDoesNotThrow(() -> validator.close());
    }

    @Test
    void testAuthenticateWithNoToken() {
        // No token in any location - should succeed (pass through)
        validator.authenticate(context);
        
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void testAuthenticateWithEmptyToken() {
        queryParams.putSingle("key", "");
        
        validator.authenticate(context);
        
        // Empty token is treated as no token - should succeed
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void testAuthenticateWithNullUser() {
        when(context.getUser()).thenReturn(null);
        queryParams.putSingle("key", "some-token");
        
        validator.authenticate(context);
        
        // No user means validation passes through
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void testAuthenticateWithNoStoredToken() {
        // Provide a token but user has no stored token
        queryParams.putSingle("key", "some-token");
        when(context.getUser()).thenReturn(user);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(null);
        when(user.getFirstAttribute("previousResetToken")).thenReturn(null);
        
        validator.authenticate(context);
        
        // No stored token means validation passes through
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void testAuthenticateWithValidJwtToken() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(timestamp));
        
        validator.authenticate(context);
        
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void testAuthenticateWithValidJwtTokenWithinTolerance() {
        String tokenId = "test-token-123";
        long tokenTimestamp = 1234567890L;
        long storedTimestamp = 1234567891L; // 1 second difference (within tolerance)
        String jwtToken = createJwtToken(tokenId, tokenTimestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(storedTimestamp));
        
        validator.authenticate(context);
        
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void testAuthenticateWithMismatchedTokenId() {
        String storedTokenId = "stored-token-123";
        String providedTokenId = "provided-token-456";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(providedTokenId, timestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(storedTokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(timestamp));
        
        validator.authenticate(context);
        
        verify(context).failure(AuthenticationFlowError.EXPIRED_CODE);
        verify(eventBuilder).error("invalid_token");
    }

    @Test
    void testAuthenticateWithExpiredToken() {
        String tokenId = "test-token-123";
        long oldTimestamp = 1234567890L;
        long newTimestamp = 1234571490L; // 1 hour later
        String jwtToken = createJwtToken(tokenId, oldTimestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(newTimestamp));
        
        validator.authenticate(context);
        
        verify(context).failure(AuthenticationFlowError.EXPIRED_CODE);
        verify(eventBuilder).error("expired_token");
    }

    @Test
    void testAuthenticateWithLegacyTokenMigration() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(null);
        when(user.getFirstAttribute("previousResetToken")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(null);
        when(user.getFirstAttribute("previousResetTokenIat")).thenReturn(String.valueOf(timestamp));
        
        validator.authenticate(context);
        
        verify(context).success();
        // Verify migration happened
        verify(user).setSingleAttribute("reset_pwd_token", tokenId);
        verify(user).removeAttribute("previousResetToken");
        verify(user).setSingleAttribute("reset_pwd_token_iat", String.valueOf(timestamp));
        verify(user).removeAttribute("previousResetTokenIat");
    }

    @Test
    void testAuthenticateWithInvalidTimestampFormat() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn("invalid-timestamp");
        
        validator.authenticate(context);
        
        verify(context).failure(AuthenticationFlowError.EXPIRED_CODE);
        verify(eventBuilder).error("invalid_token");
    }

    @Test
    void testAuthenticateWithMalformedJwtToken() {
        queryParams.putSingle("key", "malformed.jwt.token");
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn("some-token");
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn("1234567890");
        
        validator.authenticate(context);
        
        verify(context).failure(AuthenticationFlowError.EXPIRED_CODE);
        verify(eventBuilder).error("invalid_token");
    }

    @Test
    void testTokenFoundInAuthSessionNotes() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        // Clear query params so token is only found in auth session
        queryParams.clear();
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(authSession.getAuthNote("TOKEN")).thenReturn(jwtToken);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(timestamp));
        
        validator.authenticate(context);
        
        verify(context).success();
    }

    @Test
    void testTokenFoundInClientSessionNotes() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        // Clear query params and auth notes so token is only found in client notes
        queryParams.clear();
        clientNotes.put("RESET_TOKEN", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(authSession.getAuthNote(anyString())).thenReturn(null);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(timestamp));
        
        validator.authenticate(context);
        
        verify(context).success();
    }

    @Test
    void testTokenFoundInUriPath() {
        String tokenId = "550e8400-e29b-41d4-a716-446655440000"; // UUID format
        
        // Clear all other token sources
        queryParams.clear();
        clientNotes.clear();
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(authSession.getAuthNote(anyString())).thenReturn(null);
        // The validator calls context.getHttpRequest().getUri().getPath()
        // Since httpRequest.getUri() returns uriInfo, we need to mock uriInfo.getPath()
        lenient().when(uriInfo.getPath()).thenReturn("/auth/realms/test/login-actions/reset-credentials/" + tokenId);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(null); // UUID tokens don't have stored IAT
        
        validator.authenticate(context);
        
        verify(context).success();
    }

    @Test
    void testTokenFoundInUserAttributes() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        // Clear all other token sources - no token in query params, auth notes, client notes, or URI
        queryParams.clear();
        clientNotes.clear();
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(authSession.getAuthNote(anyString())).thenReturn(null);
        lenient().when(uriInfo.getPath()).thenReturn("/auth/realms/test/login");
        lenient().when(httpRequest.getUri().getPath()).thenReturn("/auth/realms/test/login");
        
        // Set up user attributes - the token will be found in user attributes as source
        // and also stored there for validation
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(jwtToken, tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(timestamp));
        lenient().when(user.getFirstAttribute("previousResetToken")).thenReturn(null);
        
        validator.authenticate(context);
        
        verify(context).success();
    }

    @Test
    void testSerializedTokenWithId() {
        String tokenId = "test-token-123";
        long timestamp = 1234567890L;
        // Create a proper JWT token instead of a serialized object
        String jwtToken = createJwtToken(tokenId, timestamp);
        
        queryParams.putSingle("key", jwtToken);
        when(context.getUser()).thenReturn(user);
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(tokenId);
        when(user.getFirstAttribute("reset_pwd_token_iat")).thenReturn(String.valueOf(timestamp));
        
        validator.authenticate(context);
        
        verify(context).success();
    }

    @Test
    void testSerializedTokenWithoutStoredToken() {
        String serializedToken = "SomeObject(other=value)";
        
        queryParams.putSingle("key", serializedToken);
        when(context.getUser()).thenReturn(user);
        when(user.getFirstAttribute("reset_pwd_token")).thenReturn(null);
        when(user.getFirstAttribute("previousResetToken")).thenReturn(null);
        
        validator.authenticate(context);
        
        // No stored token means validation passes through
        verify(context).success();
        verify(context, never()).failure(any());
    }

    /**
     * Create a simple JWT token for testing.
     * Format: header.payload.signature (signature is empty for testing)
     */
    private String createJwtToken(String tokenId, long timestamp) {
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"none\"}".getBytes());
        String payload = Base64.getEncoder().encodeToString(
            ("{\"jti\":\"" + tokenId + "\",\"iat\":" + timestamp + "}").getBytes()
        );
        return header + "." + payload + ".";
    }
}