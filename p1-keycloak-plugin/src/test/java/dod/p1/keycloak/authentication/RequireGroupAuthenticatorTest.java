package dod.p1.keycloak.authentication;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import org.apache.commons.io.FilenameUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.yaml.snakeyaml.Yaml;

import java.util.Collections;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RequireGroupAuthenticatorTest {

    private RequireGroupAuthenticator subject;
    private AuthenticationFlowContext context;
    private RealmModel realm;
    private UserModel user;
    private GroupModel group;
    private KeycloakSession session;
    private AuthenticationSessionModel authenticationSession;
    private RootAuthenticationSessionModel parentAuthenticationSession;
    private ClientModel client;
    private CommonConfig commonConfig;
    private GroupProvider groupProvider;

    @BeforeEach
    void setup() throws Exception {
        setupFileMocks();

        subject = new RequireGroupAuthenticator();

        context = mock(AuthenticationFlowContext.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        group = mock(GroupModel.class);
        session = mock(KeycloakSession.class);
        authenticationSession = mock(AuthenticationSessionModel.class);
        parentAuthenticationSession = mock(RootAuthenticationSessionModel.class);
        client = mock(ClientModel.class);
        groupProvider = mock(GroupProvider.class);
        commonConfig = mock(CommonConfig.class);

        // Context stubs
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getSession()).thenReturn(session);
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);

        // Authentication Session stubs
        when(authenticationSession.getClient()).thenReturn(client);
        when(authenticationSession.getParentSession()).thenReturn(parentAuthenticationSession);

        // Parent Authentication Session stubs
        when(parentAuthenticationSession.getId()).thenReturn("bleh");

        // Realm stub
        when(realm.getGroupById(anyString())).thenReturn(group);

        // Session stub
        when(session.groups()).thenReturn(groupProvider);

        // For tests using the CommonConfig, stub methods as needed.
        when(commonConfig.getUserActive509Attribute()).thenReturn("dummyAttribute");
        // Default: no clients are ignored.
        when(commonConfig.getIgnoredGroupProtectionClients()).thenReturn(Collections.emptyList());
    }

    @Test
    void testShouldRejectUnknownClients() {
        when(client.getClientId()).thenReturn("random-bad-client");
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            // Return our mock for any session/realm (even if realm is null)
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);

            subject.authenticate(context);
        }
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    void testShouldPermitBuiltinClient() {
        // For built-in clients the pattern does not match.
        // So the authenticator will check ignored clients.
        when(client.getClientId()).thenReturn("test-client");
        // Stub ignored clients to include "test-client"
        when(commonConfig.getIgnoredGroupProtectionClients()).thenReturn(Collections.singletonList("test-client"));
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        // We don't verify user methods since user is null in this test
        verify(context).success();
    }

    @Test
    void testShouldRejectClientsWithWrongCase() {
        // The clientId does not match the expected pattern due to case issues.
        when(client.getClientId()).thenReturn("test_3e47dd99-9ab6-492e-a341-3bafc371cb13_THINGY");
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    void testShouldRejectClientsWithUnknownGroupUUID() {
        when(client.getClientId()).thenReturn("test_c58fa397-4af8-49a7-9b73-5b1d85222884_test");
        // Simulate that the realm returns no group for this UUID.
        when(realm.getGroupById("c58fa397-4af8-49a7-9b73-5b1d85222884")).thenReturn(null);
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    void testShouldRejectValidClientWithInvalidRealm() {
        when(client.getClientId()).thenReturn("test_38ac4deb-5aa4-4cc7-9174-bbbadd9070cf_test");
        when(context.getRealm()).thenReturn(null);
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            // Stub to return our commonConfig even if realm is null
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any()))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    void testShouldRejectValidClientWithInvalidUser() {
        when(client.getClientId()).thenReturn("test_6e9a012a-556b-4b63-9b68-799b58c606fa_test");
        when(context.getUser()).thenReturn(null);
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        verify(context).failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
    }

    @Test
    void testShouldRejectValidClientWithUserNotInGroup() {
        // Use a client id that matches the pattern.
        when(client.getClientId()).thenReturn("test_46062b74-bbd9-44a7-b1a4-64b7bf53cf22_test");
        // Simulate that the user is not a member of the group.
        when(user.isMemberOf(group)).thenReturn(false);
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        verify(context).failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
    }

    @Test
    void testShouldAcceptValidClientWithUserInValidGroup() {
        // Client id matches the pattern.
        when(client.getClientId()).thenReturn("test_f289ee42-3088-415d-bab6-e444d7d58c57_valid-client-test");
        // Simulate that the user is a member of the group.
        when(user.isMemberOf(group)).thenReturn(true);
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        // We don't verify user methods since user is null in this test
        verify(context).success();
    }

    @Test
    void testShouldAcceptValidClientWithUnderscoresWithUserInValidGroup() {
        // Client id with underscores that matches the pattern.
        when(client.getClientId()).thenReturn("test_f289ee42-3088-415d-bab6-e444d7d58c57_valid_client_test");
        when(user.isMemberOf(group)).thenReturn(true);
        try (var commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            subject.authenticate(context);
        }
        // We don't verify user methods since user is null in this test
        verify(context).success();
    }

    @Test
    void testOverrides() {
        subject.action(null);
        subject.setRequiredActions(null, null, null);
        subject.close();
        assertFalse(subject.requiresUser());
        assertTrue(subject.configuredFor(null, null, null));
    }
}
