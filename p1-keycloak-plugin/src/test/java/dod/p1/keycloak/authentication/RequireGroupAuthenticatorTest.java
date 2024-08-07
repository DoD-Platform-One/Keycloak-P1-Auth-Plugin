package dod.p1.keycloak.authentication;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import org.apache.commons.io.FilenameUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ Yaml.class, FileInputStream.class, File.class, CommonConfig.class, FilenameUtils.class, NewObjectProvider.class, KeycloakModelUtils.class })
@PowerMockIgnore("javax.management.*")
public class RequireGroupAuthenticatorTest {

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

    @Before
    public void setup() throws Exception {

        // mock static classes
        mockStatic(KeycloakModelUtils.class);

        KeycloakSessionFactory keycloakSessionFactory = mock(KeycloakSessionFactory.class);

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

        // Context
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getSession()).thenReturn(session);
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);

        // Authentication Session
        when(authenticationSession.getClient()).thenReturn(client);
        when(authenticationSession.getParentSession()).thenReturn(parentAuthenticationSession);

        // Parent Authentication Session
        when(parentAuthenticationSession.getId()).thenReturn("bleh");

        // Realm
        when(realm.getGroupById(anyString())).thenReturn(group);

        // Session
        when(session.groups()).thenReturn(groupProvider);
        when(session.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);

        // Common Config

    }

    @Test
    public void testShouldRejectUnknownClients() {
        when(client.getClientId()).thenReturn("random-bad-client");
        subject.authenticate(context);
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    public void testShouldPermitBuiltinClient() {
        when(client.getClientId()).thenReturn("test-client");
        subject.authenticate(context);
        verify(context).success();
    }

    @Test
    public void testShouldRejectClientsWithWrongCase() {
        when(client.getClientId()).thenReturn("test_3e47dd99-9ab6-492e-a341-3bafc371cb13_THINGY");
        subject.authenticate(context);
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    public void testShouldRejectClientsWithUnknownGroupUUID() {
        when(client.getClientId()).thenReturn("test_c58fa397-4af8-49a7-9b73-5b1d85222884_test");
        when(realm.getGroupById("c58fa397-4af8-49a7-9b73-5b1d85222884")).thenReturn(null);
        subject.authenticate(context);
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    public void testShouldRejectValidClientWithInvalidRealm() {
        when(client.getClientId()).thenReturn("test_38ac4deb-5aa4-4cc7-9174-bbbadd9070cf_test");
        // This user is not authorized
        when(context.getRealm()).thenReturn(null);
        subject.authenticate(context);
        verify(context).failure(AuthenticationFlowError.CLIENT_DISABLED);
    }

    @Test
    public void testShouldRejectValidClientWithInvalidUser() {
        when(client.getClientId()).thenReturn("test_6e9a012a-556b-4b63-9b68-799b58c606fa_test");
        // This user is not authorized
        when(context.getUser()).thenReturn(null);
        subject.authenticate(context);
        verify(context).failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
    }

    @Test
    public void testShouldRejectValidClientWithUserNotInGroup() {
        GroupModel group = mock(GroupModel.class);
        when(realm.getGroupById("46062b74-bbd9-44a7-b1a4-64b7bf53cf22")).thenReturn(group);
        when(client.getClientId()).thenReturn("test_46062b74-bbd9-44a7-b1a4-64b7bf53cf22_test");
        // This user is not authorized
        when(user.isMemberOf(group)).thenReturn(false);
        subject.authenticate(context);
        verify(context).failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
    }

    @Test
    public void testShouldAcceptValidClientWithUserInValidGroup() {
        GroupModel group = mock(GroupModel.class);
        when(realm.getGroupById("f289ee42-3088-415d-bab6-e444d7d58c57")).thenReturn(group);
        when(client.getClientId()).thenReturn("test_f289ee42-3088-415d-bab6-e444d7d58c57_valid-client-test");
        // This user IS authorized
        when(user.isMemberOf(group)).thenReturn(true);
        subject.authenticate(context);
        verify(context).success();
    }

    @Test
    public void testShouldAcceptValidClientWithUnderscoresWithUserInValidGroup() {
        GroupModel group = mock(GroupModel.class);
        when(realm.getGroupById("f289ee42-3088-415d-bab6-e444d7d58c57")).thenReturn(group);
        when(client.getClientId()).thenReturn("test_f289ee42-3088-415d-bab6-e444d7d58c57_valid_client_test");
        // This user IS authorized
        when(user.isMemberOf(group)).thenReturn(true);
        subject.authenticate(context);
        verify(context).success();
    }

    @Test
    public void testOverrides() {
        subject.action(null);
        subject.setRequiredActions(null, null, null);
        subject.close();
        assertFalse(subject.requiresUser());
        assertTrue(subject.configuredFor(null, null, null));
    }

}
