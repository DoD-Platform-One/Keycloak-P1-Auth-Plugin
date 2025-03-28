package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.account.AccountFormService;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AccountFederatedIdentityBeanExtendedTest {

    @Mock
    private KeycloakSession mockKcSession;

    @Mock
    private UserProvider mockUserProvider;

    @Mock
    private RealmModel mockRealm;

    @Mock
    private UserModel mockUser;

    @Mock
    private FederatedIdentityModel mockFederatedIdentityModel;

    private AccountFederatedIdentityBean accountFederatedIdentityBean;

    @BeforeEach
    void setup() {
        // Use lenient() for stubbing that may not be used by every test.
        lenient().when(mockKcSession.users()).thenReturn(mockUserProvider);
        // Stub getKeycloakSessionFactory() to return a dummy factory so that KeycloakModelUtils works.
        KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
        lenient().when(mockKcSession.getKeycloakSessionFactory()).thenReturn(factory);

        // Stub the user's credential manager to avoid NPE.
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        lenient().when(mockUser.credentialManager()).thenReturn(credentialManager);
        // Stub isConfiguredFor() as needed (for our test, false is fine).
        lenient().when(credentialManager.isConfiguredFor(any())).thenReturn(false);
    }

    @Test
    void testGetIdentities_WithMultipleProviders() {
        try (var mockKeycloakModelUtils = mockStatic(KeycloakModelUtils.class);
             var mockAccountFormService = mockStatic(AccountFormService.class)) {

            // Define static mocks.
            mockKeycloakModelUtils.when(() -> KeycloakModelUtils.getIdentityProviderDisplayName(any(), any()))
                                  .thenReturn("MockedProviderDisplayName");
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(true);

            // Setup multiple identity providers with different configurations
            IdentityProviderModel provider1 = createMockProvider("facebook", true, "1");
            IdentityProviderModel provider2 = createMockProvider("google", true, "2");
            IdentityProviderModel provider3 = createMockProvider("github", true, null); // No GUI order
            IdentityProviderModel provider4 = createMockProvider("twitter", false, "4"); // Disabled

            when(mockRealm.getIdentityProvidersStream())
                    .thenReturn(Arrays.asList(provider1, provider2, provider3, provider4).stream());

            // Setup federated identities - create a new stream for each call
            when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser))
                    .thenAnswer(invocation -> {
                        FederatedIdentityModel identity1 = mock(FederatedIdentityModel.class);
                        when(identity1.getIdentityProvider()).thenReturn("facebook");
                        when(identity1.getUserId()).thenReturn("facebook-user-id");
                        when(identity1.getUserName()).thenReturn("facebook-user");

                        FederatedIdentityModel identity2 = mock(FederatedIdentityModel.class);
                        when(identity2.getIdentityProvider()).thenReturn("google");
                        when(identity2.getUserId()).thenReturn("google-user-id");
                        when(identity2.getUserName()).thenReturn("google-user");
                        
                        return Stream.of(identity1, identity2);
                    });

            // Re-instantiate bean within static mock block
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );

            List<AccountFederatedIdentityBean.FederatedIdentityEntry> identities =
                    accountFederatedIdentityBean.getIdentities();

            // We expect 3 entries from the enabled providers (facebook, google, github)
            assertEquals(3, identities.size());
            
            // Verify the entries are sorted by GUI order
            assertEquals("facebook", identities.get(0).getProviderId());
            assertEquals("google", identities.get(1).getProviderId());
            assertEquals("github", identities.get(2).getProviderId());
            
            // Verify connected status
            assertTrue(identities.get(0).isConnected());
            assertTrue(identities.get(1).isConnected());
            assertFalse(identities.get(2).isConnected());
            
            // Verify user IDs and names
            assertEquals("facebook-user-id", identities.get(0).getUserId());
            assertEquals("facebook-user", identities.get(0).getUserName());
            assertEquals("google-user-id", identities.get(1).getUserId());
            assertEquals("google-user", identities.get(1).getUserName());
            assertNull(identities.get(2).getUserId());
            assertNull(identities.get(2).getUserName());
        }
    }

    @Test
    void testRemoveLinkPossible_WithMultipleIdentities() {
        try (var mockKeycloakModelUtils = mockStatic(KeycloakModelUtils.class);
             var mockAccountFormService = mockStatic(AccountFormService.class)) {

            // Define static mocks.
            mockKeycloakModelUtils.when(() -> KeycloakModelUtils.getIdentityProviderDisplayName(any(), any()))
                                  .thenReturn("MockedProviderDisplayName");
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(false);

            // Setup multiple identity providers
            IdentityProviderModel provider1 = createMockProvider("facebook", true, "1");
            IdentityProviderModel provider2 = createMockProvider("google", true, "2");

            when(mockRealm.getIdentityProvidersStream())
                    .thenReturn(Arrays.asList(provider1, provider2).stream());

            // Setup multiple federated identities - create a new stream for each call
            when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser))
                    .thenAnswer(invocation -> {
                        FederatedIdentityModel identity1 = mock(FederatedIdentityModel.class);
                        when(identity1.getIdentityProvider()).thenReturn("facebook");
                        FederatedIdentityModel identity2 = mock(FederatedIdentityModel.class);
                        when(identity2.getIdentityProvider()).thenReturn("google");
                        return Stream.of(identity1, identity2);
                    });

            // No federation link
            when(mockUser.getFederationLink()).thenReturn(null);

            // Re-instantiate bean within static mock block
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );

            // Should be true because there are multiple identities
            assertTrue(accountFederatedIdentityBean.isRemoveLinkPossible());
        }
    }

    @Test
    void testRemoveLinkPossible_WithSingleIdentityAndFederationLink() {
        try (var mockKeycloakModelUtils = mockStatic(KeycloakModelUtils.class);
             var mockAccountFormService = mockStatic(AccountFormService.class)) {

            // Define static mocks.
            mockKeycloakModelUtils.when(() -> KeycloakModelUtils.getIdentityProviderDisplayName(any(), any()))
                                  .thenReturn("MockedProviderDisplayName");
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(false);

            // Setup one identity provider
            IdentityProviderModel provider = createMockProvider("facebook", true, "1");
            when(mockRealm.getIdentityProvidersStream())
                    .thenReturn(Stream.of(provider));

            // Setup one federated identity - create a new stream for each call
            when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser))
                    .thenAnswer(invocation -> {
                        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
                        when(identity.getIdentityProvider()).thenReturn("facebook");
                        return Stream.of(identity);
                    });

            // With federation link
            when(mockUser.getFederationLink()).thenReturn("federation-link");

            // Re-instantiate bean within static mock block
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );

            // Should be true because there's a federation link
            assertTrue(accountFederatedIdentityBean.isRemoveLinkPossible());
        }
    }

    @Test
    void testRemoveLinkPossible_WithSingleIdentityAndPassword() {
        try (var mockKeycloakModelUtils = mockStatic(KeycloakModelUtils.class);
             var mockAccountFormService = mockStatic(AccountFormService.class)) {

            // Define static mocks.
            mockKeycloakModelUtils.when(() -> KeycloakModelUtils.getIdentityProviderDisplayName(any(), any()))
                                  .thenReturn("MockedProviderDisplayName");
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(true);

            // Setup one identity provider
            IdentityProviderModel provider = createMockProvider("facebook", true, "1");
            when(mockRealm.getIdentityProvidersStream())
                    .thenReturn(Stream.of(provider));

            // Setup one federated identity - create a new stream for each call
            when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser))
                    .thenAnswer(invocation -> {
                        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
                        when(identity.getIdentityProvider()).thenReturn("facebook");
                        return Stream.of(identity);
                    });

            // No federation link
            when(mockUser.getFederationLink()).thenReturn(null);

            // Re-instantiate bean within static mock block
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );

            // Should be true because there's a password set
            assertTrue(accountFederatedIdentityBean.isRemoveLinkPossible());
        }
    }

    @Test
    void testRemoveLinkPossible_WithSingleIdentityNoPasswordNoFederationLink() {
        try (var mockKeycloakModelUtils = mockStatic(KeycloakModelUtils.class);
             var mockAccountFormService = mockStatic(AccountFormService.class)) {

            // Define static mocks.
            mockKeycloakModelUtils.when(() -> KeycloakModelUtils.getIdentityProviderDisplayName(any(), any()))
                                  .thenReturn("MockedProviderDisplayName");
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(false);

            // Setup one identity provider
            IdentityProviderModel provider = createMockProvider("facebook", true, "1");
            when(mockRealm.getIdentityProvidersStream())
                    .thenReturn(Stream.of(provider));

            // Setup one federated identity - create a new stream for each call
            when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser))
                    .thenAnswer(invocation -> {
                        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
                        when(identity.getIdentityProvider()).thenReturn("facebook");
                        return Stream.of(identity);
                    });

            // No federation link
            when(mockUser.getFederationLink()).thenReturn(null);

            // Re-instantiate bean within static mock block
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );

            // Should be false because there's only one identity, no password, and no federation link
            assertFalse(accountFederatedIdentityBean.isRemoveLinkPossible());
        }
    }

    @Test
    void testFederatedIdentityEntry_GettersAndSetters() {
        // Create a FederatedIdentityEntry
        FederatedIdentityModel model = mock(FederatedIdentityModel.class);
        when(model.getUserId()).thenReturn("user-id");
        when(model.getUserName()).thenReturn("user-name");
        
        AccountFederatedIdentityBean.FederatedIdentityEntry entry = 
                new AccountFederatedIdentityBean.FederatedIdentityEntry(
                        model, 
                        "Display Name", 
                        "provider-id", 
                        "provider-name", 
                        "10"
                );
        
        // Test getters
        assertEquals("provider-id", entry.getProviderId());
        assertEquals("provider-name", entry.getProviderName());
        assertEquals("user-id", entry.getUserId());
        assertEquals("user-name", entry.getUserName());
        assertEquals("10", entry.getGuiOrder());
        assertEquals("Display Name", entry.getDisplayName());
        assertTrue(entry.isConnected());
    }

    @Test
    void testFederatedIdentityEntry_WithNullModel() {
        // Create a FederatedIdentityEntry with null model
        AccountFederatedIdentityBean.FederatedIdentityEntry entry = 
                new AccountFederatedIdentityBean.FederatedIdentityEntry(
                        null, 
                        "Display Name", 
                        "provider-id", 
                        "provider-name", 
                        "10"
                );
        
        // Test getters
        assertNull(entry.getUserId());
        assertNull(entry.getUserName());
        assertFalse(entry.isConnected());
    }

    // Helper method to create a mock IdentityProviderModel with config
    private IdentityProviderModel createMockProvider(String alias, boolean enabled, String guiOrder) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(alias);
        model.setEnabled(enabled);
        
        if (guiOrder != null) {
            Map<String, String> config = new HashMap<>();
            config.put("guiOrder", guiOrder);
            model.setConfig(config);
        }
        
        return model;
    }
}