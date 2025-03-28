package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.forms.account.AccountPages;
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

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class AccountFederatedIdentityBeanTest {

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

        // Stub the identity providers stream on the realm with two providers.
        lenient().when(mockRealm.getIdentityProvidersStream())
                .thenReturn(Arrays.asList(
                        getMockIdentityProvider("facebook"),
                        getMockIdentityProvider("google")
                ).stream());

        // Stub UserProvider behavior to return a new stream for each invocation.
        lenient().when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser))
                .thenAnswer(invocation -> Stream.of(mockFederatedIdentityModel));

        // Stub the user's credential manager to avoid NPE.
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        lenient().when(mockUser.credentialManager()).thenReturn(credentialManager);
        // Stub isConfiguredFor() as needed (for our test, false is fine).
        lenient().when(credentialManager.isConfiguredFor(any())).thenReturn(false);
    }

    @Test
    void testGetIdentities() {
        try (var mockKeycloakModelUtils = mockStatic(KeycloakModelUtils.class);
             var mockAccountFormService = mockStatic(AccountFormService.class)) {

            // Define static mocks.
            mockKeycloakModelUtils.when(() -> KeycloakModelUtils.getIdentityProviderDisplayName(any(), any()))
                                  .thenReturn("MockedProviderDisplayName");
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(true);

            // Re-instantiate bean within static mock block so that the static mocks are active during construction.
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );

            List<AccountFederatedIdentityBean.FederatedIdentityEntry> identities =
                    accountFederatedIdentityBean.getIdentities();

            // We expect two entries from the two providers.
            assertEquals(2, identities.size());
            // Since our stubbed federated identity returns "facebook" for getIdentityProvider(),
            // the first entry should have providerId "facebook".
            assertEquals("facebook", identities.get(0).getProviderId());
            // The display name is overridden by our static mock.
            assertEquals("MockedProviderDisplayName", identities.get(0).getDisplayName());
        }
    }

    @Test
    void testIsRemoveLinkPossible() {
        try (var mockAccountFormService = mockStatic(AccountFormService.class)) {
            mockAccountFormService.when(() -> AccountFormService.isPasswordSet(any()))
                                  .thenReturn(true);
            // Re-instantiate bean within static mock block.
            accountFederatedIdentityBean = new AccountFederatedIdentityBean(
                    mockKcSession,
                    mockRealm,
                    mockUser,
                    URI.create("http://example.com"),
                    "stateChecker"
            );
            boolean removeLinkPossible = accountFederatedIdentityBean.isRemoveLinkPossible();
            assertTrue(removeLinkPossible, "isRemoveLinkPossible should return true based on static mock");
        }
    }

    // Helper method to create a mock IdentityProviderModel.
    private IdentityProviderModel getMockIdentityProvider(String alias) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(alias);
        model.setEnabled(true);
        return model;
    }
}
