package org.keycloak.forms.account.freemarker.model;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserModel;
import org.keycloak.forms.account.freemarker.model.AccountFederatedIdentityBean;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.account.AccountFormService;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@RunWith(PowerMockRunner.class)
@PrepareForTest({KeycloakModelUtils.class, AccountFormService.class})
public class AccountFederatedIdentityBeanTest {

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

    @Before
    public void setup() {
        mockStatic(KeycloakModelUtils.class, AccountFormService.class);

        // Mock the behavior of KeycloakSession and RealmModel
        when(mockKcSession.users()).thenReturn(mockUserProvider);
        when(mockRealm.getIdentityProvidersStream())
                .thenReturn(Arrays.asList(getMockIdentityProvider("facebook"), getMockIdentityProvider("google")).stream());

        // Mock the behavior of UserModel
        // when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser)).thenReturn(Collections.singletonList(mockFederatedIdentityModel).stream());
        when(mockUserProvider.getFederatedIdentitiesStream(mockRealm, mockUser)).thenAnswer(invocation -> getMockBehavior());

        // Mock the static methods
        when(KeycloakModelUtils.getIdentityProviderDisplayName(any(), any())).thenReturn("MockedProviderDisplayName");
        when(AccountFormService.isPasswordSet(any())).thenReturn(true);

        // Instantiate the class to be tested
        accountFederatedIdentityBean = new AccountFederatedIdentityBean(mockKcSession, mockRealm, mockUser, URI.create("http://example.com"), "stateChecker");
        // accountFederatedIdentityBean = new AccountFederatedIdentityBean(mockKcSession, mockRealm, mockUser, "http://example.com", "stateChecker");

    }

    @Test
    public void testGetIdentities() {
        List<AccountFederatedIdentityBean.FederatedIdentityEntry> identities = accountFederatedIdentityBean.getIdentities();

        // Perform assertions based on the mocked data
        assertEquals(2, identities.size());
        assertEquals("facebook", identities.get(0).getProviderId());
        assertEquals("google", identities.get(1).getProviderId());
        // Add more assertions based on your specific use case
    }

    @Test
    public void testIsRemoveLinkPossible() {
        boolean removeLinkPossible = accountFederatedIdentityBean.isRemoveLinkPossible();

        // Perform assertions based on the mocked data
        assertEquals(true, removeLinkPossible);
        // Add more assertions based on your specific use case
    }

    private IdentityProviderModel getMockIdentityProvider(String alias) {
        IdentityProviderModel identityProviderModel = new IdentityProviderModel();
        identityProviderModel.setAlias(alias);
        identityProviderModel.setEnabled(true);
        // Mock other properties as needed
        return identityProviderModel;
    }

    private Stream<FederatedIdentityModel> getMockBehavior() {
        // Return a new stream for each invocation
        return Stream.of(mockFederatedIdentityModel);
    }
}
