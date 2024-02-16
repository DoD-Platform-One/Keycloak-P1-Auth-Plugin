package org.keycloak.services.resources.account;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.events.EventBuilder;
import org.keycloak.common.ClientConnection;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({EventBuilder​.class, AccountFormService.class})
public class AccountFormServiceFactoryTest {

    @Mock
    private ClientModel clientModel;
    @Mock
    private RealmModel realmModel;

    private AccountFormServiceFactory accountFormServiceFactory;

    @Before
    public void setUp(){
        accountFormServiceFactory = new AccountFormServiceFactory();
    }
    @Test
    public void testAccountFormServiceFactory(){
        // getId test
        assertEquals(AccountFormServiceFactory.ID, accountFormServiceFactory.getId());

        // getAccountManagementClient test
        when(realmModel.getClientByClientId(anyString())).thenReturn(clientModel);
        when(clientModel.isEnabled()).thenReturn(true);
        assertEquals(clientModel, accountFormServiceFactory.getAccountManagementClient(realmModel));

        // init test
        accountFormServiceFactory.init(mock(Config.Scope.class));

        // postInit test
        accountFormServiceFactory.postInit(mock(KeycloakSessionFactory.class));

        // close test
        accountFormServiceFactory.close();
    }

    @Test(expected = NotFoundException.class)
    public void testNotFoundExceptionClientModelNull(){
        // getAccountManagementClient test
        when(realmModel.getClientByClientId(anyString())).thenReturn(null);
        assertEquals(clientModel, accountFormServiceFactory.getAccountManagementClient(realmModel));
    }

    @Test(expected = NotFoundException.class)
    public void testNotFoundExceptionClientModelNotEnabled(){
        // getAccountManagementClient test
        when(realmModel.getClientByClientId(anyString())).thenReturn(clientModel);
        when(clientModel.isEnabled()).thenReturn(false);
        assertEquals(clientModel, accountFormServiceFactory.getAccountManagementClient(realmModel));
    }

    @Test
    public void testPITACreate() throws Exception {
        // Mocks
        AccountFormService accountFormService = mock(AccountFormService.class);
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        EventBuilder eventBuilder = mock(EventBuilder.class);

        // setups
        when(keycloakSession.getContext()).thenReturn(mock(KeycloakContext.class));
        when(keycloakSession.getContext().getConnection()).thenReturn(mock(ClientConnection.class));
        when(keycloakSession.getContext().getRealm()).thenReturn(realmModel);
        when(realmModel.getClientByClientId(anyString())).thenReturn(clientModel);
        when(clientModel.isEnabled()).thenReturn(true);

        // AccountFormService Init method suppressed (main PITA)
        suppress(method(AccountFormService.class, "init"));

        whenNew(EventBuilder.class).withAnyArguments().thenReturn(eventBuilder);
        whenNew(AccountFormService.class).withAnyArguments().thenReturn(accountFormService);

        // create test
        assertNotNull(accountFormServiceFactory.create(keycloakSession));

    }
}
