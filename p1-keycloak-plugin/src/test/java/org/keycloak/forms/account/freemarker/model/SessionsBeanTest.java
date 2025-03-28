package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.forms.account.freemarker.model.SessionsBean.UserSessionBean;
import org.keycloak.models.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionsBeanTest {

    @Mock
    private RealmModel realmModel;

    @Mock
    private UserSessionModel userSessionModel;

    @Mock
    private ClientModel clientModel;

    @Test
    void testSessionsBean() {
        long currentTime = System.currentTimeMillis();

        // Set up userSessionModel
        when(userSessionModel.getId()).thenReturn("session123");
        when(userSessionModel.getIpAddress()).thenReturn("192.168.0.1");
        when(userSessionModel.getStarted()).thenReturn((int) (currentTime / 1000));
        when(userSessionModel.getLastSessionRefresh()).thenReturn((int) (currentTime / 1000));
        when(userSessionModel.isRememberMe()).thenReturn(false);

        // Set up clientModel
        when(clientModel.getClientId()).thenReturn("client1");
        when(realmModel.getClientById("client1")).thenReturn(clientModel);

        // Mock authenticated client sessions
        Map<String, AuthenticatedClientSessionModel> clientSessions = new HashMap<>();
        AuthenticatedClientSessionModel authClientSession = mock(AuthenticatedClientSessionModel.class);
        clientSessions.put("client1", authClientSession);
        when(userSessionModel.getAuthenticatedClientSessions()).thenReturn(clientSessions);

        // Prepare a list of user sessions
        List<UserSessionModel> userSessionModels = new ArrayList<>();
        userSessionModels.add(userSessionModel);

        // Instantiate SessionsBean
        SessionsBean sessionsBean = new SessionsBean(realmModel, userSessionModels);

        // Verify SessionsBean logic
        List<UserSessionBean> sessions = sessionsBean.getSessions();
        assertEquals(1, sessions.size());

        UserSessionBean userSessionBean = sessions.get(0);
        assertEquals("session123", userSessionBean.getId());
        assertEquals("192.168.0.1", userSessionBean.getIpAddress());

        // Compare expected Date objects using Time.toDate(currentTime)
        String expectedDateString = Time.toDate(currentTime).toString();
        assertEquals(expectedDateString, userSessionBean.getStarted().toString());
        assertEquals(expectedDateString, userSessionBean.getLastAccess().toString());
        assertEquals(expectedDateString, userSessionBean.getExpires().toString());

        // Verify clients
        assertEquals(1, userSessionBean.getClients().size());
        assertEquals("client1", userSessionBean.getClients().iterator().next());
    }
}
