package org.keycloak.forms.account.freemarker.model;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.common.util.Time;
import org.keycloak.forms.account.freemarker.model.SessionsBean.UserSessionBean;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.keycloak.models.AuthenticatedClientSessionModel;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.mockito.Mock;

import static org.junit.Assert.assertEquals;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({RealmModel.class, ClientModel.class, UserSessionModel.class})
public class SessionsBeanTest {

    @Mock
    private UserSessionModel userSessionModel;

    @Mock
    private ClientModel clientModel;

    @Test
    public void testSessionsBean() throws Exception {

        // Variable
        long currentTime = System.currentTimeMillis();

        // Mock RealmModel
        RealmModel realmModel = mock(RealmModel.class);

        // Mock UserSessionModel
        when(userSessionModel.getId()).thenReturn("session123");
        when(userSessionModel.getIpAddress()).thenReturn("192.168.0.1");
        when(userSessionModel.getStarted()).thenReturn((int) (currentTime/1000));
        when(userSessionModel.getLastSessionRefresh()).thenReturn((int) (currentTime/1000));
        when(userSessionModel.isRememberMe()).thenReturn(false);

        // Mock ClientModel
        when(clientModel.getClientId()).thenReturn("client1");

        // Mock associated client sessions
        when(realmModel.getClientById("client1")).thenReturn(clientModel);
        Map<String, AuthenticatedClientSessionModel> clientSessions = new HashMap<>();
        clientSessions.put("client1", mock(AuthenticatedClientSessionModel.class));
        when(userSessionModel.getAuthenticatedClientSessions()).thenReturn(clientSessions);

        // Mock list of UserSessionModel
        List<UserSessionModel> userSessionModels = new ArrayList<>();
        userSessionModels.add(userSessionModel);

        // Create SessionsBean
        SessionsBean sessionsBean = new SessionsBean(realmModel, userSessionModels);

        // Test SessionsBean methods
        List<UserSessionBean> sessions = sessionsBean.getSessions();
        assertEquals(1, sessions.size());

        UserSessionBean userSessionBean = sessions.get(0);
        assertEquals("session123", userSessionBean.getId());
        assertEquals("192.168.0.1", userSessionBean.getIpAddress());
        assertEquals(Time.toDate(currentTime).toString(), userSessionBean.getStarted().toString());
        assertEquals(Time.toDate(currentTime).toString(), userSessionBean.getLastAccess().toString());
        assertEquals(Time.toDate(currentTime).toString(), userSessionBean.getExpires().toString());

        assertEquals(1, userSessionBean.getClients().size());
        assertEquals("client1", userSessionBean.getClients().iterator().next());
    }
}
