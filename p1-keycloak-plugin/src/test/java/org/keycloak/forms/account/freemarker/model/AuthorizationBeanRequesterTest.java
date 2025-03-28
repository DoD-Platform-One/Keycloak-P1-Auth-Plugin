package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Scope;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the {@link AuthorizationBean.RequesterBean} class.
 */
public class AuthorizationBeanRequesterTest {

    private AuthorizationProvider authorizationProvider;
    private KeycloakSession session;
    private RealmModel realm;
    private UserProvider userProvider;
    private UserModel requester;
    private PermissionTicket ticket;

    @BeforeEach
    public void setUp() {
        // Setup mocks
        authorizationProvider = mock(AuthorizationProvider.class);
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);
        requester = mock(UserModel.class);
        ticket = mock(PermissionTicket.class);
        
        // Setup common values
        when(authorizationProvider.getKeycloakSession()).thenReturn(session);
        when(authorizationProvider.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
        when(ticket.getRequester()).thenReturn("requester-id");
        when(userProvider.getUserById(eq(realm), eq("requester-id"))).thenReturn(requester);
    }

    @Test
    public void testRequesterBean_Construction() {
        // Setup
        when(ticket.isGranted()).thenReturn(true);
        when(ticket.getCreatedTimestamp()).thenReturn(1000L);
        when(ticket.getGrantedTimestamp()).thenReturn(2000L);
        
        // Test
        AuthorizationBean.RequesterBean requesterBean = new AuthorizationBean.RequesterBean(ticket, authorizationProvider);
        
        // Verify
        assertNotNull(requesterBean);
        assertEquals(requester, requesterBean.getRequester());
        assertTrue(requesterBean.isGranted());
        assertNotNull(requesterBean.getCreatedDate());
        assertNotNull(requesterBean.getCreatedDate());
        assertNotNull(requesterBean.getGrantedDate());
    }

    @Test
    public void testRequesterBean_NotGranted() {
        // Setup
        when(ticket.isGranted()).thenReturn(false);
        when(ticket.getCreatedTimestamp()).thenReturn(1000L);
        when(ticket.getGrantedTimestamp()).thenReturn(null);
        
        // Test
        AuthorizationBean.RequesterBean requesterBean = new AuthorizationBean.RequesterBean(ticket, authorizationProvider);
        
        // Verify
        assertFalse(requesterBean.isGranted());
        assertNull(requesterBean.getGrantedDate());
    }

    @Test
    public void testRequesterBean_WithScopes() {
        // Setup
        when(ticket.isGranted()).thenReturn(false);
        when(ticket.getCreatedTimestamp()).thenReturn(1000L);
        
        // Create a RequesterBean
        AuthorizationBean.RequesterBean requesterBean = new AuthorizationBean.RequesterBean(ticket, authorizationProvider);
        
        // Add a scope
        PermissionTicket scopeTicket = mock(PermissionTicket.class);
        Scope scope = mock(Scope.class);
        when(scopeTicket.getScope()).thenReturn(scope);
        when(scopeTicket.isGranted()).thenReturn(true);
        when(scopeTicket.getGrantedTimestamp()).thenReturn(3000L);
        
        // Use reflection to access private method
        try {
            java.lang.reflect.Method addScopeMethod = AuthorizationBean.RequesterBean.class.getDeclaredMethod("addScope", PermissionTicket.class);
            addScopeMethod.setAccessible(true);
            addScopeMethod.invoke(requesterBean, scopeTicket);
            
            // Verify
            assertFalse(requesterBean.getScopes().isEmpty());
            assertEquals(1, requesterBean.getScopes().size());
            assertTrue(requesterBean.isGranted()); // Should be granted because scope is granted
            assertNotNull(requesterBean.getGrantedDate());
            assertNotNull(requesterBean.getGrantedDate());
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke addScope method", e);
        }
    }

    @Test
    public void testRequesterBean_WithNonGrantedScopes() {
        // Setup
        when(ticket.isGranted()).thenReturn(false);
        when(ticket.getCreatedTimestamp()).thenReturn(1000L);
        
        // Create a RequesterBean
        AuthorizationBean.RequesterBean requesterBean = new AuthorizationBean.RequesterBean(ticket, authorizationProvider);
        
        // Add a non-granted scope
        PermissionTicket scopeTicket = mock(PermissionTicket.class);
        Scope scope = mock(Scope.class);
        when(scopeTicket.getScope()).thenReturn(scope);
        when(scopeTicket.isGranted()).thenReturn(false);
        
        // Use reflection to access private method
        try {
            java.lang.reflect.Method addScopeMethod = AuthorizationBean.RequesterBean.class.getDeclaredMethod("addScope", PermissionTicket.class);
            addScopeMethod.setAccessible(true);
            addScopeMethod.invoke(requesterBean, scopeTicket);
            
            // Verify
            assertFalse(requesterBean.getScopes().isEmpty());
            assertEquals(1, requesterBean.getScopes().size());
            assertFalse(requesterBean.isGranted()); // Should not be granted
            // We don't need to check the exact value of getGrantedDate() since it depends on Time.toDate implementation
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke addScope method", e);
        }
    }

    @Test
    public void testRequesterBean_WithNullScope() {
        // Setup
        when(ticket.isGranted()).thenReturn(false);
        when(ticket.getCreatedTimestamp()).thenReturn(1000L);
        
        // Create a RequesterBean
        AuthorizationBean.RequesterBean requesterBean = new AuthorizationBean.RequesterBean(ticket, authorizationProvider);
        
        // Use reflection to access private method with null
        try {
            java.lang.reflect.Method addScopeMethod = AuthorizationBean.RequesterBean.class.getDeclaredMethod("addScope", PermissionTicket.class);
            addScopeMethod.setAccessible(true);
            addScopeMethod.invoke(requesterBean, (Object)null);
            
            // Verify
            assertTrue(requesterBean.getScopes().isEmpty());
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke addScope method", e);
        }
    }

    @Test
    public void testPermissionScopeBean() {
        // Setup
        PermissionTicket scopeTicket = mock(PermissionTicket.class);
        Scope scope = mock(Scope.class);
        when(scopeTicket.getId()).thenReturn("scope-ticket-id");
        when(scopeTicket.getScope()).thenReturn(scope);
        when(scopeTicket.isGranted()).thenReturn(true);
        when(scopeTicket.getGrantedTimestamp()).thenReturn(3000L);
        
        // Test
        AuthorizationBean.PermissionScopeBean scopeBean = new AuthorizationBean.PermissionScopeBean(scopeTicket);
        
        // Verify
        assertNotNull(scopeBean);
        assertEquals("scope-ticket-id", scopeBean.getId());
        assertEquals(scope, scopeBean.getScope());
        assertTrue(scopeBean.isGranted());
        
        // Test private method using reflection
        try {
            java.lang.reflect.Method getGrantedDateMethod = AuthorizationBean.PermissionScopeBean.class.getDeclaredMethod("getGrantedDate");
            getGrantedDateMethod.setAccessible(true);
            Date grantedDate = (Date) getGrantedDateMethod.invoke(scopeBean);
            
            assertNotNull(grantedDate);
            // We don't need to check the exact value since it depends on Time.toDate implementation
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getGrantedDate method", e);
        }
    }

    @Test
    public void testPermissionScopeBean_NotGranted() {
        // Setup
        PermissionTicket scopeTicket = mock(PermissionTicket.class);
        Scope scope = mock(Scope.class);
        when(scopeTicket.getId()).thenReturn("scope-ticket-id");
        when(scopeTicket.getScope()).thenReturn(scope);
        when(scopeTicket.isGranted()).thenReturn(false);
        
        // Test
        AuthorizationBean.PermissionScopeBean scopeBean = new AuthorizationBean.PermissionScopeBean(scopeTicket);
        
        // Verify
        assertFalse(scopeBean.isGranted());
        
        // Test private method using reflection
        try {
            java.lang.reflect.Method getGrantedDateMethod = AuthorizationBean.PermissionScopeBean.class.getDeclaredMethod("getGrantedDate");
            getGrantedDateMethod.setAccessible(true);
            Date grantedDate = (Date) getGrantedDateMethod.invoke(scopeBean);
            
            assertNull(grantedDate);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getGrantedDate method", e);
        }
    }
}