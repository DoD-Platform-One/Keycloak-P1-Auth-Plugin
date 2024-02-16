package org.keycloak.forms.account.freemarker.model;

import org.junit.Test;
import static org.junit.Assert.*;
import org.keycloak.models.RealmModel;
import org.mockito.Mockito;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.HashSet;
import java.util.stream.Stream;

public class RealmBeanTest {

    @Test
    public void testRealmBeanMethods() {
        // Mock a RealmModel
        RealmModel realmModel = Mockito.mock(RealmModel.class);
        Mockito.when(realmModel.getName()).thenReturn("testRealm");
        Mockito.when(realmModel.getDisplayName()).thenReturn("Test Realm");
        Mockito.when(realmModel.getDisplayNameHtml()).thenReturn("<b>Test Realm</b>");
        Mockito.when(realmModel.isInternationalizationEnabled()).thenReturn(true);
        Mockito.when(realmModel.getSupportedLocalesStream()).thenReturn(Stream.of("en", "fr", "de"));
        Mockito.when(realmModel.isEditUsernameAllowed()).thenReturn(true);
        Mockito.when(realmModel.isRegistrationEmailAsUsername()).thenReturn(false);
        Mockito.when(realmModel.isUserManagedAccessAllowed()).thenReturn(true);

        // Create a RealmBean instance
        RealmBean realmBean = new RealmBean(realmModel);

        // Test the methods in RealmBean
        assertEquals("testRealm", realmBean.getName());
        assertEquals("Test Realm", realmBean.getDisplayName());
        assertEquals("<b>Test Realm</b>", realmBean.getDisplayNameHtml());
        assertTrue(realmBean.isInternationalizationEnabled());
        assertEquals(new HashSet<>(Arrays.asList("en", "fr", "de")), realmBean.getSupportedLocales());
        assertTrue(realmBean.isEditUsernameAllowed());
        assertFalse(realmBean.isRegistrationEmailAsUsername());
        assertTrue(realmBean.isUserManagedAccessAllowed());
    }
}
