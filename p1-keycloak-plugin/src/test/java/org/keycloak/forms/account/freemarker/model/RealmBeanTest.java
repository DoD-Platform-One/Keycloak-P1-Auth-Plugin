package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.HashSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class RealmBeanTest {

    @Test
    void testRealmBeanMethods() {
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
        assertEquals("testRealm", realmBean.getName(), "Realm name should match mocked name");
        assertEquals("Test Realm", realmBean.getDisplayName(), "Display name should match mocked value");
        assertEquals("<b>Test Realm</b>", realmBean.getDisplayNameHtml(), "Display name HTML should match mocked value");
        assertTrue(realmBean.isInternationalizationEnabled(), "Internationalization should be enabled");
        assertEquals(new HashSet<>(Arrays.asList("en", "fr", "de")), realmBean.getSupportedLocales(),
                "Supported locales should match the mocked stream");
        assertTrue(realmBean.isEditUsernameAllowed(), "Username editing should be allowed");
        assertFalse(realmBean.isRegistrationEmailAsUsername(), "Registration email as username should be disabled");
        assertTrue(realmBean.isUserManagedAccessAllowed(), "User-managed access should be allowed");
    }

    @Test
    void testRealmBeanMethods2() {
        // Mock a RealmModel
        RealmModel realmModel = Mockito.mock(RealmModel.class);
        Mockito.when(realmModel.getName()).thenReturn("testRealm");
        Mockito.when(realmModel.getDisplayName()).thenReturn("");
        Mockito.when(realmModel.getDisplayNameHtml()).thenReturn("");

        // Create a RealmBean instance
        RealmBean realmBean = new RealmBean(realmModel);

        // Test the methods in RealmBean
        // If displayName is empty, fallback is realmModel.getName()
        assertEquals("testRealm", realmBean.getDisplayName(),
                "Display name should fall back to realm name when empty");
        assertEquals("testRealm", realmBean.getDisplayNameHtml(),
                "Display name HTML should fall back to realm name when empty");
    }

    @Test
    void testRealmBeanMethodsNull() {
        // Mock a RealmModel
        RealmModel realmModel = Mockito.mock(RealmModel.class);
        Mockito.when(realmModel.getName()).thenReturn("testRealm");
        Mockito.when(realmModel.getDisplayName()).thenReturn(null);
        Mockito.when(realmModel.getDisplayNameHtml()).thenReturn(null);

        // Create a RealmBean instance
        RealmBean realmBean = new RealmBean(realmModel);

        // Test the methods in RealmBean
        // If displayName is null, fallback is realmModel.getName()
        assertEquals("testRealm", realmBean.getDisplayName(),
                "Display name should fall back to realm name when null");
        assertEquals("testRealm", realmBean.getDisplayNameHtml(),
                "Display name HTML should fall back to realm name when null");
    }
}
