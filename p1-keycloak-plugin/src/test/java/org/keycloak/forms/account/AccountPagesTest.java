package org.keycloak.forms.account;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class AccountPagesTest {

    @Test
    public void testEnumConstants() {
        // Test all enum constants
        assertEquals(AccountPages.ACCOUNT, AccountPages.valueOf("ACCOUNT"));
        assertEquals(AccountPages.PASSWORD, AccountPages.valueOf("PASSWORD"));
        assertEquals(AccountPages.TOTP, AccountPages.valueOf("TOTP"));
        assertEquals(AccountPages.FEDERATED_IDENTITY, AccountPages.valueOf("FEDERATED_IDENTITY"));
        assertEquals(AccountPages.LOG, AccountPages.valueOf("LOG"));
        assertEquals(AccountPages.SESSIONS, AccountPages.valueOf("SESSIONS"));
        assertEquals(AccountPages.APPLICATIONS, AccountPages.valueOf("APPLICATIONS"));
        assertEquals(AccountPages.RESOURCES, AccountPages.valueOf("RESOURCES"));
        assertEquals(AccountPages.RESOURCE_DETAIL, AccountPages.valueOf("RESOURCE_DETAIL"));
    }

    @Test
    public void testEnumValues() {
        // Test enum values method
        AccountPages[] expectedValues = {
            AccountPages.ACCOUNT,
            AccountPages.PASSWORD,
            AccountPages.TOTP,
            AccountPages.FEDERATED_IDENTITY,
            AccountPages.LOG,
            AccountPages.SESSIONS,
            AccountPages.APPLICATIONS,
            AccountPages.RESOURCES,
            AccountPages.RESOURCE_DETAIL
        };

        assertEquals(expectedValues.length, AccountPages.values().length);
        for (int i = 0; i < expectedValues.length; i++) {
            assertEquals(expectedValues[i], AccountPages.values()[i]);
        }
    }

    @Test
    public void testEnumEquality() {
        // Test equality of enum instances
        assertEquals(AccountPages.ACCOUNT, AccountPages.ACCOUNT);
        assertNotEquals(AccountPages.ACCOUNT, AccountPages.PASSWORD);
    }

    // Add more tests based on your specific use cases

}
