package org.keycloak.forms.account;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AccountPagesTest {

    @Test
    public void testEnumConstants() {
        // Test all enum constants
        assertEquals(AccountPages.ACCOUNT, AccountPages.valueOf("ACCOUNT"),
                "AccountPages.valueOf(\"ACCOUNT\") should return AccountPages.ACCOUNT");
        assertEquals(AccountPages.PASSWORD, AccountPages.valueOf("PASSWORD"),
                "AccountPages.valueOf(\"PASSWORD\") should return AccountPages.PASSWORD");
        assertEquals(AccountPages.TOTP, AccountPages.valueOf("TOTP"),
                "AccountPages.valueOf(\"TOTP\") should return AccountPages.TOTP");
        assertEquals(AccountPages.FEDERATED_IDENTITY, AccountPages.valueOf("FEDERATED_IDENTITY"),
                "AccountPages.valueOf(\"FEDERATED_IDENTITY\") should return AccountPages.FEDERATED_IDENTITY");
        assertEquals(AccountPages.LOG, AccountPages.valueOf("LOG"),
                "AccountPages.valueOf(\"LOG\") should return AccountPages.LOG");
        assertEquals(AccountPages.SESSIONS, AccountPages.valueOf("SESSIONS"),
                "AccountPages.valueOf(\"SESSIONS\") should return AccountPages.SESSIONS");
        assertEquals(AccountPages.APPLICATIONS, AccountPages.valueOf("APPLICATIONS"),
                "AccountPages.valueOf(\"APPLICATIONS\") should return AccountPages.APPLICATIONS");
        assertEquals(AccountPages.RESOURCES, AccountPages.valueOf("RESOURCES"),
                "AccountPages.valueOf(\"RESOURCES\") should return AccountPages.RESOURCES");
        assertEquals(AccountPages.RESOURCE_DETAIL, AccountPages.valueOf("RESOURCE_DETAIL"),
                "AccountPages.valueOf(\"RESOURCE_DETAIL\") should return AccountPages.RESOURCE_DETAIL");
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

        AccountPages[] actualValues = AccountPages.values();
        assertEquals(expectedValues.length, actualValues.length,
                "The length of expected and actual AccountPages.values() should be equal");

        for (int i = 0; i < expectedValues.length; i++) {
            assertEquals(expectedValues[i], actualValues[i],
                    "AccountPages.values()[" + i + "] should be " + expectedValues[i]);
        }
    }

    @Test
    public void testEnumEquality() {
        // Test equality of enum instances
        assertEquals(AccountPages.ACCOUNT, AccountPages.ACCOUNT,
                "AccountPages.ACCOUNT should be equal to itself");
        assertNotEquals(AccountPages.ACCOUNT, AccountPages.PASSWORD,
                "AccountPages.ACCOUNT should not be equal to AccountPages.PASSWORD");
    }

    // Add more tests based on your specific use cases

}
