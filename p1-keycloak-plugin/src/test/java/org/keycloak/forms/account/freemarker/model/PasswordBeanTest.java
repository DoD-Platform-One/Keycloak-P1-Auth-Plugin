package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordBeanTest {

    @Test
    void testIsPasswordSet() {
        // Test when password is set
        PasswordBean passwordBeanWithPassword = new PasswordBean(true);
        assertTrue(passwordBeanWithPassword.isPasswordSet(),
                "Expected isPasswordSet() to be true when constructed with 'true'");

        // Test when password is not set
        PasswordBean passwordBeanWithoutPassword = new PasswordBean(false);
        assertFalse(passwordBeanWithoutPassword.isPasswordSet(),
                "Expected isPasswordSet() to be false when constructed with 'false'");
    }
}
