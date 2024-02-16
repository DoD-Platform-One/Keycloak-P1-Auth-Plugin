package org.keycloak.forms.account.freemarker.model;

import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class PasswordBeanTest {

    @Test
    public void testIsPasswordSet() {
        // Test when password is set
        PasswordBean passwordBeanWithPassword = new PasswordBean(true);
        assertTrue(passwordBeanWithPassword.isPasswordSet());

        // Test when password is not set
        PasswordBean passwordBeanWithoutPassword = new PasswordBean(false);
        assertFalse(passwordBeanWithoutPassword.isPasswordSet());
    }
}