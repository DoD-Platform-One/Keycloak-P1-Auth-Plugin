package org.keycloak.forms.account;

import org.junit.Test;
import static org.junit.Assert.*;

public class AccountSpiTest {

    @Test
    public void testIsInternal() {
        AccountSpi accountSpi = new AccountSpi();
        assertTrue("Expected the SPI implementation to be internal", accountSpi.isInternal());
    }

    @Test
    public void testGetName() {
        AccountSpi accountSpi = new AccountSpi();
        assertEquals("Expected the SPI name to be 'account'", "account", accountSpi.getName());
    }

    @Test
    public void testGetProviderClass() {
        AccountSpi accountSpi = new AccountSpi();
        assertEquals("Expected the provider class to be AccountProvider.class", AccountProvider.class, accountSpi.getProviderClass());
    }

    @Test
    public void testGetProviderFactoryClass() {
        AccountSpi accountSpi = new AccountSpi();
        assertEquals("Expected the provider factory class to be AccountProviderFactory.class", AccountProviderFactory.class, accountSpi.getProviderFactoryClass());
    }
}