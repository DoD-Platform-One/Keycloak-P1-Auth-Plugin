package org.keycloak.forms.account;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AccountSpiTest {

    @Test
    public void testIsInternal() {
        AccountSpi accountSpi = new AccountSpi();
        assertTrue(accountSpi.isInternal(), "Expected the SPI implementation to be internal");
    }

    @Test
    public void testGetName() {
        AccountSpi accountSpi = new AccountSpi();
        assertEquals("account", accountSpi.getName(), "Expected the SPI name to be 'account'");
    }

    @Test
    public void testGetProviderClass() {
        AccountSpi accountSpi = new AccountSpi();
        assertEquals(AccountProvider.class, accountSpi.getProviderClass(),
                "Expected the provider class to be AccountProvider.class");
    }

    @Test
    public void testGetProviderFactoryClass() {
        AccountSpi accountSpi = new AccountSpi();
        assertEquals(AccountProviderFactory.class, accountSpi.getProviderFactoryClass(),
                "Expected the provider factory class to be AccountProviderFactory.class");
    }
}
