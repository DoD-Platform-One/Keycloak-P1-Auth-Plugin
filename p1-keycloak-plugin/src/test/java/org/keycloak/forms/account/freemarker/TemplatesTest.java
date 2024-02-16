package org.keycloak.forms.account.freemarker;

import org.junit.Test;
import static org.junit.Assert.*;
import org.keycloak.forms.account.AccountPages;

public class TemplatesTest {

    @Test
    public void testGetTemplate() {
        // Test the getTemplate method for each AccountPages enum value

        assertEquals("account.ftl", Templates.getTemplate(AccountPages.ACCOUNT));
        assertEquals("password.ftl", Templates.getTemplate(AccountPages.PASSWORD));
        assertEquals("totp.ftl", Templates.getTemplate(AccountPages.TOTP));
        assertEquals("federatedIdentity.ftl", Templates.getTemplate(AccountPages.FEDERATED_IDENTITY));
        assertEquals("log.ftl", Templates.getTemplate(AccountPages.LOG));
        assertEquals("sessions.ftl", Templates.getTemplate(AccountPages.SESSIONS));
        assertEquals("applications.ftl", Templates.getTemplate(AccountPages.APPLICATIONS));
        assertEquals("resources.ftl", Templates.getTemplate(AccountPages.RESOURCES));
        assertEquals("resource-detail.ftl", Templates.getTemplate(AccountPages.RESOURCE_DETAIL));
    }
}