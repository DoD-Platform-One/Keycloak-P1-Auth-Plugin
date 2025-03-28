package org.keycloak.forms.account.freemarker;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.keycloak.forms.account.AccountPages;

public class TemplatesTest {

    @Test
    public void testGetTemplate() {
        // Test the getTemplate method for each AccountPages enum value
        assertEquals("account.ftl", Templates.getTemplate(AccountPages.ACCOUNT),
                "Templates.getTemplate(ACCOUNT) should return 'account.ftl'");
        assertEquals("password.ftl", Templates.getTemplate(AccountPages.PASSWORD),
                "Templates.getTemplate(PASSWORD) should return 'password.ftl'");
        assertEquals("totp.ftl", Templates.getTemplate(AccountPages.TOTP),
                "Templates.getTemplate(TOTP) should return 'totp.ftl'");
        assertEquals("federatedIdentity.ftl", Templates.getTemplate(AccountPages.FEDERATED_IDENTITY),
                "Templates.getTemplate(FEDERATED_IDENTITY) should return 'federatedIdentity.ftl'");
        assertEquals("log.ftl", Templates.getTemplate(AccountPages.LOG),
                "Templates.getTemplate(LOG) should return 'log.ftl'");
        assertEquals("sessions.ftl", Templates.getTemplate(AccountPages.SESSIONS),
                "Templates.getTemplate(SESSIONS) should return 'sessions.ftl'");
        assertEquals("applications.ftl", Templates.getTemplate(AccountPages.APPLICATIONS),
                "Templates.getTemplate(APPLICATIONS) should return 'applications.ftl'");
        assertEquals("resources.ftl", Templates.getTemplate(AccountPages.RESOURCES),
                "Templates.getTemplate(RESOURCES) should return 'resources.ftl'");
        assertEquals("resource-detail.ftl", Templates.getTemplate(AccountPages.RESOURCE_DETAIL),
                "Templates.getTemplate(RESOURCE_DETAIL) should return 'resource-detail.ftl'");
    }
}
