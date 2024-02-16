package org.keycloak.forms.account.freemarker.model;

import org.junit.Test;
import static org.junit.Assert.*;

public class ReferrerBeanTest {

    @Test
    public void testReferrerBean() {
        // Arrange
        String[] referrerArray = {"Example Referrer", "http://example.com"};
        ReferrerBean referrerBean = new ReferrerBean(referrerArray);

        // Act
        String name = referrerBean.getName();
        String url = referrerBean.getUrl();

        // Assert
        assertEquals(referrerArray[0], name);
        assertEquals(referrerArray[1], url);
    }

    // You can add more tests to cover edge cases or additional scenarios as needed.
}
