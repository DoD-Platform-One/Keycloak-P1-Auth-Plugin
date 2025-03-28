package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReferrerBeanTest {

    @Test
    void testReferrerBean() {
        // Arrange
        String[] referrerArray = { "Example Referrer", "http://example.com" };
        ReferrerBean referrerBean = new ReferrerBean(referrerArray);

        // Act
        String name = referrerBean.getName();
        String url = referrerBean.getUrl();

        // Assert
        assertEquals(referrerArray[0], name, "Expected referrer name to match the first element of the array");
        assertEquals(referrerArray[1], url, "Expected referrer URL to match the second element of the array");
    }

    // Additional tests for edge cases or other scenarios can be added here
}
