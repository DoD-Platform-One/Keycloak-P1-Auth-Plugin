package org.keycloak.forms.account.freemarker.model;

import org.junit.Test;
import static org.junit.Assert.*;

public class FeaturesBeanTest {

    @Test
    public void testFeaturesBean() {
        // Arrange
        boolean identityFederation = true;
        boolean log = false;
        boolean passwordUpdateSupported = true;
        boolean authorization = false;

        // Act
        FeaturesBean featuresBean = new FeaturesBean(
                identityFederation,
                log,
                passwordUpdateSupported,
                authorization
        );

        // Assert
        assertEquals(identityFederation, featuresBean.isIdentityFederation());
        assertEquals(log, featuresBean.isLog());
        assertEquals(passwordUpdateSupported, featuresBean.isPasswordUpdateSupported());
        assertEquals(authorization, featuresBean.isAuthorization());
    }

    // You can add more tests to cover edge cases or additional scenarios as needed.
}