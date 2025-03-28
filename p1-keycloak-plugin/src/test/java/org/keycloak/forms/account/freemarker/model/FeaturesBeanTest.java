package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FeaturesBeanTest {

    @Test
    void testFeaturesBean() {
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
        assertEquals(identityFederation, featuresBean.isIdentityFederation(),
                "Expected identityFederation to match constructor arg");
        assertEquals(log, featuresBean.isLog(),
                "Expected log to match constructor arg");
        assertEquals(passwordUpdateSupported, featuresBean.isPasswordUpdateSupported(),
                "Expected passwordUpdateSupported to match constructor arg");
        assertEquals(authorization, featuresBean.isAuthorization(),
                "Expected authorization to match constructor arg");
    }

    // Additional tests for edge cases or scenarios can be added here
}
