package org.keycloak.services.resources.account;

import org.junit.jupiter.api.Test;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PolicyStore;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

/**
 * Tests for the {@link PolicyRevocationContext} class.
 */
public class PolicyRevocationContextTest {

    @Test
    public void testConstructorAndGetters() {
        // Setup
        PolicyStore policyStore = mock(PolicyStore.class);
        ResourceServer resourceServer = mock(ResourceServer.class);
        Policy policy = mock(Policy.class);
        List<String> remainingIds = Arrays.asList("id1", "id2", "id3");

        // Create the context
        PolicyRevocationContext context = new PolicyRevocationContext(
                policyStore, resourceServer, policy, remainingIds);

        // Verify
        assertSame(policyStore, context.getPolicyStore(), "PolicyStore should be the same instance");
        assertSame(resourceServer, context.getResourceServer(), "ResourceServer should be the same instance");
        assertSame(policy, context.getPolicy(), "Policy should be the same instance");
        assertSame(remainingIds, context.getRemainingIds(), "RemainingIds should be the same instance");
        
        // Verify the content of remainingIds
        assertEquals(3, context.getRemainingIds().size(), "RemainingIds should have 3 elements");
        assertEquals("id1", context.getRemainingIds().get(0), "First ID should be 'id1'");
        assertEquals("id2", context.getRemainingIds().get(1), "Second ID should be 'id2'");
        assertEquals("id3", context.getRemainingIds().get(2), "Third ID should be 'id3'");
    }
}