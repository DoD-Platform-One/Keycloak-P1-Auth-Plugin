package org.keycloak.services.resources.account;

import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PolicyStore;

import java.util.List;

/**
 * Class to hold the context for policy revocation.
 */
public class PolicyRevocationContext {
  /** The policy store. */
  private final PolicyStore contextPolicyStore;
  /** The resource server. */
  private final ResourceServer contextResourceServer;
  /** The policy. */
  private final Policy contextPolicy;
  /** The list of remaining IDs. */
  private final List<String> contextRemainingIds;

  /**
   * Constructs a PolicyRevocationContext.
   *
   * @param policyStore The policy store.
   * @param resourceServer The resource server.
   * @param policy The policy.
   * @param remainingIds The list of remaining IDs.
   */
  public PolicyRevocationContext(
      final PolicyStore policyStore,
      final ResourceServer resourceServer,
      final Policy policy,
      final List<String> remainingIds) {
    this.contextPolicyStore = policyStore;
    this.contextResourceServer = resourceServer;
    this.contextPolicy = policy;
    this.contextRemainingIds = remainingIds;
  }

  /**
   * Gets the policy store.
   *
   * @return The policy store.
   */
  public PolicyStore getPolicyStore() {
    return contextPolicyStore;
  }

  /**
   * Gets the resource server.
   *
   * @return The resource server.
   */
  public ResourceServer getResourceServer() {
    return contextResourceServer;
  }

  /**
   * Gets the policy.
   *
   * @return The policy.
   */
  public Policy getPolicy() {
    return contextPolicy;
  }

  /**
   * Gets the list of remaining IDs.
   *
   * @return The list of remaining IDs.
   */
  public List<String> getRemainingIds() {
    return contextRemainingIds;
  }
}
