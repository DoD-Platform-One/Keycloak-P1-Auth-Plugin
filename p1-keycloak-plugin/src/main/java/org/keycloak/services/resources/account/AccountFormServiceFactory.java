package org.keycloak.services.resources.account;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config.Scope;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.AccountResourceProvider;
import org.keycloak.services.resource.AccountResourceProviderFactory;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.models.Constants;

/**
 * The {@code AccountFormServiceFactory} class is a factory for creating instances of the
 * {@code AccountFormService}, which implements the {@code AccountResourceProvider} interface.
 * This factory is responsible for providing the necessary initialization and cleanup operations
 * for the account management resources.
 *
 * It is annotated with {@code @AutoService(AccountResourceProviderFactory.class)} to indicate
 * that it should be discovered and registered as a service.
 *
 * @see AccountResourceProviderFactory
 * @see AccountFormService
 */
@JBossLog
@AutoService(AccountResourceProviderFactory.class)
public class AccountFormServiceFactory implements AccountResourceProviderFactory {

  /** The identifier for this factory. */
  public static final String ID = "account-v1";

  /**
   * Returns the identifier for this factory.
   *
   * @return The identifier for this factory.
   */
  @Override
  public String getId() {
    return ID;
  }

  /**
   * Retrieves the account management client for the given realm.
   *
   * @param realm The realm for which the account management client is retrieved.
   * @return The account management client.
   * @throws NotFoundException if the account management client is not found or not enabled.
   */
  public ClientModel getAccountManagementClient(final RealmModel realm) {
    ClientModel client = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
    if (client == null || !client.isEnabled()) {
      log.debug("account management not enabled");
      throw new NotFoundException("account management not enabled");
    }
    return client;
  }

  /**
   * Creates an instance of {@code AccountFormService} with the provided session, realm, and event builder.
   *
   * @param session The Keycloak session.
   * @return An instance of {@code AccountFormService}.
   */
  @Override
  public AccountResourceProvider create(final KeycloakSession session) {
    log.info("create");
    RealmModel realm = session.getContext().getRealm();
    ClientModel client = getAccountManagementClient(realm);
    EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());
    return new AccountFormService(session, client, event);
  }

  /**
   * Initializes the factory with the provided configuration scope.
   *
   * @param config The configuration scope.
   */
  @Override
  public void init(final Scope config) {
    log.info("init");
  }

  /**
   * Performs post-initialization tasks after the factory has been initialized.
   *
   * @param factory The Keycloak session factory.
   */
  @Override
  public void postInit(final KeycloakSessionFactory factory) {
    log.info("postInit");
  }

  /**
   * Closes any resources associated with the factory. This method is called during the shutdown of Keycloak.
   */
  @Override
  public void close() {
    log.info("close");
  }
}
