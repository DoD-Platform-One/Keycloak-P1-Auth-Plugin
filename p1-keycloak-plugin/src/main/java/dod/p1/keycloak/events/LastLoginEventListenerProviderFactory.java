package dod.p1.keycloak.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory class for creating instances of {@link LastLoginEventListenerProvider}.
 * Implements {@link EventListenerProviderFactory}.
 */
public class LastLoginEventListenerProviderFactory implements EventListenerProviderFactory {

    /** Identifier for the LastLoginEventListenerProviderFactory. */
    public static final String ID = "Lastlogin";

    /**
     * Creates a new instance of {@link LastLoginEventListenerProvider}.
     *
     * @param keycloakSession The Keycloak session.
     * @return A new instance of LastLoginEventListenerProvider.
     */
    @Override
    public LastLoginEventListenerProvider create(final KeycloakSession keycloakSession) {
        return new LastLoginEventListenerProvider(keycloakSession);
    }

    /**
     * Initializes the factory based on the provided configuration scope.
     *
     * @param scope The configuration scope.
     */
    @Override
    public void init(final Config.Scope scope) {
        // Implementation specific initialization, if needed.
    }

    /**
     * Performs post-initialization actions after the Keycloak session factory has been initialized.
     *
     * @param keycloakSessionFactory The Keycloak session factory.
     */

    @Override
    public void postInit(final KeycloakSessionFactory keycloakSessionFactory) {
        // Implementation specific post-initialization, if needed.
    }

    /**
     * Closes any resources held by the factory.
     */
    @Override
    public void close() {
        // Implementation specific cleanup, if needed.
    }

    /**
     * Retrieves the identifier of the factory.
     *
     * @return The identifier.
     */
    @Override
    public String getId() {
        return ID;
    }

}
