package dod.p1.keycloak.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.jboss.logging.Logger;

/**
 * Factory for creating ResetPasswordProvider instances.
 * Implements {@link EventListenerProviderFactory}.
 */
public class ResetPasswordProviderFactory implements EventListenerProviderFactory {

    /** Logger instance. */
    private static final Logger LOG = Logger.getLogger(ResetPasswordProviderFactory.class);

    /** Log prefix for easy grepping. */
    private static final String LOG_PREFIX = "ResetPwd: ";

    /** Provider ID. */
    private static final String PROVIDER_ID = "reset-password";

    /**
     * Create a new instance of the provider.
     *
     * @param session The Keycloak session
     * @return The provider instance
     */
    @Override
    public EventListenerProvider create(final KeycloakSession session) {
        return new ResetPasswordProvider(session);
    }

    /**
     * Initialize the factory.
     *
     * @param config The configuration
     */
    @Override
    public void init(final Config.Scope config) {
        LOG.debug(LOG_PREFIX + "Initializing factory");
    }

    /**
     * Post-initialize the factory.
     *
     * @param factory The Keycloak session factory
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        LOG.debug(LOG_PREFIX + "Post-initializing factory");
    }

    /**
     * Close the factory.
     */
    @Override
    public void close() {
        LOG.debug(LOG_PREFIX + "Closing factory");
    }

    /**
     * Get the ID of this provider factory.
     *
     * @return The ID
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
