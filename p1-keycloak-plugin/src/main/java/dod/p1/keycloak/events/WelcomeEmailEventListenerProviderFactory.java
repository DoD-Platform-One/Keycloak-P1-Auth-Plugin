package dod.p1.keycloak.events;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.Config.Scope;

/**
 * Factory for creating WelcomeEmailEventListenerProvider instances.
 * This factory is responsible for creating and initializing the event listener
 * that sends welcome emails to new users.
 */
public final class WelcomeEmailEventListenerProviderFactory implements EventListenerProviderFactory {

    /**
     * Creates a new instance of the WelcomeEmailEventListenerProvider.
     *
     * @param session the Keycloak session
     * @return a new WelcomeEmailEventListenerProvider instance
     */
    @Override
    public EventListenerProvider create(final KeycloakSession session) {
        return new WelcomeEmailEventListenerProvider(session);
    }

    /**
     * Initializes the factory with configuration.
     *
     * @param config the configuration scope
     */
    @Override
    public void init(final Scope config) {
        // Optional initialization logic.
    }

    /**
     * Performs post-initialization tasks.
     *
     * @param factory the Keycloak session factory
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // Optional post-initialization logic.
    }

    /**
     * Returns the unique identifier for this event listener.
     *
     * @return the event listener ID
     */
    @Override
    public String getId() {
        return "WelcomeEmail";
    }

    /**
     * Closes the factory and cleans up resources.
     */
    @Override
    public void close() {
        // Clean up resources if necessary.
    }
}
