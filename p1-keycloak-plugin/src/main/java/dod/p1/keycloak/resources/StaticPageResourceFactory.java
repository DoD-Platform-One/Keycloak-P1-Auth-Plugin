package dod.p1.keycloak.resources;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Factory for creating StaticPageResource instances.
 * This factory creates resource providers that can serve multiple static pages
 * from FreeMarker templates in the LOGIN theme.
 */
public class StaticPageResourceFactory implements RealmResourceProviderFactory {

    /**
     * Logger variable.
     */
    private static final Logger LOGGER = LogManager.getLogger(StaticPageResourceFactory.class);

    /**
     * The ID of this provider.
     */
    public static final String ID = "onboarding";

    /**
     * Returns the ID of this resource provider factory.
     *
     * @return The ID of this resource provider factory
     */
    @Override
    public String getId() {
        return ID;
    }

    /**
     * Creates a new instance of the resource provider.
     *
     * @param session The Keycloak session
     * @return A new instance of the resource provider
     */
    @Override
    public RealmResourceProvider create(final KeycloakSession session) {
        LOGGER.debug("Creating new StaticPageResource instance");
        return new StaticPageResource(session);
    }


    /**
     * Initializes this factory.
     *
     * @param config The configuration scope
     */
    @Override
    public void init(final Scope config) {
        LOGGER.debug("Initializing StaticPageResourceFactory");
        // Nothing to initialize
    }

    /**
     * Performs post-initialization tasks.
     *
     * @param factory The Keycloak session factory
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        LOGGER.debug("Post-initializing StaticPageResourceFactory");
        // Nothing to post-initialize
    }

    /**
     * Closes this factory.
     */
    @Override
    public void close() {
        LOGGER.debug("Closing StaticPageResourceFactory");
        // Nothing to close
    }
}
