package dod.p1.keycloak.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory class for creating MattermostProvisioningEventListenerProvider instances.
 * This factory handles configuration and lifecycle of the provisioning event listener.
 */
public class MattermostProvisioningEventListenerProviderFactory implements EventListenerProviderFactory {

    /** The provider ID for this event listener. */
    public static final String ID = "mattermost-provisioning";

    /**
     * {@inheritDoc}
     */
    @Override
    public EventListenerProvider create(final KeycloakSession session) {
        return new MattermostProvisioningEventListenerProvider(session);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(final Config.Scope config) {
        // Configuration is loaded from YAML file via CommonConfig
        // Log that the factory has been initialized
        org.jboss.logging.Logger.getLogger(getClass()).info(
            "Mattermost Provisioning Event Listener Factory initialized - configuration will be loaded from YAML"
        );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        // Cleanup if needed
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getId() {
        return ID;
    }
}
