package dod.p1.keycloak.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.HashSet;

/**
 * Factory class for creating MattermostEventListenerProvider instances.
 */
public class MattermostEventListenerProviderFactory implements EventListenerProviderFactory {

    /** The unique identifier for the Mattermost event listener provider factory. */
    public static final String ID = "Mattermost";

    /** Set of excluded Keycloak events for the Mattermost event listener provider. */
    private HashSet<EventType> excludedEvents;

    /** Set of included admin Keycloak events for the Mattermost event listener provider. */
    private HashSet<ResourceType> includedAdminEvents;

    /** The Mattermost server URI used by the Mattermost event listener provider. */
    private String serverUri;

    /** Array of groups used in the Mattermost event listener provider. */
    private String[] groups;

    // Sonarqube consider this a critical issue
    /** GROUP_MEMBERSHIP_VALUES constant. */
    private static final String GROUP_MEMBERSHIP_VALUES = "group-membership-values";

    /**
     * Creates a new instance of MattermostEventListenerProvider using the provided Keycloak session.
     *
     * @param session The Keycloak session associated with the Mattermost event listener provider.
     * @return A new MattermostEventListenerProvider instance.
     */
    @Override
    public EventListenerProvider create(final KeycloakSession session) {
        return new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
    }

    /**
     * Initializes the Mattermost event listener provider factory using the provided configuration.
     *
     * @param config The configuration scope for the Mattermost event listener provider factory.
     */
    @Override
    public void init(final Config.Scope config) {
        // Initialize excluded events
        String[] excludes = config.getArray("exclude-events");
        if (excludes != null) {
            excludedEvents = new HashSet<>();
            for (String e : excludes) {
                excludedEvents.add(EventType.valueOf(e));
            }
        }

        // Initialize included admin events
        String[] includes = config.getArray("include-admin-events");
        if (includes != null) {
            includedAdminEvents = new HashSet<>();
            for (String e : includes) {
                includedAdminEvents.add(ResourceType.valueOf(e));
            }
        }

        // Initialize groups
        if (config.getArray(GROUP_MEMBERSHIP_VALUES) != null) {
          groups = new String[config.getArray(GROUP_MEMBERSHIP_VALUES).length];
          groups = config.getArray(GROUP_MEMBERSHIP_VALUES).clone();
        }

        // Initialize Mattermost server URI
        serverUri = config.get("serverUri", null);
    }

    /**
     * Performs post-initialization actions for the Mattermost event listener provider factory.
     *
     * @param factory The Keycloak session factory associated with the Mattermost event listener provider factory.
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // Performs post-initialization actions for the Mattermost event listener provider factory.
    }

    /**
     * Closes and releases resources associated with the Mattermost event listener provider factory.
     */
    @Override
    public void close() {
        // Closes and releases resources associated with the Mattermost event listener provider factory.
    }

    /**
     * Returns the unique identifier for the Mattermost event listener provider factory.
     *
     * @return The identifier "Mattermost".
     */
    @Override
    public String getId() {
        return ID;
    }

}
