package dod.p1.keycloak.events;

import org.jboss.logging.Logger;
import org.keycloak.Config;

import org.keycloak.events.EventType;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.HashSet;

/**
 * Factory for creating instances of {@link JBossLoggingExtEventListenerProvider}.
 * Implements {@link EventListenerProviderFactory}.
 */
public class JBossLoggingExtEventListenerProviderFactory implements EventListenerProviderFactory {

    /** The unique identifier for this factory. */
    public static final String ID = "jboss-logging-ext";

    /** The logger used by the factory. */
    private static final Logger LOGGER = Logger.getLogger(JBossLoggingExtEventListenerProvider.class);

    /** The log level for successful events. */
    private Logger.Level successLevel;

    /** The log level for error events. */
    private Logger.Level errorLevel;

    /** The set of event types to be excluded from processing by the event listener. */
    private HashSet<EventType> excludedEvents;

    /**
     * Creates a new instance of the event listener provider based on the provided Keycloak session.
     *
     * @param session The Keycloak session.
     * @return A new instance of {@link JBossLoggingExtEventListenerProvider}.
     */
    @Override
    public EventListenerProvider create(final KeycloakSession session) {
        return new JBossLoggingExtEventListenerProvider(excludedEvents, session, LOGGER, successLevel, errorLevel);
    }

    /**
     * Initializes the factory with the configuration parameters.
     *
     * @param config The configuration scope.
     */
    @Override
    public void init(final Config.Scope config) {
        successLevel = Logger.Level.valueOf(config.get("success-level", "debug").toUpperCase());
        errorLevel = Logger.Level.valueOf(config.get("error-level", "warn").toUpperCase());

        String[] excludes = config.getArray("exclude-events");
        if (excludes != null) {
            excludedEvents = new HashSet<>();
            for (String e : excludes) {
                excludedEvents.add(EventType.valueOf(e));
            }
        }
    }

    /**
     * Performs any necessary post-initialization tasks.
     *
     * @param factory The Keycloak session factory.
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // Performs any necessary post-initialization tasks.
    }

    /**
     * Closes any resources held by the factory.
     */
    @Override
    public void close() {
        // Closes any resources held by the factory.
    }

    /**
     * Returns the unique identifier for this factory.
     *
     * @return The identifier.
     */
    @Override
    public String getId() {
        return ID;
    }

}
