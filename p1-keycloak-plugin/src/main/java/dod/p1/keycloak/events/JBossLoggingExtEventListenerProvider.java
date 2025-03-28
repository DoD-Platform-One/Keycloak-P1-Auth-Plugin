package dod.p1.keycloak.events;

import org.jboss.logging.Logger;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.events.admin.AdminEvent;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.util.Map;
import java.util.Set;

import static dod.p1.keycloak.events.EventListenerUtils.COMMA_CLIENT_ID;
import static dod.p1.keycloak.events.EventListenerUtils.COMMA_USERNAME;
import static dod.p1.keycloak.events.EventListenerUtils.appendRepresentationInfo;
import static dod.p1.keycloak.events.EventListenerUtils.buildBasicAdminEventInfo;
import static dod.p1.keycloak.events.EventListenerUtils.initializeAllAttrResourceTypes;
import static dod.p1.keycloak.events.EventListenerUtils.initializeNameOnlyResourceTypes;

/**
 * Implementation of {@link EventListenerProvider} that logs Keycloak events and admin events using JBoss Logging.
 */
public class JBossLoggingExtEventListenerProvider implements EventListenerProvider {

    /** The Keycloak session associated with this event listener provider. */
    private final KeycloakSession session;

    /** The logger used for logging events. */
    private final Logger logger;

    /** The log level for successful events. */
    private final Logger.Level successLevel;

    /** The log level for error events. */
    private final Logger.Level errorLevel;

    /** The set of event types to be excluded from processing by the event listener. */
    private final Set<EventType> excludedEvents;

    /** The set of resource types for which all attributes are considered in the event processing. */
    private final Set<ResourceType> allAttrResourceTypes;

    /** The set of resource types for which only the name attribute is considered in the event processing. */
    private final Set<ResourceType> nameOnlyResourceTypes;

    /**
     * Constructs a new instance of the event listener provider with the specified parameters.
     *
     * @param excludedEventType     The set of event types to be excluded.
     * @param keycloakSession       The Keycloak session.
     * @param eventLogger           The logger for event logging.
     * @param successEvent          The log level for successful events.
     * @param errorEvent            The log level for error events.
     */
    public JBossLoggingExtEventListenerProvider(
            final Set<EventType> excludedEventType,
            final KeycloakSession keycloakSession,
            final Logger eventLogger,
            final Logger.Level successEvent,
            final Logger.Level errorEvent) {
        this.session = keycloakSession;
        this.logger = eventLogger;
        this.successLevel = successEvent;
        this.errorLevel = errorEvent;
        this.excludedEvents = excludedEventType;

        this.allAttrResourceTypes = initializeAllAttrResourceTypes();
        this.nameOnlyResourceTypes = initializeNameOnlyResourceTypes();
    }

    /**
     * Handles Keycloak events by logging the details.
     *
     * @param event The Keycloak event.
     */
    @Override
    public void onEvent(final Event event) {
        Logger.Level level = event.getError() != null ? errorLevel : successLevel;

        if (logger.isEnabled(level)) {
            StringBuilder sb = buildBasicEventInfo(event);
            appendErrorInfo(sb, event);
            processEventDetails(sb, event);
            if (logger.isTraceEnabled()) {
                setKeycloakContext(sb);
            }

            logEvent(sb, level);
        }
    }

    /**
     * Builds the basic event information.
     *
     * @param event The Keycloak event.
     * @return StringBuilder with basic event info.
     */
    private StringBuilder buildBasicEventInfo(final Event event) {
        StringBuilder sb = new StringBuilder();
        sb.append("type=");
        sb.append(event.getType());
        sb.append(", realmId=");
        sb.append(event.getRealmId());
        sb.append(COMMA_CLIENT_ID);
        sb.append(event.getClientId());
        sb.append(", userId=");
        sb.append(event.getUserId());
        sb.append(", ipAddress=");
        sb.append(event.getIpAddress());
        return sb;
    }

    /**
     * Appends error information to the log message if present.
     *
     * @param sb The StringBuilder to append to.
     * @param event The Keycloak event.
     */
    private void appendErrorInfo(final StringBuilder sb, final Event event) {
        if (event.getError() != null) {
            sb.append(", error=");
            sb.append(event.getError());
        }
    }

    /**
     * Processes event details and appends them to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param event The Keycloak event.
     */
    private void processEventDetails(final StringBuilder sb, final Event event) {
        if (event.getDetails() != null) {
            boolean[] flags = appendEventDetails(sb, event);
            appendUserInfo(sb, event, flags[0], flags[1]);
        }
    }

    /**
     * Appends event details to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param event The Keycloak event.
     * @return boolean array with flags for username and email found.
     */
    private boolean[] appendEventDetails(final StringBuilder sb, final Event event) {
        boolean founduser = false;
        boolean foundemail = false;

        for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
            if (e.getKey().equals("username")) {
                founduser = true;
            }
            if (e.getKey().equals("email")) {
                foundemail = true;
            }

            sb.append(", ");
            sb.append(e.getKey());
            appendDetailValue(sb, e.getValue());
        }
        return new boolean[] {founduser, foundemail};
    }

    /**
     * Appends a detail value to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param value The value to append.
     */
    private void appendDetailValue(final StringBuilder sb, final String value) {
        if (value == null || value.indexOf(' ') == -1) {
            sb.append("=");
            sb.append(value);
        } else {
            sb.append("='");
            sb.append(value);
            sb.append("'");
        }
    }

    /**
     * Appends user information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param event The Keycloak event.
     * @param founduser Whether username was found in details.
     * @param foundemail Whether email was found in details.
     */
    private void appendUserInfo(final StringBuilder sb, final Event event,
                               final boolean founduser, final boolean foundemail) {
        if (event.getUserId() != null && !excludedEvents.contains(event.getType())) {
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, event.getUserId());
            if (user != null) {
                String username = user.getUsername();
                String email = user.getEmail();

                if (username != null && !founduser) {
                    sb.append(COMMA_USERNAME);
                    sb.append(username);
                }
                if (email != null && !foundemail) {
                    sb.append(", email=");
                    sb.append(email);
                }
            }
        }
    }
/**
 * Logs the event with the appropriate level.
 *
 * @param sb The StringBuilder containing the log message.
 * @param level The log level.
 */
private void logEvent(final StringBuilder sb, final Logger.Level level) {
    EventListenerUtils.logEvent(logger, sb, level);
}

/**
 * Handles admin events by logging the details.
 *
 * @param adminEvent          The admin event.
 * @param includeRepresentation Whether to include the representation in the log.
 */
@Override
public void onEvent(final AdminEvent adminEvent, final boolean includeRepresentation) {
    Logger.Level level = adminEvent.getError() != null ? errorLevel : successLevel;

    if (logger.isEnabled(level)) {
        StringBuilder sb = buildBasicAdminEventInfo(adminEvent);
        if (adminEvent.getRepresentation() != null) {
            appendRepresentationInfo(
                    sb, adminEvent, session, allAttrResourceTypes, nameOnlyResourceTypes);
        }
        EventListenerUtils.appendErrorInfo(sb, adminEvent);
        EventListenerUtils.appendAdminUserInfo(sb, adminEvent, session);
        if (logger.isTraceEnabled()) {
            setKeycloakContext(sb);
        }
        logEvent(sb, level);
    }
}

    /**
     * Closes the event listener provider.
     */
    @Override
    public void close() {
        // Closes the event listener provider.
    }

    /**
     * Sets additional Keycloak context details in the log message.
     *
     * @param sb The StringBuilder to append details to.
     */
    private void setKeycloakContext(final StringBuilder sb) {
        KeycloakContext context = session.getContext();
        UriInfo uriInfo = context.getUri();
        HttpHeaders headers = context.getRequestHeaders();
        if (uriInfo != null) {
            sb.append(", requestUri=");
            sb.append(uriInfo.getRequestUri().toString());
        }

        if (headers != null) {
            sb.append(", cookies=[");
            boolean f = true;
            for (Map.Entry<String, Cookie> e : headers.getCookies().entrySet()) {
                if (f) {
                    f = false;
                } else {
                    sb.append(", ");
                }
                sb.append(e.getValue().toString());
            }
            sb.append("]");
        }

    }

}
