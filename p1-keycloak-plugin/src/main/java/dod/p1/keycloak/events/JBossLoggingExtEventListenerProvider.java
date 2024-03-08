package dod.p1.keycloak.events;

import org.jboss.logging.Logger;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.events.admin.AdminEvent;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.util.Map;
import java.util.HashSet;
import org.json.JSONObject;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

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
    private final HashSet<EventType> excludedEvents;

    /** The set of resource types for which all attributes are considered in the event processing. */
    private final HashSet<ResourceType> allAttrResourceTypes;

    /** The set of resource types for which only the name attribute is considered in the event processing. */
    private final HashSet<ResourceType> nameOnlyResourceTypes;

    // Sonarqube consider this a critical issue
    /** COMMA_CLIENT_ID constant. */
    private static final String COMMA_CLIENT_ID = ", clientId=";

    /** COMMA_USERNAME constant. */
    private static final String COMMA_USERNAME = ", username=";

    /** COMMA_NAME constant. */
    private static final String COMMA_NAME = ", name=";

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
            final HashSet<EventType> excludedEventType,
            final KeycloakSession keycloakSession,
            final Logger eventLogger,
            final Logger.Level successEvent,
            final Logger.Level errorEvent) {
        this.session = keycloakSession;
        this.logger = eventLogger;
        this.successLevel = successEvent;
        this.errorLevel = errorEvent;
        this.excludedEvents = excludedEventType;

        this.allAttrResourceTypes = new HashSet<>();
        this.allAttrResourceTypes.add(ResourceType.AUTH_EXECUTION);
        this.allAttrResourceTypes.add(ResourceType.AUTH_FLOW);
        this.allAttrResourceTypes.add(ResourceType.AUTHENTICATOR_CONFIG);
        this.allAttrResourceTypes.add(ResourceType.REQUIRED_ACTION);
        this.allAttrResourceTypes.add(ResourceType.REALM_ROLE_MAPPING);

        this.nameOnlyResourceTypes = new HashSet<>();
        this.nameOnlyResourceTypes.add(ResourceType.CLIENT_ROLE);
        this.nameOnlyResourceTypes.add(ResourceType.CLIENT_SCOPE_MAPPING);
        this.nameOnlyResourceTypes.add(ResourceType.CLIENT_ROLE_MAPPING);
        this.nameOnlyResourceTypes.add(ResourceType.CLIENT_SCOPE);
        this.nameOnlyResourceTypes.add(ResourceType.REALM_ROLE);
        this.nameOnlyResourceTypes.add(ResourceType.AUTHORIZATION_RESOURCE_SERVER);

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


            if (event.getError() != null) {
                sb.append(", error=");
                sb.append(event.getError());
            }

            if (event.getDetails() != null) {
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
                    if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
                        sb.append("=");
                        sb.append(e.getValue());
                    } else {
                        sb.append("='");
                        sb.append(e.getValue());
                        sb.append("'");
                    }
                }
                if (event.getUserId() != null && !excludedEvents.contains(event.getType())) {
                    RealmModel realm = session.getContext().getRealm();
                    UserModel user = session.users().getUserById(realm, event.getUserId());
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

            if (logger.isTraceEnabled()) {
                setKeycloakContext(sb);
            }

            logger.log(logger.isTraceEnabled() ? Logger.Level.TRACE : level, sb.toString());
        }
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
        final int limit = 4;

        if (logger.isEnabled(level)) {
            StringBuilder sb = new StringBuilder();

            sb.append("operationType=");
            sb.append(adminEvent.getOperationType());
            sb.append(", resourceType=");
            sb.append(adminEvent.getResourceType());
            sb.append(", realmId=");
            sb.append(adminEvent.getAuthDetails().getRealmId());
            sb.append(COMMA_CLIENT_ID);
            sb.append(adminEvent.getAuthDetails().getClientId());
            sb.append(", userId=");
            sb.append(adminEvent.getAuthDetails().getUserId());
            sb.append(", ipAddress=");
            sb.append(adminEvent.getAuthDetails().getIpAddress());
            sb.append(", resourcePath=");
            sb.append(adminEvent.getResourcePath());

            if (adminEvent.getRepresentation() != null) {
                JSONObject representation = new JSONObject(adminEvent.getRepresentation());
                if (adminEvent.getResourceType().equals(ResourceType.GROUP)) {
                    sb.append(COMMA_NAME);
                    sb.append(representation.getString("name"));
                    if (!representation.isNull("path")) {
                        sb.append(", path=");
                        sb.append(representation.getString("path"));
                    }

                }
                if (adminEvent.getResourceType().equals(ResourceType.GROUP_MEMBERSHIP)) {
                    sb.append(COMMA_NAME);
                    sb.append(representation.getString("name"));
                    sb.append(", path=");
                    sb.append(representation.getString("path"));

                    String[] resourcePath = adminEvent.getResourcePath().split("/", limit);

                    sb.append(COMMA_USERNAME);
                    sb.append(
                            session.users().getUserById(session.getContext().getRealm(), resourcePath[1]).getUsername()
                    );
                } else if (adminEvent.getResourceType().equals(ResourceType.USER)) {
                    sb.append(COMMA_USERNAME);
                    sb.append(representation.getString("username"));
                    sb.append(", email=");
                    sb.append(representation.getString("email"));
                } else if (adminEvent.getResourceType().equals(ResourceType.CLIENT)) {
                    sb.append(COMMA_CLIENT_ID);
                    sb.append(representation.getString("clientId"));

                    if (!representation.isNull("name")) {
                        sb.append(COMMA_NAME);
                        sb.append(representation.getString("name"));
                    }
                } else if (adminEvent.getResourceType().equals(ResourceType.PROTOCOL_MAPPER)) {
                    sb.append(COMMA_NAME);
                    sb.append(representation.getString("name"));
                    sb.append(", protocol=");
                    sb.append(representation.getString("protocol"));
                    sb.append(", protocolMapper=");
                    sb.append(representation.getString("protocolMapper"));
                } else if (nameOnlyResourceTypes.contains(adminEvent.getResourceType())) {
                    sb.append(COMMA_NAME);
                    sb.append(representation.getString("name"));
                } else if (allAttrResourceTypes.contains(adminEvent.getResourceType())) {
                    sb.append(", representation=");
                    sb.append(adminEvent.getRepresentation());
                }
            }

            if (adminEvent.getError() != null) {
                sb.append(", error=");
                sb.append(adminEvent.getError());
            }

            if (adminEvent.getAuthDetails().getUserId() != null) {
                RealmModel realm = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realm, adminEvent.getAuthDetails().getUserId());
                String username = user.getUsername();
                String email = user.getEmail();

                if (username != null) {
                    sb.append(", Admin_username=");
                    sb.append(username);
                }
                if (email != null) {
                    sb.append(", Admin_email=");
                    sb.append(email);
                }

            }

            if (logger.isTraceEnabled()) {
                setKeycloakContext(sb);
            }

            logger.log(logger.isTraceEnabled() ? Logger.Level.TRACE : level, sb.toString());
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
