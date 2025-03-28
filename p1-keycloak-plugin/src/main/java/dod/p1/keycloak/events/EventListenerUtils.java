package dod.p1.keycloak.events;

import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashSet;
import java.util.Set;

/**
 * Utility class for event listeners to reduce code duplication.
 */
public final class EventListenerUtils {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private EventListenerUtils() {
        // Utility class should not be instantiated
    }

    /** COMMA_CLIENT_ID constant. */
    public static final String COMMA_CLIENT_ID = ", clientId=";

    /** COMMA_USERNAME constant. */
    public static final String COMMA_USERNAME = ", username=";

    /** COMMA_NAME constant. */
    public static final String COMMA_NAME = ", name=";

    /**
     * Creates and initializes a set of resource types for which all attributes are considered.
     *
     * @return Set of resource types
     */
    public static Set<ResourceType> initializeAllAttrResourceTypes() {
        Set<ResourceType> allAttrResourceTypes = new HashSet<>();
        allAttrResourceTypes.add(ResourceType.AUTH_EXECUTION);
        allAttrResourceTypes.add(ResourceType.AUTH_FLOW);
        allAttrResourceTypes.add(ResourceType.AUTHENTICATOR_CONFIG);
        allAttrResourceTypes.add(ResourceType.REQUIRED_ACTION);
        allAttrResourceTypes.add(ResourceType.REALM_ROLE_MAPPING);
        return allAttrResourceTypes;
    }

    /**
     * Creates and initializes a set of resource types for which only the name attribute is considered.
     *
     * @return Set of resource types
     */
    public static Set<ResourceType> initializeNameOnlyResourceTypes() {
        Set<ResourceType> nameOnlyResourceTypes = new HashSet<>();
        nameOnlyResourceTypes.add(ResourceType.CLIENT_ROLE);
        nameOnlyResourceTypes.add(ResourceType.CLIENT_SCOPE_MAPPING);
        nameOnlyResourceTypes.add(ResourceType.CLIENT_ROLE_MAPPING);
        nameOnlyResourceTypes.add(ResourceType.CLIENT_SCOPE);
        nameOnlyResourceTypes.add(ResourceType.REALM_ROLE);
        nameOnlyResourceTypes.add(ResourceType.AUTHORIZATION_RESOURCE_SERVER);
        return nameOnlyResourceTypes;
    }

    /**
     * Builds the basic admin event information.
     *
     * @param adminEvent The admin event.
     * @return StringBuilder with basic admin event info.
     */
    public static StringBuilder buildBasicAdminEventInfo(final AdminEvent adminEvent) {
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
        return sb;
    }

    /**
     * Appends representation information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param adminEvent The admin event.
     * @param session The Keycloak session.
     * @param allAttrResourceTypes Set of resource types for which all attributes are considered.
     * @param nameOnlyResourceTypes Set of resource types for which only the name attribute is considered.
     * @return The representation path if applicable, empty string otherwise.
     */
    public static String appendRepresentationInfo(
            final StringBuilder sb,
            final AdminEvent adminEvent,
            final KeycloakSession session,
            final Set<ResourceType> allAttrResourceTypes,
            final Set<ResourceType> nameOnlyResourceTypes) {

        JSONObject representation = new JSONObject(adminEvent.getRepresentation());
        String repPath = "";

        if (adminEvent.getResourceType().equals(ResourceType.GROUP)) {
            appendGroupInfo(sb, representation);
        } else if (adminEvent.getResourceType().equals(ResourceType.GROUP_MEMBERSHIP)) {
            repPath = appendGroupMembershipInfo(sb, representation, adminEvent, session);
        } else if (adminEvent.getResourceType().equals(ResourceType.USER)) {
            appendUserRepresentationInfo(sb, representation);
        } else if (adminEvent.getResourceType().equals(ResourceType.CLIENT)) {
            appendClientInfo(sb, representation);
        } else if (adminEvent.getResourceType().equals(ResourceType.PROTOCOL_MAPPER)) {
            appendProtocolMapperInfo(sb, representation);
        } else if (nameOnlyResourceTypes.contains(adminEvent.getResourceType())) {
            sb.append(COMMA_NAME);
            sb.append(representation.getString("name"));
        } else if (allAttrResourceTypes.contains(adminEvent.getResourceType())) {
            sb.append(", representation=");
            sb.append(adminEvent.getRepresentation());
        }

        return repPath;
    }

    /**
     * Gets the JSON representation from an admin event.
     *
     * @param adminEvent The admin event.
     * @return The JSON representation.
     */
    public static JSONObject getRepresentation(final AdminEvent adminEvent) {
        return new JSONObject(adminEvent.getRepresentation());
    }

    /**
     * Appends group information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param representation The JSON representation.
     */
    public static void appendGroupInfo(final StringBuilder sb, final JSONObject representation) {
        sb.append(COMMA_NAME);
        sb.append(representation.getString("name"));
        if (!representation.isNull("path")) {
            sb.append(", path=");
            sb.append(representation.getString("path"));
        }
    }

    /**
     * Appends group membership information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param representation The JSON representation.
     * @param adminEvent The admin event.
     * @param session The Keycloak session.
     * @return The representation path.
     */
    public static String appendGroupMembershipInfo(
            final StringBuilder sb,
            final JSONObject representation,
            final AdminEvent adminEvent,
            final KeycloakSession session) {

        final int limit = 4;
        sb.append(COMMA_NAME);
        sb.append(representation.getString("name"));
        sb.append(", path=");
        sb.append(representation.getString("path"));
        String repPath = representation.getString("path");

        String[] resourcePath = adminEvent.getResourcePath().split("/", limit);

        sb.append(COMMA_USERNAME);
        UserModel user = session.users().getUserById(session.getContext().getRealm(), resourcePath[1]);
        sb.append(user.getUsername());

        return repPath;
    }

    /**
     * Appends user representation information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param representation The JSON representation.
     */
    public static void appendUserRepresentationInfo(final StringBuilder sb, final JSONObject representation) {
        sb.append(COMMA_USERNAME);
        sb.append(representation.getString("username"));
        sb.append(", email=");
        sb.append(representation.getString("email"));
    }

    /**
     * Appends client information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param representation The JSON representation.
     */
    public static void appendClientInfo(final StringBuilder sb, final JSONObject representation) {
        sb.append(COMMA_CLIENT_ID);
        sb.append(representation.getString("clientId"));

        if (!representation.isNull("name")) {
            sb.append(COMMA_NAME);
            sb.append(representation.getString("name"));
        }
    }

    /**
     * Appends protocol mapper information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param representation The JSON representation.
     */
    public static void appendProtocolMapperInfo(final StringBuilder sb, final JSONObject representation) {
        sb.append(COMMA_NAME);
        sb.append(representation.getString("name"));
        sb.append(", protocol=");
        sb.append(representation.getString("protocol"));
        sb.append(", protocolMapper=");
        sb.append(representation.getString("protocolMapper"));
    }

    /**
     * Appends error information to the log message if present.
     *
     * @param sb The StringBuilder to append to.
     * @param adminEvent The admin event.
     */
    public static void appendErrorInfo(final StringBuilder sb, final AdminEvent adminEvent) {
        if (adminEvent.getError() != null) {
            sb.append(", error=");
            sb.append(adminEvent.getError());
        }
    }

    /**
     * Appends user information to the log message.
     *
     * @param sb The StringBuilder to append to.
     * @param adminEvent The admin event.
     * @param session The Keycloak session.
     */
    public static void appendAdminUserInfo(
                    final StringBuilder sb,
                    final AdminEvent adminEvent,
                    final KeycloakSession session) {
        if (adminEvent.getAuthDetails().getUserId() != null) {
            RealmModel realm = session.getContext().getRealm();
            UserModel user = session.users().getUserById(realm, adminEvent.getAuthDetails().getUserId());
            if (user != null) {
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
        }
    }

    /**
     * Logs a message with the appropriate level.
     *
     * @param logger The logger to use.
     * @param sb The StringBuilder containing the log message.
     * @param level The log level.
     */
    public static void logEvent(final Logger logger, final StringBuilder sb, final Logger.Level level) {
        logger.log(logger.isTraceEnabled() ? Logger.Level.TRACE : level, sb.toString());
    }
}
