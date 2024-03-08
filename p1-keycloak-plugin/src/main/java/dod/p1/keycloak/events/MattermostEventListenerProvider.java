package dod.p1.keycloak.events;

import org.jboss.logging.Logger;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.events.admin.AdminEvent;

import org.keycloak.models.KeycloakSession;

import com.slack.api.Slack;
import com.slack.api.webhook.Payload;
import com.slack.api.webhook.WebhookResponse;

import java.util.HashSet;
import java.util.Arrays;

import java.io.IOException;

import org.json.JSONObject;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Event listener provider for Mattermost integration.
 * Implements {@link EventListenerProvider}.
 */
public class MattermostEventListenerProvider implements EventListenerProvider {

    /** The Keycloak session associated with the MattermostEventListenerProvider. */
    private final KeycloakSession session;

    /** The logger for logging events in the MattermostEventListenerProvider. */
    private static final Logger LOGGER = Logger.getLogger(MattermostEventListenerProvider.class);

    /** Set of included admin Keycloak events in MattermostEventListenerProvider. */
    private HashSet<ResourceType> includedAdminEvents;

    /** The Mattermost server URI used by MattermostEventListenerProvider. */
    private String serverUri;

    /** Array of groups used in MattermostEventListenerProvider. */
    private String[] groups;

    /** Set of all attribute resource types used by MattermostEventListenerProvider. */
    private final HashSet<ResourceType> allAttrResourceTypes;

    /** Set of name-only resource types used by MattermostEventListenerProvider. */
    private final HashSet<ResourceType> nameOnlyResourceTypes;

    // Sonarqube consider this a critical issue
    /** COMMA_NAME constant. */
    private static final String COMMA_NAME = ", name=";

    /**
     * Constructs a new MattermostEventListenerProvider.
     *
     * @param excludedEventSet      Set of excluded events.
     * @param includedAdminEventSet Set of included admin events.
     * @param groupArray            Array of groups.
     * @param serverURI             Mattermost server URI.
     * @param keycloakSession       The Keycloak session.
     */
    public MattermostEventListenerProvider(
            final HashSet<EventType> excludedEventSet,
            final HashSet<ResourceType> includedAdminEventSet,
            final String[] groupArray,
            final String serverURI,
            final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
        this.includedAdminEvents = includedAdminEventSet;
        this.serverUri = serverURI;
        this.groups = groupArray;

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
     * Handles non-admin events.
     *
     * @param event The non-admin event.
     */
    @Override
    public void onEvent(final Event event) {
        // Ignore excluded events
      }

    /**
     * Handles admin events.
     *
     * @param event              The admin event.
     * @param includeRepresentation Flag indicating whether to include the representation.
     */
    @Override
    public void onEvent(final AdminEvent event, final boolean includeRepresentation) {
        // Ignore excluded operations
        if (includedAdminEvents != null && includedAdminEvents.contains(event.getResourceType())) {
            String buf = toString(event);
            if (buf != null) {
              send(buf);
            }
        }
    }

    /**
     * Sends the event data to Mattermost.
     *
     * @param stringEvent The event data in string format.
     */

    private void send(final String stringEvent) {
        try {
          Slack slack = Slack.getInstance();
          String webhookUrl  = this.serverUri;

          Payload payload = Payload.builder().text(stringEvent).build();
          LOGGER.info("stringEvent:" + stringEvent);

          WebhookResponse response = slack.send(webhookUrl, payload);

          LOGGER.info(response); // WebhookResponse(code=200, message=OK, body=ok)
        } catch (IOException e) {
          LOGGER.error("UH OH!! " + e.toString());
        }

    }

    /**
     * Converts the admin event to a string representation.
     *
     * @param adminEvent The admin event.
     * @return The string representation of the admin event.
     */
    private String toString(final AdminEvent adminEvent) {
        StringBuilder sb = new StringBuilder();
        String repPath = "";
        final int limit = 4;

        sb.append("operationType=");
        sb.append(adminEvent.getOperationType());
        sb.append(", resourceType=");
        sb.append(adminEvent.getResourceType());
        sb.append(", realmId=");
        sb.append(adminEvent.getAuthDetails().getRealmId());
        sb.append(", clientId=");
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
            LOGGER.info("groups: " + groups);
            LOGGER.info("path: " + representation.getString("path"));
            sb.append(COMMA_NAME);
            sb.append(representation.getString("name"));
            sb.append(", path=");
            sb.append(representation.getString("path"));
            repPath = representation.getString("path");

            String[] resourcePath = adminEvent.getResourcePath().split("/", limit);

            sb.append(", username=");
            sb.append(session.users().getUserById(session.getContext().getRealm(), resourcePath[1]).getUsername());
          } else if (adminEvent.getResourceType().equals(ResourceType.USER)) {
            sb.append(", username=");
            sb.append(representation.getString("username"));
            sb.append(", email=");
            sb.append(representation.getString("email"));
          } else if (adminEvent.getResourceType().equals(ResourceType.CLIENT)) {
            sb.append(", clientId=");
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
        if (adminEvent.getResourceType().equals(ResourceType.GROUP_MEMBERSHIP)
                && !Arrays.asList(groups).contains(repPath)) {
            return null;
        } else {
            return sb.toString();
        }
    }

    /**
     * Closes the event listener provider.
     */
    @Override
    public void close() {
        // Implementation specific cleanup, if needed.
    }

}
