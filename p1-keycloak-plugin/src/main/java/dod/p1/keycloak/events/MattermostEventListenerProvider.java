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

import java.util.Arrays;
import java.util.Set;

import java.io.IOException;

import org.json.JSONObject;

import static dod.p1.keycloak.events.EventListenerUtils.appendAdminUserInfo;
import static dod.p1.keycloak.events.EventListenerUtils.appendErrorInfo;
import static dod.p1.keycloak.events.EventListenerUtils.appendGroupMembershipInfo;
import static dod.p1.keycloak.events.EventListenerUtils.appendRepresentationInfo;
import static dod.p1.keycloak.events.EventListenerUtils.buildBasicAdminEventInfo;
import static dod.p1.keycloak.events.EventListenerUtils.getRepresentation;
import static dod.p1.keycloak.events.EventListenerUtils.initializeAllAttrResourceTypes;
import static dod.p1.keycloak.events.EventListenerUtils.initializeNameOnlyResourceTypes;

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
    private Set<ResourceType> includedAdminEvents;

    /** The Mattermost server URI used by MattermostEventListenerProvider. */
    private String serverUri;

    /** Array of groups used in MattermostEventListenerProvider. */
    private String[] groups;

    /** Set of all attribute resource types used by MattermostEventListenerProvider. */
    private final Set<ResourceType> allAttrResourceTypes;

    /** Set of name-only resource types used by MattermostEventListenerProvider. */
    private final Set<ResourceType> nameOnlyResourceTypes;

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
            final Set<EventType> excludedEventSet,
            final Set<ResourceType> includedAdminEventSet,
            final String[] groupArray,
            final String serverURI,
            final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
        this.includedAdminEvents = includedAdminEventSet;
        this.serverUri = serverURI;
        this.groups = groupArray;

        this.allAttrResourceTypes = initializeAllAttrResourceTypes();
        this.nameOnlyResourceTypes = initializeNameOnlyResourceTypes();
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
        StringBuilder sb = buildBasicAdminEventInfo(adminEvent);
        String repPath = "";

        if (adminEvent.getRepresentation() != null) {
            JSONObject representation = getRepresentation(adminEvent);

            if (adminEvent.getResourceType().equals(ResourceType.GROUP_MEMBERSHIP)) {
                // Use custom group membership info method with additional logging
                repPath = appendCustomGroupMembershipInfo(sb, representation, adminEvent);
            } else {
                // Use standard representation info for other types
                repPath = appendRepresentationInfo(
                        sb, adminEvent, session, allAttrResourceTypes, nameOnlyResourceTypes);
            }
        }

        appendErrorInfo(sb, adminEvent);
        appendAdminUserInfo(sb, adminEvent, session);

        if (shouldFilterEvent(adminEvent, repPath)) {
            return null;
        }

        return sb.toString();
    }

    /**
     * Appends group membership information to the log message with additional logging.
     * This is a custom implementation that extends the utility method to add logging.
     *
     * @param sb The StringBuilder to append to.
     * @param representation The JSON representation.
     * @param adminEvent The admin event.
     * @return The representation path.
     */
    private String appendCustomGroupMembershipInfo(final StringBuilder sb, final JSONObject representation,
                                           final AdminEvent adminEvent) {
        LOGGER.info("groups: " + groups);
        LOGGER.info("path: " + representation.getString("path"));

        return appendGroupMembershipInfo(sb, representation, adminEvent, session);
    }

    /**
     * Checks if the event should be filtered out.
     *
     * @param adminEvent The admin event.
     * @param repPath The representation path.
     * @return True if the event should be filtered out, false otherwise.
     */
    private boolean shouldFilterEvent(final AdminEvent adminEvent, final String repPath) {
        return adminEvent.getResourceType().equals(ResourceType.GROUP_MEMBERSHIP)
                && !Arrays.asList(groups).contains(repPath);
    }

    /**
     * Closes the event listener provider.
     */
    @Override
    public void close() {
        // Implementation specific cleanup, if needed.
    }

}
