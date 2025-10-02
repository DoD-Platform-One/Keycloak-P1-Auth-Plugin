package dod.p1.keycloak.events;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.common.YAMLConfigClientLogin;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Event listener provider for tracking and updating login status of users for specific clients.
 * Implements {@link EventListenerProvider}.
 */
public class ClientSpecificLoginEventListenerProvider implements EventListenerProvider {

    /** The Keycloak session. */
    private final KeycloakSession session;

    /** The realm provider. */
    private final RealmProvider model;

    /** Logger for this class. */
    private static final Logger LOGGER = LogManager.getLogger(ClientSpecificLoginEventListenerProvider.class);

    /**
     * Constructs a new ClientSpecificLoginEventListenerProvider instance with the provided Keycloak session.
     *
     * @param keycloakSession The Keycloak session.
     */
    public ClientSpecificLoginEventListenerProvider(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
        this.model = session.realms();
    }

    /**
     * Handles the incoming event and updates the client-specific login attributes for LOGIN events.
     *
     * @param event The Keycloak event.
     */
    @Override
    public void onEvent(final Event event) {
        if (!EventType.LOGIN.equals(event.getType())) {
            return;
        }

        processLoginEvent(event);
    }

    /**
     * Process a login event to update client-specific attributes.
     *
     * @param event The login event to process
     */
    private void processLoginEvent(final Event event) {
        RealmModel realm = this.model.getRealm(event.getRealmId());
        UserModel user = this.session.users().getUserById(realm, event.getUserId());
        String clientId = event.getClientId();

        if (user == null || clientId == null) {
            return;
        }

        try {
            updateClientSpecificAttributes(user, clientId, realm);
        } catch (Exception e) {
            LOGGER.error("Error processing client-specific login event for user {}: {}",
                user.getUsername(), e.getMessage(), e);
        }
    }

    /**
     * Update client-specific attributes for a user based on the client they logged into.
     *
     * @param user The user who logged in
     * @param clientId The client ID the user logged into
     * @param realm The realm the user belongs to
     */
    private void updateClientSpecificAttributes(final UserModel user, final String clientId, final RealmModel realm) {
        CommonConfig config = CommonConfig.getInstance(session, realm);
        List<YAMLConfigClientLogin> clientLoginConfigs = config.getClientLoginAttributes();

        if (clientLoginConfigs == null) {
            return;
        }

        // Build a map for O(1) lookup: clientId -> attributeName
        Map<String, String> clientToAttributeMap = buildClientToAttributeMap(clientLoginConfigs);

        // Check if the current client has a configured attribute
        String attributeName = clientToAttributeMap.get(clientId);
        if (attributeName != null) {
            String loginTimeS = getCurrentTimestamp();
            updateUserAttribute(user, attributeName, loginTimeS);
        }
    }

    /**
     * Build a map for fast O(1) lookup of client ID to attribute name.
     * This replaces the O(n*m) nested loop approach with O(1) lookup.
     *
     * @param clientLoginConfigs The list of client login configurations
     * @return A map where key is clientId and value is attributeName
     */
    private Map<String, String> buildClientToAttributeMap(final List<YAMLConfigClientLogin> clientLoginConfigs) {
        Map<String, String> clientToAttributeMap = new HashMap<>();

        for (YAMLConfigClientLogin config : clientLoginConfigs) {
            if (config.getClientIds() != null && config.getAttributeName() != null) {
                for (String clientId : config.getClientIds()) {
                    clientToAttributeMap.put(clientId, config.getAttributeName());
                }
            }
        }

        return clientToAttributeMap;
    }

    /**
     * Update a user attribute with a new value, preserving the old value as a "prior" attribute.
     *
     * @param user The user to update
     * @param attributeName The attribute name to update
     * @param newValue The new value to set
     */
    private void updateUserAttribute(final UserModel user, final String attributeName, final String newValue) {
        LOGGER.debug("Setting attribute {} for user {} with value {}",
            attributeName, user.getUsername(), newValue);

        // Store previous value as prior attribute if it exists
        preservePriorValue(user, attributeName);

        // Set the new timestamp
        user.setSingleAttribute(attributeName, newValue);
    }

    /**
     * Preserve the prior value of an attribute if it exists.
     *
     * @param user The user to update
     * @param attributeName The attribute name to preserve
     */
    private void preservePriorValue(final UserModel user, final String attributeName) {
        Map<String, List<String>> userAttrs = user.getAttributes();
        if (!userAttrs.containsKey(attributeName)) {
            return;
        }

        List<String> userLastLogin = userAttrs.get(attributeName);
        if (userLastLogin != null && !userLastLogin.isEmpty()) {
            user.setSingleAttribute("prior" + attributeName, userLastLogin.get(0));
        }
    }

    /**
     * Get the current timestamp in ISO format.
     *
     * @return The current timestamp as a string
     */
    private String getCurrentTimestamp() {
        OffsetDateTime loginTime = OffsetDateTime.now(ZoneOffset.UTC);
        return DateTimeFormatter.ISO_INSTANT.format(loginTime);
    }

    /**
     * Handles the incoming admin event (unused in this implementation).
     *
     * @param adminEvent The admin event.
     * @param includeRepresentation A flag indicating whether to include the event representation.
     */
    @Override
    public void onEvent(final AdminEvent adminEvent, final boolean includeRepresentation) {
        // Handles the incoming admin event (unused in this implementation).
    }

    /**
     * Closes any resources held by the event listener provider.
     */
    @Override
    public void close() {
        // Nothing to close
    }
}
