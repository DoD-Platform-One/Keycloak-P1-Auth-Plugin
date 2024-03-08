package dod.p1.keycloak.events;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Map;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Event listener provider for tracking and updating the last login status of users.
 * Implements {@link EventListenerProvider}.
 */
public class LastLoginEventListenerProvider implements EventListenerProvider {

    /** The Keycloak session. */
    private final KeycloakSession session;

    /** The realm provider. */
    private final RealmProvider model;

    // Sonarqube consider this a critical issue
    /** LASTLOGIN constant. */
    private static final String LASTLOGIN = "lastlogin";

    /**
     * Constructs a new LastLoginEventListenerProvider instance with the provided Keycloak session.
     *
     * @param keycloakSession The Keycloak session.
     */
    public LastLoginEventListenerProvider(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
        this.model = session.realms();
    }

    /**
     * Handles the incoming event and updates the last login status for LOGIN events.
     *
     * @param event The Keycloak event.
     */
    @Override
    public void onEvent(final Event event) {

        if (EventType.LOGIN.equals(event.getType())) {
            RealmModel realm = this.model.getRealm(event.getRealmId());
            UserModel user = this.session.users().getUserById(realm, event.getUserId());

            if (user != null) {

                Map<String, List<String>> userAttrs = user.getAttributes();
                if (userAttrs.containsKey(LASTLOGIN)) {
                    List<String> userLastLogin = userAttrs.get(LASTLOGIN);
                    if (userLastLogin != null && !userLastLogin.isEmpty()) {
                        user.setSingleAttribute("priorlogin", userLastLogin.get(0));
                    }
                }

                // Use current server time for login event
                OffsetDateTime loginTime = OffsetDateTime.now(ZoneOffset.UTC);
                String loginTimeS = DateTimeFormatter.ISO_INSTANT.format(loginTime);
                user.setSingleAttribute(LASTLOGIN, loginTimeS);
            }
        }
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
