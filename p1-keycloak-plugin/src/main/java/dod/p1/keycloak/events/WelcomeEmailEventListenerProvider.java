package dod.p1.keycloak.events;

import org.jboss.logging.Logger;
import org.keycloak.email.DefaultEmailSenderProviderFactory;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.email.DefaultEmailSenderProvider;

/**
 * Event listener that sends a welcome email to users when they verify their
 * email.
 */
public class WelcomeEmailEventListenerProvider implements EventListenerProvider {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(WelcomeEmailEventListenerProvider.class);

    /**
     * The Keycloak session.
     */
    private final KeycloakSession session;

    /**
     * Threshold (5 days) in milliseconds to consider an account "new".
     */
    private static final long NEW_ACCOUNT_THRESHOLD_MS = 5L * 24 * 60 * 60 * 1000;

    /**
     * Attribute name to track if welcome email has been sent.
     */
    private static final String WELCOME_EMAIL_SENT = "welcomeEmailSent";

    /**
     * The URL for the Applications tab—pulled from an env var or defaults to
     * https://login.dso.mil.
     */
    private static final String APPLICATIONS_URL = System.getenv().getOrDefault("APPLICATIONS_URL",
            "https://login.dso.mil");

    /**
     * Constructs a new WelcomeEmailEventListenerProvider with the provided session.
     *
     * @param keycloakSession The Keycloak session.
     */
    public WelcomeEmailEventListenerProvider(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
    }

    /**
     * Handles the incoming event and sends a welcome email for VERIFY_EMAIL events.
     *
     * @param event The Keycloak event.
     */
    @Override
    public void onEvent(final Event event) {
        if (!EventType.VERIFY_EMAIL.equals(event.getType())) {
            return;
        }

        RealmModel realm = session.realms().getRealm(event.getRealmId());
        if (realm == null) {
            return;
        }

        UserModel user = session.users().getUserById(realm, event.getUserId());
        if (user == null) {
            return;
        }

        String email = event.getDetails().get("email");
        if (email == null) {
            email = user.getEmail();
        }
        if (email == null || email.isEmpty()) {
            LOG.infof("Unable to retrieve email for user: %s", user.getUsername());
            return;
        } else if (email.toLowerCase().endsWith(".mil")) {
            LOG.infof("User %s has military email %s, send a custom welcome email", user.getUsername(), email);
        } else {
            LOG.infof("User %s has email %s, send a welcome email", user.getUsername(), email);
        }

        // only send once
        if (user.getFirstAttribute(WELCOME_EMAIL_SENT) != null) {
            return;
        }

        Long createdTimestamp = user.getCreatedTimestamp();
        long now = System.currentTimeMillis();
        if (createdTimestamp == null || (now - createdTimestamp) > NEW_ACCOUNT_THRESHOLD_MS) {
            return;
        }

        // --- email content ---
        String subject = "Welcome to P1 – Your Gateway to Secure DoD Software!";

        String plainTextContent = String.format(
                "Thank you for registering at login.dso.mil and joining Platform One (P1)! "
                        + "We're excited to have you onboard as you explore our secure, agile platform designed "
                        + "to empower DoD teams.%n%n"
                        + "Please visit the Applications tab on your account page to explore useful sites such as "
                        + "Ironbank, Repo One, Mattermost, Jira, Confluence, and more (%s).%n%n"
                        + "If you have any questions, please contact our support team at help@dsop.io.%n%n"
                        + "This is an auto-generated message from DoD Platform One – please do not reply.",
                APPLICATIONS_URL);

        String htmlContent = String.format(
                "<h1>Welcome to P1 – Your Gateway to Secure DoD Software!</h1>"
                        + "<p>Thank you for registering at <a href=\"https://login.dso.mil\">login.dso.mil</a> "
                        + "and joining Platform One (P1)! We're excited to have you onboard as you explore our "
                        + "secure, agile platform designed to empower DoD teams.</p>"
                        + "<p>Please visit the <strong>Applications</strong> tab on your "
                        + "<a href=\"%s\">account page</a> to explore useful sites such as Ironbank, "
                        + "<strong>Repo One</strong>, Mattermost, Jira, Confluence, and more "
                        + "(<a href=\"%s\">%s</a>).</p>"
                        + "<p>If you have any questions, please contact our "
                        + "<a href=\"mailto:help@dsop.io\">support team</a>.</p>"
                        + "<p>This is an auto-generated message from DoD Platform One – please do not reply.</p>",
                APPLICATIONS_URL, APPLICATIONS_URL, APPLICATIONS_URL);
        // --- end email content ---

        try {
            EmailSenderProvider senderProvider = createEmailSenderProvider(session);
            senderProvider.send(realm.getSmtpConfig(), user, subject, plainTextContent, htmlContent);
            user.setSingleAttribute(WELCOME_EMAIL_SENT, "true");
            LOG.infof("Sent welcome email to user %s at %s", user.getUsername(), email);
        } catch (EmailException e) {
            LOG.error("Failed to send email", e);
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
        // no-op
    }

    /**
     * Closes any resources held by the event listener provider.
     */
    @Override
    public void close() {
        // no-op
    }

    /**
     * Creates an email sender provider for sending welcome emails.
     *
     * @param keycloakSession The Keycloak session.
     * @return A new DefaultEmailSenderProvider instance.
     */
    public DefaultEmailSenderProvider createEmailSenderProvider(final KeycloakSession keycloakSession) {
        return (DefaultEmailSenderProvider) new DefaultEmailSenderProviderFactory().create(keycloakSession);
    }
}
