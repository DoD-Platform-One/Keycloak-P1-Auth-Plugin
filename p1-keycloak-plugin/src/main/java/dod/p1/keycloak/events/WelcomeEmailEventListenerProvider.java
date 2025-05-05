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
     * Define a threshold (5 days) in milliseconds to consider an account as "new".
     */
    private static final long NEW_ACCOUNT_THRESHOLD_MS = 5L * 24 * 60 * 60 * 1000;

    /**
     * Attribute name to track if welcome email has been sent.
     */
    private static final String WELCOME_EMAIL_SENT = "welcomeEmailSent";

    /**
     * Constructor for the WelcomeEmailEventListenerProvider.
     *
     * @param keycloakSession the Keycloak session
     */
    public WelcomeEmailEventListenerProvider(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
    }

    /**
     * Handles user events, specifically VERIFY_EMAIL events to send welcome emails.
     *
     * @param event the event to process
     */
    @Override
    public void onEvent(final Event event) {
        // Process only VERIFY_EMAIL events
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

        // Get email from event details or user model
        String email = event.getDetails().get("email");
        if (email == null) {
            email = user.getEmail();
        }

        // Check if email is valid
        if (email == null || email.isEmpty()) {
            LOG.infof("Unable to retrieve email for user: %s", user.getUsername());
            return;

        } else if (email.toLowerCase().endsWith(".mil")) {
            LOG.infof("User %s has military email %s, send a custom welcome email", user.getUsername(), email);

        } else {
            LOG.infof("User %s has email %s, send a welcome email", user.getUsername(), email);
        }

        //
        // Check if welcome email has already been sent
        if (user.getFirstAttribute(WELCOME_EMAIL_SENT) != null) {
            return;
        }

        // Check if account is new enough
        Long createdTimestamp = user.getCreatedTimestamp();
        long now = System.currentTimeMillis();
        if (createdTimestamp == null || (now - createdTimestamp) > NEW_ACCOUNT_THRESHOLD_MS) {
            return;
        }

        // Build email content
        String subject = "Welcome to P1 – Your Gateway to Secure DoD Software!";
        String plainTextContent = "Thank you for registering at login.dso.mil and joining Platform One (P1)! "
                + "We're excited to have you onboard as you explore our secure, agile platform designed "
                + "to empower DoD teams.\n\n"
                + "If you are part of an Organization, please be sure to request access to your "
                + "Organization's resources by clicking the following link:\n"
                + "https://launchboard.staging.dso.mil\n\n"
                + "If you have any questions, please contact our support team at help@dsop.io.\n\n"
                + "This is an auto-generated message from DoD Platform One – please do not reply.";

        String htmlContent = "<h1>Welcome to P1 – Your Gateway to Secure DoD Software!</h1>"
                + "<p>Thank you for registering at <a href='https://login.dso.mil'>login.dso.mil</a> and joining "
                + "Platform One (P1)! We're excited to have you onboard as you explore our secure, agile platform "
                + "designed to empower DoD teams.</p>"
                + "<p>If you are part of an Organization, please be sure to "
                + "<a href='https://launchboard.staging.dso.mil'>request access to your "
                + "Organization's resources</a>.</p>"
                + "<p>If you have any questions, please contact our "
                + "<a href='mailto:help@dsop.io'>support team</a>.</p>"
                + "<p>This is an auto-generated message from DoD Platform One – please do not reply.</p>";

        try {
            // Use DefaultEmailSenderProvider to send the email directly
            EmailSenderProvider senderProvider = createEmailSenderProvider(session);
            senderProvider.send(realm.getSmtpConfig(), user, subject, plainTextContent, htmlContent);
            // Mark the user as having received the welcome email
            user.setSingleAttribute(WELCOME_EMAIL_SENT, "true");
            LOG.infof("Sent welcome email to user %s at %s", user.getUsername(), email);
        } catch (EmailException e) {
            LOG.error("Failed to send email", e);
        }
    }

    @Override
    public void onEvent(final AdminEvent adminEvent, final boolean includeRepresentation) {
        // No admin event processing needed
    }

    @Override
    public void close() {
        // Clean up any resources if necessary
    }

    /**
     * Creates a DefaultEmailSenderProvider instance.
     * This method is extracted to make it easier to mock in tests.
     *
     * @param keycloakSession the Keycloak session
     * @return a DefaultEmailSenderProvider instance
     */
    public EmailSenderProvider createEmailSenderProvider(
            final KeycloakSession keycloakSession) {
        return new DefaultEmailSenderProviderFactory().create(keycloakSession);
    }
}
