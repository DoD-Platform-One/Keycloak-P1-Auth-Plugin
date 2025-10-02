package dod.p1.keycloak.events;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.common.util.Time;

import java.util.Map;
import java.util.HashMap;
import java.time.Instant;
import org.jboss.logging.Logger;

/**
 * Event listener provider that invalidates any previous password-reset token
 * when a new forgot-password email is sent.
 * Implements {@link EventListenerProvider}.
 */
public final class ResetPasswordProvider implements EventListenerProvider {

    /** Keycloak session. */
    private final KeycloakSession session;

    /** Logger instance. */
    private static final Logger LOG = Logger.getLogger(ResetPasswordProvider.class);

    /** Log prefix for easy grepping. */
    private static final String LOG_PREFIX = "ResetPwd: ";

    /** User attribute where the last token ID is stored. */
    private static final String RESET_PWD_TOKEN = "reset_pwd_token";

    /** User attribute where token issued-at timestamp is stored. */
    private static final String RESET_PWD_TOKEN_IAT = "reset_pwd_token_iat";

    /** One day in seconds. */
    private static final int ONE_DAY_IN_SECONDS = 24 * 60 * 60;

    /** Action token type for reset credentials. */
    private static final String RESET_CREDENTIALS_TOKEN_TYPE = "reset-credentials";

    /** Action for reset credentials. */
    private static final String RESET_CREDENTIALS_ACTION = "RESET_CREDENTIALS";

    /** Token field name. */
    private static final String TOKEN_FIELD = "token";

    /** Action token field name. */
    private static final String ACTION_TOKEN_FIELD = "action_token";

    /** Code ID field name. */
    private static final String CODE_ID_FIELD = "code_id";

    /** Action field name. */
    private static final String ACTION_FIELD = "action";

    /** Action token type field name. */
    private static final String ACTION_TOKEN_TYPE_FIELD = "action_token_type";

    /** Previous reset token attribute name for backward compatibility. */
    private static final String PREVIOUS_RESET_TOKEN = "previousResetToken";

    /** User log prefix. */
    private static final String USER_LOG_PREFIX = "User ";

    /**
     * Constructor.
     *
     * @param keycloakSession the active Keycloak session
     */
    public ResetPasswordProvider(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
    }

    @Override
    public void onEvent(final Event event) {
        if (event == null) {
            LOG.debug(LOG_PREFIX + "Received null event, ignoring");
            return;
        }

        try {
            // Handle different event types
            if (EventType.SEND_RESET_PASSWORD.equals(event.getType())) {
                LOG.debug(LOG_PREFIX + "Processing SEND_RESET_PASSWORD event");
                handleSendResetPasswordEvent(event);
            } else if (EventType.UPDATE_PASSWORD.equals(event.getType())) {
                LOG.debug(LOG_PREFIX + "Processing UPDATE_PASSWORD event");
                handleUpdatePasswordEvent(event);
            } else if (EventType.EXECUTE_ACTION_TOKEN.equals(event.getType())
                    || EventType.EXECUTE_ACTION_TOKEN_ERROR.equals(event.getType())) {
                LOG.debug(LOG_PREFIX + "Processing action token event: " + event.getType());
                handleActionTokenEvent(event);
            }
        } catch (Exception e) {
            LOG.error(LOG_PREFIX + "Error processing event: " + event.getType(), e);
        }
    }

    /**
     * Handle SEND_RESET_PASSWORD event.
     *
     * @param event The event to handle
     */
    private void handleSendResetPasswordEvent(final Event event) {
        UserModel user = getUserFromEvent(event);
        if (user == null) {
            LOG.debug(LOG_PREFIX + "User not found for event: userId=" + event.getUserId());
            return;
        }

        LOG.debug(LOG_PREFIX + "Found user: " + user.getUsername());

        String tokenFromEvent = extractTokenFromDetails(event.getDetails());
        LOG.debug(LOG_PREFIX + "Extracted token from event details: '" + tokenFromEvent + "'");
        if (tokenFromEvent == null || tokenFromEvent.isEmpty() || tokenFromEvent.trim().isEmpty()) {
            LOG.debug(LOG_PREFIX + "No token found in event details after trying multiple field names (null or empty)");
            return;
        }

        LOG.debug(LOG_PREFIX + "Found valid token in event details: " + tokenFromEvent);
        processResetPasswordToken(user, tokenFromEvent);
    }

    /**
     * Process the reset password token for a user.
     *
     * @param user The user
     * @param tokenFromEvent The token from the event
     */
    private void processResetPasswordToken(final UserModel user, final String tokenFromEvent) {
        try {
            // Try to invalidate the old token (if present)
            invalidatePreviousToken(user);
        } catch (Exception e) {
            // Just log the error but continue with storing the new token
            LOG.warn(LOG_PREFIX + "Error while invalidating previous reset token for user "
                    + user.getUsername() + ": " + e.getMessage());
        }

        try {
            // Store the new token for future reference
            storeNewToken(user, tokenFromEvent);
            LOG.info(LOG_PREFIX + "Successfully processed reset password event for user " + user.getUsername());
        } catch (Exception e) {
            LOG.error(LOG_PREFIX + "Error while storing new reset token for user "
                    + user.getUsername() + ": " + e.getMessage());
        }
    }

    /**
     * Handle UPDATE_PASSWORD event.
     *
     * @param event The event to handle
     */
    private void handleUpdatePasswordEvent(final Event event) {
        UserModel user = getUserFromEvent(event);
        if (user == null) {
            LOG.debug(LOG_PREFIX + "User not found for UPDATE_PASSWORD event: userId=" + event.getUserId());
            return;
        }

        LOG.debug(LOG_PREFIX + "Found user for UPDATE_PASSWORD: " + user.getUsername());

        // Check if this is a reset credentials action
        Map<String, String> details = event.getDetails();
        if (isResetCredentialsAction(details)) {
            handleResetCredentialsPasswordUpdate(user, details);
        } else {
            LOG.debug(LOG_PREFIX + "UPDATE_PASSWORD event processed (relying on 5-minute token expiration)");
        }
    }

    /**
     * Check if the event details indicate a reset credentials action.
     *
     * @param details The event details
     * @return true if this is a reset credentials action
     */
    private boolean isResetCredentialsAction(final Map<String, String> details) {
        if (details == null) {
            return false;
        }

        // Check for action_token_type field (primary method)
        if (details.containsKey(ACTION_TOKEN_TYPE_FIELD)) {
            String actionTokenType = details.get(ACTION_TOKEN_TYPE_FIELD);
            LOG.debug(LOG_PREFIX + "Found action_token_type: " + actionTokenType);
            return RESET_CREDENTIALS_TOKEN_TYPE.equals(actionTokenType);
        }

        // Fallback: Check for other indicators of password reset
        // If there's a token or action_token field, it's likely a reset
        if (details.containsKey(TOKEN_FIELD) || details.containsKey(ACTION_TOKEN_FIELD)) {
            LOG.debug(LOG_PREFIX + "Found token field, assuming reset credentials action");
            return true;
        }

        // Check for reset credentials action
        if (RESET_CREDENTIALS_ACTION.equals(details.get(ACTION_FIELD))) {
            LOG.debug(LOG_PREFIX + "Found reset credentials action");
            return true;
        }

        return false;
    }

    /**
     * Handle password update for reset credentials action.
     *
     * @param user The user
     * @param details The event details
     */
    private void handleResetCredentialsPasswordUpdate(final UserModel user, final Map<String, String> details) {
        LOG.debug(LOG_PREFIX + "This is a reset-credentials action");

        String tokenUsed = extractTokenFromDetails(details);
        String storedToken = getStoredToken(user);
        LOG.debug(LOG_PREFIX + "Stored token: " + storedToken);

        if (tokenUsed != null && storedToken != null) {
            validateAndHandleTokenUsage(user, tokenUsed, storedToken, "password update");
        }

        // Always clear the reset token after password update if there's a stored token
        if (storedToken != null) {
            clearResetTokens(user);
        }
    }

    /**
     * Validate token usage and handle accordingly.
     *
     * @param user The user
     * @param tokenUsed The token used
     * @param storedToken The stored token
     * @param context The context (e.g., "password update", "action token event")
     */
    private void validateAndHandleTokenUsage(final UserModel user, final String tokenUsed,
                                           final String storedToken, final String context) {
        if (!tokenUsed.equals(storedToken)) {
            LOG.info(LOG_PREFIX + USER_LOG_PREFIX + user.getUsername()
                    + " attempted to use an old reset token: " + tokenUsed
                    + " (current: " + storedToken + ")");

            try {
                invalidateToken(tokenUsed);
                LOG.info(LOG_PREFIX + "Invalidated old token " + tokenUsed
                        + " for user " + user.getUsername() + " during " + context);
            } catch (Exception e) {
                LOG.warn(LOG_PREFIX + "Error invalidating old token during " + context + " for user "
                        + user.getUsername() + ": " + e.getMessage());
            }
        } else {
            LOG.debug(LOG_PREFIX + USER_LOG_PREFIX + user.getUsername()
                    + " used the current reset token in " + context);
        }
    }

    /**
     * Extract token from event details.
     *
     * @param details The event details
     * @return The extracted token or null if not found
     */
    private String extractTokenFromDetails(final Map<String, String> details) {
        if (details == null) {
            return null;
        }

        String token = details.get("key");
        if (token == null) {
            token = details.get(TOKEN_FIELD);
        }
        if (token == null) {
            token = details.get(ACTION_TOKEN_FIELD);
        }
        if (token == null) {
            token = details.get(CODE_ID_FIELD);
        }
        return token;
    }

    /**
     * Get the stored token for a user.
     *
     * @param user The user
     * @return The stored token or null if not found
     */
    private String getStoredToken(final UserModel user) {
        String storedToken = user.getFirstAttribute(RESET_PWD_TOKEN);
        if (storedToken == null) {
            // Try the old attribute name for backward compatibility
            storedToken = user.getFirstAttribute(PREVIOUS_RESET_TOKEN);
        }
        return storedToken;
    }

    /**
     * Handle action token events.
     *
     * @param event The event to handle
     */
    private void handleActionTokenEvent(final Event event) {
        UserModel user = getUserFromEvent(event);
        if (user == null) {
            LOG.debug(LOG_PREFIX + "User not found for action token event: userId=" + event.getUserId());
            return;
        }

        LOG.debug(LOG_PREFIX + "Found user for action token event: " + user.getUsername());
        LOG.debug(LOG_PREFIX + "Action token event processed (relying on 5-minute token expiration)");
    }


    /**
     * Get the user associated with the event.
     *
     * @param event The event containing user information
     * @return The user model or null if not found
     */
    private UserModel getUserFromEvent(final Event event) {
        try {
            if (event.getRealmId() == null || event.getUserId() == null) {
                LOG.debug(LOG_PREFIX + "Missing realm ID or user ID in event");
                return null;
            }
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            if (realm == null) {
                LOG.debug(LOG_PREFIX + "Realm not found: " + event.getRealmId());
                return null;
            }
            return session.users().getUserById(realm, event.getUserId());
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error getting user from event: " + e.getMessage());
            return null;
        }
    }

    /**
     * Invalidate the previous token if it exists.
     *
     * @param user The user whose token should be invalidated
     * @throws Exception if token invalidation fails
     */
    private void invalidatePreviousToken(final UserModel user) throws Exception {
        String oldToken = user.getFirstAttribute(RESET_PWD_TOKEN);
        if (oldToken == null) {
            // Try the old attribute name for backward compatibility
            oldToken = user.getFirstAttribute(PREVIOUS_RESET_TOKEN);
        }
        if (oldToken == null) {
            LOG.debug(LOG_PREFIX + "No previous token found for user: " + user.getUsername());
            return;
        }

        LOG.debug(LOG_PREFIX + "Found previous token for user " + user.getUsername() + ": " + oldToken);

        // Try to invalidate using SingleUseObjectProvider
        invalidateToken(oldToken);

        LOG.info(LOG_PREFIX + "Invalidated previous reset token for user " + user.getUsername());
    }

    /**
     * Invalidate a specific token.
     *
     * @param token The token to invalidate
     * @throws Exception if token invalidation fails
     */
    private void invalidateToken(final String token) throws Exception {
        // Get the SingleUseObject provider
        SingleUseObjectProvider singleUseStore = session.getProvider(SingleUseObjectProvider.class);
        if (singleUseStore == null) {
            LOG.warn(LOG_PREFIX + "SingleUseObjectProvider not available");
            throw new IllegalStateException("SingleUseObjectProvider not available");
        }

        LOG.debug(LOG_PREFIX + "Got SingleUseObjectProvider, invalidating token: " + token);

        // Use multiple strategies to ensure the token is invalidated

        // 1. Remove the token directly
        singleUseStore.remove(token);
        LOG.debug(LOG_PREFIX + "Removed token: " + token);

        // 2. Mark the token as consumed
        Map<String, String> consumedData = new HashMap<>();
        consumedData.put("consumed", "true");
        consumedData.put("timestamp", String.valueOf(Time.currentTime()));
        singleUseStore.put(token + ".consumed", Time.currentTime() + ONE_DAY_IN_SECONDS, consumedData);
        LOG.debug(LOG_PREFIX + "Marked token as consumed: " + token + ".consumed");

        // 3. Create an expired entry for the token
        Map<String, String> expiredData = new HashMap<>();
        expiredData.put("expired", "true");
        expiredData.put("timestamp", String.valueOf(Time.currentTime()));
        // Use a past time for expiration (1 day ago)
        singleUseStore.put(token, Time.currentTime() - ONE_DAY_IN_SECONDS, expiredData);
        LOG.debug(LOG_PREFIX + "Set token to expired: " + token);

        // 4. Try with different prefixes/suffixes
        singleUseStore.remove("action." + token);
        singleUseStore.remove("actionToken." + token);
        singleUseStore.remove("token." + token);
        singleUseStore.remove("reset." + token);
        LOG.debug(LOG_PREFIX + "Removed token with different prefixes");

        // 5. Try with different variations
        String tokenWithoutDashes = token.replace("-", "");
        if (!tokenWithoutDashes.equals(token)) {
            singleUseStore.remove(tokenWithoutDashes);
            LOG.debug(LOG_PREFIX + "Removed token without dashes: " + tokenWithoutDashes);
        }
    }

    /**
     * Store the new token and related audit information.
     *
     * @param user The user to store the token for
     * @param tokenFromEvent The token from the event
     */
    private void storeNewToken(final UserModel user, final String tokenFromEvent) {
        // Store the token from the event
        user.setSingleAttribute(RESET_PWD_TOKEN, tokenFromEvent);
        LOG.debug(LOG_PREFIX + "Stored token for user " + user.getUsername() + ": " + tokenFromEvent);

        // Store the current time as the IAT (issued at) timestamp
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        user.setSingleAttribute(RESET_PWD_TOKEN_IAT, timestamp);
        LOG.debug(LOG_PREFIX + "Stored token IAT timestamp for user " + user.getUsername() + ": " + timestamp);

        // Clean up legacy attributes
        cleanupLegacyAttributes(user);
    }

    /**
     * Clean up legacy attributes from previous versions.
     *
     * @param user The user to clean up attributes for
     */
    private void cleanupLegacyAttributes(final UserModel user) {
        String[] legacyAttributes = {
            PREVIOUS_RESET_TOKEN,
            "previousResetTokenIat",
            "resetTokenInfo",
            "resetTokenTimestamp",
            "invalidatedToken",
            "invalidatedTokenTime",
            "invalidTokenAttempt",
            "invalidTokenAttemptTime",
            "reset_pwd_token_info",
            "reset_pwd_token_timestamp",
            "reset_pwd_invalidated_token",
            "reset_pwd_invalidated_token_time",
            "reset_pwd_invalid_attempt",
            "reset_pwd_invalid_attempt_time",
            "reset_pwd_unique_token",
            "reset_pwd_prev_unique_token"
        };

        for (String attribute : legacyAttributes) {
            if (user.getFirstAttribute(attribute) != null) {
                user.removeAttribute(attribute);
            }
        }
    }

    /**
     * Clear reset password tokens from user attributes.
     *
     * @param user The user to clear tokens for
     */
    private void clearResetTokens(final UserModel user) {
        // Always clear the tokens, even if they are null
        user.removeAttribute(RESET_PWD_TOKEN);
        LOG.debug(LOG_PREFIX + "Cleared reset_pwd_token for user " + user.getUsername());

        user.removeAttribute(RESET_PWD_TOKEN_IAT);
        LOG.debug(LOG_PREFIX + "Cleared reset_pwd_token_iat for user " + user.getUsername());
    }

    @Override
    public void onEvent(final AdminEvent adminEvent, final boolean includeRepresentation) {
        // unused
    }

    @Override
    public void close() {
        // nothing to clean up
    }
}
