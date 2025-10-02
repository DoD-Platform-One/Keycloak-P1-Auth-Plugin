package dod.p1.keycloak.authentication;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

import java.util.Map;

/**
 * Custom authenticator that validates reset password tokens.
 * It ensures that only the most recent token for a user is valid.
 */
public class ResetPasswordTokenValidator implements Authenticator {

    /** Logger instance. */
    private static final Logger LOG = Logger.getLogger(ResetPasswordTokenValidator.class);

    /** Log prefix for easy grepping. */
    private static final String LOG_PREFIX = "ResetPwdValidator: ";

    /** User attribute where the last token ID is stored. */
    private static final String RESET_PWD_TOKEN = "reset_pwd_token";

    /** User attribute where the last token IAT timestamp is stored. */
    private static final String RESET_PWD_TOKEN_IAT = "reset_pwd_token_iat";

    /** Legacy user attribute for backward compatibility. */
    private static final String LEGACY_RESET_TOKEN = "previousResetToken";

    /** Legacy user attribute for IAT timestamp for backward compatibility. */
    private static final String LEGACY_RESET_TOKEN_IAT = "previousResetTokenIat";

    /** Timestamp tolerance in seconds to account for slight timing differences. */
    private static final long TIMESTAMP_TOLERANCE_SECONDS = 1;

    /** Log message prefix for user operations. */
    private static final String USER_LOG_PREFIX = "User ";

    /** Field name offset for JSON parsing. */
    private static final int FIELD_NAME_OFFSET = 2;

    /** ID field prefix length. */
    private static final int ID_FIELD_PREFIX_LENGTH = 3;

    /**
     * Token information holder.
     */
    private static class TokenInfo {
        /**
         * The token ID.
         */
        private final String tokenId;
        /**
         * The issued at timestamp.
         */
        private final String iat;

        /**
         * Constructor.
         *
         * @param tokenIdParam The token ID
         * @param iatParam The issued at timestamp
         */
        TokenInfo(final String tokenIdParam, final String iatParam) {
            this.tokenId = tokenIdParam;
            this.iat = iatParam;
        }
    }

    /**
     * Authenticate the user by validating the reset password token.
     * This method validates that the token used matches the most recent token
     * issued for the user and that the timestamp is within tolerance.
     *
     * @param context The authentication flow context
     */
    @Override
    public void authenticate(final AuthenticationFlowContext context) {
        LOG.debug(LOG_PREFIX + "Authenticating reset password token");

        String tokenString = findTokenInContext(context);
        if (tokenString == null) {
            LOG.debug(LOG_PREFIX + "No token found in context");
            context.success();
            return;
        }

        UserModel user = context.getUser();
        if (user == null) {
            LOG.debug(LOG_PREFIX + "No user found in context");
            context.success();
            return;
        }

        LOG.debug(LOG_PREFIX + "Found user: " + user.getUsername());

        String storedToken = getAndMigrateStoredToken(user);
        if (storedToken == null) {
            LOG.debug(LOG_PREFIX + "No stored token found for user");
            context.success();
            return;
        }

        TokenInfo tokenInfo = extractTokenInfo(tokenString);
        if (tokenInfo.tokenId == null) {
            LOG.debug(LOG_PREFIX + "Could not extract token ID");
            context.success();
            return;
        }

        String storedIat = getAndMigrateStoredIat(user);
        boolean isValid = validateToken(tokenInfo, storedToken, storedIat);

        if (isValid) {
            LOG.info(LOG_PREFIX + USER_LOG_PREFIX + user.getUsername() + " used a valid reset token");
            context.success();
        } else {
            handleInvalidToken(context, tokenInfo, storedToken, storedIat, user.getUsername());
        }
    }

    /**
     * Get and migrate stored token from user attributes.
     *
     * @param user The user
     * @return The stored token or null if not found
     */
    private String getAndMigrateStoredToken(final UserModel user) {
        String storedToken = user.getFirstAttribute(RESET_PWD_TOKEN);
        if (storedToken == null) {
            // Try the old attribute name for backward compatibility
            storedToken = user.getFirstAttribute(LEGACY_RESET_TOKEN);
            if (storedToken != null) {
                LOG.debug(LOG_PREFIX + "Found token in legacy attribute");
                // Migrate to the new attribute name
                user.setSingleAttribute(RESET_PWD_TOKEN, storedToken);
                user.removeAttribute(LEGACY_RESET_TOKEN);
            }
        }
        return storedToken;
    }

    /**
     * Get and migrate stored IAT from user attributes.
     *
     * @param user The user
     * @return The stored IAT or null if not found
     */
    private String getAndMigrateStoredIat(final UserModel user) {
        String storedIat = user.getFirstAttribute(RESET_PWD_TOKEN_IAT);
        if (storedIat == null) {
            // Try the old attribute name for backward compatibility
            storedIat = user.getFirstAttribute(LEGACY_RESET_TOKEN_IAT);
            if (storedIat != null) {
                LOG.debug(LOG_PREFIX + "Found IAT in legacy attribute");
                // Migrate to the new attribute name
                user.setSingleAttribute(RESET_PWD_TOKEN_IAT, storedIat);
                user.removeAttribute(LEGACY_RESET_TOKEN_IAT);
            }
        }
        LOG.debug(LOG_PREFIX + "Stored token IAT: " + storedIat);
        return storedIat;
    }

    /**
     * Validate the token against stored values.
     *
     * @param tokenInfo The extracted token information
     * @param storedToken The stored token
     * @param storedIat The stored IAT
     * @return true if the token is valid
     */
    private boolean validateToken(final TokenInfo tokenInfo, final String storedToken,
                                 final String storedIat) {
        LOG.debug(LOG_PREFIX + "Extracted token ID: " + tokenInfo.tokenId);
        LOG.debug(LOG_PREFIX + "Extracted token IAT: " + tokenInfo.iat);

        // Check if the token IDs match
        boolean tokenIdsMatch = tokenInfo.tokenId.equals(storedToken);

        // Check if the IAT timestamps match within tolerance
        boolean validTimestamp = validateTimestamp(tokenInfo.iat, storedIat);

        // The token is valid if both conditions are met
        return tokenIdsMatch && validTimestamp;
    }

    /**
     * Validate timestamp within tolerance.
     *
     * @param tokenIat The token IAT
     * @param storedIat The stored IAT
     * @return true if timestamps are within tolerance
     */
    private boolean validateTimestamp(final String tokenIat, final String storedIat) {
        // If both are null, this is valid (e.g., UUID tokens don't have timestamps)
        if (tokenIat == null && storedIat == null) {
            return true;
        }

        // If only one is null, this is invalid
        if (tokenIat == null || storedIat == null) {
            return false;
        }

        try {
            long tokenIatLong = Long.parseLong(tokenIat);
            long storedIatLong = Long.parseLong(storedIat);
            long difference = Math.abs(tokenIatLong - storedIatLong);

            boolean isValid = difference <= TIMESTAMP_TOLERANCE_SECONDS;
            LOG.debug(LOG_PREFIX + "Token IAT comparison: token=" + tokenIatLong
                    + ", stored=" + storedIatLong + ", difference=" + difference
                    + " seconds, isValid=" + isValid);
            return isValid;
        } catch (NumberFormatException e) {
            LOG.warn(LOG_PREFIX + "Error parsing IAT timestamps: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check if a token is expired based on timestamps.
     *
     * @param tokenIat The token IAT
     * @param storedIat The stored IAT
     * @return true if the token is expired
     */
    private boolean isTokenExpired(final String tokenIat, final String storedIat) {
        if (tokenIat == null || storedIat == null) {
            return false;
        }

        try {
            long tokenIatLong = Long.parseLong(tokenIat);
            long storedIatLong = Long.parseLong(storedIat);
            // If the stored token is newer than the provided token, it's expired
            return storedIatLong > tokenIatLong;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Handle invalid token authentication.
     *
     * @param context The authentication context
     * @param tokenInfo The token information
     * @param storedToken The stored token
     * @param storedIat The stored IAT
     * @param username The username for logging
     */
    private void handleInvalidToken(final AuthenticationFlowContext context, final TokenInfo tokenInfo,
                                   final String storedToken, final String storedIat, final String username) {
        boolean tokenIdsMatch = tokenInfo.tokenId.equals(storedToken);

        if (!tokenIdsMatch) {
            LOG.info(LOG_PREFIX + USER_LOG_PREFIX + username
                    + " attempted to use a token with non-matching ID: "
                    + tokenInfo.tokenId + " (current: " + storedToken + ")");
            context.getEvent().error("invalid_token");
        } else {
            LOG.info(LOG_PREFIX + USER_LOG_PREFIX + username
                    + " attempted to use a token with invalid timestamp: "
                    + tokenInfo.iat + " (current: " + storedIat + ")");
            // Check if it's specifically an expired token (timestamp issue)
            if (isTokenExpired(tokenInfo.iat, storedIat)) {
                context.getEvent().error("expired_token");
            } else {
                context.getEvent().error("invalid_token");
            }
        }

        context.failure(AuthenticationFlowError.EXPIRED_CODE);
    }

    /**
     * Find the token in the authentication context.
     * Try various places where the token might be stored.
     *
     * @param context The authentication flow context
     * @return The token string or null if not found
     */
    private String findTokenInContext(final AuthenticationFlowContext context) {
        // Try different sources in order of preference
        String token = findTokenInQueryParameters(context);
        if (token != null) {
            return token;
        }

        token = findTokenInAuthSessionNotes(context);
        if (token != null) {
            return token;
        }

        token = findTokenInClientSessionNotes(context);
        if (token != null) {
            return token;
        }

        token = findTokenInUserAttributes(context);
        if (token != null) {
            return token;
        }

        return findTokenInUriPath(context);
    }

    /**
     * Find token in HTTP request query parameters.
     *
     * @param context The authentication flow context
     * @return The token string or null if not found
     */
    private String findTokenInQueryParameters(final AuthenticationFlowContext context) {
        try {
            String key = context.getHttpRequest().getUri().getQueryParameters().getFirst("key");
            if (key != null) {
                LOG.debug(LOG_PREFIX + "Found token in 'key' query parameter");
                return key;
            }

            String[] paramNames = {
                "token", "code", "code_id", "execution", "tab_id", "client_id", "user_id"
            };

            for (String paramName : paramNames) {
                String paramValue = context.getHttpRequest().getUri().getQueryParameters().getFirst(paramName);
                if (paramValue != null) {
                    LOG.debug(LOG_PREFIX + "Found token in '" + paramName + "' query parameter");
                    return paramValue;
                }
            }
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error checking HTTP request query parameters: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find token in authentication session notes.
     *
     * @param context The authentication flow context
     * @return The token string or null if not found
     */
    private String findTokenInAuthSessionNotes(final AuthenticationFlowContext context) {
        String[] noteNames = {
            "TOKEN", "ACTION_TOKEN_ID", "RESET_CREDENTIALS_TOKEN", "KEY", "ACTION_TOKEN",
            "CODE_ID", "VERIFY_EMAIL_CODE", "VERIFY_EMAIL_KEY"
        };

        for (String noteName : noteNames) {
            String noteValue = context.getAuthenticationSession().getAuthNote(noteName);
            if (noteValue != null) {
                LOG.debug(LOG_PREFIX + "Found token in '" + noteName + "' auth note");
                return noteValue;
            }
        }
        return null;
    }

    /**
     * Find token in client session notes.
     *
     * @param context The authentication flow context
     * @return The token string or null if not found
     */
    private String findTokenInClientSessionNotes(final AuthenticationFlowContext context) {
        try {
            Map<String, String> clientSessionNotes = context.getAuthenticationSession().getClientNotes();
            for (Map.Entry<String, String> entry : clientSessionNotes.entrySet()) {
                if (entry.getKey().contains("TOKEN") || entry.getKey().contains("KEY")
                        || entry.getKey().contains("CODE")) {
                    LOG.debug(LOG_PREFIX + "Found token in client session note '" + entry.getKey() + "'");
                    return entry.getValue();
                }
            }
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error checking client session notes: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find token in user attributes.
     *
     * @param context The authentication flow context
     * @return The token string or null if not found
     */
    private String findTokenInUserAttributes(final AuthenticationFlowContext context) {
        try {
            UserModel user = context.getUser();
            if (user != null) {
                String[] attributeNames = {
                    RESET_PWD_TOKEN, LEGACY_RESET_TOKEN
                };

                for (String attributeName : attributeNames) {
                    String attributeValue = user.getFirstAttribute(attributeName);
                    if (attributeValue != null) {
                        LOG.debug(LOG_PREFIX + "Found token in user attribute '" + attributeName + "'");
                        return attributeValue;
                    }
                }
            }
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error checking user attributes: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find token in HTTP request URI path.
     *
     * @param context The authentication flow context
     * @return The token string or null if not found
     */
    private String findTokenInUriPath(final AuthenticationFlowContext context) {
        try {
            String path = context.getHttpRequest().getUri().getPath();

            // Look for UUIDs in the path
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                    "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}");
            java.util.regex.Matcher matcher = pattern.matcher(path);
            if (matcher.find()) {
                String uuid = matcher.group();
                LOG.debug(LOG_PREFIX + "Found UUID in path");
                return uuid;
            }
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error checking HTTP request URI path: " + e.getMessage());
        }
        return null;
    }

    /**
     * Extract the token ID and IAT from the token string.
     *
     * @param tokenString The token string
     * @return The token information
     */
    private TokenInfo extractTokenInfo(final String tokenString) {
        try {
            // If it contains a dot, it might be a JWT
            if (tokenString.contains(".")) {
                return extractFromJwt(tokenString);
            }

            // If it's a UUID, return it as is
            if (tokenString.matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")) {
                return new TokenInfo(tokenString, null);
            }

            // If it's a serialized object, try to extract the ID from the string representation
            return extractFromSerializedObject(tokenString);
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error extracting token info: " + e.getMessage());
            return new TokenInfo(null, null);
        }
    }

    /**
     * Extract token information from JWT.
     *
     * @param tokenString The JWT token string
     * @return The token information
     */
    private TokenInfo extractFromJwt(final String tokenString) {
        String[] parts = tokenString.split("\\.");
        if (parts.length < 2) {
            return new TokenInfo(tokenString, null);
        }

        String payload = new String(java.util.Base64.getDecoder().decode(parts[1]));
        LOG.debug(LOG_PREFIX + "Extracted JWT payload");

        String iat = extractIatFromPayload(payload);
        String tokenId = extractTokenIdFromPayload(payload);

        return new TokenInfo(tokenId != null ? tokenId : tokenString, iat);
    }

    /**
     * Extract IAT timestamp from JWT payload.
     *
     * @param payload The JWT payload
     * @return The IAT timestamp or null if not found
     */
    private String extractIatFromPayload(final String payload) {
        if (!payload.contains("iat")) {
            return null;
        }

        int iatIndex = payload.indexOf("\"iat\"");
        if (iatIndex == -1) {
            // Try without quotes (shouldn't happen in valid JSON, but be defensive)
            iatIndex = payload.indexOf("iat");
        }

        int startIndex = payload.indexOf(":", iatIndex) + 1;
        int endIndex = payload.indexOf(",", startIndex);
        if (endIndex == -1) {
            // No comma found, look for closing brace
            endIndex = payload.indexOf("}", startIndex);
        }
        if (endIndex > startIndex) {
            String iat = payload.substring(startIndex, endIndex).trim();
            LOG.debug(LOG_PREFIX + "Found iat in JWT: " + iat);
            return iat;
        }
        return null;
    }

    /**
     * Extract token ID from JWT payload.
     *
     * @param payload The JWT payload
     * @return The token ID or null if not found
     */
    private String extractTokenIdFromPayload(final String payload) {
        // Look for the asid field first
        String tokenId = extractFieldFromPayload(payload, "asid");
        if (tokenId != null) {
            LOG.debug(LOG_PREFIX + "Found asid in JWT: " + tokenId);
            // The asid might contain the code_id as the first part
            if (tokenId.contains(".")) {
                String extractedId = tokenId.split("\\.")[0];
                LOG.debug(LOG_PREFIX + "Extracted code_id from asid: " + extractedId);
                return extractedId;
            }
            return tokenId;
        }

        // If asid is not found, try jti as a fallback
        tokenId = extractFieldFromPayload(payload, "jti");
        if (tokenId != null) {
            LOG.debug(LOG_PREFIX + "Found jti in JWT: " + tokenId);
        }
        return tokenId;
    }

    /**
     * Extract a field value from JWT payload.
     *
     * @param payload The JWT payload
     * @param fieldName The field name to extract
     * @return The field value or null if not found
     */
    private String extractFieldFromPayload(final String payload, final String fieldName) {
        if (!payload.contains(fieldName)) {
            return null;
        }

        int fieldIndex = payload.indexOf(fieldName);
        int startIndex = payload.indexOf("\"", fieldIndex + fieldName.length() + FIELD_NAME_OFFSET) + 1;
        int endIndex = payload.indexOf("\"", startIndex);
        if (startIndex > 0 && endIndex > startIndex) {
            return payload.substring(startIndex, endIndex);
        }
        return null;
    }

    /**
     * Extract token information from serialized object string.
     *
     * @param tokenString The serialized object string
     * @return The token information
     */
    private TokenInfo extractFromSerializedObject(final String tokenString) {
        try {
            // Look for patterns like "id=<uuid>" in the string representation
            if (tokenString.contains("id=")) {
                int idIndex = tokenString.indexOf("id=");
                int startIndex = idIndex + ID_FIELD_PREFIX_LENGTH;
                int endIndex = tokenString.indexOf(",", startIndex);
                if (endIndex == -1) {
                    endIndex = tokenString.indexOf(")", startIndex);
                }
                if (endIndex > startIndex) {
                    String tokenId = tokenString.substring(startIndex, endIndex).trim();
                    return new TokenInfo(tokenId, null);
                }
            }
        } catch (Exception e) {
            LOG.warn(LOG_PREFIX + "Error extracting ID from string representation: " + e.getMessage());
        }

        return new TokenInfo(tokenString, null); // Return the token string itself if we can't extract an ID
    }

    /**
     * Perform action after authentication.
     * This authenticator does not require any post-authentication actions.
     *
     * @param context The authentication flow context
     */
    @Override
    public void action(final AuthenticationFlowContext context) {
        // Not used for this authenticator
        context.success();
    }

    /**
     * Check if this authenticator requires a user.
     * This authenticator requires a user to validate the token against.
     *
     * @return true as this authenticator requires a user
     */
    @Override
    public boolean requiresUser() {
        return true;
    }

    /**
     * Check if this authenticator is configured for the given user.
     * This authenticator is always considered configured.
     *
     * @param session The Keycloak session
     * @param realm The realm model
     * @param user The user model
     * @return true as this authenticator is always configured
     */
    @Override
    public boolean configuredFor(final KeycloakSession session, final RealmModel realm,
            final UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(final KeycloakSession session, final RealmModel realm,
            final UserModel user) {
        // Not used for this authenticator
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
