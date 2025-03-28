package dod.p1.keycloak.authentication;

import dod.p1.keycloak.utils.OCSPUtils;
import org.keycloak.models.UserModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import jakarta.ws.rs.core.Response;
import org.keycloak.events.Errors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

/**
 * Authenticator for performing OCSP Certificate Verification with caching.
 */
public class OCSPCheckAuthenticator implements Authenticator {

    /**
     * Logger for the {@code OCSPCheckAuthenticator} class.
     * This logger is used to log information, warnings, and errors related to OCSP authentication checks.
     */
    private static final Logger LOGGER = LogManager.getLogger(OCSPCheckAuthenticator.class);

    /**
     * A constant representing the auth note key {@code authenticated_via_x509}.
     * This constant is used to indicate that the user has been authenticated via X.509 certificate.
     */
    private static final String AUTH_VIA_X509 = "authenticated_via_x509";

    /**
     * A constant representing the cache status attribute key {@code ocsp_cache_status}.
     * This attribute stores the cached OCSP status ("GOOD" or "REVOKED") for the user.
     */
    private static final String OCSP_CACHE_STATUS_ATTR = "ocsp_cache_status";

    /**
     * A constant representing the cache timestamp attribute key {@code ocsp_cache_timestamp}.
     * This attribute stores the timestamp of when the OCSP status was last cached.
     */
    private static final String OCSP_CACHE_TIMESTAMP_ATTR = "ocsp_cache_timestamp";

    /**
     * Constant representing the string value "false".
     * <p>
     * This is used to avoid hardcoding the "false" string multiple times in the code, promoting
     * maintainability and clarity.
     * </p>
     */
    private static final String FALSE = "false";

    // Removed unused constants

    /**
     * Error message for missing certificate chain.
     */
    private static final String ERROR_NO_CERT_CHAIN =
            "No certificate chain found. Please ensure you are using a valid certificate.";

    /**
     * Error message for OCSP validation issues.
     */
    private static final String ERROR_OCSP_VALIDATION =
            "Certificate validation failed. Please ensure you are using a valid certificate and try again.";

    /**
     * Error message for internal errors during certificate validation.
     */
    private static final String ERROR_INTERNAL_CERT_VALIDATION =
            "Certificate validation failed, possibly due to an unreachable OCSP server. "
                    + "Please remove CAC/PIV and try again later.";

    // Magic numbers replaced with constants

    /**
     * A constant representing the configuration scope {@code babyYodaOcsp}.
     */
    private static final String CONFIG_SCOPE = "babyYodaOcsp";

    /**
     * A constant representing the configuration key {@code enabled}.
     */
    private static final String CONFIG_ENABLED = "enabled";

    /**
     * A constant representing the configuration key {@code CacheTTLHours}.
     */
    private static final String CONFIG_CACHE_TTL_HOURS = "CacheTTLHours";

    /**
     * A constant representing the configuration key {@code CacheEnabled}.
     */
    private static final String CONFIG_CACHE_ENABLED = "CacheEnabled";

    /**
     * A constant representing the default TTL hours as a string.
     */
    private static final String DEFAULT_TTL_HOURS = "24";

    /**
     * A constant representing the default cache enabled state as a string.
     */
    private static final String DEFAULT_CACHE_ENABLED = "false";

    /**
     * A constant representing the number of milliseconds in one hour.
     */
    private static final long MILLIS_PER_HOUR = 3_600_000L;

    /**
     * A constant representing the default TTL hours as a numeric value.
     */
    private static final long DEFAULT_TTL_HOURS_VALUE = 24L;

    /**
     * Log message for certificate validation failure.
     */
    private static final String LOG_CERT_VALIDATION_FAILED =
            "OCSPCheckAuthenticator: Certificate validation failed for user: {}";

    /**
     * Authenticates the user by performing an Online Certificate Status Protocol (OCSP) check with caching.
     * <p>
     * This method retrieves the configuration for OCSP checks and determines whether to proceed with
     * validating the user's certificate chain. It utilizes caching to avoid redundant OCSP checks within the TTL.
     * Based on the result of the OCSP validation, it sets the {@code authenticated_via_x509} auth note
     * and either succeeds or fails the authentication process.
     * </p>
     *
     * @param context the {@link AuthenticationFlowContext} containing the user and session information
     */
    @Override
    public void authenticate(final AuthenticationFlowContext context) {
        if (context.getUser() == null) {
            LOGGER.warn("OCSPCheckAuthenticator: No user found in context.");
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS);
            return;
        }

        final String username = context.getUser().getUsername();
        LOGGER.trace("OCSPCheckAuthenticator: authenticate invoked for user: {}", username);

        try {
            // Retrieve OCSP enabled configuration
            final String ocspEnabled = org.keycloak.Config.scope(CONFIG_SCOPE)
                    .get(CONFIG_ENABLED, FALSE);
            LOGGER.trace("OCSPCheckAuthenticator: {}.{} set to: {}", CONFIG_SCOPE, CONFIG_ENABLED, ocspEnabled);

            if (!"true".equalsIgnoreCase(ocspEnabled)) {
                LOGGER.debug("OCSPCheckAuthenticator: OCSP is disabled. Skipping OCSP check for user: {}", username);
                context.getAuthenticationSession().setAuthNote(AUTH_VIA_X509, "true");
                LOGGER.debug("OCSPCheckAuthenticator: Set authenticated_via_x509 to true for user: {}", username);
                context.success();
                return;
            }

            LOGGER.trace("OCSPCheckAuthenticator: OCSP is enabled. Proceeding with OCSP check for user: {}", username);

            // Retrieve the certificate chain
            final X509Certificate[] certChain = OCSPUtils.getCertificateChain(context);

            if (certChain == null || certChain.length == 0) {
                LOGGER.warn("OCSPCheckAuthenticator: No certificate chain found for user: {}", username);
                LOGGER.debug(LOG_CERT_VALIDATION_FAILED, username);

                // Log the error event
                context.getEvent().error(Errors.IDENTITY_PROVIDER_ERROR);

                // Create a challenge response with the custom error message
                final Response challenge = context.form()
                        .setError(ERROR_NO_CERT_CHAIN)
                        .createErrorPage(Response.Status.BAD_REQUEST);

                // Fail the authentication with a specific error and challenge
                context.failureChallenge(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, challenge);
                return; // Ensure the method exits after failure
            }

            LOGGER.debug("OCSPCheckAuthenticator: Checking for cached OCSP result for user: {}", username);

            // Retrieve cache settings from configuration
            String ttlHoursStr = org.keycloak.Config.scope(CONFIG_SCOPE)
                    .get(CONFIG_CACHE_TTL_HOURS, DEFAULT_TTL_HOURS).trim();
            long ttlHours = parseTTLHours(ttlHoursStr);
            final long ttlMillis = ttlHours * MILLIS_PER_HOUR;

            final String cacheEnabledStr = org.keycloak.Config.scope(CONFIG_SCOPE)
                    .get(CONFIG_CACHE_ENABLED, DEFAULT_CACHE_ENABLED).trim();
            final boolean ocspCacheEnabled = Boolean.parseBoolean(cacheEnabledStr);
            LOGGER.trace("OCSPCheckAuthenticator: OCSP Cache TTL is set to {} hours ({} milliseconds).",
                    ttlHours, ttlMillis);

            final CacheResult cacheResult = getCachedOCSPResult(context, username, ttlMillis, ocspCacheEnabled);

            boolean isOCSPGood;
            boolean usedCache = false;

            if (cacheResult.isValid()) {
                isOCSPGood = cacheResult.isOCSPGood();
                usedCache = cacheResult.isUsedCache();
            } else {
                isOCSPGood = performOCSPCheck(context, certChain, username, ocspCacheEnabled);
            }

            if (isOCSPGood) {
                handleOCSPSuccess(context, username);
            } else {
                handleOCSPFailure(context, username, usedCache);
            }

        } catch (final GeneralSecurityException e) {
            handleOCSPException(context, username, e);
        }
    }

    /**
     * Performs the OCSP check and updates the cache if enabled.
     *
     * @param context          the authentication flow context
     * @param certChain        the certificate chain of the user
     * @param username         the username of the user
     * @param ocspCacheEnabled whether caching is enabled
     * @return {@code true} if OCSP is good, {@code false} otherwise
     * @throws GeneralSecurityException if an error occurs during OCSP check
     */
    private boolean performOCSPCheck(final AuthenticationFlowContext context,
                                     final X509Certificate[] certChain,
                                     final String username,
                                     final boolean ocspCacheEnabled) throws GeneralSecurityException {
        LOGGER.debug("OCSPCheckAuthenticator: Performing OCSP check for user: {}", username);

        final OCSPUtils.OCSPResult ocspResult = OCSPUtils.performOCSPCheck(
                context.getSession(),
                certChain
        );
        LOGGER.debug("OCSPCheckAuthenticator: OCSP check result: {} for user {}", ocspResult.isOCSPGood(), username);

        final boolean isOCSPGood = ocspResult.isOCSPGood();

        if (ocspCacheEnabled) {
            // Update cache with the new OCSP result
            final String newStatus = isOCSPGood ? "GOOD" : "REVOKED";
            context.getUser().setSingleAttribute(OCSP_CACHE_STATUS_ATTR, newStatus);
            context.getUser().setSingleAttribute(OCSP_CACHE_TIMESTAMP_ATTR, String.valueOf(System.currentTimeMillis()));
            LOGGER.debug("OCSPCheckAuthenticator: Updated OCSP cache for user: {} with status: {}",
                    username, newStatus);
        }

        return isOCSPGood;
    }

    /**
     * Handles the scenario when OCSP validation is successful.
     *
     * @param context  the authentication flow context
     * @param username the username of the user
     */
    private void handleOCSPSuccess(final AuthenticationFlowContext context, final String username) {
        LOGGER.debug("OCSPCheckAuthenticator: Certificate is valid for user: {}", username);
        context.getAuthenticationSession().setAuthNote(AUTH_VIA_X509, "true");
        LOGGER.debug("OCSPCheckAuthenticator: Set authenticated_via_x509 to true for user: {}", username);
        context.success();
    }

    /**
     * Handles the scenario when OCSP validation fails.
     *
     * @param context    the authentication flow context
     * @param username   the username of the user
     * @param usedCache  whether the failure was due to cached result
     */
    private void handleOCSPFailure(final AuthenticationFlowContext context,
                                                          final String username,
                                                          final boolean usedCache) {
        final String reason = usedCache ? "Cached OCSP status: REVOKED" : "OCSP status: REVOKED";
        LOGGER.warn("OCSPCheckAuthenticator: Certificate is invalid or revoked for user: {}. Reason: {}",
                username, reason);
        LOGGER.debug(LOG_CERT_VALIDATION_FAILED, username);

        // Log the error event
        context.getEvent().error(Errors.IDENTITY_PROVIDER_ERROR);

        // Create a challenge response with the custom error message
        final Response challengeResponse = context.form()
                .setError(ERROR_OCSP_VALIDATION)
                .createErrorPage(Response.Status.BAD_REQUEST);

        // Fail the authentication with a specific error and challenge
        context.failureChallenge(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, challengeResponse);
    }

    /**
     * Handles exceptions during OCSP check.
     *
     * @param context  the authentication flow context
     * @param username the username of the user
     * @param e        the exception encountered
     */
    private void handleOCSPException(final AuthenticationFlowContext context,
                                                              final String username,
                                                              final GeneralSecurityException e) {
        LOGGER.error("OCSPCheckAuthenticator: OCSP Check encountered an error for user {}: {}",
                username, e.getMessage(), e);
        LOGGER.debug(LOG_CERT_VALIDATION_FAILED, username);

        // Log the error event
        context.getEvent().error(Errors.IDENTITY_PROVIDER_ERROR);

        // Create a challenge response with the custom error message
        final Response challengeResponse = context.form()
                .setError(ERROR_INTERNAL_CERT_VALIDATION)
                .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);

        // Fail the authentication with a specific error and challenge
        context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
    }

    /**
     * Retrieves the cached OCSP result if available and valid.
     *
     * @param context          the authentication flow context
     * @param username         the username of the user
     * @param ttlMillis        the cache TTL in milliseconds
     * @param ocspCacheEnabled whether caching is enabled
     * @return the cached OCSP result
     */
    private CacheResult getCachedOCSPResult(final AuthenticationFlowContext context,
                                           final String username,
                                           final long ttlMillis,
                                           final boolean ocspCacheEnabled) {
        if (!ocspCacheEnabled) {
            LOGGER.trace("OCSPCheckAuthenticator: OCSP caching is disabled. Proceeding to perform new OCSP check.");
            return new CacheResult(false, false, false);
        }

        LOGGER.debug("OCSPCheckAuthenticator: Checking for cached OCSP result for user: {}", username);

        final String cachedStatus = context.getUser().getFirstAttribute(OCSP_CACHE_STATUS_ATTR);
        final String cachedTimestampStr = context.getUser().getFirstAttribute(OCSP_CACHE_TIMESTAMP_ATTR);
        long cachedTimestamp = 0;
        boolean isValid = false;
        boolean isOCSPGood = false;

        if (cachedTimestampStr != null) {
            try {
                cachedTimestamp = Long.parseLong(cachedTimestampStr);
                final long ageInMs = System.currentTimeMillis() - cachedTimestamp;
                final double ageInHours = ageInMs / (double) MILLIS_PER_HOUR;
                // Using the logging framework's built-in formatting is more efficient
                LOGGER.debug("OCSPCheckAuthenticator: Retrieved cached timestamp: {} ({,.2f} hrs"
                  + " ago) for user {}", cachedTimestamp, ageInHours, username);
            } catch (NumberFormatException e) {
                LOGGER.warn("OCSPCheckAuthenticator: Invalid 'ocsp_cache_timestamp'"
                 + " value '{}' for user {}. Ignoring cache.", cachedTimestampStr, username);
            }
        }

        final long ageInMs = System.currentTimeMillis() - cachedTimestamp;

        if (ageInMs < ttlMillis && cachedStatus != null) {
            LOGGER.debug("OCSPCheckAuthenticator: Valid OCSP cache found for user: {}."
              + " Using cached status: {}", username, cachedStatus);
            // Interpret cachedStatus as "GOOD" or "REVOKED"
            if ("GOOD".equalsIgnoreCase(cachedStatus)) {
                isOCSPGood = true;
                isValid = true;
                LOGGER.trace("OCSPCheckAuthenticator: Using cached status 'GOOD' for user: {}", username);
            } else if ("REVOKED".equalsIgnoreCase(cachedStatus)) {
                isValid = true;
                LOGGER.trace("OCSPCheckAuthenticator: Using cached status 'REVOKED' for user: {}", username);
            } else {
                LOGGER.warn("OCSPCheckAuthenticator: Unknown cached status '{}' for user {}. Ignoring cache.",
                        cachedStatus, username);
            }
        } else {
            if (cachedStatus != null) {
                final double cacheAgeHours = ageInMs / (double) MILLIS_PER_HOUR;
                // Using the logging framework's built-in formatting is more efficient
                LOGGER.debug("OCSPCheckAuthenticator: Cached OCSP result is expired for user {}. "
                                + "Cache age: {} ms ({,.2f} hrs).",
                        username, ageInMs, cacheAgeHours);
            } else {
                LOGGER.debug("OCSPCheckAuthenticator: No cached OCSP result found for user: {}", username);
            }
        }

        final boolean usedCache = isValid;
        return new CacheResult(isValid, isOCSPGood, usedCache);
    }

    /**
     * Executes the action for this authenticator.
     * <p>
     * No additional actions are required in this implementation.
     * </p>
     *
     * @param context the {@link AuthenticationFlowContext} for the current authentication flow
     */
    @Override
    public void action(final AuthenticationFlowContext context) {
        // No additional actions required
    }

    /**
     * Closes the authenticator and releases any resources, if necessary.
     */
    @Override
    public void close() {
        // Cleanup resources if necessary
    }

    /**
     * Indicates whether this authenticator requires a user to be authenticated.
     *
     * @return {@code true}, indicating that a user is required
     */
    @Override
    public boolean requiresUser() {
        return true;
    }

    /**
     * Checks if this authenticator is configured for a specific user.
     * <p>
     * Always returns {@code true} to ensure this authenticator is invoked.
     * </p>
     *
     * @param session the {@link KeycloakSession} for the current session
     * @param realm   the {@link RealmModel} for the current realm
     * @param user    the {@link UserModel} for the current user
     * @return {@code true}, indicating the authenticator is always configured
     */
    @Override
    public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        return true; // Always return true to ensure the authenticator is invoked
    }

    /**
     * Sets any required actions for the user.
     * <p>
     * This implementation does not define any required actions.
     * </p>
     *
     * @param session the {@link KeycloakSession} for the current session
     * @param realm   the {@link RealmModel} for the current realm
     * @param user    the {@link UserModel} for the current user
     */
    @Override
    public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        // No required actions to set
    }

    /**
     * Represents the result of a cache lookup.
     */
    private static class CacheResult {
        /**
         * Indicates if the cache is valid.
         */
        private final boolean valid;

        /**
         * Indicates if the OCSP result is good.
         */
        private final boolean ocspGood;

        /**
         * Indicates if the cache was used.
         */
        private final boolean usedCache;

        /**
         * Constructs a new {@code CacheResult}.
         *
         * @param cacheValid     indicates if the cache is valid
         * @param cacheOCSPGood  indicates if the OCSP result is good
         * @param cacheUsedCache indicates if the cache was used
         */
        CacheResult(final boolean cacheValid,
                   final boolean cacheOCSPGood,
                   final boolean cacheUsedCache) {
            this.valid = cacheValid;
            this.ocspGood = cacheOCSPGood;
            this.usedCache = cacheUsedCache;
        }

        /**
         * Returns whether the cache is valid.
         *
         * @return {@code true} if the cache is valid, {@code false} otherwise
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * Returns whether the OCSP result is good.
         *
         * @return {@code true} if the OCSP result is good, {@code false} otherwise
         */
        public boolean isOCSPGood() {
            return ocspGood;
        }

        /**
         * Returns whether the cache was used.
         *
         * @return {@code true} if the cache was used, {@code false} otherwise
         */
        public boolean isUsedCache() {
            return usedCache;
        }
    }

    /**
     * Parses the TTL hours from a string value.
     *
     * @param ttlHoursStr the TTL hours as a string
     * @return the parsed TTL hours as a long
     */
    private long parseTTLHours(final String ttlHoursStr) {
        try {
            return Long.parseLong(ttlHoursStr);
        } catch (NumberFormatException e) {
            LOGGER.warn("OCSPCheckAuthenticator: Invalid TTL value '{}'. Defaulting to {} hours.",
                    ttlHoursStr, DEFAULT_TTL_HOURS_VALUE);
            return DEFAULT_TTL_HOURS_VALUE;
        }
    }
}
