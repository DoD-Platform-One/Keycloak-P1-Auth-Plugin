package dod.p1.keycloak.registration;

import java.util.Date;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import dod.p1.keycloak.utils.OCSPUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import dod.p1.keycloak.common.CommonConfig;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * Handles the required action for updating X.509 certificate information for users.
 */
public class UpdateX509 implements RequiredActionProvider, RequiredActionFactory {

    /** Provider ID for this required action. */
    private static final String PROVIDER_ID = "UPDATE_X509";

    /** Auth note key to ignore X.509 processing. */
    private static final String IGNORE_X509 = "IGNORE_X509";

    /** Logger instance for logging. */
    private static final Logger LOGGER = LogManager.getLogger(UpdateX509.class);

    /** Configuration scope for OCSP settings. */
    private static final String OCSP_CONFIG_SCOPE = "babyYodaOcsp";

    /** Configuration key for OCSP enabled setting. */
    private static final String OCSP_ENABLED_KEY = "enabled";

    /** Default value for boolean settings. */
    private static final String DEFAULT_BOOLEAN_VALUE = "false";

    /** True value for boolean settings. */
    private static final String TRUE_BOOLEAN_VALUE = "true";

    /** Auth note key for X.509 authentication status. */
    private static final String AUTH_VIA_X509 = "authenticated_via_x509";

    /** Error message for CommonConfig issues. */
    private static final String COMMON_CONFIG_ERROR_MSG = "UpdateX509:evaluateTriggers: Error getting CommonConfig: {}";

    /**
     * Position index for the first certificate policy in the certificate chain.
     */
    private static final int POLICY_CERTIFICATE_POLICY_POS = 0;

    /**
     * Position index for the first identifier within the certificate policy.
     */
    private static final int POLICY_IDENTIFIER_POS = 0;

    /**
     * Checks if the user is a direct member of the specified group.
     *
     * @param user  The user to check.
     * @param group The group to verify membership against.
     * @return      True if the user is a direct member of the group, false otherwise.
     */
    private boolean isDirectMemberOfGroup(final UserModel user, final GroupModel group) {
        if (user == null || group == null) {
            LOGGER.warn("isDirectMemberOfGroup: User or Group is null.");
            return false;
        }

        return user.getGroupsStream()
                   .anyMatch(g -> g.getId().equals(group.getId()));
    }

    /**
     * Evaluates whether the user requires additional actions based on their X.509 certificate status.
     * This method is called for all successful authentications. CAC associated, CAC associating
     * user/pw/otp, and after user hits ignore on PIV login and falls back on user/pw.
     * If a PIV/CAC is present in browser x509Username will be populated, meaning for CAC associated users
     * and user/pw/otp logins that hit ignore on PIV prompt. handleUserRegistration() is required during
     * for CAC assoications to add the UpdateX509 RA to the user profile which will call
     * requiredActionChallenge and then processAction. handleCertificateAttributes() performs attribute and
     * group assignments for CAC associated users. This should only happen for users with a present usercertificate
     * attribute. handleCertificateAttributes() depends on authenticated_via_x509 auth note from OCSP authflow
     * to be set to true.
     * @param context the {@link RequiredActionContext} containing the user and session details
     */
    @Override
    public void evaluateTriggers(final RequiredActionContext context) {
        LOGGER.debug("UpdateX509:evaluateTriggers invoked for user: {}", context.getUser().getUsername());

        try {
            String ignore = context.getAuthenticationSession().getAuthNote(IGNORE_X509);
            String x509Username = X509Tools.getX509Username(context);

            if (x509Username == null || (ignore != null && ignore.equals(TRUE_BOOLEAN_VALUE))) {
                LOGGER.debug("UpdateX509:evaluateTriggers: Not a x509 session. user: {} ignore: {}",
                      context.getUser().getUsername(), ignore);
                return;
            }

            final UserModel user = context.getUser();
            // No longer using ALLOW_X509 attribute
            final RealmModel realm = context.getRealm();

            // No longer using ALLOW_X509 attribute
            LOGGER.debug("UpdateX509:evaluateTriggers Retrieved X509 Username = {} from Realm {}",
                    x509Username, realm.getName());

            handleUserRegistration(context, user);
            handleOCSPConfiguration();
            handleCertificateAttributes(context, user, x509Username);

        } catch (Exception e) {
            LOGGER.error("UpdateX509:evaluateTriggers: Exception in evaluateTriggers for user {}: {}",
                    context.getUser().getUsername(), e.getMessage(), e);
        }
    }

    /**
     * Handles user registration with X509.
     *
     * @param context the {@link RequiredActionContext}
     * @param user the {@link UserModel} representing the user
     */
    private void handleUserRegistration(final RequiredActionContext context, final UserModel user) {
        if (!X509Tools.isX509Registered(context)) {
            LOGGER.debug("UpdateX509:evaluateTriggers: User is not registered with X509. Adding required action '{}'",
                         PROVIDER_ID);
            user.addRequiredAction(PROVIDER_ID);
        } else {
            LOGGER.debug("UpdateX509:evaluateTriggers: User is already registered with X509."
                          + " No required action needed.");
        }
    }

    /**
     * Handles OCSP configuration.
     */
    private void handleOCSPConfiguration() {
        final String ocspEnabled = Config.scope(OCSP_CONFIG_SCOPE).get(OCSP_ENABLED_KEY, DEFAULT_BOOLEAN_VALUE);
        LOGGER.info("UpdateX509:evaluateTriggers: {}.{} = {}", OCSP_CONFIG_SCOPE, OCSP_ENABLED_KEY, ocspEnabled);
    }

    /**
     * Handles certificate attributes extraction and setting.
     *
     * @param context the {@link RequiredActionContext}
     * @param user the {@link UserModel} representing the user
     * @param x509Username the X509 username
     * @throws GeneralSecurityException if a security exception occurs
     */
     private void handleCertificateAttributes(final RequiredActionContext context,
                                                final UserModel user,
                                                final String x509Username) throws GeneralSecurityException {
         final X509Certificate[] certChain = OCSPUtils.getCertificateChain(context);
         if (certChain == null || certChain.length == 0) {
             LOGGER.warn("UpdateX509:evaluateTriggers: No certificate chain found for user: {}", user.getUsername());
             return;
         }
         final X509Certificate cert = certChain[0];
         final RealmModel realm = context.getRealm();
         final KeycloakSession session = context.getSession();

         // Check and set the activeCAC attribute.
         // If the conditions are not met, exit early.
         if (!handleActiveCAC(context, user, x509Username)) {
             return;
         }

         // Continue with extraction and setting of other certificate attributes.
         extractAndSetCertificateAttributes(user, cert);

         // Continue with Group membership of il2/il4/il5 for being a CAC user
         handleGroupAssignments(user, realm, session);

     }

     /**
      * Gets the user certificate value from the user's attributes.
      *
      * @param context the current required action context
      * @param user the user model
      * @return the user's certificate value, or null if not found
      */
     private String getUserCertificateValue(final RequiredActionContext context, final UserModel user) {
         String userIdentityAttribute = null;
         String userCertValue = null;

         try {
             CommonConfig config = CommonConfig.getInstance(context.getSession(), context.getRealm());
             if (config != null) {
                 userIdentityAttribute = config.getUserIdentityAttribute(context.getRealm());
                 userCertValue = user.getFirstAttribute(userIdentityAttribute);
             }
         } catch (Exception e) {
             LOGGER.warn(COMMON_CONFIG_ERROR_MSG, e.getMessage());
         }

         return userCertValue;
     }

     /**
      * Gets the user active 509 attribute name.
      *
      * @param context the current required action context
      * @return the user active 509 attribute name, or "activeCAC" if not found
      */
     private String getUserActive509AttributeName(final RequiredActionContext context) {
         String userActive509Attribute = null;
         try {
             CommonConfig config = CommonConfig.getInstance(context.getSession(), context.getRealm());
             if (config != null) {
                 userActive509Attribute = config.getUserActive509Attribute();
             }
         } catch (Exception e) {
             LOGGER.warn(COMMON_CONFIG_ERROR_MSG, e.getMessage());
         }

         // Default to "activeCAC" if we couldn't get it from CommonConfig
         return userActive509Attribute != null ? userActive509Attribute : "activeCAC";
     }

     /**
      * Checks and sets the active CAC attribute based on OCSP configuration, the authenticated_via_x509 auth note,
      * and whether the user is registered with X509.
      *
      * @param context the current required action context
      * @param user the user model
      * @param x509Username the X509 username extracted from the certificate
      * @return true if the active CAC attribute was set successfully; false otherwise
      */
     private boolean handleActiveCAC(final RequiredActionContext context,
                                     final UserModel user,
                                     final String x509Username) {
         // Retrieve OCSP configuration
         final String ocspEnabled = Config.scope(OCSP_CONFIG_SCOPE).get(OCSP_ENABLED_KEY, DEFAULT_BOOLEAN_VALUE);
         final boolean ocspIsEnabled = TRUE_BOOLEAN_VALUE.equalsIgnoreCase(ocspEnabled);

         // Check for authenticated_via_x509 auth note
         final String authViaX509 = context.getAuthenticationSession().getAuthNote(AUTH_VIA_X509);
         final boolean isAuthenticatedViaX509 = TRUE_BOOLEAN_VALUE.equalsIgnoreCase(authViaX509);

         // Get user certificate value
         String userCertValue = getUserCertificateValue(context, user);

         // Check if certificate matches
         boolean certificateMatches = userCertValue == null || userCertValue.equals(x509Username);

         // Determine if we should set activeCAC
         boolean shouldSetActiveCAC;
         if (ocspIsEnabled) {
             shouldSetActiveCAC = x509Username != null && isAuthenticatedViaX509 && certificateMatches;
             LOGGER.debug("UpdateX509:evaluateTriggers: OCSP enabled, authenticated_via_x509: {},"
                    + " shouldSetActiveCAC: {}, userCertValue: {}, x509Username: {}",
                    authViaX509, shouldSetActiveCAC, userCertValue, x509Username);
         } else {
             shouldSetActiveCAC = x509Username != null && certificateMatches;
             LOGGER.debug("UpdateX509:evaluateTriggers: OCSP disabled, shouldSetActiveCAC: {},"
                    + " userCertValue: {}, x509Username: {}", shouldSetActiveCAC, userCertValue, x509Username);
         }

         if (!shouldSetActiveCAC) {
             LOGGER.info("UpdateX509:evaluateTriggers: Skipping required action. Conditions"
                           + " - username: {}, shouldSetActiveCAC: {}", x509Username, shouldSetActiveCAC);
             return false;
         }

        // Set the activeCAC attribute
        String userActive509Attribute = getUserActive509AttributeName(context);

        LOGGER.info("UpdateX509:evaluateTriggers: Setting user identity attribute '{}' for user '{}'",
            userActive509Attribute, user.getUsername());
        user.setSingleAttribute(userActive509Attribute, x509Username);

         return true;
     }

    /**
     * Extracts and sets certificate attributes for the user.
     *
     * @param user the {@link UserModel} representing the user
     * @param cert the {@link X509Certificate} certificate
     */
    private void extractAndSetCertificateAttributes(final UserModel user, final X509Certificate cert) {
        try {
            // Extract Subject DN
            final String subjectDN = cert.getSubjectX500Principal().getName();
            user.setSingleAttribute("x509_subject", subjectDN);
            LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_subject for user {}: {}",
                         user.getUsername(), subjectDN);

            // Extract Issuer DN
            final String issuerDN = cert.getIssuerX500Principal().getName();
            user.setSingleAttribute("x509_issuer", issuerDN);
            LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_issuer for user {}: {}",
                         user.getUsername(), issuerDN);

            // Extract and set Expiration Date
            final Date expirationDate = cert.getNotAfter();
            final ZonedDateTime zonedDateTime = expirationDate.toInstant().atZone(ZoneId.systemDefault());
            final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
            final String formattedExpirationDate = zonedDateTime.format(formatter);
            user.setSingleAttribute("x509_expiration_date", formattedExpirationDate);
            LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_expiration_date for user {}: {}",
                         user.getUsername(), formattedExpirationDate);

            // Extract PEM-encoded certificate
            final String pemCert = X509Tools.convertCertToPEM(cert);
            user.setSingleAttribute("x509_certificate", pemCert);
            LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_certificate for user {}.",
                         user.getUsername());

            // Extract UPN using X509Tools
            final String upn = X509Tools.extractUPN(cert);
            if (upn != null) {
                user.setSingleAttribute("x509_upn", upn);
                LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_upn for user {}: {}",
                             user.getUsername(), upn);
                 // Also store just the 16-digit portion as x509_piv (before @mil)
                 if (upn.contains("@")) {
                     String pivId = upn.split("@")[0];
                     user.setSingleAttribute("x509_piv", pivId);
                     LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_piv for user {}: {}",
                             user.getUsername(), pivId);
                 }
            } else {
                LOGGER.warn("UpdateX509:evaluateTriggers: UPN extraction failed for user {}",
                            user.getUsername());
            }

            // Extract Policy ID using the existing method
            final String policyId = X509Tools.getCertificatePolicyId(cert,
                                            POLICY_CERTIFICATE_POLICY_POS, POLICY_IDENTIFIER_POS);
            if (policyId != null) {
                user.setSingleAttribute("x509_policy_id", policyId);
                LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_policy_id for user {}: {}",
                             user.getUsername(), policyId);
            } else {
                LOGGER.warn("UpdateX509:evaluateTriggers: Policy ID extraction failed for user {}",
                            user.getUsername());
            }

            // Extract URN using X509Tools
            final String urn = X509Tools.extractURN(cert);
            if (urn != null) {
                user.setSingleAttribute("x509_urn", urn);
                LOGGER.debug("UpdateX509:evaluateTriggers: Set x509_urn for user {}: {}",
                             user.getUsername(), urn);
            } else {
                LOGGER.warn("UpdateX509:evaluateTriggers: URN extraction failed for user {}",
                            user.getUsername());
            }
        } catch (final CertificateEncodingException e) {
            LOGGER.error("UpdateX509:evaluateTriggers: Certificate encoding exception for user {}: {}",
                         user.getUsername(), e.getMessage(), e);
        } catch (final IOException e) {
            LOGGER.error("UpdateX509:evaluateTriggers: IO exception while processing certificate for user {}: {}",
                         user.getUsername(), e.getMessage(), e);
        }
    }

    /**
     * Handles group assignments for the user.
     *
     * @param user the {@link UserModel} representing the user
     * @param realm the {@link RealmModel} representing the realm
     * @param session the {@link KeycloakSession} session
     */
    private void handleGroupAssignments(final UserModel user, final RealmModel realm, final KeycloakSession session) {
        LOGGER.debug("UpdateX509:evaluateTriggers: Retrieving auto-join groups for X509 in Realm {}",
                     realm.getName());
        CommonConfig.getInstance(session, realm)
            .getAutoJoinGroupX509()
            .forEach(group -> {
                if (group != null) {
                    if (!isDirectMemberOfGroup(user, group)) {
                        LOGGER.info("UpdateX509:evaluateTriggers: Joining user '{}' to group '{}' in Realm '{}'",
                                    user.getUsername(), group.getName(), realm.getName());
                        try {
                            user.joinGroup(group);
                        } catch (final Exception e) {
                            LOGGER.error("UpdateX509:evaluateTriggers: Failed to join user '{}' to group '{}'"
                                         + " in Realm '{}': {}",
                                         user.getUsername(), group.getName(),
                                         realm.getName(), e.getMessage(), e);
                        }
                    } else {
                        LOGGER.debug("UpdateX509:evaluateTriggers: User '{}' is already a member of group '{}'."
                                      + " Skipping.", user.getUsername(), group.getName());
                    }
                } else {
                    LOGGER.error("UpdateX509:evaluateTriggers: Encountered null group"
                                  + " while attempting to join user '{}'. Skipping.", user.getUsername());
                }
            });
    }

    /**
     * Presents a required action challenge to the user for X.509 certificate confirmation.
     *
     * @param context the {@link RequiredActionContext} containing the user and session details
     */
    @Override
    public void requiredActionChallenge(final RequiredActionContext context) {
        LOGGER.debug("UpdateX509:requiredActionChallenge invoked for user: {}",
                     context.getUser().getUsername());

        try {
            final MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
            formData.add("username",
                                    context.getUser() != null ? context.getUser().getUsername() : "unknown user");
            formData.add("subjectDN", X509Tools.getX509Username(context));
            formData.add("isUserEnabled", "true");

            LOGGER.debug("UpdateX509:requiredActionChallenge: Setting form data for challenge - {}",
                         formData);
            context.form().setFormData(formData);

            final Response challenge = context.form().createX509ConfirmPage();
            LOGGER.debug("UpdateX509:requiredActionChallenge: Sending challenge response for X509 confirmation.");
            context.challenge(challenge);

        } catch (final Exception e) {
            LOGGER.error("UpdateX509:requiredActionChallenge: Exception in requiredActionChallenge for user {}: {}",
                         context.getUser().getUsername(), e.getMessage(), e);
            context.failure();
        }
    }

    /**
     * Processes the user's action for X.509 certificate confirmation.
     *
     * @param context the {@link RequiredActionContext} containing the user and session details
     */
    @Override
    public void processAction(final RequiredActionContext context) {
        // Early null check for the user
        UserModel user = context.getUser();
        if (user == null) {
            LOGGER.error("UpdateX509:processAction: No user present in context; aborting.");
            context.failure();
            return;
        }

        LOGGER.debug("UpdateX509:processAction invoked for user: {}", user.getUsername());

        try {
            final MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            LOGGER.debug("UpdateX509:processAction: Received form data - {}", formData);

            if (formData.containsKey("cancel")) {
                handleCancellation(context);
                return;
            }

            final String x509Username = X509Tools.getX509Username(context);
            final RealmModel realm = context.getRealm();
            final KeycloakSession session = context.getSession();

            LOGGER.debug("UpdateX509:processAction: Retrieved X509 Username from form - {}", x509Username);

            // Assign attributes and autoJoinGroups inside handleOCSPProcessing if OCSP passes
            handleOCSPProcessing(context, x509Username, realm, session);

            LOGGER.debug("UpdateX509:processAction: Processing action completed successfully for user: {}",
                context.getUser().getUsername());
            context.success();

        } catch (final GeneralSecurityException e) {
            LOGGER.error("UpdateX509:processAction: OCSP Check encountered an error for user {}: {}",
                         user.getUsername(), e.getMessage(), e);
            LOGGER.debug("UpdateX509:processAction: Certificate validation failed for user: {}", user.getUsername());
            context.failure();
        } catch (final Exception e) {
            LOGGER.error("UpdateX509:processAction: Exception in processAction for user {}: {}",
                         user.getUsername(), e.getMessage(), e);
            context.failure();
        }
    }


    /**
     * Handles user cancellation during X509 confirmation.
     *
     * @param context the {@link RequiredActionContext}
     */
    private void handleCancellation(final RequiredActionContext context) {
        LOGGER.info("UpdateX509:processAction: User canceled the X509 confirmation.");
        context.getAuthenticationSession().setAuthNote(IGNORE_X509, TRUE_BOOLEAN_VALUE);
        LOGGER.debug("UpdateX509:processAction: Set IGNORE_X509 to true for user: {}",
                     context.getUser().getUsername());
        context.success();
    }

    /**
     * Handles OCSP processing during action.
     *
     * @param context the {@link RequiredActionContext}
     * @param x509Username the X509 username
     * @param realm the {@link RealmModel} representing the realm
     * @param session the {@link KeycloakSession} session
     * @throws GeneralSecurityException if a security exception occurs
     */
    private void handleOCSPProcessing(final RequiredActionContext context,
                                                              final String x509Username,
                                                              final RealmModel realm,
                                                              final KeycloakSession session)
                                                              throws GeneralSecurityException {
        final String ocspEnabled = Config.scope(OCSP_CONFIG_SCOPE).get(OCSP_ENABLED_KEY, DEFAULT_BOOLEAN_VALUE);
        LOGGER.info("UpdateX509:processAction: {}.{} set to: {}", OCSP_CONFIG_SCOPE, OCSP_ENABLED_KEY, ocspEnabled);

        final UserModel user = context.getUser();
        final String userIdentityAttribute = CommonConfig.getInstance(session, realm)
                                                   .getUserIdentityAttribute(realm);
        final String userActive509Attribute = CommonConfig.getInstance(session, realm)
                                                 .getUserActive509Attribute();

        final X509Certificate[] certChain = OCSPUtils.getCertificateChain(context);
        if (certChain == null || certChain.length == 0) {
            LOGGER.warn("UpdateX509:processAction: No certificate chain found for user: {}",
                        user.getUsername());
            context.failure();
            context.getEvent().error("invalid_client_credentials");
            return;
        }

        final X509Certificate cert = certChain[0];

        // Check for authenticated_via_x509 auth note
        final String authViaX509 = context.getAuthenticationSession().getAuthNote(AUTH_VIA_X509);
        boolean ocspPass = false;

        if (TRUE_BOOLEAN_VALUE.equalsIgnoreCase(ocspEnabled)) {
            if (authViaX509 != null) {
                // For new configuration, check if authenticated_via_x509 is set to true
                LOGGER.debug("UpdateX509:processAction: Using new OCSP authenticator configuration");
                ocspPass = TRUE_BOOLEAN_VALUE.equalsIgnoreCase(authViaX509);

                if (ocspPass) {
                    LOGGER.debug("UpdateX509:processAction: authenticated_via_x509 is set to true"
                            + " by OCSPCheckAuthenticator");
                } else {
                    LOGGER.warn("UpdateX509:processAction: authenticated_via_x509 is not set to true");
                }
            } else {
                // For old configuration, perform OCSP check directly
                LOGGER.debug("UpdateX509:processAction: Using old configuration, performing OCSP check");
                ocspPass = performOCSPCheck(context, user, cert, session);
            }
        } else {
            // OCSP is disabled
            LOGGER.debug("UpdateX509:processAction: OCSP is disabled. Skipping OCSP check for user: {}",
                         user.getUsername());
            // Set authenticated_via_x509 auth note
            context.getAuthenticationSession().setAuthNote(AUTH_VIA_X509, TRUE_BOOLEAN_VALUE);
            LOGGER.debug("UpdateX509:processAction: Set authenticated_via_x509 to true for user: {}",
                         user.getUsername());
            // Auto pass on OCSP if set to disable.
            ocspPass = true;
        }

        // Only assign groups if OCSP check passes
        if (ocspPass) {
          setUserCACAttributes(user, userIdentityAttribute, userActive509Attribute, x509Username);
          handleGroupAssignmentsAfterProcessing(context, realm, session);
        } else {
            LOGGER.warn("UpdateX509:processAction: OCSP check failed for user: {}; "
                    + "skipping certificate and group assignments.", x509Username);
        }
    }

    /**
     * Performs an OCSP check for the given user and updates the user attributes based on the result.
     * Returns {@code true} if the OCSP check passes, and {@code false} otherwise.
     *
     * @param context the {@link RequiredActionContext} for the current action
     * @param user the {@link UserModel} representing the user
     * @param cert the {@link X509Certificate} used for the OCSP check
     * @param session the {@link KeycloakSession} for the current session
     * @return {@code true} if the OCSP check passes, {@code false} if it fails
     * @throws GeneralSecurityException if a security exception occurs during the OCSP check
     */
     private boolean performOCSPCheck(final RequiredActionContext context, final UserModel user,
                                      final X509Certificate cert, final KeycloakSession session)
                                      throws GeneralSecurityException {
         LOGGER.debug("UpdateX509:processAction: OCSP is enabled. Proceeding with OCSP check for user: {}",
                      user.getUsername());

         final OCSPUtils.OCSPResult ocspResult = OCSPUtils.performOCSPCheck(session, new X509Certificate[]{cert});

         if (ocspResult.isOCSPGood()) {
             LOGGER.debug("UpdateX509:processAction: OCSP check passed for user: {}", user.getUsername());
             context.getAuthenticationSession().setAuthNote(AUTH_VIA_X509, TRUE_BOOLEAN_VALUE);
             LOGGER.debug("UpdateX509:processAction: Set authenticated_via_x509 to true for user: {}",
                    user.getUsername());
             return true;
         } else {
             LOGGER.warn("UpdateX509:processAction: OCSP check failed for user: {}. Reason: {}",
                         user.getUsername(), ocspResult.getFailureReason());
             LOGGER.debug("UpdateX509:processAction: Certificate validation failed for user: {}", user.getUsername());
             context.failure();
             return false;
         }
     }

    /**
     * Sets user identity attributes.
     *
     * @param user the {@link UserModel} representing the user
     * @param userIdentityAttribute the user identity attribute
     * @param userActive509Attribute the user active 509 attribute
     * @param x509Username the X509 username
     */
    private void setUserCACAttributes(final UserModel user, final String userIdentityAttribute,
                                   final String userActive509Attribute, final String x509Username) {
        LOGGER.info("UpdateX509:processAction: Setting user identity attribute '{}' for user '{}'",
                    userIdentityAttribute, user.getUsername());
        user.setSingleAttribute(userIdentityAttribute, x509Username);

        LOGGER.info("UpdateX509:processAction: Setting user active CAC attribute '{}' for user '{}'",
                    userActive509Attribute, user.getUsername());
        user.setSingleAttribute(userActive509Attribute, x509Username);
    }

    /**
     * Handles group assignments after processing.
     *
     * @param context the {@link RequiredActionContext}
     * @param realm the {@link RealmModel} representing the realm
     * @param session the {@link KeycloakSession} session
     */
    private void handleGroupAssignmentsAfterProcessing(final RequiredActionContext context,
                                                       final RealmModel realm,
                                                       final KeycloakSession session) {
        LOGGER.debug("UpdateX509:processAction: Retrieving auto-join groups for X509.");
        CommonConfig.getInstance(session, realm)
            .getAutoJoinGroupX509()
            .forEach(group -> {
                if (group != null) {
                    if (!isDirectMemberOfGroup(context.getUser(), group)) {
                        LOGGER.info("UpdateX509:processAction: Joining user '{}' to group '{}'",
                                    context.getUser().getUsername(), group.getName());
                        try {
                            context.getUser().joinGroup(group);
                        } catch (final Exception e) {
                            LOGGER.error("UpdateX509:processAction: Failed to join user '{}' to group '{}': {}",
                                         context.getUser().getUsername(), group.getName(),
                                         e.getMessage(), e);
                        }
                    } else {
                        LOGGER.debug("UpdateX509:processAction: User '{}' is already a member of group '{}'. Skipping.",
                                     context.getUser().getUsername(), group.getName());
                    }
                } else {
                    LOGGER.error("UpdateX509:processAction: Encountered null group while attempting to join user"
                                  + " '{}'. Skipping.", context.getUser().getUsername());
                }
            });
    }


    /**
     * Returns the display text for this required action.
     *
     * @return the display text as a {@link String}
     */
    @Override
    public String getDisplayText() {
        return "Update X509";
    }

    /**
     * Indicates whether this required action is a one-time action.
     *
     * @return {@code true}, indicating that the action is performed only once
     */
    @Override
    public boolean isOneTimeAction() {
        return true;
    }

    /**
     * Creates a new instance of the required action provider.
     *
     * @param session the {@link KeycloakSession} for the current session
     * @return the required action provider instance
     */
    @Override
    public RequiredActionProvider create(final KeycloakSession session) {
        LOGGER.debug("UpdateX509: Creating RequiredActionProvider instance.");
        return this;
    }

    /**
     * Initializes the required action provider with the given configuration.
     *
     * @param config the {@link Config.Scope} for the provider configuration
     */
    @Override
    public void init(final Config.Scope config) {
        LOGGER.debug("UpdateX509: init called with config scope: {}", config);
        // No implementation needed or implement based on your needs
    }

    /**
     * Performs post-initialization tasks for the required action provider.
     *
     * @param factory the {@link KeycloakSessionFactory} for creating sessions
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        LOGGER.debug("UpdateX509: postInit called.");
        // No implementation needed or implement based on your needs
    }

    /**
     * Closes the required action provider and releases any resources, if necessary.
     */
    @Override
    public void close() {
        LOGGER.debug("UpdateX509: close called.");
        // Cleanup resources if necessary
    }

    /**
     * Returns the unique identifier for this required action provider.
     *
     * @return the provider ID as a {@link String}
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
