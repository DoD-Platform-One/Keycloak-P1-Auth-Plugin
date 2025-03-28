package dod.p1.keycloak.registration;

import static dod.p1.keycloak.common.CommonConfig.getInstance;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationUserCreation;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import dod.p1.keycloak.common.CommonConfig;
import org.keycloak.services.x509.X509ClientCertificateLookup;


public class RegistrationValidation extends RegistrationUserCreation {
    /** Logger. **/
    private static final Logger LOGGER = LogManager.getLogger(RegistrationValidation.class);

    /**
     * constant for logging message.
     */
    private static final String LOGGING_USER_TEXT = " user ";
    /**
     * get user by email constant.
     */
    private static final String EMAIL = "email";

    /**
     * Provider ID.
     */
    public static final String PROVIDER_ID = "registration-validation-action";

    /**
     * Name for form element containing the user affiliation value.
     */
    public static final String USER_ATTRIBUTES_AFFILIATION = "user.attributes.affiliation";

    /**
     * Requirement choices.
     */
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED };

    /**
     * The minimum length of username.
     */
    private static final int MIN_USER_NAME_LENGTH = 3;

    /**
     * The max length of username.
     */
    private static final int MAX_USER_NAME_LENGTH = 22;


    /**
     * Sets requirements for post registration actions by user for completion of user registration.
     * @param user contains user information and allows for updating of user attributes
     * @param x509Username the username taken from a CAC card if present
     */
    private static void bindRequiredActions(final UserModel user, final String x509Username) {
        // Default actions for all users
        user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
        user.addRequiredAction("TERMS_AND_CONDITIONS");

        LOGGER.info("x509Username: {}", x509Username);
        if (x509Username == null) {
            // This user must configure MFA for their login
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    private static void processX509UserAttribute(
        final KeycloakSession session,
        final RealmModel realm,
        final UserModel user,
        final String x509Username) {
        if (x509Username != null) {
            // Bind the X509 attribute to the user
            user.setSingleAttribute(getInstance(session, realm).getUserIdentityAttribute(realm), x509Username);
            // Bind the active509 attribute to the user
            user.setSingleAttribute(getInstance(session, realm).getUserActive509Attribute(), x509Username);
        }
    }

    /**
     * Join a user to a single group, handling null checks and exceptions.
     *
     * @param user the user to join to the group
     * @param group the group to join
     * @param logMessages log message templates for different scenarios
     */
    private static void joinUserToGroup(
            final UserModel user,
            final org.keycloak.models.GroupModel group,
            final LogMessages logMessages) {
        if (group == null) {
            CommonConfig.LOGGER_COMMON.warn(logMessages.getEncounterNullGroup(), user.getUsername());
            return;
        }
        CommonConfig.LOGGER_COMMON.info(logMessages.getJoiningUser(), user.getUsername(), group.getName());
        try {
            user.joinGroup(group);
        } catch (Exception e) {
            CommonConfig.LOGGER_COMMON.error(logMessages.getFailedToJoinUser(),
                    user.getUsername(), group.getName(), e);
        }
    }

    /**
     * Container for log message templates.
     */
    private static class LogMessages {
        /** Message template for joining a user to a group. */
        private final String joiningUser;
        /** Message template for encountering a null group. */
        private final String encounterNullGroup;
        /** Message template for failing to join a user to a group. */
        private final String failedToJoinUser;

        /**
         * Constructor for LogMessages.
         *
         * @param joiningUserTemplate joining user log message template
         * @param encounterNullGroupTemplate null group log message template
         * @param failedToJoinUserTemplate failed join log message template
         */
        LogMessages(final String joiningUserTemplate, final String encounterNullGroupTemplate,
                final String failedToJoinUserTemplate) {
            this.joiningUser = joiningUserTemplate;
            this.encounterNullGroup = encounterNullGroupTemplate;
            this.failedToJoinUser = failedToJoinUserTemplate;
        }

        /**
         * Get the joining user message template.
         * @return the joining user message template
         */
        public String getJoiningUser() {
            return joiningUser;
        }

        /**
         * Get the encounter null group message template.
         * @return the encounter null group message template
         */
        public String getEncounterNullGroup() {
            return encounterNullGroup;
        }

        /**
         * Get the failed to join user message template.
         * @return the failed to join user message template
         */
        public String getFailedToJoinUser() {
            return failedToJoinUser;
        }
    }

    /**
     * Handle X509 user group assignments.
     *
     * @param user the user model
     * @param x509Username the X509 username
     * @param config the common configuration
     * @param logMessages log message templates
     */
    private static void handleX509UserGroups(
            final UserModel user,
            final String x509Username,
            final CommonConfig config,
            final LogMessages logMessages) {
        CommonConfig.LOGGER_COMMON.info("{} {} / {} found with X509: {}",
                LOGGING_USER_TEXT, user.getId(), user.getUsername(), x509Username);
        config.getAutoJoinGroupX509().forEach(group ->
            joinUserToGroup(user, group, logMessages)
        );
    }

    /**
     * Handle email domain matched user group assignments.
     *
     * @param user the user model
     * @param email the user's email
     * @param config the common configuration
     * @param logMessages log message templates
     */
    private static void handleEmailMatchedGroups(
            final UserModel user,
            final String email,
            final CommonConfig config,
            final LogMessages logMessages) {
        CommonConfig.LOGGER_COMMON.info("{} {} / {}: Email found in whitelist",
                LOGGING_USER_TEXT, user.getUsername(), email);
        config.getEmailMatchAutoJoinGroup()
              .filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith))
              .forEach(match -> {
                  CommonConfig.LOGGER_COMMON.info("Adding user {} to group(s): {}",
                          user.getUsername(), match.getGroups());
                  match.getGroupModels().forEach(group ->
                      joinUserToGroup(user, group, logMessages)
                  );
              });
    }

    /**
     * Handle non-matched email domain user group assignments.
     *
     * @param user the user model
     * @param email the user's email
     * @param config the common configuration
     * @param logMessages log message templates
     */
    private static void handleNonMatchedEmailGroups(
            final UserModel user,
            final String email,
            final CommonConfig config,
            final LogMessages logMessages) {
        CommonConfig.LOGGER_COMMON.info("{} {} / {}: Email Not found in whitelist",
                LOGGING_USER_TEXT, user.getUsername(), email);
        config.getNoEmailMatchAutoJoinGroup().forEach(group ->
            joinUserToGroup(user, group, logMessages)
        );
        user.setSingleAttribute("public-registrant", "true");
    }

    /**
     * Join a valid user to appropriate groups based on X509 status and email domain.
     *
     * @param context the form context
     * @param user the user model
     * @param x509Username the X509 username if available, null otherwise
     */
    private static void joinValidUserToGroups(
            final FormContext context,
            final UserModel user,
            final String x509Username) {
        String email = user.getEmail().toLowerCase();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        CommonConfig config = CommonConfig.getInstance(session, realm);
        LogMessages logMessages = new LogMessages(
                "Joining user {} to group: {}",
                "Encountered null group for user: {}",
                "Failed to join user {} to group: {}");

        // Handle X509 users
        if (x509Username != null) {
            handleX509UserGroups(user, x509Username, config, logMessages);
            return;
        }

        // For non-X509 users, check email domain matches
        long domainMatchCount = config.getEmailMatchAutoJoinGroup()
                .filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith))
                .count();

        if (domainMatchCount > 0) {
            handleEmailMatchedGroups(user, email, config, logMessages);
        } else {
            handleNonMatchedEmailGroups(user, email, config, logMessages);
        }
    }


    /**
     * Add a custom user attribute (mattermostid) to enable direct mattermost <>
     * keycloak auth on mattermost teams edition.
     *
     * @param formData The user registration form data
     * @param user the Keycloak user object
     */
    private static void generateUniqueStringIdForMattermost(
        final MultivaluedMap<String, String> formData,
        final UserModel user) {
        String email = formData.getFirst(Validation.FIELD_EMAIL);

        byte[] encodedEmail;
        int emailByteTotal = 0;
        Date today = new Date();

        encodedEmail = email.getBytes(StandardCharsets.US_ASCII);
        for (byte b : encodedEmail) {
            emailByteTotal += b;
        }

        SimpleDateFormat formatDate = new SimpleDateFormat("yyDHmsS");

        user.setSingleAttribute("mattermostid", formatDate.format(today) + emailByteTotal);
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public void success(final FormContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String x509Username = X509Tools.getX509Username(context);

        generateUniqueStringIdForMattermost(formData, user);
        joinValidUserToGroups(context, user, x509Username);
        processX509UserAttribute(session, realm, user, x509Username);
        bindRequiredActions(user, x509Username);
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public void buildPage(final FormContext context, final LoginFormsProvider form) {
        String x509Username = X509Tools.getX509Username(context);
        if (x509Username != null) {
            form.setAttribute("cacIdentity", x509Username);
            try {
                KeycloakSession kcSession = context.getSession();
                X509ClientCertificateLookup provider = kcSession.getProvider(X509ClientCertificateLookup.class);
                final X509Certificate[] certs = provider.getCertificateChain(context.getHttpRequest());
                if (certs.length > 0) {
                    form.setFormData(buildFormFromX509(context, certs));
                }
                LOGGER.info(X509Tools.getX509IdentityFromCertChain(context.getHttpRequest().
                        getClientCertificateChain(), kcSession, context.getRealm(),
                        context.getAuthenticationSession()));
            } catch (GeneralSecurityException e) {
                LOGGER.error("Unable to read certificate chain. Reg form won't be filled by CAC: {}", e.getMessage());
            }
        }
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public String getDisplayType() {
        return "Platform One Registration Validation";
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public boolean isConfigurable() {
        return false;
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    /**
     * Validate required user profile fields.
     *
     * @param formData the form data
     * @param errors the list of errors to add to
     */
    private void validateRequiredFields(
            final MultivaluedMap<String, String> formData,
            final List<FormMessage> errors) {
        // Check required fields
        if (Validation.isBlank(formData.getFirst(RegistrationPage.FIELD_FIRST_NAME))) {
            errors.add(new FormMessage(RegistrationPage.FIELD_FIRST_NAME, Messages.MISSING_FIRST_NAME));
        }

        if (Validation.isBlank(formData.getFirst(RegistrationPage.FIELD_LAST_NAME))) {
            errors.add(new FormMessage(RegistrationPage.FIELD_LAST_NAME, Messages.MISSING_LAST_NAME));
        }

        if (Validation.isBlank(formData.getFirst(USER_ATTRIBUTES_AFFILIATION))) {
            errors.add(new FormMessage(USER_ATTRIBUTES_AFFILIATION, "Please specify your organization affiliation."));
        }

        if (Validation.isBlank(formData.getFirst("user.attributes.rank"))) {
            errors.add(new FormMessage("user.attributes.rank", "Please specify your rank or choose n/a."));
        }

        if (Validation.isBlank(formData.getFirst("user.attributes.organization"))) {
            errors.add(new FormMessage("user.attributes.organization", "Please specify your organization."));
        }
    }

    /**
     * Validate email fields.
     *
     * @param context the validation context
     * @param formData the form data
     * @param errors the list of errors to add to
     * @param email the email address
     * @param emailConfirm the confirmation email address
     * @return the event error if email is in use, or null
     */
    private String validateEmailFields(
            final ValidationContext context,
            final MultivaluedMap<String, String> formData,
            final List<FormMessage> errors,
            final String email,
            final String emailConfirm) {
        String eventError = null;

        if (Validation.isBlank(email) || !Validation.isEmailValid(email)) {
            context.getEvent().detail(Details.EMAIL, email);
            errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL,
                    "Please check your email address, it seems to be invalid"));
        }

        if (Validation.isBlank(emailConfirm) || !Validation.isEmailValid(emailConfirm) || !email.equals(emailConfirm)) {
            errors.add(new FormMessage("confirmEmail",
                    "Email addresses do not match. Please try again."));
        }

        if (context.getSession().users().getUserByEmail(context.getRealm(), email) != null) {
            eventError = Errors.EMAIL_IN_USE;
            formData.remove(EMAIL);
            context.getEvent().detail(EMAIL, email);
            errors.add(new FormMessage(EMAIL, Messages.EMAIL_EXISTS));
        }

        return eventError;
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public void validate(final ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        String username = formData.getFirst(Validation.FIELD_USERNAME);
        String email = formData.getFirst(Validation.FIELD_EMAIL);
        String emailConfirm = formData.getFirst("confirmEmail");
        String eventError = Errors.INVALID_REGISTRATION;

        // Check for bot-like activity
        String location = formData.getFirst("user.attributes.location");
        if (Validation.isBlank(location) || !location.equals("42")) {
            errors.add(new FormMessage("Bot-like activity detected, try disabling auto form filling"));
        }

        // Validate username
        if (Validation.isBlank(username)) {
            errors.add(new FormMessage(Validation.FIELD_USERNAME, Messages.MISSING_USERNAME));
        }
        mattermostUsernameValidation(errors, username);

        // Validate required fields
        validateRequiredFields(formData, errors);

        // Check if X509 is already registered
        if (X509Tools.getX509Username(context) != null && X509Tools.isX509Registered(context)) {
            errors.add(new FormMessage(null, "Sorry, this CAC seems to already be registered."));
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            return;
        }

        // Validate email fields
        String emailError = validateEmailFields(context, formData, errors, email, emailConfirm);
        if (emailError != null) {
            eventError = emailError;
        }

        // Process validation results
        if (!errors.isEmpty()) {
            context.error(eventError);
            context.validationError(formData, errors);
        } else {
            context.success();
        }
    }

    /**
     * Validates the mattermost username.
     * @param errors - List of FormMessage objects for storing error messages that will be displayed on front end.
     * @param username - The Mattermost username to validate
     */
    protected void mattermostUsernameValidation(final List<FormMessage> errors, final String username) {
        if (!Validation.isBlank(username)) {
            if (!username.matches("[A-Za-z0-9-_.]+")) {
                errors.add(new FormMessage(Validation.FIELD_USERNAME,
                        "Username can only contain alphanumeric, underscore, hyphen and period characters."));
            }

            if (!Character.isLetter(username.charAt(0))) {
                errors.add(new FormMessage(Validation.FIELD_USERNAME, "Username must begin with a letter."));
            }

            if (username.length() < MIN_USER_NAME_LENGTH || username.length() > MAX_USER_NAME_LENGTH) {
                errors.add(new FormMessage(Validation.FIELD_USERNAME, "Username must be between 3 to 22 characters."));
            }
        }
    }

    /**
     *
     * @param context - allows access to form data for population from CAC valus
     * @param certs - the CAC certificates which contain pertinent user information
     * @return a MultiValuedMap containing CAC data to display in form
     */
     protected MultivaluedMap<String, String> buildFormFromX509(final FormContext context,
                                                                final X509Certificate[] certs) {
         String x509Username = X509Tools.getX509Username(context);
         MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
         MultivaluedMap<String, String> retFormData = new MultivaluedHashMap<>(formData);

         try {
             if (certs == null || certs.length == 0) {
                 LOGGER.error("No certificates found in the request.");
                 return retFormData;
             }

             String subjectDN = certs[0].getSubjectX500Principal().getName();
             LOGGER.debug("Subject DN: {}", subjectDN);

             String[] subjectNameArray = subjectDN.split(",");

             // Validate that subjectNameArray has at least 2 elements
             if (subjectNameArray.length < 2) {
                 LOGGER.error("Unexpected Subject DN format: {}", subjectDN);
                 return retFormData;
             }

             // Extracting first name and last name
             String[] cnParts = subjectNameArray[0].split("\\.");
             if (cnParts.length < 2) {
                 LOGGER.error("Unexpected CN format in Subject DN: {}", subjectNameArray[0]);
                 return retFormData;
             }

             String firstName = cnParts[1].trim().toLowerCase();
             String lastName = cnParts[0].replace("CN=", "").trim().toLowerCase();

             // Extracting affiliation
             String affiliationPart = subjectNameArray[1].trim();
             if (!affiliationPart.startsWith("OU=")) {
                 LOGGER.error("Unexpected OU format in Subject DN: {}", affiliationPart);
                 return retFormData;
             }
             String affiliation = affiliationPart.replace("OU=", "").trim();
             String translatedAffiliation = X509Tools.translateAffiliationShortName(affiliation);

             // Populate form data
             retFormData.add("cacIdentity", x509Username);
             retFormData.add(RegistrationPage.FIELD_FIRST_NAME, StringUtils.capitalize(firstName));
             retFormData.add(RegistrationPage.FIELD_LAST_NAME, StringUtils.capitalize(lastName));
             retFormData.add(USER_ATTRIBUTES_AFFILIATION, translatedAffiliation);
             LOGGER.debug("Form Data after X509 processing: {}", retFormData);
         } catch (Exception e) {
             LOGGER.error("Error processing X509 certificate: ", e);
         }

         return retFormData;
     }
}
