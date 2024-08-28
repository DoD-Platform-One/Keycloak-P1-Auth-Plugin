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
        // Make GS-15 Matt and the Cyber Humans happy
        user.addRequiredAction("TERMS_AND_CONDITIONS");
        LOGGER.info("x509Username: {}", x509Username);
        if (x509Username == null) {
            //Non CAC users will require email verification but not CAC users
            user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
            // This user must configure MFA for their login
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        } else {
            //Allow CAC users to bypass email verification step
            LOGGER.debug("Setting CAC user emailVerified to true.");
            user.setEmailVerified(true);
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
        }
    }

    private static void joinValidUserToGroups(
        final FormContext context,
        final UserModel user,
        final String x509Username) {
        String email = user.getEmail().toLowerCase();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        CommonConfig config = getInstance(session, realm);

        long domainMatchCount = config.getEmailMatchAutoJoinGroup()
                .filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith)).count();

        // Sonarqube was complaining about this strings
        String joiningUserLog = "Joining user {} to group: {}";
        String encounterNullGroupLog = "Encountered null group for user: {}";
        String failedToJoinUserLog = "Failed to join user {} to group: {}";

        // In each of the next 3 checks we will have to make sure that the group is null.
        // Sometimes for some reason it is and this will cause an exception that will make
        // keycloak end up in a limbo state. The following conditions takes care of it and now
        // keycloak can continue with account creation and assignment without getting into limbo state.
        if (x509Username != null) {
            // User is a X509 user - Has a CAC
            CommonConfig.LOGGER_COMMON.info("{} {} / {} found with X509: {}",
                    LOGGING_USER_TEXT, user.getId(), user.getUsername(), x509Username);
            config.getAutoJoinGroupX509().forEach(group -> {
                if (group != null) {
                    CommonConfig.LOGGER_COMMON.info(joiningUserLog, user.getUsername(), group.getName());
                    try {
                        user.joinGroup(group);
                    } catch (Exception e) {
                        CommonConfig.LOGGER_COMMON.error(failedToJoinUserLog,
                                user.getUsername(), group.getName(), e);
                    }
                } else {
                    CommonConfig.LOGGER_COMMON.warn(encounterNullGroupLog, user.getUsername());
                }
            });
        } else {
            if (domainMatchCount != 0) {
                // User is not a X509 user but is in the whitelist
                CommonConfig.LOGGER_COMMON.info("{} {} / {}: Email found in whitelist",
                        LOGGING_USER_TEXT, user.getUsername(), email);
                config.getEmailMatchAutoJoinGroup()
                      .filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith))
                      .forEach(match -> {
                          CommonConfig.LOGGER_COMMON.info("Adding user {} to group(s): {}",
                                  user.getUsername(), match.getGroups());
                          match.getGroupModels().forEach(group -> {
                              if (group != null) {
                                  CommonConfig.LOGGER_COMMON.info(joiningUserLog, user.getUsername(), group.getName());
                                  try {
                                      user.joinGroup(group);
                                  } catch (Exception e) {
                                      CommonConfig.LOGGER_COMMON.error(failedToJoinUserLog,
                                              user.getUsername(), group.getName(), e);
                                  }
                              } else {
                                  CommonConfig.LOGGER_COMMON.warn(encounterNullGroupLog, user.getUsername());
                              }
                          });
                      });
            } else {
                // User is not a X509 user or in whitelist
                CommonConfig.LOGGER_COMMON.info("{} {} / {}: Email Not found in whitelist",
                        LOGGING_USER_TEXT, user.getUsername(), email);
                config.getNoEmailMatchAutoJoinGroup().forEach(group -> {
                    if (group != null) {
                        CommonConfig.LOGGER_COMMON.info(joiningUserLog, user.getUsername(), group.getName());
                        try {
                            user.joinGroup(group);
                        } catch (Exception e) {
                            CommonConfig.LOGGER_COMMON.error(failedToJoinUserLog,
                                    user.getUsername(), group.getName(), e);
                        }
                    } else {
                        CommonConfig.LOGGER_COMMON.warn(encounterNullGroupLog, user.getUsername());
                    }
                });
                user.setSingleAttribute("public-registrant", "true");
            }
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
                LOGGER.error(String.format("Unable to read certificate chain. Reg form won't be filled by CAC. %1s$",
                        e));
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

        String location = formData.getFirst("user.attributes.location");
        if (Validation.isBlank(location) || !location.equals("42")) {
            errors.add(new FormMessage("Bot-like activity detected, try disabling auto form filling"));
        }

        if (Validation.isBlank(username)) {
            errors.add(new FormMessage(Validation.FIELD_USERNAME, Messages.MISSING_USERNAME));
        }

        // Username validation based on Mattermost requirements.
        mattermostUsernameValidation(errors, username);

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

        if (X509Tools.getX509Username(context) != null && X509Tools.isX509Registered(context)) {
            // X509 auth, invite code not required
            errors.add(new FormMessage(null, "Sorry, this CAC seems to already be registered."));
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
        }

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
        String  x509Username = X509Tools.getX509Username(context);
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String[] subjectNameArray = certs[0].getSubjectX500Principal().getName().split(",");
        String firstName = subjectNameArray[0].split("\\.")[1];
        String lastName = subjectNameArray[0].split("\\.")[0].replace("CN=", "");
        String affiliation = subjectNameArray[1].replace("OU=", "");
        String translatedAffiliation = X509Tools.translateAffiliationShortName(affiliation);

        MultivaluedMap<String, String> retFormData = new MultivaluedHashMap<>(formData);
        retFormData.add("cacIdentity", x509Username);
        retFormData.add(RegistrationPage.FIELD_FIRST_NAME, firstName);
        retFormData.add(RegistrationPage.FIELD_LAST_NAME, lastName);
        retFormData.add(USER_ATTRIBUTES_AFFILIATION, translatedAffiliation);
        LOGGER.debug(retFormData);
        return retFormData;
    }
}
