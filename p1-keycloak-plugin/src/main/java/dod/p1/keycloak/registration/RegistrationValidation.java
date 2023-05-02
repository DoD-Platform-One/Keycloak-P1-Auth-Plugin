package dod.p1.keycloak.registration;

import static dod.p1.keycloak.common.CommonConfig.getInstance;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationProfile;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import dod.p1.keycloak.common.CommonConfig;

public class RegistrationValidation extends RegistrationProfile {

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
     * Requirement choices.
     */
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED };

    /**
     * The minimum length of user name.
     */
    private static final int MIN_USER_NAME_LENGTH = 3;

    /**
     * The max length of user name.
     */
    private static final int MAX_USER_NAME_LENGTH = 22;

    private static void bindRequiredActions(final UserModel user, final String x509Username) {
        // Default actions for all users
        user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);

        // Make GS-15 Matt and the Cyber Humans happy
        user.addRequiredAction("TERMS_AND_CONDITIONS");

        if (x509Username == null) {
            // This user must configure MFA for their login
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    private static void processX509UserAttribute(
        final RealmModel realm,
        final UserModel user,
        final String x509Username) {

        if (x509Username != null) {
            // Bind the X509 attribute to the user
            user.setSingleAttribute(getInstance(realm).getUserIdentityAttribute(), x509Username);
        }
    }

    private static void joinValidUserToGroups(
        final FormContext context,
        final UserModel user,
        final String x509Username) {

        String email = user.getEmail().toLowerCase();
        RealmModel realm = context.getRealm();
        CommonConfig config = getInstance(realm);

        long domainMatchCount = config.getEmailMatchAutoJoinGroup()
                .filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith)).count();

        if (x509Username != null) {
            // User is a X509 user - Has a CAC
            CommonConfig.LOGGER_COMMON.info(
        "{} {} / {} found with X509: {}",
                LOGGING_USER_TEXT, user.getId(), user.getUsername(), x509Username);
            config.getAutoJoinGroupX509().forEach(user::joinGroup);
        } else {
          if (domainMatchCount != 0) {
            // User is not a X509 user but is in the whitelist
            CommonConfig.LOGGER_COMMON.info(
        "{} {} / {}: Email found in whitelist",
                LOGGING_USER_TEXT, user.getUsername(), email);
            config.getEmailMatchAutoJoinGroup()
                  .filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith))
                  .forEach(match -> {
                    CommonConfig.LOGGER_COMMON.info(
                "Adding user {} to group(s): {}",
                        user.getUsername(), match.getGroups());
                    match.getGroupModels().forEach(user::joinGroup);
                  });

        } else {
            // User is not a X509 user or in whitelist
            CommonConfig.LOGGER_COMMON.info(
        "{} {} / {}: Email Not found in whitelist",
                LOGGING_USER_TEXT, user.getUsername(), email);
            config.getNoEmailMatchAutoJoinGroup().forEach(user::joinGroup);
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
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String x509Username = X509Tools.getX509Username(context);

        generateUniqueStringIdForMattermost(formData, user);
        joinValidUserToGroups(context, user, x509Username);
        processX509UserAttribute(realm, user, x509Username);
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

        if (Validation.isBlank(formData.getFirst("user.attributes.affiliation"))) {
            errors.add(new FormMessage("user.attributes.affiliation", "Please specify your organization affiliation."));
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

    private void mattermostUsernameValidation(final List<FormMessage> errors, final String username) {
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

}
