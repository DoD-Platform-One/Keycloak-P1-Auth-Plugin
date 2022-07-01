package dod.p1.keycloak.registration;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationPassword;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

public class RegistrationX509Password extends RegistrationPassword {

    /**
     * Provider ID.
     */
    public static final String PROVIDER_ID = "registration-x509-password-action";
    /**
     * Requirement choices.
     */
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED };

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public String getHelpText() {
        return "Disables password registration if CAC authentication is possible.";
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>();
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public void validate(final ValidationContext context) {
        if (X509Tools.getX509Username(context) == null) {
            super.validate(context);
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        if (formData.getFirst(RegistrationPage.FIELD_PASSWORD).isEmpty()
                && formData.getFirst(RegistrationPage.FIELD_PASSWORD_CONFIRM).isEmpty()) {
            context.success();
            return;
        }

        if (!formData.getFirst(RegistrationPage.FIELD_PASSWORD)
                .equals(formData.getFirst(RegistrationPage.FIELD_PASSWORD_CONFIRM))) {
            errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD_CONFIRM, Messages.INVALID_PASSWORD_CONFIRM));
        }

        if (formData.getFirst(RegistrationPage.FIELD_PASSWORD) != null) {
            PolicyError err = context.getSession().getProvider(PasswordPolicyManagerProvider.class).validate(
                    context.getRealm().isRegistrationEmailAsUsername() ? formData.getFirst(RegistrationPage.FIELD_EMAIL)
                            : formData.getFirst(RegistrationPage.FIELD_USERNAME),
                    formData.getFirst(RegistrationPage.FIELD_PASSWORD));
            if (err != null) {
                errors.add(new FormMessage(RegistrationPage.FIELD_PASSWORD, err.getMessage(), err.getParameters()));
            }
        }

        if (errors.size() > 0) {
            context.error(Errors.INVALID_REGISTRATION);
            formData.remove(RegistrationPage.FIELD_PASSWORD);
            formData.remove(RegistrationPage.FIELD_PASSWORD_CONFIRM);
            context.validationError(formData, errors);
        } else {
            context.success();
        }
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public void success(final FormContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        UserModel user = context.getUser();

        if ((X509Tools.getX509Username(context) == null)
                || (!formData.getFirst(RegistrationPage.FIELD_PASSWORD).isEmpty())) {
            super.success(context);
            // TOTP also enforced in RegistrationValidation class for non-CAC registration
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public void buildPage(final FormContext context, final LoginFormsProvider form) {
        if (X509Tools.getX509Username(context) == null) {
            form.setAttribute("passwordRequired", true);
        }
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public boolean requiresUser() {
        return false;
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        // no implementation needed
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() {
        // no implementation needed
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public String getDisplayType() {
        return "Platform One X509 Password Validation";
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
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
    public FormAction create(final KeycloakSession session) {
        return this;
    }

    @Override
    public void init(final Config.Scope config) {
        // no implementation needed
    }

    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // no implementation needed
    }

    /**
     * This implementation is not intended to be overridden.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
