package dod.p1.keycloak.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.ArrayList;

/**
 * Factory for creating ResetPasswordTokenValidator instances.
 */
public class ResetPasswordTokenValidatorFactory implements AuthenticatorFactory {

    /** Logger instance. */
    private static final Logger LOG = Logger.getLogger(ResetPasswordTokenValidatorFactory.class);

    /** Log prefix for easy grepping. */
    private static final String LOG_PREFIX = "ResetPwdValidator: ";

    /** ID of this authenticator. */
    public static final String PROVIDER_ID = "reset-password-token-validator";

    /** Display name of this authenticator. */
    private static final String DISPLAY_TYPE = "Reset Password Token Validator";

    /** Help text for this authenticator. */
    private static final String HELP_TEXT =
            "Validates that the reset password token is the most recent one for the user.";

    /** Reference category for this authenticator. */
    private static final String REFERENCE_CATEGORY = "Reset Password";

    /**
     * Get the display type for this authenticator.
     *
     * @return The display type
     */
    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    /**
     * Get the reference category for this authenticator.
     *
     * @return The reference category
     */
    @Override
    public String getReferenceCategory() {
        return REFERENCE_CATEGORY;
    }

    /**
     * Check if this authenticator is configurable.
     *
     * @return True if configurable, false otherwise
     */
    @Override
    public boolean isConfigurable() {
        return false;
    }

    /**
     * Get the requirement choices for this authenticator.
     *
     * @return The requirement choices
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    /**
     * Check if user setup is allowed for this authenticator.
     *
     * @return True if user setup is allowed, false otherwise
     */
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    /**
     * Get the help text for this authenticator.
     *
     * @return The help text
     */
    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    /**
     * Get the configuration properties for this authenticator.
     *
     * @return The configuration properties
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>();
    }

    /**
     * Create a new instance of the authenticator.
     *
     * @param session The Keycloak session
     * @return The authenticator instance
     */
    @Override
    public Authenticator create(final KeycloakSession session) {
        LOG.debug(LOG_PREFIX + "Creating ResetPasswordTokenValidator instance");
        return new ResetPasswordTokenValidator();
    }

    /**
     * Initialize the factory.
     *
     * @param config The configuration
     */
    @Override
    public void init(final Config.Scope config) {
        LOG.debug(LOG_PREFIX + "Initializing ResetPasswordTokenValidatorFactory");
    }

    /**
     * Post-initialize the factory.
     *
     * @param factory The Keycloak session factory
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        LOG.debug(LOG_PREFIX + "Post-initializing ResetPasswordTokenValidatorFactory");
    }

    /**
     * Close the factory.
     */
    @Override
    public void close() {
        // Nothing to close
    }

    /**
     * Get the ID of this authenticator factory.
     *
     * @return The ID
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
