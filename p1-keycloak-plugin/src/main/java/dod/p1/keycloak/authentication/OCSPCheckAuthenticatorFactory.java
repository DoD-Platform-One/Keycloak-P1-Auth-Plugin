package dod.p1.keycloak.authentication;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory class for OCSPCheckAuthenticator.
 */
public class OCSPCheckAuthenticatorFactory implements AuthenticatorFactory {

    /**
     * Provider ID variable.
     */
    public static final String PROVIDER_ID = "p1-ocsp-check";
    /**
     * OCSP authenticator instance.
     */
    public static final OCSPCheckAuthenticator OCSP_AUTHENTICATOR = new OCSPCheckAuthenticator();
    /**
     * Requirement choices variable.
     */
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    /**
     * Returns the unique identifier for this authenticator provider.
     *
     * @return the provider ID as a {@link String}
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Creates a new instance of the OCSP authenticator.
     *
     * @param session the {@link KeycloakSession} for the current session
     * @return an {@link Authenticator} instance
     */
    @Override
    public Authenticator create(final KeycloakSession session) {
        return OCSP_AUTHENTICATOR; // Corrected variable name
    }

    /**
     * Initializes the provider with the given configuration.
     * <p>
     * No initialization is required for this provider.
     * </p>
     *
     * @param scope the {@link Config.Scope} for configuration
     */
    @Override
    public void init(final Config.Scope scope) {
        // no implementation needed here
    }

    /**
     * Performs post-initialization tasks.
     * <p>
     * No post-initialization tasks are required for this provider.
     * </p>
     *
     * @param keycloakSessionFactory the {@link KeycloakSessionFactory} for creating sessions
     */
    @Override
    public void postInit(final KeycloakSessionFactory keycloakSessionFactory) {
        // no implementation needed here
    }

    /**
     * Closes the provider and releases any resources, if necessary.
     */
    @Override
    public void close() {
        // no implementation needed here
    }

    /**
     * Returns the display name of this authenticator.
     *
     * @return a {@link String} representing the display name
     */
    @Override
    public String getDisplayType() {
        return "Platform One OCSP Check";
    }

    /**
     * Returns the reference category for this authenticator.
     * <p>
     * This implementation does not define a reference category and returns {@code null}.
     * </p>
     *
     * @return {@code null}
     */
    @Override
    public String getReferenceCategory() {
        return null;
    }

    /**
     * Indicates whether this authenticator is configurable.
     *
     * @return {@code false}, indicating the authenticator is not configurable
     */
    @Override
    public boolean isConfigurable() {
        return false;
    }

    /**
     * Returns the set of requirement choices for this authenticator.
     *
     * @return an array of {@link AuthenticationExecutionModel.Requirement} options
     */
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    /**
     * Indicates whether the user is allowed to set up this authenticator.
     *
     * @return {@code false}, indicating user setup is not allowed
     */
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    /**
     * Provides help text describing the purpose of this authenticator.
     *
     * @return a {@link String} containing the help text
     */
    @Override
    public String getHelpText() {
        return "Performs OCSP verification on the user's X.509 certificate.";
    }

    /**
     * Returns a list of configurable properties for this provider.
     * <p>
     * This implementation does not define any configurable properties and returns an empty list.
     * </p>
     *
     * @return an empty {@link List} of {@link ProviderConfigProperty}
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        // return empty collection
        return new ArrayList<>();
    }
}
