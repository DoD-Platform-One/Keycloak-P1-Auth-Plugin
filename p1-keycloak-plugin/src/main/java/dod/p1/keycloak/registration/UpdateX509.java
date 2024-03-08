package dod.p1.keycloak.registration;

import java.util.List;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import static dod.p1.keycloak.common.CommonConfig.getInstance;
import static dod.p1.keycloak.registration.X509Tools.isX509Registered;
import static dod.p1.keycloak.registration.X509Tools.getX509Username;

/**
 * Implementation of RequiredActionProvider and RequiredActionFactory for updating X509 certificates.
 */
public class UpdateX509 implements RequiredActionProvider, RequiredActionFactory {

    /** Provider id. */
    private static final String PROVIDER_ID = "UPDATE_X509";

    /** Ignore x509. */
    private static final String IGNORE_X509 = "IGNORE_X509";

    /**
     * Evaluates triggers for the X509 update process.
     *
     * @param context The RequiredActionContext providing context information.
     */
     @Override
     public void evaluateTriggers(final RequiredActionContext context) {
         String ignore = context.getAuthenticationSession().getAuthNote(IGNORE_X509);
         String x509Username = getX509Username(context);
         if (x509Username == null || ignore != null && ignore.equals("true")) {
             return;
         }

         RealmModel realm = context.getRealm();
         KeycloakSession session = context.getSession();

         Map<String, List<String>> userAttrs = context.getUser().getAttributes();
         if (userAttrs.containsKey("usercertificate")) {
             List<String> identity = userAttrs.get("usercertificate");
             if (identity != null && !identity.isEmpty()) {
                 context.getUser().setSingleAttribute(
                         getInstance(session, realm).getUserActive509Attribute(),
                         identity.get(0));
             }
         }

         if (!isX509Registered(context)) {
             context.getUser().addRequiredAction(PROVIDER_ID);
         }

     }

    /**
     * Initiates the challenge for the X509 update process.
     *
     * @param context The RequiredActionContext providing context information.
     */
    @Override
    public void requiredActionChallenge(final RequiredActionContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user");
        formData.add("subjectDN", getX509Username(context));
        formData.add("isUserEnabled", "true");
        context.form().setFormData(formData);

        Response challenge = context.form().createX509ConfirmPage();
        context.challenge(challenge);
    }

    /**
     * Processes the action during the X509 update process.
     *
     * @param context The RequiredActionContext providing context information.
     */
    @Override
    public void processAction(final RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.getAuthenticationSession().setAuthNote(IGNORE_X509, "true");
            context.success();
            return;
        }

        String username = getX509Username(context);
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        if (username != null) {
            UserModel user = context.getUser();
            user.setSingleAttribute(getInstance(session, realm).getUserIdentityAttribute(), username);
            getInstance(session, realm).getAutoJoinGroupX509().forEach(user::joinGroup);
        }
        context.success();
    }

    /**
     * Gets the display text for the X509 update process.
     *
     * @return The display text.
     */
    @Override
    public String getDisplayText() {
        return "Update X509";
    }

    /**
     * Indicates whether the X509 update action is one-time or persistent.
     *
     * @return True if the action is one-time, false otherwise.
     */
    @Override
    public boolean isOneTimeAction() {
        return true;
    }

    /**
     * Creates an instance of the X509 update provider.
     *
     * @param session The KeycloakSession.
     * @return The RequiredActionProvider instance.
     */
    @Override
    public RequiredActionProvider create(final KeycloakSession session) {
        return this;
    }

    /**
     * Initializes the X509 update provider.
     *
     * @param config The configuration scope.
     */
    @Override
    public void init(final Config.Scope config) {
        // no implementation needed
    }

    /**
     * Performs post-initialization tasks for the X509 update provider.
     *
     * @param factory The KeycloakSessionFactory.
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // no implementation needed
    }

    /**
     * Closes the X509 update provider.
     */
    @Override
    public void close() {
        // no implementation needed
    }

    /**
     * Gets the provider id for the X509 update provider.
     *
     * @return The provider id.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
