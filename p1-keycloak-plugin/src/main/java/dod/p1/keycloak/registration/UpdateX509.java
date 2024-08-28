package dod.p1.keycloak.registration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.List;
import java.util.Map;

import dod.p1.keycloak.common.CommonConfig;
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

    /** Provider id. **/
    private static final String PROVIDER_ID = "UPDATE_X509";

    /** Ignore x509. **/
    private static final String IGNORE_X509 = "IGNORE_X509";
    /** Logger. **/
    private static final Logger LOGGER = LogManager.getLogger(UpdateX509.class);
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

         if (userAttrs.containsKey(CommonConfig.getInstance(session, realm).getUserIdentityAttribute(realm))) {
             List<String> identity = userAttrs.get(CommonConfig.getInstance(session, realm)
                                                .getUserIdentityAttribute(realm));
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
        LOGGER.debug("processAction() method");
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
            String userIdentityAttribute = getInstance(session, realm).getUserIdentityAttribute(realm);
            LOGGER.info("Setting user identity attribute: {} for user: {}",
                    userIdentityAttribute,
                    user.getUsername());
            user.setSingleAttribute(userIdentityAttribute, username);

            // In each of the next check we will have to make sure that the group is null.
            // Sometimes for some reason it is and this will cause an exception that will make
            // keycloak end up in a limbo state. The following condition takes care of it and now
            // keycloak can continue with account assignment without getting into limbo state.
            getInstance(session, realm).getAutoJoinGroupX509().forEach(group -> {
                if (group != null) {
                    LOGGER.info("Joining user: {} to group: {}",
                            user.getUsername(), group.getName());
                    user.joinGroup(group);
                } else {
                    LOGGER.error("Encountered null group for user: {}. Skipping group join operation.",
                            user.getUsername());
                }
            });
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
