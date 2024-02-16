package dod.p1.keycloak.registration;

import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.security.cert.X509Certificate;

import static dod.p1.keycloak.common.CommonConfig.getInstance;
import static dod.p1.keycloak.registration.X509Tools.isX509Registered;
import static dod.p1.keycloak.registration.X509Tools.getX509Username;

public class UpdateX509 implements RequiredActionProvider, RequiredActionFactory {

      /**
     * Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(UpdateX509.class);

    /**
     * Provider id.
     */
    private static final String PROVIDER_ID = "UPDATE_X509";
    /**
     * Ignore x509.
     */
    private static final String IGNORE_X509 = "IGNORE_X509";

    /**
     * Custom implementation.
     */
     @Override
     public void evaluateTriggers(final RequiredActionContext context) {
         //LOGGER.debugf("UpdateX509::evaluateTriggers");
         String ignore = context.getAuthenticationSession().getAuthNote(IGNORE_X509);
         String x509Username = getX509Username(context);
         if (x509Username == null || ignore != null && ignore.equals("true")) {
             //LOGGER.debugf("UpdateX509::evaluateTriggers x509Username == null");
             return;
         }

         RealmModel realm = context.getRealm();
         KeycloakSession session = context.getSession();
         AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

         X509Certificate[] certAttribute = context.getHttpRequest().getClientCertificateChain();
         Map<String, List<String>> userAttrs = context.getUser().getAttributes();
         if (userAttrs.containsKey("usercertificate")) {
             List<String> identity = userAttrs.get("usercertificate");
             if (identity != null && !identity.isEmpty()) {
                 //LOGGER.debugf("UpdateX509::evaluateTriggers: usercertificate: %s", identity);
                 context.getUser().setSingleAttribute(
                         getInstance(session, realm).getUserActive509Attribute(),
                         identity.get(0));
                 // LOGGER.debugf("UpdateX509::evaluateTriggers: activecac: %s",
                 //   getInstance(session, realm).getUserActive509Attribute());
             }
         }

         if (!isX509Registered(context)) {
             context.getUser().addRequiredAction(PROVIDER_ID);
         }

     }

    /**
     * Custom implementation.
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
     * Custom implementation.
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
     * Custom implementation.
     */
    @Override
    public String getDisplayText() {
        return "Update X509";
    }

    /**
     * Custom implementation.
     */
    @Override
    public boolean isOneTimeAction() {
        return true;
    }

    /**
     * Custom implementation.
     */
    @Override
    public RequiredActionProvider create(final KeycloakSession session) {
        return this;
    }

    /**
     * Custom implementation.
     */
    @Override
    public void init(final Config.Scope config) {
        // no implementation needed
    }

    /**
     * Custom implementation.
     */
    @Override
    public void postInit(final KeycloakSessionFactory factory) {
        // no implementation needed
    }

    /**
     * Custom implementation.
     */
    @Override
    public void close() {
        // no implementation needed
    }

    /**
     * Custom implementation.
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
