package dod.p1.keycloak.events;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.common.YAMLConfigMattermostProvisioning;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;

import org.json.JSONObject;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Event listener provider for Mattermost user provisioning.
 * Handles user registration events and provisions them in Mattermost.
 */
public class MattermostProvisioningEventListenerProvider implements EventListenerProvider {

    /** Logger instance for this class. */
    private static final Logger LOG = Logger.getLogger(MattermostProvisioningEventListenerProvider.class);

    /** The Keycloak session. */
    private final KeycloakSession session;
    /** The Mattermost provisioning configuration. */
    private final YAMLConfigMattermostProvisioning config;

    /**
     * Constructs a new MattermostProvisioningEventListenerProvider.
     *
     * @param keycloakSession The Keycloak session
     */
    public MattermostProvisioningEventListenerProvider(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;

        // Load configuration from YAML file
        YAMLConfigMattermostProvisioning loadedConfig = null;
        RealmModel realm = keycloakSession.getContext().getRealm();
        if (realm != null) {
            try {
                CommonConfig commonConfig = CommonConfig.getInstance(keycloakSession, realm);
                loadedConfig = commonConfig.getMattermostProvisioningConfig();
            } catch (Exception e) {
                LOG.error("Failed to load Mattermost provisioning config from YAML", e);
            }
        }

        // Set final config value
        this.config = (loadedConfig != null) ? loadedConfig : new YAMLConfigMattermostProvisioning();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onEvent(final Event event) {
        if (config == null || !config.isEnabled()) {
            return;
        }

        // Check if we have any environments configured
        if (config.getEnvironments() == null || config.getEnvironments().isEmpty()) {
            LOG.debug("No Mattermost environments configured");
            return;
        }

        // Handle VERIFY_EMAIL event for new user provisioning
        // This ensures the user has a valid email before provisioning
        if (event.getType() == EventType.VERIFY_EMAIL) {
            handleUserProvisioning(event);
        }
    }

    private void handleUserProvisioning(final Event event) {
        try {
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            if (realm == null) {
                LOG.warn("Realm not found for event: " + event.getRealmId());
                return;
            }

            UserModel user = session.users().getUserById(realm, event.getUserId());
            if (user == null) {
                LOG.warn("User not found for event: " + event.getUserId());
                return;
            }

            // Check if user has already been provisioned
            String provisionedAttribute = user.getFirstAttribute("mattermost_provisioned");
            if ("true".equals(provisionedAttribute)) {
                LOG.debug("User already provisioned in Mattermost: " + user.getUsername());
                return;
            }

            // Get user's persona attribute
            String persona = user.getFirstAttribute("persona");
            if (persona == null || persona.isEmpty()) {
                LOG.info("No persona attribute found for user: " + user.getUsername());
                return;
            }

            LOG.info("Provisioning user in Mattermost environments: " + user.getUsername()
                    + " with persona: " + persona);

            // Track which environments succeeded
            List<String> provisionedEnvironments = new ArrayList<>();
            List<String> failedEnvironments = new ArrayList<>();

            // Provision in each enabled environment
            for (Map.Entry<String, YAMLConfigMattermostProvisioning.MattermostEnvironment> entry
                    : config.getEnvironments().entrySet()) {

                String envName = entry.getKey();
                YAMLConfigMattermostProvisioning.MattermostEnvironment envConfig = entry.getValue();

                // Skip disabled environments
                if (!envConfig.isEnabled()) {
                    LOG.debugf("Skipping disabled environment: %s", envName);
                    continue;
                }

                LOG.infof("Provisioning user %s in environment: %s", user.getUsername(), envName);

                // Prepare provisioning request
                JSONObject request = new JSONObject();
                request.put("username", user.getUsername());
                request.put("email", user.getEmail());
                request.put("firstName", user.getFirstName());
                request.put("lastName", user.getLastName());
                request.put("persona", persona);

                // Get Keycloak ID for SAML auth_data
                String keycloakId = user.getId();
                request.put("mattermostId", keycloakId);

                // Generate unique idempotency key per environment
                String idempotencyKey = UUID.randomUUID().toString();

                // Call Mattermost provision endpoint for this environment
                boolean success = callMattermostProvisionEndpoint(request, idempotencyKey, envConfig);

                if (success) {
                    provisionedEnvironments.add(envName);
                    LOG.infof("Successfully provisioned user %s in %s", user.getUsername(), envName);
                } else {
                    failedEnvironments.add(envName);
                    LOG.warnf("Failed to provision user %s in %s", user.getUsername(), envName);
                }
            }

            // Update user attributes with provisioning status
            if (!provisionedEnvironments.isEmpty()) {
                user.setSingleAttribute("mattermost_provisioned", "true");
                user.setSingleAttribute("mattermost_provisioned_environments",
                        String.join(",", provisionedEnvironments));
                user.setSingleAttribute("mattermost_provisioned_date", String.valueOf(System.currentTimeMillis()));
                LOG.infof("User %s provisioned in environments: %s", user.getUsername(), provisionedEnvironments);
            }

            if (!failedEnvironments.isEmpty()) {
                user.setSingleAttribute("mattermost_provisioned_failed", String.join(",", failedEnvironments));
                LOG.warnf("User %s failed provisioning in environments: %s", user.getUsername(), failedEnvironments);
            }

        } catch (Exception e) {
            LOG.error("Error provisioning user in Mattermost", e);
        }
    }

    private boolean callMattermostProvisionEndpoint(final JSONObject request,
            final String idempotencyKey,
            final YAMLConfigMattermostProvisioning.MattermostEnvironment envConfig) {

        CloseableHttpClient httpClient = null;
        try {
            httpClient = createHttpClient();
            HttpPost httpPost = new HttpPost(envConfig.getProvisionUrl());

            // Set headers
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Authorization", "Bearer " + envConfig.getProvisionToken());
            httpPost.setHeader("Idempotency-Key", idempotencyKey);
            httpPost.setHeader("X-Correlation-ID", UUID.randomUUID().toString());

            // Set request body
            StringEntity entity = new StringEntity(request.toString());
            httpPost.setEntity(entity);

            // Set timeout
            final int timeoutMillis = config.getRequestTimeoutSeconds() * 1000;
            RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(timeoutMillis)
                .setConnectTimeout(timeoutMillis)
                .setConnectionRequestTimeout(timeoutMillis)
                .build();
            httpPost.setConfig(requestConfig);

            // Execute request
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());

            if (statusCode == HttpStatus.SC_OK) {
                JSONObject jsonResponse = new JSONObject(responseBody);
                if (jsonResponse.optBoolean("ok", false)) {
                    LOG.info("Mattermost provisioning successful: " + jsonResponse.toString());
                    return true;
                } else {
                    LOG.error("Mattermost provisioning failed: " + responseBody);
                    return false;
                }
            } else if (statusCode == HttpStatus.SC_UNPROCESSABLE_ENTITY) {
                LOG.warn("Persona or IL mapping issue: " + responseBody);
                return false;
            } else if (statusCode == HttpStatus.SC_CONFLICT) {
                LOG.warn("User conflict in Mattermost: " + responseBody);
                // Consider this successful since user exists
                return true;
            } else {
                LOG.error("Mattermost provisioning failed with status " + statusCode + ": " + responseBody);
                return false;
            }

        } catch (Exception e) {
            LOG.error("Error calling Mattermost provision endpoint", e);
            return false;
        } finally {
            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (IOException e) {
                    LOG.error("Error closing HTTP client", e);
                }
            }
        }
    }

    /**
     * Creates an HTTP client with SSL configuration.
     *
     * @return The configured HTTP client
     * @throws NoSuchAlgorithmException if SSL algorithm is not available
     * @throws KeyStoreException if keystore cannot be accessed
     * @throws KeyManagementException if key management fails
     */
    private CloseableHttpClient createHttpClient()
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial((chain, authType) -> true)  // Trust all certificates (for internal use)
            .build();

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
            sslContext,
            NoopHostnameVerifier.INSTANCE);

        return HttpClients.custom()
            .setSSLSocketFactory(sslSocketFactory)
            .build();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onEvent(final AdminEvent event, final boolean includeRepresentation) {
        // Not handling admin events for provisioning
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        // Cleanup if needed
    }
}
