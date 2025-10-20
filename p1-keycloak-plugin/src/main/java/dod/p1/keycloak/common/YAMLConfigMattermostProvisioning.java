package dod.p1.keycloak.common;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

/**
 * YAML configuration for Mattermost provisioning.
 */
@NoArgsConstructor
@Getter
@Setter
public class YAMLConfigMattermostProvisioning {

    /**
     * Whether Mattermost provisioning is enabled.
     */
    private boolean enabled = false;

    /**
     * Map of impact level to Mattermost configuration.
     * Example: IL2 -> {url: "https://chat.il2.dso.mil/...", token: "pvt_xxx"}
     */
    private Map<String, MattermostEnvironment> environments;

    /** Default request timeout in seconds. */
    private static final int DEFAULT_REQUEST_TIMEOUT = 30;

    /**
     * Request timeout in seconds.
     */
    private int requestTimeoutSeconds = DEFAULT_REQUEST_TIMEOUT;

    /**
     * Configuration for a specific Mattermost environment.
     */
    @NoArgsConstructor
    @Getter
    @Setter
    public static class MattermostEnvironment {
        /**
         * Whether this environment is enabled for provisioning.
         */
        private boolean enabled = true;

        /**
         * Mattermost provisioning endpoint URL.
         */
        private String provisionUrl;

        /**
         * Provisioning token for authentication.
         */
        private String provisionToken;
    }
}
